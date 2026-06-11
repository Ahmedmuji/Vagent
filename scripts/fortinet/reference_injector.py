from __future__ import annotations

import copy
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from fortinet.rag_matcher import FortinetCandidate, FortinetRAGMatcher
from product_matcher import NUMERIC_REQUIREMENT_FIELDS, ProductMatcher


REFERENCE_COLUMN = "References"
HARDWARE_REASONING_COLUMN = "Hardware_Reference_Reasoning"
MATCH_DETAILS_COLUMN = "Reference_Match_Details"


class FortinetReferenceInjector:
    def __init__(self, catalog_dir: str):
        include_juniper = os.getenv("FORTINET_RAG_INCLUDE_JUNIPER", "1").lower() not in {"0", "false", "no", "off"}
        self.matcher = FortinetRAGMatcher(
            catalog_dir,
            top_k=int(os.getenv("FORTINET_RAG_TOP_K", "8")),
            use_llm=False,
            include_juniper=include_juniper,
        )
        self.batch_candidate_limit = int(os.getenv("FORTINET_RAG_BATCH_CANDIDATES", "3"))
        self.batch_llm_enabled = os.getenv("FORTINET_RAG_USE_LLM", "1").lower() not in {"0", "false", "no", "off"}
        self.stats = {
            "rows_seen": 0,
            "sections_skipped": 0,
            "groups_seen": 0,
            "matched_rows": 0,
            "unmatched_rows": 0,
            "llm_batch_calls": 0,
            "llm_rows_sent": 0,
        }

    def inject(self, data: Dict[str, Any]) -> Dict[str, Any]:
        enriched = copy.deepcopy(data)
        for sheet in enriched.get("sheets", []) if isinstance(enriched, dict) else []:
            if isinstance(sheet, dict):
                self._inject_sheet(sheet)
        return enriched

    def _inject_sheet(self, sheet: Dict[str, Any]) -> None:
        if self._should_skip_sheet(sheet):
            return
        headers = sheet.get("headers") or []
        for column in (REFERENCE_COLUMN, HARDWARE_REASONING_COLUMN, MATCH_DETAILS_COLUMN):
            if column not in headers:
                headers.append(column)
        ref_idx = headers.index(REFERENCE_COLUMN)
        reason_idx = headers.index(HARDWARE_REASONING_COLUMN)
        details_idx = headers.index(MATCH_DETAILS_COLUMN)
        rows = sheet.get("rows") or []
        inferred_blocks = self._infer_product_blocks(sheet, headers)
        anchor_to_block = {block["anchor_idx"]: block for block in inferred_blocks}
        covered_to_anchor = {
            idx: block["anchor_idx"]
            for block in inferred_blocks
            for idx in range(block["start_idx"], block["end_idx"] + 1)
        }
        pending: List[Dict[str, Any]] = []
        for row_idx, row in enumerate(rows):
            self.stats["rows_seen"] += 1
            row_type, row_data, metadata = self._get_row_parts(row)
            self._ensure_len(row_data, len(headers))
            row_data[ref_idx] = ""
            row_data[reason_idx] = ""
            row_data[details_idx] = ""
            if isinstance(row, dict) and REFERENCE_COLUMN in row:
                row[REFERENCE_COLUMN] = ""
            if row_type == "section":
                self.stats["sections_skipped"] += 1
                continue
            text = self._row_text(headers, row_data)
            contextual_text = self._contextual_row_text(sheet, headers, text)
            effective_metadata = self._effective_metadata(metadata, contextual_text)
            inferred_block = anchor_to_block.get(row_idx)
            if inferred_block is None and row_idx in covered_to_anchor:
                continue
            if (
                inferred_block is None
                and self._is_single_product_firewall_sheet(sheet, headers, contextual_text)
                and row_idx != self._first_data_row_index(sheet)
                and metadata.get("product_group_primary_row") is not True
                and metadata.get("group_primary_row") is not True
            ):
                continue
            if not self._is_reference_anchor(metadata, effective_metadata):
                continue
            if not self._should_reference(contextual_text, effective_metadata):
                continue
            self.stats["groups_seen"] += 1
            if inferred_block is not None:
                contextual_text = self._inferred_block_context(sheet, headers, inferred_block)
            contextual_text = self._group_contextual_row_text(sheet, headers, row_idx, contextual_text, metadata)
            if inferred_block is None:
                contextual_text = self._single_product_contextual_row_text(sheet, headers, row_idx, contextual_text, effective_metadata)
            query = self.matcher._build_query(contextual_text, effective_metadata)
            constraints = self.matcher._parse_constraints(query, effective_metadata)
            vendors = self.matcher._default_vendors(constraints)
            vendor_items: Dict[str, Dict[str, Any]] = {}
            for vendor in vendors:
                retrieved = self.matcher.retrieve(query, constraints, vendor=vendor)
                safe_candidates = [
                    candidate for candidate in retrieved
                    if self.matcher._passes_hard_constraints(candidate.product, constraints)
                ]
                candidates = self.matcher._merge_candidates(
                    safe_candidates,
                    self.matcher._safe_catalog_candidates(query, constraints, vendor),
                    constraints,
                )
                local_selected = self.matcher._select_fallback(candidates, constraints) if candidates else None
                vendor_items[vendor] = {
                    "retrieved": retrieved,
                    "candidates": candidates,
                    "local_selected": local_selected,
                }
            pending.append({
                "row_id": f"{sheet.get('title') or sheet.get('name') or 'Sheet'}:{row_idx + 1}",
                "row": row,
                "row_data": row_data,
                "query": query,
                "constraints": constraints,
                "vendors": vendor_items,
            })
        decisions = self._batch_llm_decide(pending)
        for item in pending:
            result = self._result_for_pending_item(item, decisions)
            row_data = item["row_data"]
            reference = result.get("reference") or ""
            row_data[ref_idx] = reference
            row_data[reason_idx] = result.get("reasoning") or ""
            row_data[details_idx] = json.dumps(result.get("details") or {}, ensure_ascii=False, indent=2)
            row = item["row"]
            if isinstance(row, dict) and REFERENCE_COLUMN in row:
                row[REFERENCE_COLUMN] = reference
            if reference:
                self.stats["matched_rows"] += 1
            else:
                self.stats["unmatched_rows"] += 1
        sheet["headers"] = headers

    def _result_for_pending_item(self, item: Dict[str, Any], decisions: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        references: List[str] = []
        reasoning: List[str] = []
        vendor_details: Dict[str, Any] = {}
        for vendor, vendor_item in item["vendors"].items():
            candidates: List[FortinetCandidate] = vendor_item["candidates"]
            retrieved: List[FortinetCandidate] = vendor_item["retrieved"]
            decision = decisions.get(f"{item['row_id']}::{vendor.lower()}")
            if not candidates:
                vendor_result = {
                    "reference": "",
                    "reasoning": f"{vendor}: no catalog item met all hard constraints without being under-spec.",
                    "details": {
                        "provider": "fortinet-rag",
                        "vendor": vendor,
                        "match_status": "no_safe_match",
                        "query": item["query"],
                        "constraints": item["constraints"],
                        "top_candidates": self.matcher._candidate_summaries(retrieved),
                    },
                }
            else:
                selected = None
                if decision and decision.get("selected_model") and str(decision.get("match_status", "")).lower() != "no_safe_match":
                    selected = self.matcher._candidate_by_model(candidates, str(decision["selected_model"]))
                if selected is None:
                    selected = vendor_item.get("local_selected") or candidates[0]
                    decision = None
                vendor_result = self.matcher._format_result(
                    selected,
                    item["query"],
                    item["constraints"],
                    retrieved,
                    decision,
                )
            if vendor_result.get("reference"):
                references.append(vendor_result["reference"])
            if vendor_result.get("reasoning"):
                reasoning.append(vendor_result["reasoning"])
            vendor_details[vendor] = vendor_result.get("details")
        return {
            "reference": " | ".join(references),
            "reasoning": "\n\n".join(reasoning),
            "details": {
                "provider": "fortinet-rag",
                "query": item["query"],
                "constraints": item["constraints"],
                "vendors": vendor_details,
            },
        }

    def _batch_llm_decide(self, pending: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        if not self.batch_llm_enabled or not api_key or not pending:
            return {}
        payload = []
        for item in pending:
            for vendor, vendor_item in item["vendors"].items():
                candidates = vendor_item["candidates"][: self.batch_candidate_limit]
                if not candidates:
                    continue
                payload.append({
                    "row_vendor_id": f"{item['row_id']}::{vendor.lower()}",
                    "row_id": item["row_id"],
                    "vendor": vendor,
                    "requirement": item["query"][:1200],
                    "parsed_constraints": item["constraints"],
                    "candidates": [
                        {
                            "model": candidate.product.get("model"),
                            "vendor": candidate.product.get("vendor"),
                            "category": candidate.product.get("category"),
                            "datasheet_url": candidate.product.get("datasheet_url"),
                            "product_url": candidate.product.get("product_url"),
                            "retrieval_score": round(candidate.score, 4),
                            "evidence": candidate.chunk[:900],
                        }
                        for candidate in candidates
                    ],
                })
        if not payload:
            return {}
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            prompt = (
                "You are selecting Fortinet/Juniper hardware references for RFP/BOQ compliance rows.\n"
                "Choose only from the supplied candidates for each row_vendor_id. Python has already removed known under-spec candidates; "
                "still reject any candidate that appears below the parsed hard constraints. Prefer the closest safe fit.\n"
                "Return only valid JSON in this exact shape: "
                "{\"matches\":[{\"row_vendor_id\":\"...\",\"selected_model\":\"...\",\"match_status\":\"safe_match|family_match|no_safe_match\","
                "\"confidence\":0.0,\"reasoning\":\"...\",\"satisfied_requirements\":[],\"uncertain_requirements\":[]}]}\n\n"
                f"Rows:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
            )
            response = client.models.generate_content(
                model=os.getenv("FORTINET_RAG_LLM_MODEL", "gemini-3-flash-preview"),
                contents=prompt,
            )
            text = getattr(response, "text", "") or ""
            match = re.search(r"\{.*\}", text, flags=re.S)
            if not match:
                return {}
            parsed = json.loads(match.group(0))
            matches = parsed.get("matches") if isinstance(parsed, dict) else None
            if not isinstance(matches, list):
                return {}
            self.stats["llm_batch_calls"] += 1
            self.stats["llm_rows_sent"] += len(payload)
            return {
                str(item.get("row_vendor_id")): item
                for item in matches
                if isinstance(item, dict) and item.get("row_vendor_id")
            }
        except Exception:
            return {}

    @staticmethod
    def _get_row_parts(row: Any) -> Tuple[str, List[Any], Dict[str, Any]]:
        if isinstance(row, dict):
            return str(row.get("row_type", "data")), row.setdefault("data", []), row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        if isinstance(row, list):
            return "data", row, {}
        return "data", [], {}

    @staticmethod
    def _ensure_len(row_data: List[Any], target_len: int) -> None:
        while len(row_data) < target_len:
            row_data.append("")
        if len(row_data) > target_len:
            del row_data[target_len:]

    @staticmethod
    def _row_text(headers: List[str], row_data: List[Any]) -> str:
        ignored = {REFERENCE_COLUMN, HARDWARE_REASONING_COLUMN, MATCH_DETAILS_COLUMN}
        values: List[str] = []
        for idx, value in enumerate(row_data):
            header = str(headers[idx]).strip() if idx < len(headers) else ""
            if header in ignored:
                continue
            if value not in (None, ""):
                values.append(str(value))
        return " | ".join(values)

    @staticmethod
    def _contextual_row_text(sheet: Dict[str, Any], headers: List[str], text: str) -> str:
        title = str(sheet.get("title") or sheet.get("name") or sheet.get("sheet_name") or "")
        ignored = {REFERENCE_COLUMN, HARDWARE_REASONING_COLUMN, MATCH_DETAILS_COLUMN}
        header_context = " | ".join(str(header or "") for header in headers[:5] if str(header or "") not in ignored)
        return " | ".join(part for part in (title, header_context, text) if part.strip())

    @classmethod
    def _infer_product_blocks(cls, sheet: Dict[str, Any], headers: List[str]) -> List[Dict[str, int]]:
        rows = sheet.get("rows") or []
        row_texts: List[str] = []
        for row in rows:
            _, row_data, _ = cls._get_row_parts(row)
            row_texts.append(cls._row_text(headers, row_data))

        raw_anchors: List[int] = []
        for idx, text in enumerate(row_texts):
            lowered = text.lower()
            if not lowered.strip():
                continue
            if cls._is_product_anchor_text(lowered):
                raw_anchors.append(idx)

        if not raw_anchors and any("perimeter firewall" in text.lower() for text in row_texts):
            for idx, text in enumerate(row_texts):
                if "perimeter firewall" in text.lower() or "next generation firewall throughput" in text.lower():
                    raw_anchors.append(idx)
                    break

        deduped: List[int] = []
        for anchor in raw_anchors:
            if (
                deduped
                and anchor == deduped[-1] + 1
                and cls._is_section_only_product_anchor(row_texts[deduped[-1]])
            ):
                continue
            if anchor not in deduped:
                deduped.append(anchor)

        blocks: List[Dict[str, int]] = []
        for pos, start_anchor in enumerate(deduped):
            next_anchor = deduped[pos + 1] if pos + 1 < len(deduped) else len(rows)
            anchor = start_anchor
            if cls._is_section_only_product_anchor(row_texts[start_anchor]):
                for candidate_idx in range(start_anchor + 1, next_anchor):
                    if row_texts[candidate_idx].strip():
                        anchor = candidate_idx
                        break
            end_idx = max(anchor, next_anchor - 1)
            blocks.append({"anchor_idx": anchor, "start_idx": start_anchor, "end_idx": end_idx})
        return blocks

    @staticmethod
    def _is_product_anchor_text(lowered: str) -> bool:
        if "virtual router" in lowered or "virtual routers" in lowered:
            return False
        if "perimeter firewall" in lowered:
            return True
        if re.search(r"\b(?:next generation firewall|ngfw|firewall appliance|remote site firewall|central site firewall)s?\b", lowered):
            return True
        if re.search(r"\b(?:data center|datacenter|core|access|distribution)\s+switch(?:es)?\b", lowered):
            return True
        if re.search(r"\b(?:router|routing platform|edge router)s?\b", lowered):
            return True
        if re.search(r"\b(?:fortigate|fortiswitch|fortimanager|fortianalyzer|fortilogger|fortisiem)\b", lowered):
            return True
        return False

    @staticmethod
    def _is_section_only_product_anchor(text: str) -> bool:
        lowered = text.lower().strip()
        if not lowered:
            return False
        if re.search(r"\d+\s*(?:gbps|tbps|mbps|ge|gbe|g\b|tb|million|,)", lowered):
            return False
        if any(term in lowered for term in (
            "throughput", "sessions", "policies", "storage", "interfaces",
            "port", "high availability", "power supply", "routing", "inspection",
        )):
            return False
        return FortinetReferenceInjector._is_product_anchor_text(lowered)

    @classmethod
    def _inferred_block_context(cls, sheet: Dict[str, Any], headers: List[str], block: Dict[str, int]) -> str:
        title = str(sheet.get("title") or sheet.get("name") or sheet.get("sheet_name") or "")
        snippets: List[str] = []
        rows = sheet.get("rows") or []
        for idx in range(block["start_idx"], min(block["end_idx"] + 1, len(rows))):
            row_type, row_data, _ = cls._get_row_parts(rows[idx])
            if row_type == "section":
                continue
            row_text = cls._row_text(headers, row_data)
            if row_text:
                marker = "PRIMARY" if idx == block["anchor_idx"] else f"SPEC_ROW_{idx + 1}"
                snippets.append(f"{marker}: {row_text}")
        return " | ".join(part for part in (title, "Full inferred product requirement block: " + " | ".join(snippets)) if part.strip())

    @classmethod
    def _group_contextual_row_text(
        cls,
        sheet: Dict[str, Any],
        headers: List[str],
        row_idx: int,
        base_text: str,
        metadata: Dict[str, Any],
    ) -> str:
        group_id = cls._product_group_id(metadata)
        if not group_id:
            return base_text
        grouped_rows: List[str] = []
        for other_idx, other in enumerate(sheet.get("rows") or []):
            _, other_data, other_metadata = cls._get_row_parts(other)
            if cls._product_group_id(other_metadata) != group_id:
                continue
            row_text = cls._row_text(headers, other_data)
            if row_text:
                marker = "PRIMARY" if other_idx == row_idx else f"SPEC_ROW_{other_idx + 1}"
                grouped_rows.append(f"{marker}: {row_text}")
        if len(grouped_rows) <= 1:
            return base_text
        return f"{base_text} | Full product requirement block: " + " | ".join(grouped_rows)

    @staticmethod
    def _product_group_id(metadata: Dict[str, Any]) -> str:
        if not isinstance(metadata, dict):
            return ""
        return str(metadata.get("product_group_id") or metadata.get("requirement_group_id") or "").strip()

    @classmethod
    def _is_single_product_firewall_sheet(cls, sheet: Dict[str, Any], headers: List[str], text: str = "") -> bool:
        context = " ".join(
            str(part or "")
            for part in [
                sheet.get("title"),
                sheet.get("name"),
                sheet.get("sheet_name"),
                " ".join(str(header or "") for header in headers[:6]),
                text,
            ]
        ).lower()
        return (
            "per firewall appliance" in context
            or "minimum requirements per firewall" in context
            or "perimeter firewall" in context
        )

    @classmethod
    def _first_data_row_index(cls, sheet: Dict[str, Any]) -> int:
        for idx, row in enumerate(sheet.get("rows") or []):
            row_type, row_data, _ = cls._get_row_parts(row)
            if row_type != "section" and any(value not in (None, "") for value in row_data):
                return idx
        return -1

    @classmethod
    def _single_product_contextual_row_text(
        cls,
        sheet: Dict[str, Any],
        headers: List[str],
        row_idx: int,
        base_text: str,
        metadata: Dict[str, Any],
    ) -> str:
        if not cls._is_single_product_firewall_sheet(sheet, headers, base_text):
            return base_text
        row_snippets: List[str] = []
        for other_idx, other in enumerate(sheet.get("rows") or []):
            other_type, other_data, _ = cls._get_row_parts(other)
            if other_type == "section":
                continue
            row_text = cls._row_text(headers, other_data)
            if not row_text:
                continue
            marker = "PRIMARY" if other_idx == row_idx else f"SPEC_ROW_{other_idx + 1}"
            row_snippets.append(f"{marker}: {row_text}")
            if len(row_snippets) >= 80:
                break
        if len(row_snippets) <= 1:
            return base_text
        return f"{base_text} | Full single-product firewall requirement table: " + " | ".join(row_snippets)

    @staticmethod
    def _is_reference_anchor(metadata: Dict[str, Any], effective_metadata: Dict[str, Any]) -> bool:
        metadata = metadata if isinstance(metadata, dict) else {}
        effective_metadata = effective_metadata if isinstance(effective_metadata, dict) else {}
        for source in (metadata, effective_metadata):
            if source.get("product_group_primary_row") is False:
                return False
            if source.get("group_primary_row") is False:
                return False
            if source.get("is_product_spec_continuation") is True:
                return False
            if source.get("requires_reference") is False and (
                source.get("product_group_id") or source.get("requirement_group_id")
            ):
                return False
        return True

    @staticmethod
    def _effective_metadata(metadata: Dict[str, Any], text: str) -> Dict[str, Any]:
        effective = copy.deepcopy(metadata) if isinstance(metadata, dict) else {}
        fallback = ProductMatcher.extract_requirement_metadata(text)
        if not ProductMatcher.normalize_requirements(effective).get("device_type"):
            effective["device_category"] = fallback.get("device_type")
        if not isinstance(effective.get("detected_specs"), dict):
            effective["detected_specs"] = {}
        detected = effective["detected_specs"]
        for key, value in (fallback.get("requirements") or {}).items():
            if key == "interfaces":
                current = effective.setdefault("interfaces", {})
                if isinstance(current, dict):
                    for name, count in value.items():
                        current[name] = max(int(current.get(name, 0) or 0), int(count))
            elif value not in (None, "") and detected.get(key) in (None, ""):
                detected[key] = value
        for key in ("ha_supported", "ha_port", "management_port", "console_port", "redundant_power"):
            if fallback.get(key) is True:
                effective[key] = True
        if fallback.get("ha_modes"):
            effective["ha_modes"] = fallback["ha_modes"]
        effective["source_text"] = text[:1000]
        if FortinetReferenceInjector._is_reference_anchor(metadata, effective) and FortinetReferenceInjector._has_matchable_requirements(effective):
            effective["requires_reference"] = True
        return effective

    @staticmethod
    def _has_matchable_requirements(metadata: Dict[str, Any]) -> bool:
        normalized = ProductMatcher.normalize_requirements(metadata)
        if not normalized.get("device_type"):
            return False
        if metadata.get("requires_reference") is True:
            return True
        ignored = {"device_type", "requirements", "source_text", "fortinet_feature_candidates"}
        boolean_only = {"ha_supported", "ha_port", "management_port", "console_port", "redundant_power"}
        for key, value in normalized.items():
            if key in ignored:
                continue
            if key == "interfaces" and isinstance(value, dict) and any(v not in (None, "", 0) for v in value.values()):
                return True
            if key == "ha_modes" and isinstance(value, list) and value:
                return True
            if key in NUMERIC_REQUIREMENT_FIELDS and value not in (None, "", 0):
                return True
            if key in boolean_only and value is True:
                continue
        return False

    @staticmethod
    def _should_reference(text: str, metadata: Dict[str, Any]) -> bool:
        if metadata.get("requires_reference") is True:
            return True
        normalized = ProductMatcher.normalize_requirements(metadata)
        if normalized.get("device_type") in {
            "NGFW", "SWITCH", "DATACENTER_SWITCH", "ACCESS_SWITCH", "ROUTER",
            "CENTRALIZED_MANAGEMENT", "LOGGING", "SIEM_SOC", "NDR", "ENDPOINT_SECURITY",
            "IDENTITY_ACCESS", "PAM", "SANDBOX", "EMAIL_SECURITY", "NAC",
            "DECEPTION", "SOAR", "SASE", "SECURE_WEB_GATEWAY", "DDOS_MITIGATION",
            "DIGITAL_RISK_PROTECTION", "NETWORK_PERFORMANCE_MONITORING",
            "AI_NETWORK_OPERATIONS", "CLOUD_SECURITY", "WAN_EXTENDER",
            "VOIP_SECURITY", "VIDEO_SECURITY", "WAF", "ADC",
        }:
            return True
        lowered = str(text or "").lower()
        terms = (
            "fortigate", "fortiswitch", "fortimanager", "fortianalyzer", "fortisiem",
            "fortilogger", "hardware logging", "log reporting", "firewall", "ngfw", "ipsec", "ssl vpn", "vpn throughput", "interfaces",
            "sfp", "qsfp", "switch", "router", "fortinet appliance",
        )
        return any(term in lowered for term in terms)

    @staticmethod
    def _should_skip_sheet(sheet: Dict[str, Any]) -> bool:
        title = str(sheet.get("title") or sheet.get("name") or sheet.get("sheet_name") or "").lower()
        return any(term in title for term in (
            "qualification", "pre-qualification", "prequalification", "eligibility",
            "evaluation criteria", "bid evaluation", "financial criteria", "commercial criteria",
        ))


def inject_fortinet_references(data: Dict[str, Any], catalog_dir: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, int]]:
    if catalog_dir is None:
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        catalog_dir = os.path.join(project_root, "data", "product_catalogs")
    injector = FortinetReferenceInjector(catalog_dir)
    enriched = injector.inject(data)
    return enriched, injector.stats
