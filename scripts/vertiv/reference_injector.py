from __future__ import annotations

import copy
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from vertiv.rag_matcher import VertivCandidate, VertivRAGMatcher


REFERENCE_COLUMN = "References"
HARDWARE_REASONING_COLUMN = "Hardware_Reference_Reasoning"
MATCH_DETAILS_COLUMN = "Reference_Match_Details"


class VertivReferenceInjector:
    def __init__(self, catalog_dir: str):
        self.matcher = VertivRAGMatcher(catalog_dir, top_k=int(os.getenv("VERTIV_RAG_TOP_K", "8")), use_llm=False)
        self.batch_candidate_limit = int(os.getenv("VERTIV_RAG_BATCH_CANDIDATES", "3"))
        self.batch_llm_enabled = os.getenv("VERTIV_RAG_USE_LLM", "1").lower() not in {"0", "false", "no", "off"}
        self.stats = {
            "rows_seen": 0,
            "sections_skipped": 0,
            "groups_seen": 0,
            "matched_rows": 0,
            "unmatched_rows": 0,
            "llm_batch_calls": 0,
            "llm_rows_sent": 0,
            "metadata_fallback_rows": 0,
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
        pending: List[Dict[str, Any]] = []
        skipped_reference_rows: List[Dict[str, Any]] = []
        for row_idx, row in enumerate(rows):
            self.stats["rows_seen"] += 1
            row_type, row_data, metadata = self._get_row_parts(row)
            self._ensure_len(row_data, len(headers))
            row_data[ref_idx] = ""
            row_data[reason_idx] = ""
            row_data[details_idx] = ""
            if row_type == "section":
                self.stats["sections_skipped"] += 1
                continue
            text = self._row_text(headers, row_data)
            contextual_text = self._contextual_row_text(sheet, headers, text)
            if not self._is_reference_anchor(metadata):
                if self._should_reference(contextual_text, metadata):
                    skipped_reference_rows.append({
                        "row_idx": row_idx,
                        "row": row,
                        "row_data": row_data,
                        "metadata": metadata,
                        "contextual_text": contextual_text,
                    })
                continue
            contextual_text = self._group_contextual_row_text(sheet, headers, row_idx, contextual_text, metadata)
            item = self._build_pending_item(sheet, row_idx, row, row_data, metadata, contextual_text)
            if item:
                pending.append(item)
        if not any(item.get("candidates") for item in pending) and skipped_reference_rows:
            for skipped in skipped_reference_rows:
                item = self._build_pending_item(
                    sheet,
                    skipped["row_idx"],
                    skipped["row"],
                    skipped["row_data"],
                    skipped["metadata"],
                    skipped["contextual_text"],
                )
                if item and item.get("candidates"):
                    pending.append(item)
                    self.stats["metadata_fallback_rows"] += 1
        decisions = self._batch_llm_decide(pending)
        for item in pending:
            result = self._result_for_pending_item(item, decisions.get(item["row_id"]))
            reference = result.get("reference") or ""
            row_data = item["row_data"]
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

    def _build_pending_item(
        self,
        sheet: Dict[str, Any],
        row_idx: int,
        row: Any,
        row_data: List[Any],
        metadata: Dict[str, Any],
        contextual_text: str,
    ) -> Optional[Dict[str, Any]]:
        query = self.matcher._build_query(contextual_text, metadata)
        constraints = self.matcher._parse_constraints(query, metadata)
        out_of_scope_reason = self.matcher._out_of_scope_reason(query, constraints)
        if out_of_scope_reason:
            self.stats["groups_seen"] += 1
            return {
                "row_id": f"{sheet.get('title') or sheet.get('name') or 'Sheet'}:{row_idx + 1}",
                "row": row,
                "row_data": row_data,
                "query": query,
                "constraints": constraints,
                "candidates": [],
                "local_selected": None,
                "forced_result": self.matcher._no_match_result(query, constraints, out_of_scope_reason),
            }
        if not self._should_reference(contextual_text, metadata):
            return None
        self.stats["groups_seen"] += 1
        retrieved = self.matcher.retrieve(query, constraints)
        safe_candidates = [
            candidate for candidate in retrieved
            if self.matcher._passes_hard_constraints(candidate.product, constraints)
        ]
        candidates = safe_candidates or retrieved
        candidates_with_datasheets = [
            candidate for candidate in candidates
            if self.matcher._public_datasheet_url(candidate.product)
        ]
        if candidates_with_datasheets:
            candidates = candidates_with_datasheets
        local_selected = self.matcher._select_fallback(candidates, constraints) if candidates else None
        return {
            "row_id": f"{sheet.get('title') or sheet.get('name') or 'Sheet'}:{row_idx + 1}",
            "row": row,
            "row_data": row_data,
            "query": query,
            "constraints": constraints,
            "candidates": candidates,
            "local_selected": local_selected,
        }

    def _result_for_pending_item(self, item: Dict[str, Any], decision: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if item.get("forced_result"):
            return item["forced_result"]
        candidates: List[VertivCandidate] = item["candidates"]
        if not candidates:
            return {
                "reference": "",
                "reasoning": "Vertiv: no relevant catalog candidates were retrieved for this requirement.",
                "details": {
                    "provider": "vertiv",
                    "query": item["query"],
                    "constraints": item["constraints"],
                    "top_candidates": [],
                },
            }
        selected = None
        if decision and decision.get("selected_model") and str(decision.get("match_status", "")).lower() != "no_safe_match":
            selected = self.matcher._candidate_by_model(candidates, str(decision["selected_model"]))
        if selected is None:
            selected = item.get("local_selected") or candidates[0]
            decision = None
        return self.matcher._format_result(
            selected,
            item["query"],
            item["constraints"],
            candidates[: self.batch_candidate_limit],
            decision,
        )

    def _batch_llm_decide(self, pending: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        if not self.batch_llm_enabled or not api_key or not pending:
            return {}
        payload = []
        for item in pending:
            candidates = item["candidates"][: self.batch_candidate_limit]
            payload.append({
                "row_id": item["row_id"],
                "requirement": item["query"][:1200],
                "parsed_constraints": item["constraints"],
                "candidates": [
                    {
                        "model": candidate.product.get("model"),
                        "category": candidate.product.get("category"),
                        "datasheet_url": self.matcher._public_datasheet_url(candidate.product),
                        "product_url": self.matcher._public_product_url(candidate.product),
                        "retrieval_score": round(candidate.score, 4),
                        "evidence": candidate.chunk[:900],
                    }
                    for candidate in candidates
                ],
            })
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            prompt = (
                "You are selecting Vertiv hardware references for RFP/BOQ compliance rows.\n"
                "For each row, choose only from the supplied candidates. Do not choose a candidate that is under-spec. "
                "Prefer candidates with a valid datasheet_url; do not choose a candidate with no datasheet_url when a safe datasheet candidate is available. "
                "Prefer the closest candidate that satisfies hard requirements. If no candidate is safe, return no_safe_match for that row.\n"
                "Return only valid JSON in this exact shape: "
                "{\"matches\":[{\"row_id\":\"...\",\"selected_model\":\"...\",\"match_status\":\"safe_match|family_match|no_safe_match\","
                "\"confidence\":0.0,\"reasoning\":\"...\",\"satisfied_requirements\":[],\"uncertain_requirements\":[]}]}\n\n"
                f"Rows:\n{json.dumps(payload, ensure_ascii=False, indent=2)}"
            )
            response = client.models.generate_content(
                model=os.getenv("VERTIV_RAG_LLM_MODEL", "gemini-3-flash-preview"),
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
                str(item.get("row_id")): item
                for item in matches
                if isinstance(item, dict) and item.get("row_id")
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

    @staticmethod
    def _is_reference_anchor(metadata: Dict[str, Any]) -> bool:
        metadata = metadata if isinstance(metadata, dict) else {}
        if metadata.get("product_group_primary_row") is False:
            return False
        if metadata.get("group_primary_row") is False:
            return False
        if metadata.get("is_product_spec_continuation") is True:
            return False
        if metadata.get("requires_reference") is False and (
            metadata.get("product_group_id") or metadata.get("requirement_group_id")
        ):
            return False
        return True

    @staticmethod
    def _should_skip_sheet(sheet: Dict[str, Any]) -> bool:
        title = str(sheet.get("title") or sheet.get("name") or sheet.get("sheet_name") or "").lower()
        return any(term in title for term in (
            "qualification", "pre-qualification", "prequalification", "eligibility",
            "evaluation criteria", "bid evaluation", "financial criteria", "commercial criteria",
        ))

    @staticmethod
    def _should_reference(text: str, metadata: Dict[str, Any]) -> bool:
        lowered = str(text or "").lower()
        if metadata.get("requires_reference") is True:
            return not VertivReferenceInjector._is_non_vertiv_scope(lowered)
        if VertivReferenceInjector._is_non_vertiv_scope(lowered):
            return False
        terms = (
            "ups", "battery", "pdu", "rack", "enclosure", "containment", "cooling",
            "thermal", "chiller", "power distribution", "monitoring", "sensor",
            "kvm", "console", "busway", "switchgear", "cabinet", "42u", "48u",
            "kva", "kw", "inrow", "in-row", "crv", "apm", "rdu", "sts",
            "static transfer", "transfer switch", "ats", "rpdu",
            "cable manager", "cable management", "blank panel", "brush strip",
            "rack accessory",
        )
        return any(term in lowered for term in terms)

    @staticmethod
    def _is_non_vertiv_scope(lowered: str) -> bool:
        service_terms = (
            "startup", "commissioning", "installation", "testing & commissioning",
            "testing and commissioning", "complete job", "civil work",
        )
        non_catalog_terms = (
            "ip camera", "dome camera", "bullet/dome camera", "nvr", "recorder",
            "hdd", "vesda", "fire detection", "fire alarm", "fire suppression",
            "gas cylinder", "smoke detector", "smoke sensor", "speaker",
            "public address", "biometric", "fingerprint", "rfid", "ic card",
            "access control", "exit button", "electro-magnetic lock",
            "magnetic lock", "panic bar", "smoke seal", "single leaf door",
            "double leaf door", "door closer", "exit lights", "exit light",
            "cable tray", "cable ladder", "cable trunking", "perforated cable",
            "solid trunking", "distribution board", "o/g db", "db-ups", "ups o/g db",
            "subassembly", "communication cable", "seismic anchors", "function module",
            "door sensor", "microwave and infrared sensor",
            "split ac", "split a/c", "split type ac", "split air conditioner", "split air conditioning",
            "a/c unit", "ac unit", "air conditioning unit", "air conditioner unit",
            "ton split", "t3 compressor", "compressor and vendor", "video wall", "display wall",
            "lcd wall", "noc screen", "screen for the network operations room",
        )
        if any(term in lowered for term in service_terms):
            return True
        return any(term in lowered for term in non_catalog_terms)


def inject_vertiv_references(data: Dict[str, Any], catalog_dir: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, int]]:
    if catalog_dir is None:
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        catalog_dir = os.path.join(project_root, "data", "product_catalogs")
    injector = VertivReferenceInjector(catalog_dir)
    enriched = injector.inject(data)
    return enriched, injector.stats
