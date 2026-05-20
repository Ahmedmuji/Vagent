import copy
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from product_matcher import NUMERIC_REQUIREMENT_FIELDS, ProductMatcher, format_reference


REFERENCE_COLUMN = "References"
HARDWARE_REASONING_COLUMN = "Hardware_Reference_Reasoning"
ADMIN_REFERENCE_COLUMN = "Admin_Guide_Reference"
ADMIN_REASONING_COLUMN = "Admin_Guide_Reference_Reasoning"
ADMIN_TAG_COLUMN = "Admin_Guide_Reference_Tag"
MATCH_DETAILS_COLUMN = "Reference_Match_Details"


class HardwareReferenceInjector:
    def __init__(self, catalog_dir: str):
        self.matcher = ProductMatcher(catalog_dir)
        self.stats = {
            "rows_seen": 0,
            "sections_skipped": 0,
            "excluded": 0,
            "groups_seen": 0,
            "matched_rows": 0,
            "unmatched_rows": 0,
            "sibling_rows_suppressed": 0,
            "direct_model_reference_rows": 0,
            "admin_tags_created": 0,
        }

    def inject(self, data: Dict[str, Any]) -> Dict[str, Any]:
        enriched = copy.deepcopy(data)
        sheets = enriched.get("sheets", []) if isinstance(enriched, dict) else []
        for sheet in sheets:
            if isinstance(sheet, dict):
                self._inject_sheet(sheet)
        return enriched

    def _inject_sheet(self, sheet: Dict[str, Any]) -> None:
        if self._should_skip_sheet(sheet):
            return
        headers = sheet.get("headers") or []
        if REFERENCE_COLUMN not in headers:
            headers.append(REFERENCE_COLUMN)
        ref_idx = headers.index(REFERENCE_COLUMN)
        if HARDWARE_REASONING_COLUMN not in headers:
            headers.append(HARDWARE_REASONING_COLUMN)
        hardware_reason_idx = headers.index(HARDWARE_REASONING_COLUMN)
        if ADMIN_REFERENCE_COLUMN not in headers:
            headers.append(ADMIN_REFERENCE_COLUMN)
        admin_ref_idx = headers.index(ADMIN_REFERENCE_COLUMN)
        if ADMIN_REASONING_COLUMN not in headers:
            headers.insert(admin_ref_idx + 1, ADMIN_REASONING_COLUMN)
        admin_reason_idx = headers.index(ADMIN_REASONING_COLUMN)
        if ADMIN_TAG_COLUMN not in headers:
            headers.append(ADMIN_TAG_COLUMN)
        tag_idx = headers.index(ADMIN_TAG_COLUMN)
        if MATCH_DETAILS_COLUMN not in headers:
            headers.append(MATCH_DETAILS_COLUMN)
        details_idx = headers.index(MATCH_DETAILS_COLUMN)
        rows = sheet.get("rows") or []
        groups: Dict[str, Dict[str, Any]] = {}
        active_auto_group_key = ""
        active_auto_group_id = ""
        auto_group_counter = 0
        for row_idx, row in enumerate(rows):
            self.stats["rows_seen"] += 1
            row_type, row_data, metadata = self._get_row_parts(row)
            self._ensure_len(row_data, len(headers))
            row_data[ref_idx] = ""
            row_data[hardware_reason_idx] = ""
            row_data[admin_ref_idx] = ""
            row_data[admin_reason_idx] = ""
            row_data[tag_idx] = ""
            row_data[details_idx] = ""
            self._set_legacy_reference(row, "")
            if row_type == "section":
                self.stats["sections_skipped"] += 1
                active_auto_group_key = ""
                active_auto_group_id = ""
                continue
            text = self._row_text(headers, row_data)
            extraction_text = self._contextual_row_text(sheet, headers, text)
            effective_metadata = self._effective_metadata(metadata, extraction_text)
            if effective_metadata.get("excluded"):
                self.stats["excluded"] += 1
                continue
            self._write_admin_tag(row_data, tag_idx, effective_metadata, effective_metadata)
            direct_reference = self._direct_product_reference(text)
            if direct_reference:
                effective_metadata["direct_reference"] = direct_reference
                effective_metadata["requires_reference"] = True
            if not direct_reference and not self._should_hardware_reference(text, effective_metadata):
                continue
            if not self._requires_reference(effective_metadata):
                continue
            auto_group_key = self._auto_requirement_group_key(sheet, headers, row_data, text, effective_metadata)
            if auto_group_key:
                if auto_group_key != active_auto_group_key:
                    auto_group_counter += 1
                    active_auto_group_key = auto_group_key
                    active_auto_group_id = f"AUTO_{auto_group_counter}_{auto_group_key}"
                group_id = effective_metadata.get("requirement_group_id") or active_auto_group_id
            else:
                active_auto_group_key = ""
                active_auto_group_id = ""
                group_id = effective_metadata.get("requirement_group_id") or f"ROW_{row_idx + 1}"
            group = groups.setdefault(group_id, {
                "rows": [],
                "metadata": {},
                "texts": [],
                "features": [],
                "primary": None,
                "explicit_primary_flag_seen": False,
            })
            group["rows"].append((row, row_data, effective_metadata))
            group["texts"].append(text)
            group["metadata"] = self._merge_metadata(group["metadata"], effective_metadata)
            group["features"] = self._merge_features(group["features"], effective_metadata.get("fortinet_feature_candidates"))
            if effective_metadata.get("direct_reference"):
                group.setdefault("direct_references", [])
                if effective_metadata["direct_reference"] not in group["direct_references"]:
                    group["direct_references"].append(effective_metadata["direct_reference"])
            if "group_primary_row" in effective_metadata:
                group["explicit_primary_flag_seen"] = True
            if effective_metadata.get("group_primary_row") is True and group["primary"] is None:
                group["primary"] = (row, row_data, effective_metadata)
        for group in groups.values():
            self.stats["groups_seen"] += 1
            primary = group["primary"] or group["rows"][0]
            _, primary_data, primary_metadata = primary
            metadata = group["metadata"]
            metadata["source_text"] = " | ".join(group["texts"])[:1000]
            if group["features"]:
                metadata["fortinet_feature_candidates"] = group["features"]
            if not self._has_matchable_requirements(metadata):
                direct_references = group.get("direct_references") or []
                reference = " | ".join(direct_references)
                if not reference:
                    self.stats["unmatched_rows"] += 1
                    continue
                self.stats["direct_model_reference_rows"] += 1
                match_details = json.dumps({
                    "source": "direct_model_reference",
                    "selected_reference": reference,
                    "note": "Used direct model mention because no measurable catalog constraints were available.",
                }, ensure_ascii=False, indent=2)
                hardware_reasoning = (
                    "Used direct model mention from the requirement because no measurable "
                    "catalog constraints were available for a ranked comparison."
                )
            else:
                match_result = self.matcher.match(metadata)
                reference = format_reference(match_result)
                if not reference:
                    reference = self._review_reference(metadata)
                match_details = self._format_match_details(match_result)
                hardware_reasoning = self._format_hardware_reasoning(match_result, bool(reference))
            primary_data[ref_idx] = reference
            primary_data[hardware_reason_idx] = hardware_reasoning
            primary_data[details_idx] = match_details
            self._set_legacy_reference(primary[0], reference)

            for sibling_row, sibling_data, _ in group["rows"]:
                if sibling_data is primary_data:
                    continue
                sibling_data[ref_idx] = reference
                self._set_legacy_reference(sibling_row, reference)

            matched_count = len(group["rows"]) if reference else 0
            unmatched_count = 0 if reference else len(group["rows"])
            self.stats["matched_rows"] += matched_count
            self.stats["unmatched_rows"] += unmatched_count
            self.stats["sibling_rows_suppressed"] += 0
        sheet["headers"] = headers

    @staticmethod
    def _format_hardware_reasoning(match_result: Dict[str, Any], has_reference: bool) -> str:
        if not has_reference:
            return ""
        lines: List[str] = []
        for vendor, match in (match_result.get("matches") or {}).items():
            if not match:
                lines.append(f"{vendor}: no catalog item met all hard constraints without being under-spec.")
                continue
            details = match.get("match_details") or {}
            score = match.get("score_breakdown") or {}
            fit_details = score.get("fit_details") or {}
            spec_parts = []
            for field, values in fit_details.items():
                required = values.get("required")
                candidate = values.get("candidate")
                over = values.get("overprovision_factor")
                if required in (None, "") or candidate in (None, ""):
                    continue
                spec_parts.append(f"{field}: required {required}, candidate {candidate}, over {over}x")
            candidate_summary = "; ".join(
                f"{item.get('model')} (weighted closeness {item.get('weighted_closeness')}, max over {item.get('max_overprovision')}x)"
                for item in (details.get("top_valid_candidates") or [])[:3]
                if item.get("model")
            )
            reason = (
                f"{vendor}: selected {match.get('matched_product')} because it passed every hard requirement "
                f"and had the closest weighted fit among {details.get('valid_candidates_considered', 0)} valid catalog candidates."
            )
            if spec_parts:
                reason += f" Key fit checks: {'; '.join(spec_parts[:6])}."
            if candidate_summary:
                reason += f" Top valid candidates considered: {candidate_summary}."
            lines.append(reason)
        return "\n\n".join(lines)

    @staticmethod
    def _format_match_details(match_result: Dict[str, Any]) -> str:
        details = {
            "normalized_requirements": match_result.get("requirements", {}),
            "vendors": {},
        }
        for vendor, match in (match_result.get("matches") or {}).items():
            if not match:
                details["vendors"][vendor] = {"selected_model": None, "reason": "No valid catalog candidate met all hard constraints."}
                continue
            details["vendors"][vendor] = {
                "selected_model": match.get("matched_product"),
                "category": match.get("category"),
                "matched_requirements": match.get("matched_requirements", []),
                "score_breakdown": match.get("score_breakdown", {}),
                "match_details": match.get("match_details", {}),
            }
        return json.dumps(details, ensure_ascii=False, indent=2)

    def _review_reference(self, metadata: Dict[str, Any]) -> str:
        normalized = ProductMatcher.normalize_requirements(metadata)
        device_type = normalized.get("device_type")
        if not device_type:
            return ""
        return f"[Review Required] No compliant catalog match found for {device_type}."

    @staticmethod
    def _get_row_parts(row: Any) -> Tuple[str, List[Any], Dict[str, Any]]:
        if isinstance(row, dict):
            data = row.setdefault("data", [])
            metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            return str(row.get("row_type", "data")), data, metadata
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
        values: List[str] = []
        for idx, value in enumerate(row_data):
            header = str(headers[idx]).strip() if idx < len(headers) else ""
            if header in (REFERENCE_COLUMN, ADMIN_TAG_COLUMN):
                continue
            if value not in (None, ""):
                values.append(str(value))
        return " | ".join(values)

    @staticmethod
    def _contextual_row_text(sheet: Dict[str, Any], headers: List[str], text: str) -> str:
        context_parts = [
            str(sheet.get("title") or sheet.get("name") or sheet.get("sheet_name") or ""),
            " | ".join(str(header or "") for header in headers[:4]),
        ]
        context = " | ".join(part for part in context_parts if part.strip())
        return f"{context} | {text}" if context else text

    @staticmethod
    def _has_matchable_requirements(metadata: Dict[str, Any]) -> bool:
        normalized = ProductMatcher.normalize_requirements(metadata)
        device_type = normalized.get("device_type")
        if not device_type:
            return False
        if metadata.get("requires_reference") is True:
            return True
        if device_type in {
            "CENTRALIZED_MANAGEMENT", "SIEM_SOC", "NDR", "ENDPOINT_SECURITY",
            "IDENTITY_ACCESS", "PAM", "SDN_AUTOMATION", "SANDBOX",
            "EMAIL_SECURITY", "NAC", "DECEPTION", "SOAR", "SASE",
            "SECURE_WEB_GATEWAY", "DDOS_MITIGATION", "DIGITAL_RISK_PROTECTION",
            "NETWORK_PERFORMANCE_MONITORING", "AI_NETWORK_OPERATIONS",
            "CLOUD_SECURITY", "WAN_EXTENDER", "VOIP_SECURITY", "VIDEO_SECURITY",
        }:
            return True
        requirement_keys = set(normalized.keys()) - {"device_type", "requirements", "source_text"}
        if not requirement_keys:
            return False
        if requirement_keys in ({"ha_supported"}, {"ha_port"}, {"management_port"}, {"console_port"}, {"redundant_power"}):
            return False
        return True

    @staticmethod
    def _set_legacy_reference(row: Any, reference: str) -> None:
        if isinstance(row, dict) and REFERENCE_COLUMN in row:
            row[REFERENCE_COLUMN] = reference

    @staticmethod
    def _should_skip_sheet(sheet: Dict[str, Any]) -> bool:
        title = str(sheet.get("title") or sheet.get("name") or sheet.get("sheet_name") or "").lower()
        skip_terms = (
            "qualification", "pre-qualification", "prequalification", "eligibility",
            "evaluation criteria", "bid evaluation", "financial criteria",
            "commercial criteria", "mandatory criteria", "bidder qualification",
        )
        return any(term in title for term in skip_terms)

    @staticmethod
    def _auto_requirement_group_key(sheet: Dict[str, Any], headers: List[str], row_data: List[Any], text: str, metadata: Dict[str, Any]) -> str:
        normalized = ProductMatcher.normalize_requirements(metadata)
        if not normalized.get("device_type"):
            return ""
        if not HardwareReferenceInjector._has_measurable_constraints(normalized):
            return ""
        first_value = str(row_data[0]).strip() if row_data else ""
        if first_value and not re.match(r"^\d+[\).\s-]*$", first_value):
            return ""
        title = str(sheet.get("title") or sheet.get("name") or sheet.get("sheet_name") or "")
        header_context = " ".join(str(header or "") for header in headers[:4])
        context = f"{title} {header_context}".lower()
        if not any(term in context for term in ("firewall", "fortigate", "appliance", "switch", "router", "controller")):
            return ""
        label = next(
            (
                str(part).strip()
                for part in (title, headers[0] if headers else "")
                if str(part or "").strip()
            ),
            normalized.get("device_type") or "hardware",
        )
        key = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
        return key[:80] or "hardware"

    def _effective_metadata(self, metadata: Dict[str, Any], text: str) -> Dict[str, Any]:
        if metadata:
            effective = copy.deepcopy(metadata)
            fallback = self.matcher.extract_requirement_metadata(text)
            if not ProductMatcher.normalize_requirements(effective).get("device_type"):
                effective["device_category"] = fallback.get("device_type")
            if not isinstance(effective.get("detected_specs"), dict):
                effective["detected_specs"] = {}
            detected = effective["detected_specs"]
            for key, value in (fallback.get("requirements") or {}).items():
                if key == "interfaces":
                    effective["interfaces"] = self._merge_interface_dicts(effective.get("interfaces") or {}, value)
                elif key in ("ha_supported", "ha_port", "management_port", "console_port", "redundant_power") and value is True:
                    effective[key] = True
                elif key == "ha_modes" and isinstance(value, list) and value:
                    effective[key] = value
                elif detected.get(key) in (None, "") and value not in (None, ""):
                    detected[key] = value
            if self._text_requires_catalog_reference(text, fallback):
                effective["requires_reference"] = True
            effective["source_text"] = text[:1000]
            self._sanitize_boolean_constraints(effective, text)
            return effective
        fallback = self.matcher.extract_requirement_metadata(text)
        fallback["requires_reference"] = (
            self._has_matchable_requirements(fallback)
            or self._text_requires_catalog_reference(text, fallback)
        )
        fallback["group_primary_row"] = True
        self._sanitize_boolean_constraints(fallback, text)
        return fallback

    @staticmethod
    def _requires_reference(metadata: Dict[str, Any]) -> bool:
        if metadata.get("requires_reference") is True:
            return True
        if "requires_reference" in metadata:
            return False
        return HardwareReferenceInjector._has_matchable_requirements(metadata)

    @staticmethod
    def _sanitize_boolean_constraints(metadata: Dict[str, Any], text: str) -> None:
        normalized_text = ProductMatcher._normalize_text(text or "")
        if metadata.get("ha_port") is True and not ProductMatcher.text_explicitly_requires_ha_port(normalized_text):
            metadata.pop("ha_port", None)
            requirements = metadata.get("requirements")
            if isinstance(requirements, dict):
                requirements.pop("ha_port", None)
            detected_specs = metadata.get("detected_specs")
            if isinstance(detected_specs, dict):
                detected_specs.pop("ha_port", None)

    @staticmethod
    def _text_requires_catalog_reference(text: str, metadata: Dict[str, Any]) -> bool:
        normalized = ProductMatcher.normalize_requirements(metadata)
        if not normalized.get("device_type"):
            return False
        if HardwareReferenceInjector._has_measurable_constraints(normalized):
            return True
        lowered = str(text or "").lower()
        procurement_terms = (
            "supply", "provide", "proposed", "procure", "recommended solution",
            "appliance", "hardware", "equipment", "bom", "boq",
            "total remote sites", "aggregation firewalls", "remote site equipment",
        )
        return any(term in lowered for term in procurement_terms)

    @staticmethod
    def _should_hardware_reference(text: str, metadata: Dict[str, Any]) -> bool:
        normalized = ProductMatcher.normalize_requirements(metadata)
        if not normalized.get("device_type"):
            return False
        if metadata.get("direct_reference"):
            return True
        if HardwareReferenceInjector._is_bullet_fragment(text) and not HardwareReferenceInjector._has_standalone_procurement_context(text):
            return False
        if HardwareReferenceInjector._has_measurable_constraints(normalized):
            return True
        if HardwareReferenceInjector._is_service_only_requirement(text):
            return False
        return HardwareReferenceInjector._text_requires_catalog_reference(text, metadata)

    @staticmethod
    def _has_measurable_constraints(normalized: Dict[str, Any]) -> bool:
        ignored = {"device_type", "source_text", "requirements", "fortinet_feature_candidates"}
        ignored_boolean_only = {"ha_supported", "ha_port", "management_port", "console_port", "redundant_power"}
        for key, value in normalized.items():
            if key in ignored:
                continue
            if key in ignored_boolean_only:
                continue
            if key == "ha_modes" and isinstance(value, list) and value:
                return True
            if key == "interfaces" and isinstance(value, dict) and any(v not in (None, "", 0) for v in value.values()):
                return True
            if key in NUMERIC_REQUIREMENT_FIELDS and value not in (None, "", 0):
                return True
        return False

    @staticmethod
    def _is_bullet_fragment(text: str) -> bool:
        return bool(re.match(r"^\s*[a-z]\)", str(text or ""), re.IGNORECASE))

    @staticmethod
    def _has_standalone_procurement_context(text: str) -> bool:
        lowered = str(text or "").lower()
        return any(term in lowered for term in (
            "equipment hardware", "appliance", "hardware capacity", "firewall capacity",
            "total remote sites", "aggregation firewalls", "remote site equipment",
            "bidder should provide", "supply", "proposed solution",
        ))

    @staticmethod
    def _is_service_only_requirement(text: str) -> bool:
        lowered = str(text or "").lower()
        service_terms = ("support", "warranty", "nbd", "principal", "rma", "sla", "training", "delivery")
        hardware_terms = ("throughput", "interfaces", "sessions", "ports", "gbps", "mbps", "capacity")
        return any(term in lowered for term in service_terms) and not any(term in lowered for term in hardware_terms)

    def _merge_metadata(self, base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
        merged = copy.deepcopy(base)
        for key in ("device_category", "device_type", "category", "device_subcategory", "procurement_intent"):
            if not merged.get(key) and incoming.get(key):
                merged[key] = incoming[key]
        merged["requires_reference"] = merged.get("requires_reference") or incoming.get("requires_reference")
        
        if not isinstance(merged.get("detected_specs"), dict):
            merged["detected_specs"] = {}
        detected = merged["detected_specs"]
        
        incoming_specs = incoming.get("detected_specs")
        if isinstance(incoming_specs, dict):
            for key, value in incoming_specs.items():
                if value not in (None, ""):
                    current = detected.get(key)
                    detected[key] = max(current, value) if isinstance(current, (int, float)) and isinstance(value, (int, float)) else value
        for key in NUMERIC_REQUIREMENT_FIELDS:
            value = incoming.get(key)
            if value not in (None, ""):
                current = detected.get(key)
                detected[key] = max(current, value) if isinstance(current, (int, float)) and isinstance(value, (int, float)) else value
        requirements = incoming.get("requirements")
        if isinstance(requirements, dict):
            for key in NUMERIC_REQUIREMENT_FIELDS:
                value = requirements.get(key)
                if value not in (None, ""):
                    current = detected.get(key)
                    detected[key] = max(current, value) if isinstance(current, (int, float)) and isinstance(value, (int, float)) else value
            if isinstance(requirements.get("interfaces"), dict):
                merged["interfaces"] = self._merge_interface_dicts(merged.get("interfaces") or {}, requirements["interfaces"])
        if isinstance(incoming.get("interfaces"), dict):
            merged["interfaces"] = self._merge_interface_dicts(merged.get("interfaces") or {}, incoming["interfaces"])
        for key, value in incoming.items():
            if key.startswith("interfaces_") and value not in (None, ""):
                current = detected.get(key)
                detected[key] = max(current, value) if isinstance(current, int) and isinstance(value, int) else value
        for key in ("ha_supported", "ha_port", "management_port", "console_port", "redundant_power"):
            if incoming.get(key) is True:
                merged[key] = True
        if isinstance(incoming.get("ha_modes"), list) and incoming["ha_modes"]:
            existing_modes = merged.setdefault("ha_modes", [])
            for mode in incoming["ha_modes"]:
                if mode not in existing_modes:
                    existing_modes.append(mode)
        return merged

    @staticmethod
    def _merge_interface_dicts(base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(base)
        for key, value in incoming.items():
            if value in (None, ""):
                continue
            current = merged.get(key, 0)
            merged[key] = max(int(current), int(value))
        return merged

    @staticmethod
    def _merge_features(existing: List[str], incoming: Any) -> List[str]:
        merged = list(existing)
        if isinstance(incoming, list):
            for item in incoming:
                value = str(item).strip()
                if value and value not in merged:
                    merged.append(value)
        return merged

    def _write_admin_tag(self, row_data: List[Any], tag_idx: int, metadata: Dict[str, Any], primary_metadata: Dict[str, Any]) -> None:
        features = metadata.get("fortinet_feature_candidates") or primary_metadata.get("fortinet_feature_candidates") or []
        if not features:
            return
        tag = {
            "reference_needed": True,
            "lookup_query": " ".join(str(item) for item in features),
            "fortinet_feature_candidates": features,
            "fortinet_domains": features,
            "device_category": metadata.get("device_category") or metadata.get("device_type"),
            "priority": "medium",
        }
        row_data[tag_idx] = json.dumps(tag)
        self.stats["admin_tags_created"] += 1

    def _direct_product_reference(self, text: str) -> str:
        matches: List[str] = []
        normalized_text = str(text or "")
        for product in self.matcher.catalog.products:
            model = str(product.get("model") or "").strip()
            if not model:
                continue
            pattern = re.escape(model).replace("\\ ", r"[\s-]*")
            if re.search(rf"(?<![A-Za-z0-9]){pattern}(?![A-Za-z0-9])", normalized_text, re.IGNORECASE):
                vendor = str(product.get("vendor") or "").strip()
                url = product.get("datasheet_url") or product.get("product_url") or ""
                label = f"{vendor}: {model}" if vendor else model
                if url:
                    label = f"{label} — {url}"
                if label not in matches:
                    matches.append(label)
        return "\n\n".join(matches)


def inject_hardware_references(data: Dict[str, Any], catalog_dir: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, int]]:
    if catalog_dir is None:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        catalog_dir = os.path.join(project_root, "data", "product_catalogs")
    injector = HardwareReferenceInjector(catalog_dir)
    enriched = injector.inject(data)
    return enriched, injector.stats
