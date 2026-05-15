import copy
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from product_matcher import NUMERIC_REQUIREMENT_FIELDS, ProductMatcher, format_reference


REFERENCE_COLUMN = "References"
ADMIN_REFERENCE_COLUMN = "Admin_Guide_Reference"
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
        headers = sheet.get("headers") or []
        if REFERENCE_COLUMN not in headers:
            headers.append(REFERENCE_COLUMN)
        ref_idx = headers.index(REFERENCE_COLUMN)
        if ADMIN_REFERENCE_COLUMN not in headers:
            headers.append(ADMIN_REFERENCE_COLUMN)
        admin_ref_idx = headers.index(ADMIN_REFERENCE_COLUMN)
        if ADMIN_TAG_COLUMN not in headers:
            headers.append(ADMIN_TAG_COLUMN)
        tag_idx = headers.index(ADMIN_TAG_COLUMN)
        if MATCH_DETAILS_COLUMN not in headers:
            headers.append(MATCH_DETAILS_COLUMN)
        details_idx = headers.index(MATCH_DETAILS_COLUMN)
        rows = sheet.get("rows") or []
        groups: Dict[str, Dict[str, Any]] = {}
        for row_idx, row in enumerate(rows):
            self.stats["rows_seen"] += 1
            row_type, row_data, metadata = self._get_row_parts(row)
            self._ensure_len(row_data, len(headers))
            row_data[ref_idx] = ""
            row_data[admin_ref_idx] = ""
            row_data[tag_idx] = ""
            row_data[details_idx] = ""
            self._set_legacy_reference(row, "")
            if row_type == "section":
                self.stats["sections_skipped"] += 1
                continue
            text = self._row_text(headers, row_data)
            effective_metadata = self._effective_metadata(metadata, text)
            if effective_metadata.get("excluded"):
                self.stats["excluded"] += 1
                continue
            self._write_admin_tag(row_data, tag_idx, effective_metadata, effective_metadata)
            direct_reference = self._direct_product_reference(text)
            if direct_reference:
                effective_metadata["direct_reference"] = direct_reference
                effective_metadata["requires_reference"] = True
            if not self._requires_reference(effective_metadata):
                continue
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
            else:
                match_result = self.matcher.match(metadata)
                reference = format_reference(match_result)
                if not reference:
                    reference = self._review_reference(metadata)
                match_details = self._format_match_details(match_result)
            primary_data[ref_idx] = reference
            primary_data[details_idx] = match_details
            self._set_legacy_reference(primary[0], reference)
            self.stats["sibling_rows_suppressed"] += max(0, len(group["rows"]) - 1)
            if reference:
                self.stats["matched_rows"] += 1
            else:
                self.stats["unmatched_rows"] += len(group["rows"])
        sheet["headers"] = headers

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
        parts = []
        for vendor in ("Fortinet", "Juniper"):
            product = next(
                (
                    item for item in self.matcher.catalog.by_vendor(vendor)
                    if item.get("category") in ProductMatcher._candidate_categories(device_type)
                ),
                None,
            )
            if not product:
                continue
            url = product.get("datasheet_url") or product.get("product_url") or ""
            if url:
                parts.append(f"[Review Required] {vendor} catalog ({device_type}) — {url}")
        return " | ".join(parts)

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
        if requirement_keys == {"ha_port"} or requirement_keys == {"management_port"} or requirement_keys == {"console_port"}:
            return False
        return True

    @staticmethod
    def _set_legacy_reference(row: Any, reference: str) -> None:
        if isinstance(row, dict) and REFERENCE_COLUMN in row:
            row[REFERENCE_COLUMN] = reference

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
                elif detected.get(key) in (None, "") and value not in (None, ""):
                    detected[key] = value
            if self._text_requires_catalog_reference(text, fallback):
                effective["requires_reference"] = True
            effective["source_text"] = text[:1000]
            return effective
        fallback = self.matcher.extract_requirement_metadata(text)
        fallback["requires_reference"] = (
            self._has_matchable_requirements(fallback)
            or self._text_requires_catalog_reference(text, fallback)
        )
        fallback["group_primary_row"] = True
        return fallback

    @staticmethod
    def _requires_reference(metadata: Dict[str, Any]) -> bool:
        if metadata.get("requires_reference") is True:
            return True
        if "requires_reference" in metadata:
            return False
        return HardwareReferenceInjector._has_matchable_requirements(metadata)

    @staticmethod
    def _text_requires_catalog_reference(text: str, metadata: Dict[str, Any]) -> bool:
        normalized = ProductMatcher.normalize_requirements(metadata)
        if not normalized.get("device_type"):
            return False
        lowered = str(text or "").lower()
        procurement_terms = (
            "required", "requirement", "supply", "provide", "proposed",
            "recommended", "solution", "appliance", "hardware", "device",
            "equipment", "license", "subscription", "bom", "boq",
            "must comply", "must support", "must have", "shall comply",
            "shall support", "should provide", "capacity", "throughput",
            "interfaces", "sessions", "redundant", "firewall",
        )
        return any(term in lowered for term in procurement_terms)

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
        for key in ("ha_port", "management_port", "console_port"):
            if incoming.get(key) is True:
                merged[key] = True
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
