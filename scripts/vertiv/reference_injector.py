from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from vertiv.rag_matcher import VertivRAGMatcher


REFERENCE_COLUMN = "References"
HARDWARE_REASONING_COLUMN = "Hardware_Reference_Reasoning"
MATCH_DETAILS_COLUMN = "Reference_Match_Details"


class VertivReferenceInjector:
    def __init__(self, catalog_dir: str):
        self.matcher = VertivRAGMatcher(catalog_dir)
        self.stats = {
            "rows_seen": 0,
            "sections_skipped": 0,
            "groups_seen": 0,
            "matched_rows": 0,
            "unmatched_rows": 0,
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
            if not self._should_reference(contextual_text, metadata):
                continue
            self.stats["groups_seen"] += 1
            result = self.matcher.match(contextual_text, metadata)
            reference = result.get("reference") or ""
            row_data[ref_idx] = reference
            row_data[reason_idx] = result.get("reasoning") or ""
            row_data[details_idx] = json.dumps(result.get("details") or {}, ensure_ascii=False, indent=2)
            if isinstance(row, dict) and REFERENCE_COLUMN in row:
                row[REFERENCE_COLUMN] = reference
            if reference:
                self.stats["matched_rows"] += 1
            else:
                self.stats["unmatched_rows"] += 1
        sheet["headers"] = headers

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
            return True
        terms = (
            "ups", "battery", "pdu", "rack", "enclosure", "containment", "cooling",
            "thermal", "chiller", "power distribution", "monitoring", "sensor",
            "kvm", "console", "busway", "switchgear", "cabinet", "42u", "48u",
            "kva", "kw", "boq", "supply", "equipment", "hardware",
        )
        return any(term in lowered for term in terms)


def inject_vertiv_references(data: Dict[str, Any], catalog_dir: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, int]]:
    if catalog_dir is None:
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        catalog_dir = os.path.join(project_root, "data", "product_catalogs")
    injector = VertivReferenceInjector(catalog_dir)
    enriched = injector.inject(data)
    return enriched, injector.stats
