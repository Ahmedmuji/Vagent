"""
Extract Vertiv hardware specifications from the combined architecture PDF.

The extractor intentionally uses pdfplumber for both table and text extraction
so the resulting JSON keeps datasheet key-value/specification table structure.

Example:
    python scripts/vertiv/extract_pdf_specs.py
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = (
    PROJECT_ROOT
    / "data"
    / "product_catalogs"
    / "architecture_hardware"
    / "Data Sheets Combined-V0.2.pdf"
)
DEFAULT_OUTPUT = PROJECT_ROOT / "output" / "json" / "vertiv_specs.json"


@dataclass(frozen=True)
class ProductSection:
    product_name: str
    model: str
    category: str
    start_page: int
    end_page: int


VERTIV_SECTIONS = (
    ProductSection("Vertiv Liebert APM2", "Liebert APM2", "UPS", 1, 2),
    ProductSection("Vertiv Liebert CRV4", "Liebert CRV4", "Thermal Management", 3, 10),
    ProductSection("Vertiv Liebert SPM", "Liebert SPM", "Power Distribution", 11, 18),
    ProductSection("Vertiv SmartAisle Containment", "SmartAisle Containment", "Containment", 19, 50),
    ProductSection("Vertiv Liebert RDU501", "Liebert RDU501", "Monitoring & Management", 51, 54),
    ProductSection("Vertiv SmartAisle 2", "SmartAisle 2", "Integrated Data Center Solution", 55, 62),
    ProductSection("Vertiv Geist Rack PDUs", "Geist Rack PDUs", "Rack PDU", 63, 74),
    ProductSection("Vertiv Liebert MTP", "Liebert MTP", "UPS", 75, 76),
    ProductSection("Vertiv VE Rack", "VE Rack", "Rack", 77, 86),
)


def clean_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\xa0", " ")
    text = text.replace("\u2122", "")
    text = text.replace("\u00ae", "")
    text = re.sub(r"\(cid:\d+\)", "", text)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r" *\n+ *", "\n", text)
    return text.strip()


def clean_key(value: Any) -> str:
    key = clean_text(value)
    key = re.sub(r"\s+", " ", key)
    return key.strip(" :-")


def is_noise(value: str) -> bool:
    lowered = value.lower()
    return any(
        marker in lowered
        for marker in (
            "all rights reserved",
            "vertiv.com",
            "this document is provided",
            "while every precaution has been taken",
        )
    )


def compact(value: Any) -> str:
    return re.sub(r"\s+", " ", clean_text(value)).strip()


def dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        item = compact(item)
        if not item or item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped


def extract_features(text: str, limit: int = 30) -> list[str]:
    features: list[str] = []
    for raw in re.split(r"\n|•|·|\by\s+", text):
        item = compact(raw)
        if len(item) < 18 or len(item) > 220 or is_noise(item):
            continue
        lowered = item.lower()
        if any(
            word in lowered
            for word in (
                "efficiency",
                "modular",
                "redundant",
                "monitor",
                "management",
                "cooling",
                "rack",
                "power",
                "battery",
                "voltage",
                "sensor",
                "network",
                "controller",
                "containment",
                "outlet",
                "pdu",
                "static load",
                "access",
                "temperature",
            )
        ):
            features.append(item)
        if len(features) >= limit:
            break
    return dedupe_preserve_order(features)


def normalize_table_rows(table: list[list[Any]]) -> list[list[str]]:
    rows: list[list[str]] = []
    for row in table:
        cells = [clean_text(cell) for cell in row]
        while cells and not cells[-1]:
            cells.pop()
        if not any(cells):
            continue
        rows.append(cells)
    return rows


def row_as_key_value(row: list[str]) -> tuple[str, str] | None:
    cells = [compact(cell) for cell in row if compact(cell)]
    if len(cells) != 2:
        return None
    key, value = cells
    if len(key) > 120 or len(value) > 1000:
        return None
    if key.lower() in {"model", "models", "description", "features"}:
        return None
    return key, value


def looks_like_header(row: list[str]) -> bool:
    cells = [compact(cell) for cell in row if compact(cell)]
    if len(cells) < 2:
        return False
    joined = " ".join(cells).lower()
    return any(word in joined for word in ("model", "description", "part number", "rating", "capacity", "type"))


def table_to_structure(table: list[list[Any]], page_number: int, table_number: int) -> dict[str, Any] | None:
    rows = normalize_table_rows(table)
    if not rows:
        return None

    key_values: dict[str, str] = {}
    all_key_value = True
    for row in rows:
        pair = row_as_key_value(row)
        if not pair:
            all_key_value = False
            break
        key_values[pair[0]] = pair[1]

    if key_values and all_key_value:
        return {
            "page": page_number,
            "table_number": table_number,
            "type": "key_value",
            "specifications": key_values,
        }

    header = rows[0]
    body = rows[1:]
    if looks_like_header(header) and body:
        max_cols = max(len(header), *(len(row) for row in body))
        headers = [compact(cell) or f"Column {idx + 1}" for idx, cell in enumerate(header)]
        headers.extend(f"Column {idx + 1}" for idx in range(len(headers), max_cols))
        records: list[dict[str, str]] = []
        for row in body:
            padded = row + [""] * (max_cols - len(row))
            record = {
                headers[idx]: compact(value)
                for idx, value in enumerate(padded[:max_cols])
                if compact(value)
            }
            if record:
                records.append(record)
        return {
            "page": page_number,
            "table_number": table_number,
            "type": "matrix",
            "headers": headers,
            "rows": records,
        }

    return {
        "page": page_number,
        "table_number": table_number,
        "type": "raw_table",
        "rows": rows,
    }


def merge_key_value_tables(tables: list[dict[str, Any]]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for table in tables:
        if table.get("type") != "key_value":
            continue
        for key, value in table.get("specifications", {}).items():
            if key not in merged:
                merged[key] = value
            elif merged[key] != value:
                suffix = 2
                new_key = f"{key} ({suffix})"
                while new_key in merged:
                    suffix += 1
                    new_key = f"{key} ({suffix})"
                merged[new_key] = value
    return merged


def extract_inline_key_values(text: str) -> dict[str, str]:
    labels = (
        "Nominal Input Voltage",
        "Input voltage range",
        "Nominal frequency",
        "Input frequency range",
        "Input power factor",
        "Battery blocks per string",
        "Battery charger max. current",
        "Nominal output voltage",
        "Nominal output frequency",
        "Output power factor",
        "Double conversion efficiency",
        "ECO mode efficiency",
        "Rated Nominal Power",
        "Rated Current",
        "Rated Operating Voltage",
        "Operating voltage",
        "Current consumption",
        "Communications",
        "Max. Resolution",
        "Panel",
        "Static load",
        "Dynamic load",
    )
    compact_text = compact(text)
    specs: dict[str, str] = {}
    label_pattern = "|".join(re.escape(label) for label in labels)
    for label in labels:
        match = re.search(
            rf"{re.escape(label)}\s+(.{{1,180}}?)(?=\s+(?:{label_pattern})\s+|$)",
            compact_text,
            flags=re.IGNORECASE,
        )
        if match:
            specs[label] = compact(match.group(1)).strip(" :-")
    return specs


def extract_numeric_summary(specs: dict[str, Any], text: str) -> dict[str, Any]:
    joined = compact(json.dumps(specs, ensure_ascii=False) + " " + text)
    lowered = joined.lower()
    numeric: dict[str, Any] = {}

    patterns = {
        "power_capacity_kw": r"(\d+(?:\.\d+)?)\s*(?:-|to|&)\s*(\d+(?:\.\d+)?)\s*kw|(\d+(?:\.\d+)?)\s*kw",
        "power_capacity_kva": r"(\d+(?:\.\d+)?)\s*(?:-|to|&)\s*(\d+(?:\.\d+)?)\s*kva|(\d+(?:\.\d+)?)\s*kva",
        "cooling_capacity_kw": r"(\d+(?:\.\d+)?)\s*(?:-|to)\s*(\d+(?:\.\d+)?)\s*kw|cooling[^.]{0,80}?(\d+(?:\.\d+)?)\s*kw",
        "rack_units": r"\b(\d+)u\b",
        "static_load_kg": r"static load[^.]{0,80}?([\d,]+)\s*kg",
        "dynamic_load_kg": r"dynamic load[^.]{0,80}?([\d,]+)\s*kg",
        "outlet_count": r"outlets?[^.]{0,60}?(\d+)",
    }

    for field, pattern in patterns.items():
        match = re.search(pattern, lowered, flags=re.IGNORECASE)
        if not match:
            continue
        values = [group for group in match.groups() if group]
        parsed = [float(value.replace(",", "")) for value in values if re.match(r"^[\d,.]+$", value)]
        if len(parsed) >= 2 and field in {"power_capacity_kw", "power_capacity_kva", "cooling_capacity_kw"}:
            numeric[field] = {"min": parsed[0], "max": parsed[1]}
        elif parsed:
            value = parsed[0]
            numeric[field] = int(value) if value.is_integer() else value

    if re.search(r"\bredundan|n\+1|dual power|hot-?swappable", lowered):
        numeric["redundancy_or_high_availability"] = True

    return numeric


def extract_section(pdf: Any, section: ProductSection) -> dict[str, Any]:
    section_text_parts: list[str] = []
    tables: list[dict[str, Any]] = []
    pages_with_tables: list[int] = []
    low_confidence_pages: list[int] = []

    for page_number in range(section.start_page, section.end_page + 1):
        page = pdf.pages[page_number - 1]
        text = clean_text(page.extract_text() or "")
        if text:
            section_text_parts.append(text)
        if "(cid:" in (page.extract_text() or ""):
            low_confidence_pages.append(page_number)

        try:
            extracted_tables = page.extract_tables()
        except Exception as exc:
            print(f"[WARN] table extraction failed on page {page_number}: {exc}")
            extracted_tables = []

        if extracted_tables:
            pages_with_tables.append(page_number)
        for table_number, table in enumerate(extracted_tables, start=1):
            structured = table_to_structure(table, page_number, table_number)
            if structured:
                tables.append(structured)

    section_text = "\n".join(part for part in section_text_parts if part)
    table_key_values = merge_key_value_tables(tables)
    inline_key_values = extract_inline_key_values(section_text)
    key_values = {**inline_key_values, **table_key_values}

    specifications: dict[str, Any] = {}
    if key_values:
        specifications["key_values"] = key_values
    specifications["tables"] = tables

    features = extract_features(section_text)
    if features:
        specifications["features"] = features

    numeric_summary = extract_numeric_summary(specifications, section_text)
    if numeric_summary:
        specifications["normalized_summary"] = numeric_summary

    return {
        "product_name": section.product_name,
        "model": section.model,
        "category": section.category,
        "source_pdf": str(DEFAULT_INPUT.relative_to(PROJECT_ROOT)).replace("\\", "/"),
        "source_pages": {"start": section.start_page, "end": section.end_page},
        "technical_specifications": specifications,
        "extraction_metadata": {
            "method": "pdfplumber",
            "pages_with_tables": sorted(set(pages_with_tables)),
            "low_confidence_text_pages": sorted(set(low_confidence_pages)),
            "extracted_at": datetime.now(timezone.utc).isoformat(),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract Vertiv specs from the combined datasheet PDF.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    try:
        import pdfplumber
    except ImportError as exc:
        raise SystemExit(
            "pdfplumber is required. Install it with: python -m pip install pdfplumber"
        ) from exc

    if not args.input.exists():
        raise SystemExit(f"Input PDF not found: {args.input}")

    products: list[dict[str, Any]] = []
    with pdfplumber.open(str(args.input)) as pdf:
        for section in VERTIV_SECTIONS:
            print(f"[INFO] Extracting {section.product_name} pages {section.start_page}-{section.end_page}")
            products.append(extract_section(pdf, section))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(products, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[DONE] Saved {len(products)} products to {args.output}")


if __name__ == "__main__":
    main()
