"""
Extract a clean architecture hardware catalog from a combined datasheet PDF.

The input PDF in data/product_catalogs/architecture_hardware contains mixed
data-center architecture hardware datasheets: UPS, cooling, rack/containment,
PDUs, monitoring gateways, fire/suppression, cameras, and displays. This script
splits the PDF into product sections, extracts normalized specs where possible,
and writes a JSON catalog compatible with the local product catalog style.

Example:
    python scripts/architecture_hardware_catalog_extractor.py
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = PROJECT_ROOT / "data" / "product_catalogs" / "architecture_hardware" / "Data Sheets Combined-V0.2.pdf"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "product_catalogs" / "architecture_hardware.json"


SECTION_PATTERNS: Sequence[Tuple[str, str, str, Sequence[str]]] = (
    ("Vertiv", "Liebert APM2", "UPS", (r"liebert.*?\sapm2",)),
    ("Vertiv", "Liebert CRV4", "COOLING", (r"liebert.*?\scrv4",)),
    ("Vertiv", "Liebert SPM", "POWER_DISTRIBUTION", (r"liebert.*?\sspm\b",)),
    ("Vertiv", "SmartAisle Containment", "CONTAINMENT", (r"smartaisle\S*\s+containment",)),
    ("Vertiv", "Liebert RDU501", "MONITORING", (r"liebert.*?\srdu501",)),
    ("Vertiv", "SmartAisle 2", "CONTAINMENT", (r"smartaisle\s+2\b",)),
    ("Vertiv", "Geist Rack PDUs", "RACK_PDU", (r"geist\S*\s+rack\s+pdus?",)),
    ("Vertiv", "Liebert MTP", "UPS", (r"liebert.*?\smtp\b",)),
    ("Vertiv", "VE Rack", "RACK", (r"\bve\s+rack\b",)),
    ("Carrier", "AirSense Stratos Micra 25", "FIRE_DETECTION", (r"airsense\s+stratos\s+micra\s+25",)),
    ("Simplex", "4010ES Releasing Control", "FIRE_SUPPRESSION", (r"4010es\s+automatic\s+extinguishing", r"4010es\s+.*releasing")),
    ("Simplex", "Addressable Manual Stations", "FIRE_ALARM", (r"addressable\s+manual\s+stations?",)),
    ("Simplex", "BACpac Ethernet Portal Module", "FIRE_ALARM", (r"bacpac\s+ethernet\s+portal",)),
    ("Simplex", "TrueAlarm Sensors", "FIRE_DETECTION", (r"truealarm\s+analog", r"truealarm\s+sensors")),
    ("Simplex", "Non-Coded Manual Stations", "FIRE_SUPPRESSION", (r"non-coded\s+manual\s+stations?",)),
    ("Simplex", "TrueAlarm Multi-Sensor", "FIRE_DETECTION", (r"truealarm\s+photoelectric", r"multi-sensor")),
    ("Simplex", "4009 IDNet NAC Extender", "FIRE_ALARM", (r"4009\s+idnet\s+nac\s+extender",)),
    ("Simplex", "TrueAlert Horn", "FIRE_ALARM", (r"truealert\s+non-addressable\s+horn", r"4901-\d+")),
    ("Steel Recon", "Fire Suppression Check Valve", "FIRE_SUPPRESSION", (r"check\s+valve\s+data\s+sheet",)),
    ("Steel Recon", "Fire Suppression Nozzle", "FIRE_SUPPRESSION", (r"nozzle\s+data\s+sheet",)),
    ("Steel Recon", "FK-5-1-12 Agent", "FIRE_SUPPRESSION", (r"\bfk-5-1-12\b",)),
    ("Dahua", "Dahua Camera", "CAMERA", (r"technical\s+specification\s+camera", r"\bdahua\b.*camera")),
    ("Dahua", "LS550UCM-BF", "DISPLAY", (r"ls550ucm-bf", r"basic\s+series")),
)


SPEC_PATTERNS: Sequence[Tuple[str, Sequence[str]]] = (
    ("power_capacity_kw", (r"(\d+(?:\.\d+)?)\s*kw\s*(?:-|to|&)\s*(\d+(?:\.\d+)?)\s*kw", r"(\d+(?:\.\d+)?)\s*(?:-|to|&)\s*(\d+(?:\.\d+)?)\s*kw", r"(\d+(?:\.\d+)?)\s*kw")),
    ("power_capacity_kva", (r"(\d+(?:\.\d+)?)\s*kva\s*(?:-|to)\s*(\d+(?:\.\d+)?)\s*kva", r"(\d+(?:\.\d+)?)\s*(?:-|to)\s*(\d+(?:\.\d+)?)\s*kva", r"(\d+(?:\.\d+)?)\s*kva")),
    ("cooling_capacity_kw", (r"(\d+(?:\.\d+)?)\s*kw\s*(?:-|to)\s*(\d+(?:\.\d+)?)\s*kw", r"(\d+(?:\.\d+)?)\s*(?:-|to)\s*(\d+(?:\.\d+)?)\s*kw", r"cooling.*?(\d+(?:\.\d+)?)\s*kw")),
    ("efficiency_percent", (r"efficiency(?:\s+up\s+to)?\s*(\d+(?:\.\d+)?)\s*%", r"up\s+to\s+(\d+(?:\.\d+)?)\s*%")),
    ("rack_units", (r"\b(\d+)u\b",)),
    ("rack_width_mm", (r"(\d{3,4})\s*w\b", r"width\D{0,20}(\d{3,4})\s*mm")),
    ("rack_depth_mm", (r"(\d{3,4})\s*d\b", r"depth\D{0,20}(\d{3,4})\s*mm")),
    ("static_load_kg", (r"static\s+load\s+capacity\s+of\s+([\d,]+)\s*kg", r"static\s+load\D{0,30}([\d,]+)\s*kg")),
    ("voltage_v", (r"(\d+(?:/\d+)?(?:\.\d+)?)\s*vac", r"(\d+(?:/\d+)?(?:\.\d+)?)\s*vdc", r"(\d+(?:/\d+)?(?:\.\d+)?)\s*v\b")),
    ("current_a", (r"(\d+(?:\.\d+)?)\s*a\b",)),
    ("max_operating_temp_c", (r"(\d+(?:\.\d+)?)\s*°?\s*c",)),
    ("sensor_capacity", (r"support\s+up\s+to\s+(\d+)\s+sensors?", r"maximum\s+will\s+be\s+(\d+)\s+sensors?")),
    ("outlet_count", (r"socket\s+qty/\s*type\s+(\d+)", r"outlets?\D{0,20}(\d+)")),
    ("resolution", (r"(\d{3,5})\s*\(h\)\s*[×x]\s*(\d{3,5})\s*\(v\)", r"(\d{3,5})\s*[×x]\s*(\d{3,5})")),
)

RAW_SPEC_LABELS = (
    "Nominal Input Voltage", "Input voltage range", "Nominal frequency", "Input frequency range",
    "Input power factor", "Battery blocks per string", "Battery charger max. current",
    "Nominal output voltage", "Nominal output frequency", "Output power factor",
    "Double conversion efficiency", "ECO mode efficiency", "Dimensions", "Weight",
    "Noise at 1 m", "Operating Temperature", "Protection level", "Rated Nominal Power",
    "Rated Current", "Rated Operating Voltage", "Operating voltage", "Current consumption",
    "Detection principle", "Maximum number of points", "Communications", "Rated Voltage Range",
    "Image Sensor", "Max. Resolution", "ROM", "RAM", "Scanning System", "Panel",
)


@dataclass
class PageText:
    page_number: int
    text: str


@dataclass
class Section:
    vendor: str
    model: str
    category: str
    start_page: int
    pages: List[PageText] = field(default_factory=list)

    @property
    def end_page(self) -> int:
        return self.pages[-1].page_number if self.pages else self.start_page

    @property
    def text(self) -> str:
        return "\n".join(page.text for page in self.pages)


def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def extract_pdf_pages(path: Path) -> List[PageText]:
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    pages: List[PageText] = []
    for idx, page in enumerate(reader.pages, start=1):
        pages.append(PageText(idx, page.extract_text() or ""))
    return pages


def classify_page_start(text: str) -> Optional[Tuple[str, str, str]]:
    head = normalize_space(text[:500]).lower()
    if not head:
        return None
    for vendor, model, category, patterns in SECTION_PATTERNS:
        if any(re.search(pattern, head, re.IGNORECASE) for pattern in patterns):
            return vendor, model, category
    return None


def split_sections(pages: List[PageText]) -> List[Section]:
    sections: List[Section] = []
    current: Optional[Section] = None
    seen_current_on_first_page = False

    for page in pages:
        match = classify_page_start(page.text)
        starts_new = False
        if match:
            vendor, model, category = match
            if current is None or model != current.model:
                starts_new = True
            elif not seen_current_on_first_page and page.page_number == current.start_page:
                starts_new = False
        if starts_new:
            if current and current.pages:
                sections.append(current)
            vendor, model, category = match or ("Unknown", f"PDF Section {page.page_number}", "ARCHITECTURE_HARDWARE")
            current = Section(vendor=vendor, model=model, category=category, start_page=page.page_number)
            seen_current_on_first_page = True
        if current is None:
            current = Section(vendor="Unknown", model=f"PDF Section {page.page_number}", category="ARCHITECTURE_HARDWARE", start_page=page.page_number)
        current.pages.append(page)

    if current and current.pages:
        sections.append(current)
    return sections


def parse_number(value: str) -> Optional[float]:
    value = value.replace(",", "")
    match = re.search(r"\d+(?:\.\d+)?", value)
    return float(match.group(0)) if match else None


def parse_range_or_value(text: str, patterns: Sequence[str]) -> Optional[Any]:
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if not match:
            continue
        groups = [group for group in match.groups() if group]
        if len(groups) >= 2 and all(parse_number(group) is not None for group in groups[:2]):
            return {"min": parse_number(groups[0]), "max": parse_number(groups[1])}
        if len(groups) == 1:
            return parse_number(groups[0]) or groups[0]
    return None


def extract_features(text: str, limit: int = 18) -> List[str]:
    features: List[str] = []
    for raw in re.split(r"(?:\n|\r|•|\by\s+)", text):
        item = normalize_space(raw)
        if len(item) < 12 or len(item) > 180:
            continue
        lowered = item.lower()
        if any(skip in lowered for skip in ("copyright", "all rights reserved", "vertiv.com", "page ")):
            continue
        if any(term in lowered for term in (
            "efficiency", "modular", "scalable", "hot-swappable", "monitor", "management",
            "sensor", "redundant", "dual power", "touch screen", "rack", "cooling",
            "voltage", "network", "snmp", "modbus", "fire", "alarm", "detection",
        )):
            if item not in features:
                features.append(item)
        if len(features) >= limit:
            break
    return features


def extract_order_codes(text: str) -> List[str]:
    patterns = (
        r"\b\d{2}\.\d{3}\.\d{3}\.[A-Z0-9]\b",
        r"\b0\d{7}\b",
        r"\b(?:20|40|49)\d{2}-\d{4}\b",
        r"\b[A-Z]{2,}\d{3,}[A-Z0-9-]*\b",
    )
    codes: List[str] = []
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            code = match.group(0)
            if code not in codes:
                codes.append(code)
    return codes[:80]


def extract_raw_specifications(text: str) -> Dict[str, str]:
    compact = normalize_space(text)
    specs: Dict[str, str] = {}
    for label in RAW_SPEC_LABELS:
        pattern = rf"{re.escape(label)}\s+(.{{1,140}}?)(?=\s+(?:{'|'.join(re.escape(item) for item in RAW_SPEC_LABELS)})\s+|$)"
        match = re.search(pattern, compact, re.IGNORECASE)
        if match:
            specs[label] = normalize_space(match.group(1)).strip(" :-")
    return specs


def normalize_specs(section: Section) -> Dict[str, Any]:
    text = normalize_space(section.text)
    lowered = text.lower()
    normalized: Dict[str, Any] = {}

    for field, patterns in SPEC_PATTERNS:
        if not field_allowed_for_category(field, section.category):
            continue
        value = parse_range_or_value(lowered, patterns)
        if value is not None:
            if field == "resolution" and isinstance(value, dict):
                value = {"horizontal": value["min"], "vertical": value["max"]}
            normalized[field] = value

    if "dual power" in lowered or "redundant power" in lowered or "1+1 redundancy" in lowered:
        normalized["redundant_power"] = True
    if any(term in lowered for term in ("snmp", "modbus", "tcp/ip", "web server", "ethernet")):
        normalized["management_interfaces"] = [
            term.upper() if term in ("snmp", "tcp/ip") else term
            for term in ("snmp", "modbus", "tcp/ip", "web server", "ethernet")
            if term in lowered
        ]
    if "n+1" in lowered:
        normalized["redundancy"] = "N+1"
    if "hot-swappable" in lowered or "hot swappable" in lowered:
        normalized["hot_swappable"] = True

    specs = extract_raw_specifications(section.text)
    if specs:
        normalized["specifications"] = specs
    features = extract_features(section.text)
    if features:
        normalized["features"] = features
    order_codes = extract_order_codes(section.text)
    if order_codes:
        normalized["order_codes"] = order_codes
    return normalized


def field_allowed_for_category(field: str, category: str) -> bool:
    category = category.upper()
    allowed = {
        "UPS": {
            "power_capacity_kw", "power_capacity_kva", "efficiency_percent",
            "voltage_v", "current_a", "max_operating_temp_c",
        },
        "COOLING": {
            "cooling_capacity_kw", "voltage_v", "current_a", "max_operating_temp_c",
        },
        "POWER_DISTRIBUTION": {
            "power_capacity_kva", "voltage_v", "current_a", "max_operating_temp_c",
        },
        "RACK_PDU": {
            "power_capacity_kw", "power_capacity_kva", "voltage_v", "current_a",
            "outlet_count", "max_operating_temp_c",
        },
        "RACK": {"rack_units", "rack_width_mm", "rack_depth_mm", "static_load_kg"},
        "CONTAINMENT": set(),
        "MONITORING": {"sensor_capacity", "voltage_v", "current_a", "max_operating_temp_c"},
        "FIRE_DETECTION": {"voltage_v", "current_a", "max_operating_temp_c"},
        "FIRE_ALARM": {"voltage_v", "current_a", "max_operating_temp_c"},
        "FIRE_SUPPRESSION": {"voltage_v", "current_a", "max_operating_temp_c"},
        "CAMERA": {"resolution", "voltage_v", "current_a", "max_operating_temp_c"},
        "DISPLAY": {"resolution", "voltage_v", "current_a", "max_operating_temp_c"},
    }
    return field in allowed.get(category, set())


def section_to_catalog_item(section: Section, source_pdf: Path) -> Dict[str, Any]:
    item = {
        "vendor": section.vendor,
        "model": section.model,
        "category": section.category,
        **normalize_specs(section),
        "datasheet_url": str(source_pdf.as_posix()),
        "source_pdf": str(source_pdf.as_posix()),
        "source_pages": {"start": section.start_page, "end": section.end_page},
    }
    return {key: value for key, value in item.items() if value not in (None, "", {}, [])}


def extract_catalog(input_pdf: Path) -> Dict[str, Any]:
    pages = extract_pdf_pages(input_pdf)
    sections = split_sections(pages)
    products = [section_to_catalog_item(section, input_pdf) for section in sections]
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for product in products:
        key = (product.get("vendor"), product.get("model"), product.get("source_pages", {}).get("start"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(product)
    return {
        "source": "architecture_hardware_combined_pdf",
        "generated_at": date.today().isoformat(),
        "products": deduped,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract architecture hardware product catalog from a combined datasheet PDF.")
    parser.add_argument("--input", default=str(DEFAULT_INPUT), help="Combined datasheet PDF path.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output catalog JSON path.")
    args = parser.parse_args()

    input_pdf = Path(args.input)
    output_path = Path(args.output)
    if not input_pdf.exists():
        raise FileNotFoundError(f"Input PDF not found: {input_pdf}")
    catalog = extract_catalog(input_pdf)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(catalog, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Saved {len(catalog['products'])} products to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
