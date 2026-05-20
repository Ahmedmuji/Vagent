"""
Fortinet hardware catalog scraper.

Scrapes Fortinet product pages, discovers official datasheet PDFs, extracts
hardware model/spec data, and writes a JSON catalog compatible with
scripts/product_matcher.py.

Examples:
    python scripts/fortinet_hardware_scraper.py
    python scripts/fortinet_hardware_scraper.py --existing data/product_catalogs/fortinet.json
    python scripts/fortinet_hardware_scraper.py --seed-url https://www.fortinet.com/products/next-generation-firewall

Notes:
    - Uses only dependencies already present in this project: requests + PyMuPDF.
    - Fortinet datasheet layouts vary by product family. Default output is kept
      clean like data/product_catalogs/fortinet.json. Use --include-evidence
      only when debugging extraction patterns.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import date
from html import unescape
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "product_catalogs" / "fortinet_scraped.json"
DEFAULT_CACHE_DIR = PROJECT_ROOT / "data" / "product_catalogs" / ".fortinet_scrape_cache"

FORTINET_BASE = "https://www.fortinet.com"

DEFAULT_SEED_URLS = [
    "https://www.fortinet.com/products/next-generation-firewall",
    "https://www.fortinet.com/products/fortiswitch",
    "https://www.fortinet.com/products/management/fortimanager",
    "https://www.fortinet.com/products/management/fortianalyzer",
    "https://www.fortinet.com/products/web-application-firewall/fortiweb",
    "https://www.fortinet.com/products/application-delivery-controller/fortiadc",
    "https://www.fortinet.com/products/fortimail",
    "https://www.fortinet.com/products/fortiauthenticator",
    "https://www.fortinet.com/products/fortinac",
    "https://www.fortinet.com/products/fortisandbox",
    "https://www.fortinet.com/products/fortindr",
    "https://www.fortinet.com/products/fortipam",
    "https://www.fortinet.com/products/fortiddos",
    "https://www.fortinet.com/products/fortideceptor",
    "https://www.fortinet.com/products/fortiextender",
]

HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; VagentFortinetCatalogScraper/1.0; "
        "+https://github.com/Ahmedmuji/Vagent)"
    ),
    "Accept": "text/html,application/pdf,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

MODEL_RE = re.compile(
    r"\b("
    r"FortiGate(?: Rugged)?|FortiWiFi|FortiSwitch|FortiAnalyzer|FortiManager|"
    r"FortiWeb|FortiADC|FortiMail|FortiAuthenticator|FortiNAC|FortiSandbox|"
    r"FortiNDR|FortiPAM|FortiDDoS|FortiDeceptor|FortiExtender|FortiVoice|"
    r"FortiRecorder|FortiProxy"
    r")\s+([A-Z]?[0-9][A-Za-z0-9-]*(?:\s+(?:Series|VM))?|VM)\b",
    re.IGNORECASE,
)

PDF_LINK_RE = re.compile(r"""["']([^"']+?\.pdf(?:\?[^"']*)?)["']""", re.IGNORECASE)
HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)


FIELD_PATTERNS: Sequence[Tuple[str, Sequence[str]]] = (
    ("firewall_throughput_gbps", (r"firewall throughput", r"firewall performance")),
    ("ipsec_vpn_throughput_gbps", (r"ipsec vpn throughput", r"ipsec vpn", r"vpn throughput")),
    ("ips_throughput_gbps", (r"\bips throughput", r"intrusion prevention")),
    ("ngfw_throughput_gbps", (r"\bngfw throughput", r"threat protection.*ngfw")),
    ("threat_protection_gbps", (r"threat protection throughput", r"threat protection")),
    ("ssl_tls_inspection_gbps", (r"ssl[-/ ]?tls inspection", r"ssl inspection", r"tls inspection")),
    ("ssl_vpn_gbps", (r"ssl vpn throughput",)),
    ("switching_capacity_gbps", (r"switching capacity", r"switch fabric", r"backplane")),
    ("throughput_gbps", (r"\bthroughput\b", r"system throughput", r"layer 4 throughput")),
    ("concurrent_sessions", (r"concurrent sessions", r"concurrent tcp sessions", r"sessions concurrent")),
    ("connections_per_second", (r"new sessions/sec", r"connections per second", r"\bcps\b")),
    ("ssl_vpn_users", (r"ssl vpn users", r"concurrent ssl vpn users")),
    ("policies", (r"firewall policies", r"\bpolicies\b")),
    ("logs_per_day_gb", (r"logs/day", r"logs per day")),
    ("analytic_rate_logs_sec", (r"analytic.*logs/sec", r"analytics.*logs/sec", r"analytic rate")),
    ("collector_rate_logs_sec", (r"collector.*logs/sec", r"collector rate")),
    ("performance_eps", (r"\beps\b", r"events per second")),
    ("email_routing_per_hour", (r"email routing", r"messages per hour", r"emails per hour")),
    ("atp_per_hour", (r"atp scans", r"atp per hour")),
    ("max_devices_vdoms", (r"devices/vdoms", r"managed devices", r"vdoms")),
    ("max_local_remote_users", (r"local users", r"remote users")),
    ("max_user_groups", (r"user groups",)),
    ("max_nas_devices", (r"nas devices", r"radius clients")),
    ("max_fortitokens", (r"fortitokens", r"tokens")),
    ("ha_configuration", (r"high availability", r"\bha\b configuration", r"\bha\b mode", r"active[-/ ]passive", r"active[-/ ]active", r"clustering")),
)

SPEC_LABEL_MAP: Sequence[Tuple[str, Sequence[str]]] = (
    ("firewall_throughput_gbps", (r"firewall throughput", r"firewall performance", r"ipv4 firewall throughput")),
    ("ipsec_vpn_throughput_gbps", (r"ipsec vpn throughput", r"ipsec vpn", r"vpn throughput")),
    ("ips_throughput_gbps", (r"\bips throughput", r"intrusion prevention")),
    ("ngfw_throughput_gbps", (r"\bngfw throughput", r"ngfw")),
    ("threat_protection_gbps", (r"threat protection throughput", r"threat protection")),
    ("ssl_tls_inspection_gbps", (r"ssl[-/ ]?tls inspection", r"ssl inspection", r"tls inspection")),
    ("ssl_vpn_gbps", (r"ssl vpn throughput",)),
    ("ssl_vpn_users", (r"ssl vpn users", r"concurrent ssl vpn users")),
    ("concurrent_sessions", (r"concurrent sessions", r"concurrent tcp sessions")),
    ("connections_per_second", (r"new sessions/sec", r"connections per second", r"\bcps\b")),
    ("policies", (r"firewall policies", r"\bpolicies\b")),
    ("switching_capacity_gbps", (r"switching capacity", r"switch fabric", r"backplane")),
    ("throughput_gbps", (r"system throughput", r"layer 4 throughput", r"\bthroughput\b")),
    ("logs_per_day_gb", (r"logs/day", r"logs per day")),
    ("analytic_rate_logs_sec", (r"analytic.*logs/sec", r"analytics.*logs/sec", r"analytic rate")),
    ("collector_rate_logs_sec", (r"collector.*logs/sec", r"collector rate")),
    ("performance_eps", (r"\beps\b", r"events per second")),
    ("email_routing_per_hour", (r"email routing", r"messages per hour", r"emails per hour")),
    ("atp_per_hour", (r"atp scans", r"atp per hour")),
    ("email_domains", (r"email domains", r"\bdomains\b")),
    ("server_mode_mailboxes", (r"server mode mailboxes", r"\bmailboxes\b")),
    ("max_devices_vdoms", (r"devices/vdoms", r"managed devices", r"vdoms")),
    ("max_local_remote_users", (r"local users", r"remote users")),
    ("max_user_groups", (r"user groups",)),
    ("max_nas_devices", (r"nas devices", r"radius clients")),
    ("max_fortitokens", (r"fortitokens", r"tokens")),
    ("ha_configuration", (
        r"high availability",
        r"\bha\b configuration",
        r"\bha\b mode",
        r"\bha\b status",
        r"active[-/ ]passive",
        r"active[-/ ]active",
        r"clustering",
        r"cluster",
    )),
)

INTERFACE_PATTERNS: Sequence[Tuple[str, str]] = (
    ("400g_qsfp_dd", r"(\d+)\s*(?:x|\u00d7)?\s*400\s*g(?:e|bps)?\s*(?:qsfp[- ]?dd|qsfpdd)?"),
    ("200g_qsfp56", r"(\d+)\s*(?:x|\u00d7)?\s*200\s*g(?:e|bps)?\s*(?:qsfp56|qsfp)?"),
    ("100g_qsfp28", r"(\d+)\s*(?:x|\u00d7)?\s*100\s*g(?:e|bps)?\s*(?:qsfp28|qsfp)?"),
    ("50g_sfp56", r"(\d+)\s*(?:x|\u00d7)?\s*50\s*g(?:e|bps)?\s*(?:sfp56)?"),
    ("40g_qsfp_plus", r"(\d+)\s*(?:x|\u00d7)?\s*40\s*g(?:e|bps)?\s*(?:qsfp\+|qsfp)?"),
    ("25g_sfp28", r"(\d+)\s*(?:x|\u00d7)?\s*25\s*g(?:e|bps)?\s*(?:sfp28)?"),
    ("10g_sfp_plus", r"(\d+)\s*(?:x|\u00d7)?\s*10\s*g(?:e|bps)?\s*(?:sfp\+|sfp plus|sfp)?"),
    ("10g_rj45", r"(\d+)\s*(?:x|\u00d7)?\s*10\s*g(?:e|bps)?\s*(?:rj45|base-t|copper)"),
    ("1_10g_rj45", r"(\d+)\s*(?:x|\u00d7)?\s*(?:1/10\s*g|1g/10g)\s*(?:rj45|base-t|copper)"),
    ("1g_sfp", r"(\d+)\s*(?:x|\u00d7)?\s*(?:1\s*g|ge|gbe|gigabit)\s*sfp"),
    ("1g_rj45", r"(\d+)\s*(?:x|\u00d7)?\s*(?:1\s*g|ge|gbe|gigabit)\s*(?:rj45|base-t|copper)"),
)


@dataclass
class ScrapedProduct:
    model: str
    category: str
    product_url: str
    datasheet_url: str
    normalized: Dict[str, Any] = field(default_factory=dict)
    raw_spec_lines: List[str] = field(default_factory=list)
    source_text_excerpt: str = ""

    def to_catalog_item(self, include_evidence: bool = False) -> Dict[str, Any]:
        item = {
            "vendor": "Fortinet",
            "model": self.model,
            "category": self.category,
            **self.normalized,
            "product_url": self.product_url,
            "datasheet_url": self.datasheet_url,
        }
        if include_evidence:
            item["raw_spec_lines"] = self.raw_spec_lines[:40]
            item["source_text_excerpt"] = self.source_text_excerpt[:1500]
        return {k: v for k, v in item.items() if v not in (None, "", {}, [])}


def fetch_text(session: requests.Session, url: str, timeout: int) -> str:
    response = session.get(url, headers=HTTP_HEADERS, timeout=timeout)
    response.raise_for_status()
    return response.text


def cache_path_for_url(cache_dir: Path, url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:18]
    parsed = urlparse(url)
    suffix = ".pdf" if parsed.path.lower().endswith(".pdf") else ".html"
    return cache_dir / f"{digest}{suffix}"


def fetch_binary_cached(session: requests.Session, url: str, cache_dir: Path, timeout: int, refresh: bool) -> Path:
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_path_for_url(cache_dir, url)
    if cache_path.exists() and not refresh:
        return cache_path
    response = session.get(url, headers=HTTP_HEADERS, timeout=timeout)
    response.raise_for_status()
    cache_path.write_bytes(response.content)
    return cache_path


def clean_html_text(html: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return normalize_space(unescape(text))


def normalize_space(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def normalize_line(text: str) -> str:
    text = unescape(str(text or ""))
    text = text.replace("\u00a0", " ")
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def discover_links(seed_html: str, seed_url: str, same_domain_only: bool = True) -> Tuple[List[str], List[str]]:
    pdfs = set()
    pages = set()
    for match in PDF_LINK_RE.finditer(seed_html):
        pdfs.add(urljoin(seed_url, match.group(1)))
    for match in HREF_RE.finditer(seed_html):
        href = match.group(1)
        url = urljoin(seed_url, href.split("#", 1)[0])
        parsed = urlparse(url)
        if same_domain_only and parsed.netloc and parsed.netloc != urlparse(FORTINET_BASE).netloc:
            continue
        if ".pdf" in parsed.path.lower():
            pdfs.add(url)
        elif "/products/" in parsed.path or "/resources/data-sheets/" in parsed.path:
            pages.add(url)
    return sorted(pages), sorted(pdfs)


def extract_pdf_text_and_tables(pdf_path: Path) -> Tuple[str, List[List[List[str]]]]:
    try:
        import fitz  # PyMuPDF
    except ImportError as exc:
        raise RuntimeError("PyMuPDF is required for PDF parsing. Install it with: python -m pip install PyMuPDF") from exc

    chunks: List[str] = []
    tables: List[List[List[str]]] = []
    with fitz.open(pdf_path) as doc:
        for page_idx, page in enumerate(doc, start=1):
            text = page.get_text("text") or ""
            if text.strip():
                chunks.append(f"\n[PAGE {page_idx}]\n{text}")
            finder = getattr(page, "find_tables", None)
            if finder is None:
                continue
            try:
                found = finder()
                for table in getattr(found, "tables", []) or []:
                    rows = table.extract()
                    cleaned_rows = [
                        [normalize_line(cell or "") for cell in row]
                        for row in rows
                        if any(normalize_line(cell or "") for cell in row)
                    ]
                    if cleaned_rows:
                        tables.append(cleaned_rows)
            except Exception:
                continue
    return "\n".join(chunks), tables


def extract_pdf_text(pdf_path: Path) -> str:
    text, _ = extract_pdf_text_and_tables(pdf_path)
    return text


def split_lines(text: str) -> List[str]:
    lines = [normalize_line(line) for line in text.splitlines()]
    return [line for line in lines if line]


def category_from_url_or_model(url: str, model: str) -> str:
    lowered = f"{url} {model}".lower()
    if "fortiswitch" in lowered:
        if any(token in lowered for token in ("data-center", "datacenter", "1000", "2000", "3000", "1048", "3032")):
            return "DATACENTER_SWITCH"
        return "ACCESS_SWITCH"
    if "fortiweb" in lowered:
        return "WAF"
    if "fortiadc" in lowered:
        return "ADC"
    if "fortianalyzer" in lowered:
        return "CENTRALIZED_MANAGEMENT"
    if "fortimanager" in lowered:
        return "CENTRALIZED_MANAGEMENT"
    if "fortimail" in lowered:
        return "EMAIL_SECURITY"
    if "fortiauthenticator" in lowered:
        return "IDENTITY_ACCESS"
    if "fortinac" in lowered:
        return "NAC"
    if "fortisandbox" in lowered:
        return "SANDBOX"
    if "fortindr" in lowered:
        return "NDR"
    if "fortipam" in lowered:
        return "PAM"
    if "fortiddos" in lowered:
        return "DDOS_MITIGATION"
    if "fortideceptor" in lowered:
        return "DECEPTION"
    if "fortiextender" in lowered:
        return "WAN_EXTENDER"
    return "NGFW"


def find_models(text: str) -> List[str]:
    seen = set()
    models = []
    for match in MODEL_RE.finditer(text):
        family = match.group(1)
        suffix = match.group(2).strip()
        model = normalize_model_name(f"{family} {suffix}")
        if model and model.lower() not in seen:
            seen.add(model.lower())
            models.append(model)
    return models


def normalize_model_name(model: str) -> str:
    model = normalize_space(model)
    replacements = {
        "Fortigate": "FortiGate",
        "Fortiwifi": "FortiWiFi",
        "Fortiswitch": "FortiSwitch",
        "Fortianalyzer": "FortiAnalyzer",
        "Fortimanager": "FortiManager",
        "Fortiweb": "FortiWeb",
        "Fortiadc": "FortiADC",
        "Fortimail": "FortiMail",
        "Fortiauthenticator": "FortiAuthenticator",
        "Fortinac": "FortiNAC",
        "Fortisandbox": "FortiSandbox",
        "Fortindr": "FortiNDR",
        "Fortipam": "FortiPAM",
        "Fortiddos": "FortiDDoS",
        "Fortideceptor": "FortiDeceptor",
        "Fortiextender": "FortiExtender",
    }
    for bad, good in replacements.items():
        model = re.sub(rf"\b{bad}\b", good, model, flags=re.IGNORECASE)
    return model


def model_suffix(model: str) -> str:
    return re.sub(r"^Forti[A-Za-z]+(?: Rugged)?\s+", "", normalize_model_name(model), flags=re.IGNORECASE).strip()


def model_from_cell(cell: str, known_models: Sequence[str]) -> Optional[str]:
    text = normalize_space(cell)
    if not text:
        return None
    direct = find_models(text)
    if direct:
        return direct[0]
    compact = re.sub(r"[^a-z0-9]", "", text.lower())
    for model in known_models:
        suffix = model_suffix(model)
        variants = {
            suffix.lower(),
            f"fg{suffix}".lower(),
            f"fgt{suffix}".lower(),
            f"fs{suffix}".lower(),
            f"fsw{suffix}".lower(),
            f"faz{suffix}".lower(),
            f"fmg{suffix}".lower(),
        }
        if compact in {re.sub(r"[^a-z0-9]", "", item) for item in variants}:
            return model
        if suffix and re.search(rf"(?<![A-Za-z0-9]){re.escape(suffix)}(?![A-Za-z0-9])", text, re.IGNORECASE):
            return model
    return None


def extract_model_context(lines: List[str], model: str, radius: int = 18) -> List[str]:
    hits: List[int] = []
    model_pattern = re.compile(re.escape(model).replace(r"\ ", r"\s+"), re.IGNORECASE)
    short_model = re.sub(r"^Forti[A-Za-z]+\s+", "", model)
    short_pattern = re.compile(rf"(?<![A-Za-z0-9]){re.escape(short_model)}(?![A-Za-z0-9])", re.IGNORECASE)
    for idx, line in enumerate(lines):
        if model_pattern.search(line) or short_pattern.search(line):
            hits.append(idx)
    context: List[str] = []
    seen = set()
    for hit in hits:
        for idx in range(max(0, hit - radius), min(len(lines), hit + radius + 1)):
            line = lines[idx]
            if line not in seen:
                seen.add(line)
                context.append(line)
    return context


def parse_number(raw: str) -> Optional[float]:
    if not raw:
        return None
    text = raw.replace(",", "").strip()
    match = re.search(r"(\d+(?:\.\d+)?)\s*(k|m|million|thousand)?", text, re.IGNORECASE)
    if not match:
        return None
    value = float(match.group(1))
    suffix = (match.group(2) or "").lower()
    if suffix in ("m", "million"):
        value *= 1_000_000
    elif suffix in ("k", "thousand"):
        value *= 1_000
    return value


def parse_capacity_to_gbps(line: str) -> Optional[float]:
    line = line.replace(",", "")
    match = re.search(r"(\d+(?:\.\d+)?)\s*(tbps|gbps|mbps|tbit/s|gbit/s|mbit/s|g\b|m\b|t\b)", line, re.IGNORECASE)
    if not match:
        return None
    value = float(match.group(1))
    unit = match.group(2).lower()
    if unit.startswith("t"):
        return value * 1000
    if unit.startswith("m"):
        return value / 1000
    return value


def parse_storage_tb(lines: Sequence[str]) -> Optional[float]:
    text = " | ".join(lines)
    match = re.search(r"(\d+(?:\.\d+)?)\s*(tb|gb)\s*(?:ssd|storage|local storage|disk|hdd)", text, re.IGNORECASE)
    if not match:
        match = re.search(r"(?:ssd|storage|local storage|disk|hdd).{0,80}?(\d+(?:\.\d+)?)\s*(tb|gb)", text, re.IGNORECASE)
    if not match:
        return None
    value = float(match.group(1))
    return value if match.group(2).lower() == "tb" else value / 1024


def parse_interfaces(lines: Sequence[str]) -> Dict[str, int]:
    joined = " | ".join(lines)
    interfaces: Dict[str, int] = {}
    for key, pattern in INTERFACE_PATTERNS:
        total = 0
        for match in re.finditer(pattern, joined, re.IGNORECASE):
            try:
                total += int(float(match.group(1)))
            except ValueError:
                pass
        if total:
            interfaces[key] = total
    return interfaces


def parse_interfaces_from_value(value: str) -> Dict[str, int]:
    return parse_interfaces([value])


def parse_boolean_ports(lines: Sequence[str]) -> Dict[str, bool]:
    text = " ".join(lines).lower()
    return {
        "ha_port": bool(re.search(r"\bha\b.{0,35}(?:port|interface)|(?:port|interface).{0,35}\bha\b|dedicated ha", text)),
        "management_port": bool(re.search(r"\bmgmt\b|\bmanagement port\b|dedicated management", text)),
        "console_port": bool(re.search(r"\bconsole port\b|\brj45 console\b", text)),
        "redundant_power": bool(re.search(r"redundant power|dual power|dual psu|hot swappable.*power", text)),
    }


def parse_ha_configuration(lines: Sequence[str]) -> Dict[str, Any]:
    text = normalize_space(" | ".join(lines))
    lowered = text.lower()
    if not re.search(r"high availability|\bha\b|active[-/ ]passive|active[-/ ]active|clustering|cluster", lowered):
        return {}

    modes: List[str] = []
    mode_patterns = (
        ("active-passive", r"active\s*[-/]\s*passive|a-p\b"),
        ("active-active", r"active\s*[-/]\s*active|a-a\b"),
        ("clustering", r"cluster(?:ing)?"),
        ("fgcp", r"\bfgcp\b|fortigate clustering protocol"),
        ("fgsp", r"\bfgsp\b|fortigate session life support protocol"),
        ("virtual clustering", r"virtual cluster(?:ing)?"),
    )
    for label, pattern in mode_patterns:
        if re.search(pattern, lowered) and label not in modes:
            modes.append(label)

    result: Dict[str, Any] = {"ha_supported": True}
    if modes:
        result["ha_modes"] = modes
    if re.search(r"dedicated\s+ha|\bha\b.{0,35}(?:port|interface)|(?:port|interface).{0,35}\bha\b", lowered):
        result["ha_port"] = True
    return result


def field_for_spec_label(label: str) -> Optional[str]:
    lowered = normalize_space(label).lower()
    for field, patterns in SPEC_LABEL_MAP:
        if any(re.search(pattern, lowered, re.IGNORECASE) for pattern in patterns):
            return field
    return None


def parse_table_value(field: str, value: str) -> Optional[Any]:
    value = normalize_space(value)
    if not value or value in {"-", "—", "n/a", "N/A"}:
        return None
    if field == "ha_configuration":
        return parse_ha_configuration([value])
    if field.endswith("_gbps"):
        parsed = parse_capacity_to_gbps(value)
    elif field == "storage_tb":
        parsed = parse_storage_tb([value])
    else:
        parsed = parse_number(value)
    if parsed is None:
        return None
    if field.endswith("_gbps"):
        return parsed
    return int(parsed) if float(parsed).is_integer() else parsed


def merge_numeric_spec(existing: Dict[str, Any], field: str, value: Any) -> None:
    if value in (None, "", {}, []):
        return
    if field == "interfaces":
        current = existing.setdefault("interfaces", {})
        for key, count in value.items():
            current[key] = max(int(current.get(key, 0) or 0), int(count))
        return
    if isinstance(value, dict):
        for nested_key, nested_value in value.items():
            if nested_key == "ha_modes" and nested_value:
                current_modes = existing.setdefault("ha_modes", [])
                for mode in nested_value:
                    if mode not in current_modes:
                        current_modes.append(mode)
            elif nested_value not in (None, "", {}, []):
                existing[nested_key] = nested_value
        return
    if field not in existing:
        existing[field] = value
        return
    try:
        existing[field] = max(float(existing[field]), float(value))
        if float(existing[field]).is_integer() and not field.endswith("_gbps"):
            existing[field] = int(existing[field])
    except (TypeError, ValueError):
        existing[field] = value


def detect_model_columns(rows: List[List[str]], known_models: Sequence[str]) -> Dict[int, str]:
    model_columns: Dict[int, str] = {}
    max_cols = max((len(row) for row in rows), default=0)
    header_scan_rows = rows[: min(8, len(rows))]
    for col_idx in range(max_cols):
        fragments = []
        for row in header_scan_rows:
            if col_idx < len(row):
                fragments.append(row[col_idx])
        cell_text = " ".join(fragment for fragment in fragments if fragment)
        model = model_from_cell(cell_text, known_models)
        if model:
            model_columns[col_idx] = model
    return model_columns


def table_label_for_row(row: List[str], first_model_col: int) -> str:
    label_cells = [cell for cell in row[:first_model_col] if normalize_space(cell)]
    return normalize_space(" ".join(label_cells))


def parse_model_spec_tables(
    tables: Sequence[List[List[str]]],
    known_models: Sequence[str],
    product_url: str,
    datasheet_url: str,
    category_hint: str,
) -> Dict[str, ScrapedProduct]:
    products: Dict[str, ScrapedProduct] = {}
    for rows in tables:
        model_columns = detect_model_columns(rows, known_models)
        if not model_columns:
            continue
        first_model_col = min(model_columns)
        for row in rows:
            if len(row) <= first_model_col:
                continue
            label = table_label_for_row(row, first_model_col)
            if not label:
                continue
            field = field_for_spec_label(label)
            is_interface_row = bool(re.search(r"interface|port|transceiver|sfp|qsfp|rj45|base-t", label, re.IGNORECASE))
            for col_idx, model in model_columns.items():
                if col_idx >= len(row):
                    continue
                value = row[col_idx]
                if not value or model_from_cell(value, known_models):
                    continue
                product = products.setdefault(
                    model,
                    ScrapedProduct(
                        model=model,
                        category=category_hint or category_from_url_or_model(f"{product_url} {datasheet_url}", model),
                        product_url=product_url,
                        datasheet_url=datasheet_url,
                    ),
                )
                if field:
                    parsed = parse_table_value(field, value)
                    merge_numeric_spec(product.normalized, field, parsed)
                    if parsed is not None:
                        product.raw_spec_lines.append(f"{label}: {value}")
                if is_interface_row:
                    interfaces = parse_interfaces_from_value(f"{value} {label}")
                    if interfaces:
                        merge_numeric_spec(product.normalized, "interfaces", interfaces)
                        product.raw_spec_lines.append(f"{label}: {value}")
                bools = parse_boolean_ports([f"{label}: {value}"])
                for bool_field, bool_value in bools.items():
                    if bool_value:
                        product.normalized[bool_field] = True
                        product.raw_spec_lines.append(f"{label}: {value}")
    return products


def parse_specs_for_model(model: str, lines: Sequence[str]) -> Tuple[Dict[str, Any], List[str]]:
    normalized: Dict[str, Any] = {}
    raw_hits: List[str] = []
    lowered_lines = [(line, line.lower()) for line in lines]

    for field, labels in FIELD_PATTERNS:
        best_value: Optional[float] = None
        best_line = ""
        for line, lowered in lowered_lines:
            if not any(re.search(label, lowered, re.IGNORECASE) for label in labels):
                continue
            value = parse_capacity_to_gbps(line) if field.endswith("_gbps") else parse_number(line)
            if value is None:
                continue
            if best_value is None or value > best_value:
                best_value = value
                best_line = line
        if best_value is not None:
            normalized[field] = int(best_value) if best_value.is_integer() and not field.endswith("_gbps") else best_value
            raw_hits.append(best_line)

    storage_tb = parse_storage_tb(lines)
    if storage_tb is not None:
        normalized["storage_tb"] = storage_tb

    interfaces = parse_interfaces(lines)
    if interfaces:
        normalized["interfaces"] = interfaces

    for key, value in parse_boolean_ports(lines).items():
        if value:
            normalized[key] = True
    for key, value in parse_ha_configuration(lines).items():
        if key == "ha_modes":
            normalized[key] = value
        elif value:
            normalized[key] = value

    return normalized, dedupe_preserve(raw_hits)


def dedupe_preserve(values: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for value in values:
        value = normalize_line(value)
        if not value or value.lower() in seen:
            continue
        seen.add(value.lower())
        out.append(value)
    return out


def scrape_datasheet(pdf_url: str, product_url: str, category_hint: str, session: requests.Session, cache_dir: Path, timeout: int, refresh: bool) -> List[ScrapedProduct]:
    pdf_path = fetch_binary_cached(session, pdf_url, cache_dir, timeout, refresh)
    text, tables = extract_pdf_text_and_tables(pdf_path)
    lines = split_lines(text)
    models = find_models(text)
    table_products = parse_model_spec_tables(tables, models, product_url, pdf_url, category_hint)
    products: List[ScrapedProduct] = []
    for model in models:
        context = extract_model_context(lines, model)
        table_product = table_products.get(model)
        if not context and table_product is None:
            continue
        category = category_hint or category_from_url_or_model(f"{product_url} {pdf_url}", model)
        normalized, raw_hits = parse_specs_for_model(model, context) if context else ({}, [])
        if table_product:
            for field_key, field_value in table_product.normalized.items():
                merge_numeric_spec(normalized, field_key, field_value)
            raw_hits = dedupe_preserve((table_product.raw_spec_lines or []) + raw_hits)
        products.append(
            ScrapedProduct(
                model=model,
                category=category,
                product_url=product_url,
                datasheet_url=pdf_url,
                normalized=normalized,
                raw_spec_lines=raw_hits or context[:25],
                source_text_excerpt="\n".join(context[:80]) if context else "",
            )
        )
    return products


def clean_catalog_item(product: Dict[str, Any], include_evidence: bool = False) -> Dict[str, Any]:
    cleaned = dict(product)
    if not include_evidence:
        cleaned.pop("raw_spec_lines", None)
        cleaned.pop("source_text_excerpt", None)
    return {k: v for k, v in cleaned.items() if v not in (None, "", {}, [])}


def merge_existing(existing_path: Optional[Path], scraped_items: List[Dict[str, Any]], include_evidence: bool = False) -> List[Dict[str, Any]]:
    if not existing_path or not existing_path.exists():
        return [clean_catalog_item(item, include_evidence=include_evidence) for item in scraped_items]
    with existing_path.open("r", encoding="utf-8") as fh:
        existing_data = json.load(fh)
    existing_products = existing_data.get("products", []) if isinstance(existing_data, dict) else existing_data
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for product in existing_products:
        if not isinstance(product, dict):
            continue
        key = (str(product.get("vendor", "Fortinet")).lower(), str(product.get("model", "")).lower())
        if key[1]:
            merged[key] = clean_catalog_item(product, include_evidence=include_evidence)
    for product in scraped_items:
        key = (str(product.get("vendor", "Fortinet")).lower(), str(product.get("model", "")).lower())
        if not key[1]:
            continue
        base = merged.get(key, {})
        combined = dict(base)
        for field_key, value in product.items():
            if field_key in ("raw_spec_lines", "source_text_excerpt"):
                if not include_evidence:
                    continue
                if value:
                    combined[field_key] = value
            elif value not in (None, "", {}, []):
                combined[field_key] = value
        merged[key] = combined
    return sorted(
        (clean_catalog_item(item, include_evidence=include_evidence) for item in merged.values()),
        key=lambda item: (str(item.get("category", "")), str(item.get("model", ""))),
    )


def build_catalog(
    seed_urls: Sequence[str],
    output_path: Path,
    cache_dir: Path,
    existing_path: Optional[Path],
    max_pages: int,
    timeout: int,
    refresh: bool,
    delay: float,
    include_evidence: bool,
) -> Dict[str, Any]:
    try:
        import requests
    except ImportError as exc:
        raise RuntimeError("requests is required for scraping. Install it with: python -m pip install requests") from exc

    session = requests.Session()
    product_pages = list(dict.fromkeys(seed_urls))
    datasheet_pairs: List[Tuple[str, str, str]] = []
    visited_pages = set()

    for url in list(product_pages):
        if url in visited_pages:
            continue
        visited_pages.add(url)
        print(f"[page] {url}")
        try:
            html = fetch_text(session, url, timeout)
        except Exception as exc:
            print(f"  ! failed: {exc}")
            continue
        pages, pdfs = discover_links(html, url)
        category_hint = category_from_url_or_model(url, clean_html_text(html)[:500])
        for pdf_url in pdfs:
            if "fortinet" in urlparse(pdf_url).netloc or not urlparse(pdf_url).netloc:
                datasheet_pairs.append((url, pdf_url, category_hint))
        for page_url in pages:
            if len(product_pages) >= max_pages:
                break
            if page_url not in product_pages:
                product_pages.append(page_url)
        time.sleep(delay)

    unique_pairs = []
    seen_pdf_urls = set()
    for product_url, pdf_url, category_hint in datasheet_pairs:
        clean_pdf = pdf_url.split("?", 1)[0]
        if clean_pdf.lower() in seen_pdf_urls:
            continue
        seen_pdf_urls.add(clean_pdf.lower())
        unique_pairs.append((product_url, clean_pdf, category_hint))

    scraped: List[Dict[str, Any]] = []
    for idx, (product_url, pdf_url, category_hint) in enumerate(unique_pairs, start=1):
        print(f"[pdf {idx}/{len(unique_pairs)}] {pdf_url}")
        try:
            products = scrape_datasheet(pdf_url, product_url, category_hint, session, cache_dir, timeout, refresh)
            clean_products = [
                product
                for product in products
                if product.normalized
            ]
            skipped = len(products) - len(clean_products)
            print(f"  models with normalized specs: {len(clean_products)}" + (f" (skipped {skipped} weak hits)" if skipped else ""))
            scraped.extend(product.to_catalog_item(include_evidence=include_evidence) for product in clean_products)
        except Exception as exc:
            print(f"  ! failed: {exc}")
        time.sleep(delay)

    products = merge_existing(existing_path, scraped, include_evidence=include_evidence)
    catalog = {
        "metadata": {
            "source": "Fortinet product pages and official datasheet PDFs",
            "seed_urls": list(seed_urls),
            "scraped_at": date.today().isoformat(),
            "datasheets_seen": len(unique_pairs),
            "scraped_products": len(scraped),
            "merged_existing": str(existing_path) if existing_path else "",
            "notes": (
                "Clean matcher-compatible catalog. Normalized fields are best-effort regex extraction "
                "from Fortinet datasheet text."
            ),
            "include_evidence": include_evidence,
        },
        "products": products,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(catalog, fh, indent=2, ensure_ascii=False)
    return catalog


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scrape Fortinet hardware specs into a JSON product catalog.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output JSON path.")
    parser.add_argument("--existing", default="", help="Optional existing Fortinet catalog to merge with scraped specs.")
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR), help="Cache directory for downloaded PDFs.")
    parser.add_argument("--seed-url", action="append", default=[], help="Fortinet product page seed URL. Can be repeated.")
    parser.add_argument("--max-pages", type=int, default=80, help="Maximum product/resource pages to crawl from seeds.")
    parser.add_argument("--timeout", type=int, default=45, help="HTTP timeout in seconds.")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds.")
    parser.add_argument("--refresh", action="store_true", help="Re-download cached PDFs.")
    parser.add_argument(
        "--include-evidence",
        action="store_true",
        help="Include raw_spec_lines and source_text_excerpt for debugging. Off by default to keep catalog clean.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    seed_urls = args.seed_url or DEFAULT_SEED_URLS
    output_path = Path(args.output)
    existing_path = Path(args.existing) if args.existing else None
    catalog = build_catalog(
        seed_urls=seed_urls,
        output_path=output_path,
        cache_dir=Path(args.cache_dir),
        existing_path=existing_path,
        max_pages=args.max_pages,
        timeout=args.timeout,
        refresh=args.refresh,
        delay=args.delay,
        include_evidence=args.include_evidence,
    )
    print(f"\nSaved {len(catalog['products'])} products to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
