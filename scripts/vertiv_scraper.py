"""
Vertiv website + datasheet PDF catalog scraper.

This scraper follows the same output shape as fortinet_scraped.json:

{
  "metadata": {...},
  "products": [
    {
      "vendor": "Vertiv",
      "model": "...",
      "category": "UPS",
      "main_heading": "Critical Power",
      "subheading": "Uninterruptible Power Supplies (UPS)",
      "technical_specifications": {...},
      "product_url": "...",
      "datasheet_url": "..."
    }
  ]
}

Flow:
  1. Open each Vertiv main heading / subheading catalog URL with Playwright.
  2. Collect product URLs from the product-type-results component.
  3. Open each product page and find/click the Get Brochure / datasheet CTA.
  4. Download the datasheet PDF.
  5. Use pdfplumber to extract tables/text into structured technical specs.

Install:
    python -m pip install -r requirements.txt
    python -m playwright install chromium

Quick test:
    python scripts/vertiv_scraper.py --max-products 5 --headful

Full scrape:
    python scripts/vertiv_scraper.py --output data/product_catalogs/vertiv_scraped.json
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import random
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE_URL = "https://www.vertiv.com"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "product_catalogs" / "vertiv_scraped.json"
DEFAULT_CACHE_DIR = PROJECT_ROOT / "data" / "product_catalogs" / ".vertiv_scrape_cache"

PRODUCT_RESULTS_XPATH = (
    "/html/body/article[1]/div/div[2]/div/div/search-product-type/div[2]/div[2]/div[2]/div/product-type-results"
)
GET_BROCHURE_XPATH = "/html/body/article[1]/div[1]/div[2]/div/div/div/div[3]/div/div[1]/div/a[1]"

USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
)

DOCUMENT_KEYWORDS = (
    "get brochure",
    "brochure",
    "datasheet",
    "data sheet",
    "technical specifications",
    "technical specification",
    "spec sheet",
)


@dataclass(frozen=True)
class CategorySeed:
    main_heading: str
    subheading: str
    url: str
    category: str
    is_service: bool = False


CATALOG_SEEDS: tuple[CategorySeed, ...] = (
    CategorySeed("Critical Power", "Uninterruptible Power Supplies (UPS)", "/en-us/products-catalog/critical-power/uninterruptible-power-supplies-ups/", "UPS"),
    CategorySeed("Critical Power", "Energy Storage System", "/en-us/products-catalog/critical-power/energy-storage-system/", "ENERGY_STORAGE"),
    CategorySeed("Critical Power", "Battery Energy Storage System (BESS)", "/en-us/products-catalog/critical-power/battery-energy-storage-system-bess/", "ENERGY_STORAGE"),
    CategorySeed("Critical Power", "DC Power Systems", "/en-us/products-catalog/critical-power/dc-power-systems/", "DC_POWER"),
    CategorySeed("Critical Power", "Power Distribution", "/en-us/products-catalog/critical-power/power-distribution/", "POWER_DISTRIBUTION"),
    CategorySeed("Critical Power", "Static Transfer Switches", "/en-us/products-catalog/critical-power/static-transfer-switches/", "TRANSFER_SWITCH"),
    CategorySeed("Critical Power", "Switchgear and Switchboard", "/en-us/products-catalog/critical-power/switchgear/", "SWITCHGEAR"),
    CategorySeed("Critical Power", "Busway and Busduct", "/en-us/products-catalog/critical-power/busway-and-busduct/", "BUSWAY"),
    CategorySeed("Thermal Management", "Liquid Cooling Solutions", "/en-us/products-catalog/thermal-management/liquid-cooling-solutions/", "COOLING"),
    CategorySeed("Thermal Management", "High Density Solutions", "/en-us/products-catalog/thermal-management/high-density-solutions/", "COOLING"),
    CategorySeed("Thermal Management", "Heat Rejection", "/en-us/products-catalog/thermal-management/heat-rejection/", "COOLING"),
    CategorySeed("Thermal Management", "Outdoor Packaged Systems", "/en-us/products-catalog/thermal-management/outdoor-packaged-systems/", "COOLING"),
    CategorySeed("Thermal Management", "Room Cooling", "/en-us/products-catalog/thermal-management/room-cooling/", "COOLING"),
    CategorySeed("Thermal Management", "In-Row Cooling", "/en-us/products-catalog/thermal-management/in-row-cooling/", "COOLING"),
    CategorySeed("Thermal Management", "Rack Cooling", "/en-us/products-catalog/thermal-management/rack-cooling/", "COOLING"),
    CategorySeed("Thermal Management", "Free Cooling Chillers", "/en-us/products-catalog/thermal-management/free-cooling-chillers/", "COOLING"),
    CategorySeed("Thermal Management", "Evaporative Free Cooling", "/en-us/products-catalog/thermal-management/evaporative-free-cooling/", "COOLING"),
    CategorySeed("Thermal Management", "Thermal Control and Monitoring", "/en-us/products-catalog/thermal-management/thermal-control-and-monitoring/", "COOLING_CONTROL"),
    CategorySeed("Thermal Management", "Custom Thermal", "/en-us/products-catalog/thermal-management/custom-thermal/", "COOLING"),
    CategorySeed("Racks & Enclosures", "Integrated Solutions", "/en-us/products-catalog/facilities-enclosures-and-racks/integrated-solutions/", "INTEGRATED_RACK_SOLUTION"),
    CategorySeed("Racks & Enclosures", "Racks & Containment", "/en-us/products-catalog/facilities-enclosures-and-racks/racks-and-containment/", "RACK"),
    CategorySeed("Racks & Enclosures", "Outdoor Enclosures", "/en-us/products-catalog/facilities-enclosures-and-racks/outdoor-enclosures/", "ENCLOSURE"),
    CategorySeed("Monitoring & Management", "Digital Infrastructure Solutions", "/en-us/products-catalog/monitoring-control-and-management/digital-infrastructure-solutions/", "MONITORING"),
    CategorySeed("Monitoring & Management", "Embedded Device Management", "/en-us/products-catalog/monitoring-control-and-management/embedded-device-management/", "MONITORING"),
    CategorySeed("Monitoring & Management", "Serial Console", "/en-us/products-catalog/monitoring-control-and-management/serial-console/", "SERIAL_CONSOLE"),
    CategorySeed("Monitoring & Management", "Serial Console and Gateways", "/en-us/products-catalog/monitoring-control-and-management/serial-console-and-gateways/", "SERIAL_CONSOLE"),
    CategorySeed("Monitoring & Management", "IP KVM Switches", "/en-us/products-catalog/monitoring-control-and-management/ip-kvm/", "KVM"),
    CategorySeed("Monitoring & Management", "High Performance KVM", "/en-us/products-catalog/monitoring-control-and-management/high-performance-kvm/", "KVM"),
    CategorySeed("Monitoring & Management", "LCD Tray", "/en-us/products-catalog/monitoring-control-and-management/itmanagement/avocent-lcd-local-rack-access-console-/", "KVM"),
    CategorySeed("Monitoring & Management", "Desktop KVM and KM", "/en-us/products-catalog/monitoring-control-and-management/desktop-kvm-and-km/", "KVM"),
    CategorySeed("Monitoring & Management", "Secure KVM", "/en-us/products-catalog/monitoring-control-and-management/secure-kvm/", "KVM"),
    CategorySeed("Monitoring & Management", "Software", "/en-us/products-catalog/monitoring-control-and-management/software/", "SOFTWARE"),
    CategorySeed("Monitoring & Management", "Monitoring", "/en-us/products-catalog/monitoring-control-and-management/monitoring/", "MONITORING"),
    CategorySeed("Services", "Project Services", "/en-us/services/project-services/", "SERVICE", True),
    CategorySeed("Services", "Thermal Services", "/en-us/services/thermal-services/", "SERVICE", True),
    CategorySeed("Services", "UPS & Battery Services", "/en-us/services/ups-and-battery-services/", "SERVICE", True),
    CategorySeed("Services", "DC Power Services", "/en-us/services/dc-power-services/", "SERVICE", True),
    CategorySeed("Services", "Rack PDU Services", "/en-us/services/rack-pdu-services/", "SERVICE", True),
)


def clean_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\xa0", " ").replace("\u2122", "").replace("\u00ae", "")
    text = re.sub(r"\(cid:\d+\)", "", text)
    return re.sub(r"\s+", " ", text).strip()


def absolute_url(url: str, base: str = BASE_URL) -> str:
    return urljoin(base, url)


def canonical_url(url: str) -> str:
    parsed = urlparse(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=False)))
    path = parsed.path.rstrip("/") + "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", query, ""))


def path_depth(url: str) -> int:
    return len([part for part in urlparse(url).path.split("/") if part])


def is_product_url(url: str, seed_url: str) -> bool:
    parsed = urlparse(url)
    if parsed.netloc and "vertiv.com" not in parsed.netloc:
        return False
    if "/products-catalog/" not in parsed.path:
        return False
    if canonical_url(url) == canonical_url(seed_url):
        return False
    if any(skip in parsed.path.lower() for skip in ("/search/", "/support/", "/services/")):
        return False
    return path_depth(url) > path_depth(seed_url)


def detect_model(name: str | None, url: str) -> str:
    name = clean_text(name)
    if name:
        name = re.sub(r"^Vertiv\s+", "", name, flags=re.IGNORECASE)
        name = re.sub(r"^(?:™|®|\s)+", "", name)
        return name
    slug = urlparse(url).path.strip("/").split("/")[-1]
    return re.sub(r"[-_]+", " ", slug).title()


def cache_path_for_url(cache_dir: Path, url: str) -> Path:
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:18]
    suffix = ".pdf" if urlparse(url).path.lower().endswith(".pdf") else ".bin"
    return cache_dir / f"{digest}{suffix}"


def parse_number(value: str) -> float | None:
    match = re.search(r"\d+(?:,\d{3})*(?:\.\d+)?", value)
    if not match:
        return None
    return float(match.group(0).replace(",", ""))


def normalize_table_rows(table: list[list[Any]]) -> list[list[str]]:
    rows: list[list[str]] = []
    for row in table:
        cells = [clean_text(cell) for cell in row]
        while cells and not cells[-1]:
            cells.pop()
        if any(cells):
            rows.append(cells)
    return rows


def row_as_pair(row: list[str]) -> tuple[str, str] | None:
    cells = [clean_text(cell) for cell in row if clean_text(cell)]
    if len(cells) != 2:
        return None
    key, value = cells
    if not key or not value or len(key) > 140 or key.lower() in {"model", "models", "description"}:
        return None
    return key.rstrip(":"), value


def looks_like_header(row: list[str]) -> bool:
    joined = " ".join(row).lower()
    return any(word in joined for word in ("model", "description", "part number", "capacity", "rating", "input", "output"))


def table_to_structure(table: list[list[Any]], page_number: int, table_number: int) -> dict[str, Any] | None:
    rows = normalize_table_rows(table)
    if not rows:
        return None

    pairs: dict[str, str] = {}
    all_pairs = True
    for row in rows:
        pair = row_as_pair(row)
        if not pair:
            all_pairs = False
            break
        pairs[pair[0]] = pair[1]
    if pairs and all_pairs:
        return {"page": page_number, "table_number": table_number, "type": "key_value", "specifications": pairs}

    header = rows[0]
    body = rows[1:]
    if body and looks_like_header(header):
        max_cols = max(len(header), *(len(row) for row in body))
        headers = [clean_text(cell) or f"Column {idx + 1}" for idx, cell in enumerate(header)]
        headers.extend(f"Column {idx + 1}" for idx in range(len(headers), max_cols))
        matrix_rows = []
        for row in body:
            padded = row + [""] * (max_cols - len(row))
            record = {headers[idx]: clean_text(value) for idx, value in enumerate(padded[:max_cols]) if clean_text(value)}
            if record:
                matrix_rows.append(record)
        return {"page": page_number, "table_number": table_number, "type": "matrix", "headers": headers, "rows": matrix_rows}

    return {"page": page_number, "table_number": table_number, "type": "raw_table", "rows": rows}


def merge_key_values(tables: list[dict[str, Any]]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for table in tables:
        if table.get("type") != "key_value":
            continue
        for key, value in table.get("specifications", {}).items():
            if key not in merged:
                merged[key] = value
            elif merged[key] != value:
                index = 2
                candidate = f"{key} ({index})"
                while candidate in merged:
                    index += 1
                    candidate = f"{key} ({index})"
                merged[candidate] = value
    return merged


def extract_features(text: str, limit: int = 25) -> list[str]:
    features: list[str] = []
    for raw in re.split(r"\n|•|·|\by\s+", text):
        item = clean_text(raw)
        if len(item) < 18 or len(item) > 220:
            continue
        lowered = item.lower()
        if any(skip in lowered for skip in ("all rights reserved", "vertiv.com", "copyright")):
            continue
        if any(word in lowered for word in ("efficiency", "modular", "redundant", "cooling", "rack", "power", "battery", "voltage", "sensor", "network", "controller", "outlet", "pdu", "static load", "temperature", "monitor")):
            if item not in features:
                features.append(item)
        if len(features) >= limit:
            break
    return features


def normalized_specs_from_pdf(text: str, specs: dict[str, Any]) -> dict[str, Any]:
    joined = clean_text(json.dumps(specs, ensure_ascii=False) + " " + text).lower()
    normalized: dict[str, Any] = {}
    patterns = {
        "power_capacity_kw": r"(\d+(?:\.\d+)?)\s*(?:-|to|&)\s*(\d+(?:\.\d+)?)\s*kw|(\d+(?:\.\d+)?)\s*kw",
        "power_capacity_kva": r"(\d+(?:\.\d+)?)\s*(?:-|to|&)\s*(\d+(?:\.\d+)?)\s*kva|(\d+(?:\.\d+)?)\s*kva",
        "cooling_capacity_kw": r"(?:cooling|capacity)[^.]{0,100}?(\d+(?:\.\d+)?)\s*(?:-|to)\s*(\d+(?:\.\d+)?)\s*kw|(?:cooling|capacity)[^.]{0,100}?(\d+(?:\.\d+)?)\s*kw",
        "rack_units": r"\b(\d+)u\b",
        "static_load_kg": r"static load[^.]{0,80}?([\d,]+)\s*kg",
        "dynamic_load_kg": r"dynamic load[^.]{0,80}?([\d,]+)\s*kg",
        "outlet_count": r"outlets?[^.]{0,80}?(\d+)",
        "efficiency_percent": r"efficiency[^.]{0,80}?(\d+(?:\.\d+)?)\s*%",
    }
    for field, pattern in patterns.items():
        match = re.search(pattern, joined, re.IGNORECASE)
        if not match:
            continue
        groups = [group for group in match.groups() if group]
        values = [parse_number(group) for group in groups]
        values = [value for value in values if value is not None]
        if len(values) >= 2 and field in {"power_capacity_kw", "power_capacity_kva", "cooling_capacity_kw"}:
            normalized[field] = {"min": values[0], "max": values[1]}
        elif values:
            normalized[field] = int(values[0]) if values[0].is_integer() else values[0]

    if re.search(r"\bhigh availability\b|\bha\b|n\+1|active/passive|active-passive|active/passive", joined):
        normalized["ha_supported"] = True
    if re.search(r"redundant power|dual power|redundant psu|redundant power supply", joined):
        normalized["redundant_power"] = True
    if re.search(r"hot-?swappable|hot swappable", joined):
        normalized["hot_swappable"] = True
    return normalized


def extract_pdf_specs(pdf_path: Path) -> dict[str, Any]:
    import pdfplumber

    text_parts: list[str] = []
    tables: list[dict[str, Any]] = []
    with pdfplumber.open(str(pdf_path)) as pdf:
        for page_number, page in enumerate(pdf.pages, start=1):
            text = page.extract_text() or ""
            if text:
                text_parts.append(text)
            try:
                for table_number, table in enumerate(page.extract_tables(), start=1):
                    structured = table_to_structure(table, page_number, table_number)
                    if structured:
                        tables.append(structured)
            except Exception as exc:
                print(f"[WARN] pdfplumber table extraction failed on {pdf_path.name} page {page_number}: {exc}")

    text = "\n".join(text_parts)
    specs: dict[str, Any] = {"tables": tables}
    key_values = merge_key_values(tables)
    if key_values:
        specs["key_values"] = key_values
    features = extract_features(text)
    if features:
        specs["features"] = features
    return {"technical_specifications": specs, "normalized": normalized_specs_from_pdf(text, specs)}


class VertivScraper:
    def __init__(
        self,
        *,
        output: Path,
        cache_dir: Path,
        max_products: int | None,
        max_pages_per_category: int,
        delay_min: float,
        delay_max: float,
        timeout_ms: int,
        headless: bool,
        include_services: bool,
        seed_urls: list[str],
        refresh_cache: bool,
        include_evidence: bool,
    ) -> None:
        self.output = output
        self.cache_dir = cache_dir
        self.max_products = max_products
        self.max_pages_per_category = max_pages_per_category
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.timeout_ms = timeout_ms
        self.headless = headless
        self.include_services = include_services
        self.seed_urls = seed_urls
        self.refresh_cache = refresh_cache
        self.include_evidence = include_evidence
        self.scraped_products = 0
        self.datasheets_seen: set[str] = set()

    async def run(self) -> dict[str, Any]:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise SystemExit(
                "Playwright is required. Run:\n"
                "  python -m pip install -r requirements.txt\n"
                "  python -m playwright install chromium"
            ) from exc

        seeds = self.build_seed_list()
        products: list[dict[str, Any]] = []
        seen_product_urls: set[str] = set()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=self.headless,
                args=["--disable-blink-features=AutomationControlled", "--disable-dev-shm-usage", "--no-sandbox"],
            )
            context = await self.new_context(browser)

            for seed in seeds:
                if self.max_products and len(products) >= self.max_products:
                    break
                page = await context.new_page()
                print(f"[INFO] Category: {seed.main_heading} > {seed.subheading}")
                try:
                    product_urls = await self.collect_product_urls(page, seed)
                except Exception as exc:
                    print(f"[WARN] Could not collect products from {seed.url}: {exc}")
                    product_urls = []
                await page.close()

                for product_url in product_urls:
                    if self.max_products and len(products) >= self.max_products:
                        break
                    canon = canonical_url(product_url)
                    if canon in seen_product_urls:
                        continue
                    seen_product_urls.add(canon)
                    product_page = await context.new_page()
                    try:
                        product = await self.scrape_product(product_page, product_url, seed)
                        products.append(product)
                        self.scraped_products += 1
                        self.write_output(products, seeds)
                    except Exception as exc:
                        print(f"[WARN] Product failed {product_url}: {exc}")
                    finally:
                        await product_page.close()
                    await self.delay()

            await context.close()
            await browser.close()

        catalog = self.write_output(products, seeds)
        print(f"[DONE] Saved {len(products)} products to {self.output}")
        return catalog

    def build_seed_list(self) -> list[CategorySeed]:
        if self.seed_urls:
            return [CategorySeed("Custom", "Custom", canonical_url(absolute_url(url)), "CUSTOM") for url in self.seed_urls]
        seeds = [seed for seed in CATALOG_SEEDS if self.include_services or not seed.is_service]
        deduped: list[CategorySeed] = []
        seen: set[str] = set()
        for seed in seeds:
            full = canonical_url(absolute_url(seed.url))
            if full in seen:
                continue
            seen.add(full)
            deduped.append(CategorySeed(seed.main_heading, seed.subheading, full, seed.category, seed.is_service))
        return deduped

    async def new_context(self, browser: Any) -> Any:
        return await browser.new_context(
            user_agent=random.choice(USER_AGENTS),
            viewport={"width": 1366, "height": 850},
            locale="en-US",
            timezone_id="America/New_York",
            ignore_https_errors=True,
            accept_downloads=True,
            extra_http_headers={"Accept-Language": "en-US,en;q=0.9", "DNT": "1"},
        )

    async def delay(self, multiplier: float = 1.0) -> None:
        await asyncio.sleep(random.uniform(self.delay_min, self.delay_max) * multiplier)

    async def goto(self, page: Any, url: str) -> bool:
        for attempt in range(1, 4):
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                try:
                    await page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 15000))
                except Exception:
                    pass
                await asyncio.sleep(random.uniform(1.0, 2.5))
                return True
            except Exception as exc:
                print(f"[WARN] Load failed ({attempt}/3): {url} :: {exc}")
                await asyncio.sleep(2 * attempt)
        return False

    async def collect_product_urls(self, page: Any, seed: CategorySeed) -> list[str]:
        urls: list[str] = []
        seen: set[str] = set()
        next_url: str | None = seed.url
        page_count = 0

        while next_url and page_count < self.max_pages_per_category:
            page_count += 1
            if not await self.goto(page, next_url):
                break

            try:
                await page.locator(f"xpath={PRODUCT_RESULTS_XPATH}").wait_for(timeout=10000)
            except Exception:
                pass

            page_links = await page.evaluate(
                """
                (xpath) => {
                  const result = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null);
                  const root = result.singleNodeValue || document;
                  return Array.from(root.querySelectorAll('a[href]')).map((a) => ({
                    href: a.href,
                    text: (a.innerText || a.getAttribute('aria-label') || '').trim()
                  }));
                }
                """,
                PRODUCT_RESULTS_XPATH,
            )

            new_count = 0
            for link in page_links:
                href = clean_text(link.get("href"))
                if not href or not is_product_url(href, seed.url):
                    continue
                canon = canonical_url(href)
                if canon in seen:
                    continue
                seen.add(canon)
                urls.append(canon)
                new_count += 1
            print(f"[INFO]   page {page_count}: +{new_count} product URLs")

            next_url = await self.find_next_page_url(page, next_url)
            await self.delay()

        return urls

    async def find_next_page_url(self, page: Any, current_url: str) -> str | None:
        selectors = ("a[rel='next']", "a[aria-label*='Next' i]", "button[aria-label*='Next' i]", ".pagination a:last-child")
        for selector in selectors:
            try:
                element = await page.query_selector(selector)
                if not element:
                    continue
                disabled = await element.get_attribute("disabled")
                aria_disabled = await element.get_attribute("aria-disabled")
                if disabled is not None or aria_disabled == "true":
                    continue
                href = await element.get_attribute("href")
                if href:
                    candidate = canonical_url(absolute_url(href, current_url))
                    if candidate != canonical_url(current_url):
                        return candidate
            except Exception:
                continue
        return None

    async def scrape_product(self, page: Any, product_url: str, seed: CategorySeed) -> dict[str, Any]:
        print(f"[INFO]   product: {product_url}")
        if not await self.goto(page, product_url):
            return self.empty_product(product_url, seed)

        title = await self.extract_title(page)
        model = detect_model(title, product_url)
        datasheet_url = await self.find_datasheet_url(page, product_url)
        technical_specifications: dict[str, Any] | None = None
        normalized: dict[str, Any] = {}

        if datasheet_url:
            self.datasheets_seen.add(datasheet_url)
            try:
                pdf_path = await self.download_pdf(page.context, datasheet_url)
                extracted = extract_pdf_specs(pdf_path)
                technical_specifications = extracted["technical_specifications"]
                normalized = extracted["normalized"]
            except Exception as exc:
                print(f"[WARN]   PDF extraction failed for {datasheet_url}: {exc}")
        else:
            print(f"[WARN]   no datasheet/brochure found for {product_url}")

        item = {
            "vendor": "Vertiv",
            "model": model,
            "category": seed.category,
            **normalized,
            "main_heading": seed.main_heading,
            "subheading": seed.subheading,
            "technical_specifications": technical_specifications,
            "product_url": product_url,
            "datasheet_url": datasheet_url,
        }
        if not self.include_evidence:
            item = {key: value for key, value in item.items() if value not in (None, "", {}, [])}
        return item

    def empty_product(self, product_url: str, seed: CategorySeed) -> dict[str, Any]:
        return {
            "vendor": "Vertiv",
            "model": detect_model(None, product_url),
            "category": seed.category,
            "main_heading": seed.main_heading,
            "subheading": seed.subheading,
            "product_url": product_url,
            "datasheet_url": None,
            "technical_specifications": None,
        }

    async def extract_title(self, page: Any) -> str | None:
        for selector in ("h1.product-hero__title", "h1.pdp-title", ".product-detail h1", ".pdp-header h1", "h1"):
            try:
                element = await page.query_selector(selector)
                if element:
                    text = clean_text(await element.inner_text())
                    if text:
                        return text
            except Exception:
                continue
        title = clean_text(await page.title())
        return title.split("|")[0].strip() if title else None

    async def find_datasheet_url(self, page: Any, product_url: str) -> str | None:
        xpath_locator = page.locator(f"xpath={GET_BROCHURE_XPATH}")
        try:
            if await xpath_locator.count():
                href = await xpath_locator.first.get_attribute("href")
                if href and href != "#":
                    return absolute_url(href, product_url)
                opened = await self.click_and_capture_pdf(page, xpath_locator.first)
                if opened:
                    return opened
        except Exception:
            pass

        links = await page.evaluate(
            """
            () => Array.from(document.querySelectorAll('a[href]')).map((a) => ({
              href: a.href,
              text: (a.innerText || a.getAttribute('aria-label') || a.getAttribute('title') || '').trim()
            }))
            """
        )
        candidates: list[str] = []
        for link in links:
            href = clean_text(link.get("href"))
            text = clean_text(link.get("text")).lower()
            if not href or href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            lower_href = href.lower()
            if ".pdf" in lower_href or any(keyword in text for keyword in DOCUMENT_KEYWORDS):
                candidates.append(absolute_url(href, product_url))

        pdf_candidates = [url for url in candidates if ".pdf" in urlparse(url).path.lower()]
        if pdf_candidates:
            return pdf_candidates[0]

        for candidate in candidates:
            if "/search/" not in urlparse(candidate).path:
                return candidate
        return None

    async def click_and_capture_pdf(self, page: Any, locator: Any) -> str | None:
        try:
            async with page.context.expect_page(timeout=5000) as popup_info:
                await locator.click(timeout=3000)
            popup = await popup_info.value
            await popup.wait_for_load_state("domcontentloaded", timeout=10000)
            url = popup.url
            await popup.close()
            return url if url and url != "about:blank" else None
        except Exception:
            try:
                old_url = page.url
                await locator.click(timeout=3000)
                await page.wait_for_load_state("domcontentloaded", timeout=10000)
                if page.url != old_url:
                    return page.url
            except Exception:
                return None
        return None

    async def download_pdf(self, context: Any, datasheet_url: str) -> Path:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = cache_path_for_url(self.cache_dir, datasheet_url)
        if pdf_path.exists() and not self.refresh_cache:
            return pdf_path

        response = await context.request.get(datasheet_url, timeout=self.timeout_ms)
        if not response.ok:
            raise RuntimeError(f"HTTP {response.status} downloading {datasheet_url}")
        content = await response.body()
        pdf_path.write_bytes(content)
        return pdf_path

    def write_output(self, products: list[dict[str, Any]], seeds: list[CategorySeed]) -> dict[str, Any]:
        catalog = {
            "metadata": {
                "source": "Vertiv product pages and official brochure/datasheet PDFs",
                "seed_urls": [seed.url for seed in seeds],
                "scraped_at": date.today().isoformat(),
                "datasheets_seen": len(self.datasheets_seen),
                "scraped_products": len(products),
                "notes": (
                    "Clean matcher-compatible catalog. Product URLs are discovered from Vertiv "
                    "product-type-results sections. Technical specifications are extracted from "
                    "linked datasheet PDFs with pdfplumber."
                ),
                "include_evidence": self.include_evidence,
            },
            "products": products,
        }
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text(json.dumps(catalog, indent=2, ensure_ascii=False), encoding="utf-8")
        return catalog


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scrape Vertiv product pages and datasheet PDF specs.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--max-products", type=int, default=None)
    parser.add_argument("--max-pages-per-category", type=int, default=8)
    parser.add_argument("--delay-min", type=float, default=1.5)
    parser.add_argument("--delay-max", type=float, default=4.0)
    parser.add_argument("--timeout-ms", type=int, default=45000)
    parser.add_argument("--headful", action="store_true")
    parser.add_argument("--include-services", action="store_true")
    parser.add_argument("--refresh-cache", action="store_true")
    parser.add_argument("--include-evidence", action="store_true")
    parser.add_argument("--seed-url", action="append", default=[])
    return parser.parse_args()


async def async_main() -> None:
    args = parse_args()
    if args.delay_min < 0 or args.delay_max < args.delay_min:
        raise SystemExit("--delay-max must be greater than or equal to --delay-min")

    try:
        import pdfplumber  # noqa: F401
    except ImportError as exc:
        raise SystemExit("pdfplumber is required. Run: python -m pip install -r requirements.txt") from exc

    scraper = VertivScraper(
        output=args.output,
        cache_dir=args.cache_dir,
        max_products=args.max_products,
        max_pages_per_category=args.max_pages_per_category,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        timeout_ms=args.timeout_ms,
        headless=not args.headful,
        include_services=args.include_services,
        seed_urls=args.seed_url,
        refresh_cache=args.refresh_cache,
        include_evidence=args.include_evidence,
    )
    await scraper.run()


if __name__ == "__main__":
    asyncio.run(async_main())
