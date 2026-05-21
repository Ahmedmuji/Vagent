"""
Vertiv product catalog scraper.

This script uses Playwright because Vertiv product/category pages are rendered
with JavaScript. It walks the main Vertiv catalog headings, collects product
detail URLs, extracts structured technical specifications, and writes a clean
JSON list that can be used as a product catalog.

Install:
    python -m pip install -r requirements.txt
    python -m playwright install chromium

Quick test:
    python scripts/vertiv_scraper.py --max-products 10

Full scrape:
    python scripts/vertiv_scraper.py --output data/product_catalogs/vertiv_scraped.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


BASE_URL = "https://www.vertiv.com"
DEFAULT_OUTPUT = Path("data/product_catalogs/vertiv_scraped.json")

USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
)

DOCUMENT_KEYWORDS = (
    "datasheet",
    "data sheet",
    "brochure",
    "technical specification",
    "technical specifications",
    "specification sheet",
    "spec sheet",
    "manual",
    "installation guide",
    "user guide",
)

SPEC_SECTION_WORDS = (
    "specification",
    "specifications",
    "technical data",
    "technical details",
    "product details",
)


@dataclass(frozen=True)
class CategorySeed:
    parent_category: str
    subcategory: str
    url: str
    normalized_category: str
    is_service: bool = False


CATALOG_SEEDS: tuple[CategorySeed, ...] = (
    CategorySeed(
        "Critical Power",
        "Uninterruptible Power Supplies (UPS)",
        "/en-us/products-catalog/critical-power/uninterruptible-power-supplies-ups/",
        "UPS",
    ),
    CategorySeed(
        "Critical Power",
        "Energy Storage System",
        "/en-us/products-catalog/critical-power/energy-storage-system/",
        "ENERGY_STORAGE",
    ),
    CategorySeed(
        "Critical Power",
        "Battery Energy Storage System (BESS)",
        "/en-us/products-catalog/critical-power/battery-energy-storage-system-bess/",
        "ENERGY_STORAGE",
    ),
    CategorySeed(
        "Critical Power",
        "DC Power Systems",
        "/en-us/products-catalog/critical-power/dc-power-systems/",
        "DC_POWER",
    ),
    CategorySeed(
        "Critical Power",
        "Power Distribution",
        "/en-us/products-catalog/critical-power/power-distribution/",
        "POWER_DISTRIBUTION",
    ),
    CategorySeed(
        "Critical Power",
        "Static Transfer Switches",
        "/en-us/products-catalog/critical-power/static-transfer-switches/",
        "TRANSFER_SWITCH",
    ),
    CategorySeed(
        "Critical Power",
        "Switchgear and Switchboard",
        "/en-us/products-catalog/critical-power/switchgear/",
        "SWITCHGEAR",
    ),
    CategorySeed(
        "Critical Power",
        "Busway and Busduct",
        "/en-us/products-catalog/critical-power/busway-and-busduct/",
        "BUSWAY",
    ),
    CategorySeed(
        "Thermal Management",
        "Liquid Cooling Solutions",
        "/en-us/products-catalog/thermal-management/liquid-cooling-solutions/",
        "COOLING",
    ),
    CategorySeed(
        "Thermal Management",
        "High Density Solutions",
        "/en-us/products-catalog/thermal-management/high-density-solutions/",
        "COOLING",
    ),
    CategorySeed(
        "Thermal Management",
        "Heat Rejection",
        "/en-us/products-catalog/thermal-management/heat-rejection/",
        "COOLING",
    ),
    CategorySeed(
        "Thermal Management",
        "Outdoor Packaged Systems",
        "/en-us/products-catalog/thermal-management/outdoor-packaged-systems/",
        "COOLING",
    ),
    CategorySeed(
        "Thermal Management",
        "Room Cooling",
        "/en-us/products-catalog/thermal-management/room-cooling/",
        "COOLING",
    ),
    CategorySeed(
        "Thermal Management",
        "In-Row Cooling",
        "/en-us/products-catalog/thermal-management/in-row-cooling/",
        "COOLING",
    ),
    CategorySeed(
        "Thermal Management",
        "Rack Cooling",
        "/en-us/products-catalog/thermal-management/rack-cooling/",
        "COOLING",
    ),
    CategorySeed(
        "Thermal Management",
        "Free Cooling Chillers",
        "/en-us/products-catalog/thermal-management/free-cooling-chillers/",
        "COOLING",
    ),
    CategorySeed(
        "Thermal Management",
        "Evaporative Free Cooling",
        "/en-us/products-catalog/thermal-management/evaporative-free-cooling/",
        "COOLING",
    ),
    CategorySeed(
        "Thermal Management",
        "Thermal Control and Monitoring",
        "/en-us/products-catalog/thermal-management/thermal-control-and-monitoring/",
        "COOLING_CONTROL",
    ),
    CategorySeed(
        "Thermal Management",
        "Custom Thermal",
        "/en-us/products-catalog/thermal-management/custom-thermal/",
        "COOLING",
    ),
    CategorySeed(
        "Racks & Enclosures",
        "Integrated Solutions",
        "/en-us/products-catalog/facilities-enclosures-and-racks/integrated-solutions/",
        "INTEGRATED_RACK_SOLUTION",
    ),
    CategorySeed(
        "Racks & Enclosures",
        "Racks & Containment",
        "/en-us/products-catalog/facilities-enclosures-and-racks/racks-and-containment/",
        "RACK",
    ),
    CategorySeed(
        "Racks & Enclosures",
        "Racks & Containment",
        "/en-us/products-catalog/racks-and-enclosures/racks-and-containment/",
        "RACK",
    ),
    CategorySeed(
        "Racks & Enclosures",
        "Outdoor Enclosures",
        "/en-us/products-catalog/facilities-enclosures-and-racks/outdoor-enclosures/",
        "ENCLOSURE",
    ),
    CategorySeed(
        "Monitoring & Management",
        "Digital Infrastructure Solutions",
        "/en-us/products-catalog/monitoring-control-and-management/digital-infrastructure-solutions/",
        "MONITORING",
    ),
    CategorySeed(
        "Monitoring & Management",
        "Embedded Device Management",
        "/en-us/products-catalog/monitoring-control-and-management/embedded-device-management/",
        "MONITORING",
    ),
    CategorySeed(
        "Monitoring & Management",
        "Serial Console",
        "/en-us/products-catalog/monitoring-control-and-management/serial-console/",
        "SERIAL_CONSOLE",
    ),
    CategorySeed(
        "Monitoring & Management",
        "Serial Console and Gateways",
        "/en-us/products-catalog/monitoring-control-and-management/serial-console-and-gateways/",
        "SERIAL_CONSOLE",
    ),
    CategorySeed(
        "Monitoring & Management",
        "IP KVM Switches",
        "/en-us/products-catalog/monitoring-control-and-management/ip-kvm/",
        "KVM",
    ),
    CategorySeed(
        "Monitoring & Management",
        "High Performance KVM",
        "/en-us/products-catalog/monitoring-control-and-management/high-performance-kvm/",
        "KVM",
    ),
    CategorySeed(
        "Monitoring & Management",
        "LCD Tray",
        "/en-us/products-catalog/monitoring-control-and-management/itmanagement/avocent-lcd-local-rack-access-console-/",
        "KVM",
    ),
    CategorySeed(
        "Monitoring & Management",
        "Desktop KVM and KM",
        "/en-us/products-catalog/monitoring-control-and-management/desktop-kvm-and-km/",
        "KVM",
    ),
    CategorySeed(
        "Monitoring & Management",
        "Secure KVM",
        "/en-us/products-catalog/monitoring-control-and-management/secure-kvm/",
        "KVM",
    ),
    CategorySeed(
        "Monitoring & Management",
        "Software",
        "/en-us/products-catalog/monitoring-control-and-management/software/",
        "SOFTWARE",
    ),
    CategorySeed(
        "Monitoring & Management",
        "Monitoring",
        "/en-us/products-catalog/monitoring-control-and-management/monitoring/",
        "MONITORING",
    ),
    CategorySeed("Services", "Project Services", "/en-us/services/project-services/", "SERVICE", True),
    CategorySeed("Services", "Thermal Services", "/en-us/services/thermal-services/", "SERVICE", True),
    CategorySeed("Services", "UPS & Battery Services", "/en-us/services/ups-and-battery-services/", "SERVICE", True),
    CategorySeed("Services", "DC Power Services", "/en-us/services/dc-power-services/", "SERVICE", True),
    CategorySeed("Services", "Rack PDU Services", "/en-us/services/rack-pdu-services/", "SERVICE", True),
)


def clean_text(value: str | None) -> str:
    if not value:
        return ""
    return re.sub(r"\s+", " ", value.replace("\xa0", " ")).strip()


def absolute_url(url: str, base: str = BASE_URL) -> str:
    return urljoin(base, url)


def canonical_url(url: str) -> str:
    parsed = urlparse(url)
    query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=False)))
    path = parsed.path.rstrip("/") + "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", query, ""))


def path_depth(url: str) -> int:
    return len([part for part in urlparse(url).path.split("/") if part])


def is_probable_product_url(url: str, seed_url: str) -> bool:
    parsed = urlparse(url)
    if parsed.netloc and "vertiv.com" not in parsed.netloc:
        return False
    if "/products-catalog/" not in parsed.path:
        return False
    if any(bad in parsed.path.lower() for bad in ("/search/", "/support/", "/services/")):
        return False
    if canonical_url(url) == canonical_url(seed_url):
        return False
    return path_depth(url) > path_depth(seed_url)


def detect_model(name: str | None, url: str) -> str | None:
    text = clean_text(name)
    candidates = re.findall(r"\b(?:[A-Z]{2,}[A-Z0-9-]*\d+[A-Z0-9-]*|\d+[A-Z]{1,}[A-Z0-9-]*)\b", text)
    if candidates:
        return max(candidates, key=len)

    slug = urlparse(url).path.strip("/").split("/")[-1]
    slug = re.sub(r"[-_]+", " ", slug).strip()
    return slug.title() if slug else None


def parse_numeric_value(raw_value: str) -> float | None:
    match = re.search(r"[-+]?\d+(?:,\d{3})*(?:\.\d+)?", raw_value)
    if not match:
        return None
    try:
        return float(match.group(0).replace(",", ""))
    except ValueError:
        return None


def extract_normalized_specs(specs: dict[str, Any] | None) -> dict[str, Any]:
    if not specs:
        return {}

    flat: dict[str, str] = {}
    for key, value in specs.items():
        if isinstance(value, dict):
            for inner_key, inner_value in value.items():
                flat[f"{key} {inner_key}".lower()] = clean_text(str(inner_value))
        elif isinstance(value, list):
            flat[key.lower()] = " ".join(clean_text(str(item)) for item in value)
        else:
            flat[key.lower()] = clean_text(str(value))

    joined = " | ".join(f"{key}: {value}" for key, value in flat.items())
    normalized: dict[str, Any] = {}

    patterns = {
        "power_capacity_kva": r"(?:capacity|power rating|output power)[^|]{0,80}?(\d+(?:\.\d+)?)\s*kva",
        "power_capacity_kw": r"(?:capacity|power rating|output power|cooling capacity)[^|]{0,80}?(\d+(?:\.\d+)?)\s*kw",
        "cooling_capacity_kw": r"(?:cooling capacity|total cooling|net sensible)[^|]{0,80}?(\d+(?:\.\d+)?)\s*kw",
        "rack_units": r"(?:rack units|height|u space)[^|]{0,40}?(\d+)\s*u\b",
        "outlet_count": r"(?:outlets|receptacles)[^|]{0,80}?(\d+)",
        "static_load_kg": r"(?:static load|load capacity|weight capacity)[^|]{0,80}?(\d+(?:,\d{3})*(?:\.\d+)?)\s*kg",
    }

    lower_joined = joined.lower()
    for field, pattern in patterns.items():
        match = re.search(pattern, lower_joined, flags=re.IGNORECASE)
        if match:
            value = parse_numeric_value(match.group(1))
            if value is not None:
                normalized[field] = int(value) if value.is_integer() else value

    if re.search(r"\bn\+1\b|redundan|dual\s+power|2n\b", lower_joined, flags=re.IGNORECASE):
        normalized["redundancy"] = True
    if re.search(r"\bhot[- ]?swappable\b", lower_joined, flags=re.IGNORECASE):
        normalized["hot_swappable"] = True

    return normalized


class VertivScraper:
    def __init__(
        self,
        *,
        output: Path,
        max_products: int | None,
        max_pages_per_category: int,
        delay_min: float,
        delay_max: float,
        timeout_ms: int,
        headless: bool,
        include_services: bool,
        seed_urls: list[str],
    ) -> None:
        self.output = output
        self.max_products = max_products
        self.max_pages_per_category = max_pages_per_category
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.timeout_ms = timeout_ms
        self.headless = headless
        self.include_services = include_services
        self.seed_urls = seed_urls

    async def run(self) -> list[dict[str, Any]]:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise SystemExit(
                "Playwright is not installed.\n"
                "Run: python -m pip install -r requirements.txt\n"
                "Then: python -m playwright install chromium"
            ) from exc

        seeds = self._build_seed_list()
        products: list[dict[str, Any]] = []
        seen_products: set[str] = set()

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(
                headless=self.headless,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                ],
            )

            for seed in seeds:
                if self.max_products and len(products) >= self.max_products:
                    break

                context = await self._new_context(browser)
                page = await context.new_page()
                print(f"[INFO] Category: {seed.parent_category} > {seed.subcategory}")

                try:
                    urls = await self.collect_product_urls(page, seed)
                except Exception as exc:
                    print(f"[WARN] Failed to collect URLs from {seed.url}: {exc}")
                    urls = []

                await page.close()

                product_page = await context.new_page()
                for url in urls:
                    if self.max_products and len(products) >= self.max_products:
                        break
                    canon = canonical_url(url)
                    if canon in seen_products:
                        continue
                    seen_products.add(canon)

                    record = await self.scrape_product(product_page, url, seed)
                    products.append(record)
                    self._write_output(products)
                    await self.polite_delay()

                await product_page.close()
                await context.close()
                await self.polite_delay(multiplier=2.0)

            await browser.close()

        self._write_output(products)
        print(f"[DONE] Saved {len(products)} products to {self.output.resolve()}")
        return products

    def _build_seed_list(self) -> list[CategorySeed]:
        if self.seed_urls:
            return [
                CategorySeed("Custom", "Custom Seed", absolute_url(url), "CUSTOM")
                for url in self.seed_urls
            ]

        seeds = [seed for seed in CATALOG_SEEDS if self.include_services or not seed.is_service]
        deduped: list[CategorySeed] = []
        seen: set[str] = set()
        for seed in seeds:
            full_url = canonical_url(absolute_url(seed.url))
            if full_url in seen:
                continue
            seen.add(full_url)
            deduped.append(
                CategorySeed(
                    seed.parent_category,
                    seed.subcategory,
                    full_url,
                    seed.normalized_category,
                    seed.is_service,
                )
            )
        return deduped

    async def _new_context(self, browser: Any) -> Any:
        return await browser.new_context(
            user_agent=random.choice(USER_AGENTS),
            viewport={"width": random.choice((1280, 1366, 1440)), "height": random.choice((768, 900))},
            locale="en-US",
            timezone_id="America/New_York",
            ignore_https_errors=True,
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "DNT": "1",
                "Upgrade-Insecure-Requests": "1",
            },
        )

    async def polite_delay(self, multiplier: float = 1.0) -> None:
        await asyncio.sleep(random.uniform(self.delay_min, self.delay_max) * multiplier)

    async def goto(self, page: Any, url: str) -> bool:
        for attempt in range(1, 4):
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
                try:
                    await page.wait_for_load_state("networkidle", timeout=min(self.timeout_ms, 15000))
                except Exception:
                    pass
                await asyncio.sleep(random.uniform(1.0, 2.0))
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

            page_links = await page.evaluate(
                """
                () => Array.from(document.querySelectorAll('a[href]')).map((a) => ({
                  href: a.href,
                  text: (a.innerText || a.getAttribute('aria-label') || '').trim(),
                  className: a.className || ''
                }))
                """
            )

            new_count = 0
            for link in page_links:
                href = clean_text(link.get("href"))
                if not href or not is_probable_product_url(href, seed.url):
                    continue
                canon = canonical_url(href)
                if canon in seen:
                    continue
                seen.add(canon)
                urls.append(canon)
                new_count += 1

            print(f"[INFO]   page {page_count}: +{new_count} product URLs")
            next_url = await self.find_next_page_url(page, next_url)
            await self.polite_delay()

        return urls

    async def find_next_page_url(self, page: Any, current_url: str) -> str | None:
        next_selectors = (
            "a[rel='next']",
            "a[aria-label*='Next' i]",
            "button[aria-label*='Next' i]",
            ".pagination a:last-child",
            ".pagination button:last-child",
        )
        for selector in next_selectors:
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

    async def scrape_product(self, page: Any, url: str, seed: CategorySeed) -> dict[str, Any]:
        print(f"[INFO]   product: {url}")
        record: dict[str, Any] = {
            "vendor": "Vertiv",
            "model": None,
            "product_name": None,
            "category": seed.normalized_category,
            "product_category": f"{seed.parent_category} > {seed.subcategory}",
            "parent_category": seed.parent_category,
            "subcategory": seed.subcategory,
            "technical_specifications": None,
            "normalized_specifications": {},
            "datasheet_urls": None,
            "documents": None,
            "source_product_page_url": url,
            "product_url": url,
            "scraped_at": datetime.now(timezone.utc).isoformat(),
        }

        if not await self.goto(page, url):
            return record

        try:
            record["product_name"] = await self.extract_title(page)
            record["model"] = detect_model(record["product_name"], url)
        except Exception as exc:
            print(f"[WARN]   title extraction failed for {url}: {exc}")

        try:
            specs = await self.extract_specifications(page)
            record["technical_specifications"] = specs or None
            record["normalized_specifications"] = extract_normalized_specs(specs)
            if not specs:
                print(f"[WARN]   no technical specs found for {record['product_name'] or url}")
        except Exception as exc:
            print(f"[WARN]   spec extraction failed for {url}: {exc}")

        try:
            documents = await self.extract_documents(page, url)
            record["documents"] = documents or None
            pdfs = [doc["url"] for doc in documents if doc.get("is_pdf")]
            record["datasheet_urls"] = pdfs or None
            if not pdfs:
                print(f"[WARN]   no datasheet PDFs found for {record['product_name'] or url}")
        except Exception as exc:
            print(f"[WARN]   document extraction failed for {url}: {exc}")

        return record

    async def extract_title(self, page: Any) -> str | None:
        selectors = (
            "h1.product-hero__title",
            "h1.pdp-title",
            "h1.product-detail__name",
            "[data-testid*='product'][data-testid*='title']",
            ".product-detail h1",
            ".pdp-header h1",
            "h1",
        )
        for selector in selectors:
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

    async def extract_specifications(self, page: Any) -> dict[str, Any]:
        await self.open_possible_sections(page, ("Specifications", "Technical", "Product Details", "Resources"))
        specs: dict[str, Any] = {}

        table_specs = await self.extract_table_specs(page)
        specs.update(table_specs)

        dl_specs = await self.extract_definition_specs(page)
        for key, value in dl_specs.items():
            specs.setdefault(key, value)

        section_specs = await self.extract_text_section_specs(page)
        for key, value in section_specs.items():
            specs.setdefault(key, value)

        return self.clean_specs(specs)

    async def extract_table_specs(self, page: Any) -> dict[str, Any]:
        rows = await page.evaluate(
            """
            () => Array.from(document.querySelectorAll('table')).flatMap((table) => {
              const caption = (table.caption && table.caption.innerText || '').trim();
              return Array.from(table.querySelectorAll('tr')).map((tr) => ({
                caption,
                cells: Array.from(tr.querySelectorAll('th,td')).map((cell) => cell.innerText.trim())
              }));
            })
            """
        )

        specs: dict[str, Any] = {}
        active_headers: list[str] | None = None
        for row in rows:
            cells = [clean_text(cell) for cell in row.get("cells", []) if clean_text(cell)]
            if len(cells) < 2:
                continue

            lower_cells = [cell.lower() for cell in cells]
            headerish = any(word in " ".join(lower_cells) for word in ("model", "specification", "parameter"))
            if headerish and len(cells) > 2:
                active_headers = cells
                continue

            key = cells[0].rstrip(":")
            if not self.looks_like_spec_key(key):
                continue

            if len(cells) == 2:
                specs[key] = cells[1]
                continue

            if active_headers and len(active_headers) == len(cells):
                specs[key] = {
                    active_headers[index]: value
                    for index, value in enumerate(cells[1:], start=1)
                    if value
                }
            else:
                specs[key] = cells[1:]

        return specs

    async def extract_definition_specs(self, page: Any) -> dict[str, Any]:
        pairs = await page.evaluate(
            """
            () => Array.from(document.querySelectorAll('dl')).flatMap((dl) => {
              const children = Array.from(dl.children);
              const pairs = [];
              for (let i = 0; i < children.length; i++) {
                if (children[i].tagName.toLowerCase() === 'dt') {
                  const next = children.slice(i + 1).find((el) => el.tagName.toLowerCase() === 'dd');
                  if (next) pairs.push([children[i].innerText.trim(), next.innerText.trim()]);
                }
              }
              return pairs;
            })
            """
        )
        specs: dict[str, Any] = {}
        for key, value in pairs:
            key = clean_text(key).rstrip(":")
            value = clean_text(value)
            if key and value and self.looks_like_spec_key(key):
                specs[key] = value
        return specs

    async def extract_text_section_specs(self, page: Any) -> dict[str, Any]:
        sections = await page.evaluate(
            """
            () => Array.from(document.querySelectorAll('section, .accordion, .tab-pane, [role="tabpanel"], div'))
              .map((el) => ({
                heading: (el.querySelector('h2,h3,h4,[role="heading"]')?.innerText || '').trim(),
                text: (el.innerText || '').trim()
              }))
              .filter((item) => item.text.length > 20 && item.text.length < 5000)
            """
        )
        specs: dict[str, Any] = {}
        for section in sections:
            heading = clean_text(section.get("heading"))
            body = clean_text(section.get("text"))
            if not body:
                continue
            section_name = f"{heading} {body[:120]}".lower()
            if not any(word in section_name for word in SPEC_SECTION_WORDS):
                continue

            for line in re.split(r"\n| {2,}", section.get("text", "")):
                line = clean_text(line)
                match = re.match(r"^(.{3,80}?):\s*(.{1,500})$", line)
                if not match:
                    continue
                key = clean_text(match.group(1)).rstrip(":")
                value = clean_text(match.group(2))
                if key and value and self.looks_like_spec_key(key):
                    specs[key] = value

        return specs

    @staticmethod
    def looks_like_spec_key(key: str) -> bool:
        key = clean_text(key)
        if not key or len(key) > 100:
            return False
        lowered = key.lower()
        bad_keys = {
            "model",
            "models",
            "description",
            "overview",
            "resources",
            "documents",
            "download",
            "downloads",
            "support",
        }
        if lowered in bad_keys:
            return False
        return bool(re.search(r"[A-Za-z]", key))

    @staticmethod
    def clean_specs(specs: dict[str, Any]) -> dict[str, Any]:
        cleaned: dict[str, Any] = {}
        for key, value in specs.items():
            cleaned_key = clean_text(str(key)).rstrip(":")
            if not cleaned_key:
                continue
            if isinstance(value, dict):
                cleaned_value = {
                    clean_text(str(k)): clean_text(str(v))
                    for k, v in value.items()
                    if clean_text(str(k)) and clean_text(str(v))
                }
            elif isinstance(value, list):
                cleaned_value = [clean_text(str(item)) for item in value if clean_text(str(item))]
            else:
                cleaned_value = clean_text(str(value))
            if cleaned_value:
                cleaned[cleaned_key] = cleaned_value
        return cleaned

    async def extract_documents(self, page: Any, source_url: str) -> list[dict[str, Any]]:
        await self.open_possible_sections(page, ("Documents", "Downloads", "Resources", "Brochures"))
        links = await page.evaluate(
            """
            () => Array.from(document.querySelectorAll('a[href]')).map((a) => ({
              href: a.href,
              text: (a.innerText || '').trim(),
              aria: (a.getAttribute('aria-label') || '').trim(),
              title: (a.getAttribute('title') || '').trim()
            }))
            """
        )

        docs: list[dict[str, Any]] = []
        seen: set[str] = set()
        for link in links:
            href = clean_text(link.get("href"))
            label = clean_text(link.get("text") or link.get("aria") or link.get("title"))
            if not href or href.startswith("javascript:") or href.startswith("mailto:"):
                continue

            full_url = absolute_url(href, source_url)
            lower_url = full_url.lower()
            lower_label = label.lower()
            is_pdf = ".pdf" in lower_url.split("?", 1)[0]
            has_doc_keyword = any(keyword in lower_label for keyword in DOCUMENT_KEYWORDS)

            if not is_pdf and not has_doc_keyword:
                continue
            if not is_pdf and "vertiv.com" in urlparse(full_url).netloc and "/search/" in urlparse(full_url).path:
                continue

            canon = canonical_url(full_url)
            if canon in seen:
                continue
            seen.add(canon)
            docs.append(
                {
                    "title": label or Path(urlparse(full_url).path).name,
                    "url": full_url,
                    "is_pdf": is_pdf,
                    "document_type": self.classify_document(label, full_url),
                }
            )

        return docs

    async def open_possible_sections(self, page: Any, labels: tuple[str, ...]) -> None:
        for label in labels:
            selectors = (
                f"button:has-text('{label}')",
                f"a:has-text('{label}')",
                f"[role='tab']:has-text('{label}')",
                f"[aria-controls*='{label.lower()}']",
            )
            for selector in selectors:
                try:
                    elements = await page.query_selector_all(selector)
                    for element in elements[:2]:
                        if await element.is_visible():
                            await element.click(timeout=2000)
                            await asyncio.sleep(0.5)
                except Exception:
                    continue

    @staticmethod
    def classify_document(label: str, url: str) -> str:
        text = f"{label} {url}".lower()
        if "datasheet" in text or "data-sheet" in text or "data sheet" in text:
            return "datasheet"
        if "brochure" in text:
            return "brochure"
        if "technical" in text or "specification" in text or "spec-sheet" in text:
            return "technical_specification"
        if "manual" in text or "guide" in text:
            return "manual"
        return "document"

    def _write_output(self, products: list[dict[str, Any]]) -> None:
        self.output.parent.mkdir(parents=True, exist_ok=True)
        self.output.write_text(json.dumps(products, indent=2, ensure_ascii=False), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scrape Vertiv hardware technical specs and datasheet PDFs into JSON."
    )
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help="JSON output path.")
    parser.add_argument("--max-products", type=int, default=None, help="Stop after N product pages.")
    parser.add_argument("--max-pages-per-category", type=int, default=8, help="Pagination cap per category.")
    parser.add_argument("--delay-min", type=float, default=1.5, help="Minimum random delay in seconds.")
    parser.add_argument("--delay-max", type=float, default=4.0, help="Maximum random delay in seconds.")
    parser.add_argument("--timeout-ms", type=int, default=45000, help="Page load timeout.")
    parser.add_argument("--headful", action="store_true", help="Run Chromium visibly for debugging.")
    parser.add_argument("--include-services", action="store_true", help="Also scrape service category pages.")
    parser.add_argument(
        "--seed-url",
        action="append",
        default=[],
        help="Scrape one or more custom category URLs instead of the built-in Vertiv catalog seeds.",
    )
    return parser.parse_args()


async def async_main() -> None:
    args = parse_args()
    if args.delay_min < 0 or args.delay_max < args.delay_min:
        raise SystemExit("--delay-max must be greater than or equal to --delay-min")

    scraper = VertivScraper(
        output=args.output,
        max_products=args.max_products,
        max_pages_per_category=args.max_pages_per_category,
        delay_min=args.delay_min,
        delay_max=args.delay_max,
        timeout_ms=args.timeout_ms,
        headless=not args.headful,
        include_services=args.include_services,
        seed_urls=args.seed_url,
    )
    await scraper.run()


if __name__ == "__main__":
    asyncio.run(async_main())
