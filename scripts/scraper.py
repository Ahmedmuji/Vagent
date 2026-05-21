"""
Fortinet Administration Guide — Sidebar Scraper
================================================
Uses Playwright (Python) to:
  1. Load the dynamic page and wait for the sidebar to render
  2. Expand ALL collapsed sections in the left-nav tree
  3. Walk the DOM tree to build a hierarchical JSON structure
  4. Deduplicate URLs
  5. Output:
       data/navigation/fortinet_sidebar.json       – hierarchical tree
       data/navigation/fortinet_sidebar_flat.json  – flat list with breadcrumb paths

Setup:
    pip install playwright
    playwright install chromium
"""

import json
from pathlib import Path
import time
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────
BASE_URL  = "https://docs.fortinet.com"
START_URL = (
    "https://docs.fortinet.com/document/fortigate/7.6.6/"
    "administration-guide/954635/getting-started"
)
PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = PROJECT_ROOT / "data" / "navigation"
OUTPUT_TREE = OUTPUT_DIR / "fortinet_sidebar.json"
OUTPUT_FLAT = OUTPUT_DIR / "fortinet_sidebar_flat.json"

# Selector: any <a> whose href contains the guide path segment
GUIDE_PATH   = "/administration-guide/"
NAV_LINK_SEL = f"a[href*='{GUIDE_PATH}']"

# Maximum rounds of "expand collapsed nodes" to handle deeply-nested trees
MAX_EXPAND_ROUNDS = 15


# ─────────────────────────────────────────────────────────────────────────────
# Step 1 – Expand all collapsed sidebar nodes
# ─────────────────────────────────────────────────────────────────────────────
def expand_all_sections(page) -> None:
    """
    Fortinet's sidebar renders collapsed sub-trees lazily.
    We repeatedly:
      - Find every toggle / expand button / collapsed node
      - Click them all
      - Wait briefly for newly-inserted DOM nodes
    until nothing new can be expanded.

    Multiple selector strategies are tried so the script degrades
    gracefully if the site changes its CSS classes.
    """
    # Selectors that commonly represent a "collapsed" toggle on doc sites
    TOGGLE_SELECTORS = [
        # collapsed aria-expanded buttons
        "button[aria-expanded='false']",
        # items with class variants that hint at collapse
        ".collapsed",
        ".tree-toggle[aria-expanded='false']",
        # generic list-item expanders
        "li.has-children:not(.open) > span",
        "li.has-children:not(.open) > a",
        # Fortinet-specific patterns (may vary by version)
        ".sidebar-item.collapsed > .sidebar-toggle",
        "[data-toggle='collapse'][aria-expanded='false']",
    ]

    print("[*] Expanding collapsed sidebar sections ...")
    for round_num in range(1, MAX_EXPAND_ROUNDS + 1):
        clicked = 0
        for sel in TOGGLE_SELECTORS:
            try:
                toggles = page.query_selector_all(sel)
                for toggle in toggles:
                    try:
                        if toggle.is_visible():
                            toggle.click()
                            clicked += 1
                    except Exception:
                        pass  # element may have gone stale – skip it
            except Exception:
                pass  # selector produced an error – skip it

        if clicked == 0:
            print(f"   [ok] No more collapsed nodes found (after {round_num} rounds).")
            break

        print(f"   Round {round_num}: clicked {clicked} toggle(s). Waiting for render …")
        time.sleep(1.5)  # give JS time to render new nodes

    # Final safety wait
    page.wait_for_timeout(2000)


# ─────────────────────────────────────────────────────────────────────────────
# Step 2 – Locate the sidebar container element
# ─────────────────────────────────────────────────────────────────────────────
def find_sidebar(page):
    """
    Returns the sidebar container ElementHandle.
    Tries multiple candidate selectors in priority order.
    Falls back to document.body if nothing matches.
    """
    # Priority-ordered list of containers that typically wrap the left-nav
    SIDEBAR_SELECTORS = [
        "nav[aria-label*='sidebar' i]",
        "nav[aria-label*='navigation' i]",
        "[class*='sidebar']",
        "[class*='left-nav']",
        "[class*='toc']",        # table-of-contents panels
        "[class*='nav-tree']",
        "aside",
        "nav",
    ]

    for sel in SIDEBAR_SELECTORS:
        try:
            el = page.query_selector(sel)
            if el:
                # Verify it actually contains at least one guide link
                if el.query_selector(NAV_LINK_SEL):
                    print(f"   Sidebar located via: {sel!r}")
                    return el
        except Exception:
            pass

    print("   [!] Could not isolate sidebar container -- falling back to <body>.")
    return page.query_selector("body")


# ─────────────────────────────────────────────────────────────────────────────
# Step 3 – Recursively walk the DOM tree to build hierarchical data
# ─────────────────────────────────────────────────────────────────────────────
def walk_node(node, seen_urls: set, parent_path: str = "") -> list:
    """
    Recursively traverses *node* (an ElementHandle) and returns a list of
    dicts shaped like:
        {
            "title": str,
            "url":   str,          # absolute URL
            "path":  str,          # breadcrumb e.g. "IPsec VPN > Site-to-site VPN"
            "children": [ ... ]    # nested items (same shape, minus "path" key
        }

    Strategy
    --------
    - If the node is an <a> with a matching href  → it's a leaf item.
    - If the node is a <li> / <ul> / <nav> / <div> → recurse into children.
    - Build the breadcrumb path as we descend.
    """
    items = []

    # --- Check if *this* node is a qualifying link ---------------------------
    tag = (node.evaluate("el => el.tagName.toLowerCase()") or "").lower()
    if tag == "a":
        href = node.get_attribute("href") or ""
        if GUIDE_PATH in href:
            url   = urljoin(BASE_URL, href)
            title = (node.inner_text() or "").strip()
            if title and url not in seen_urls:
                seen_urls.add(url)
                path = f"{parent_path} > {title}" if parent_path else title
                return [{
                    "title":    title,
                    "url":      url,
                    "path":     path,
                    "children": [],
                }]
        return []

    # --- Otherwise recurse into child elements --------------------------------
    try:
        children_handles = node.query_selector_all(":scope > *")
    except Exception:
        return []

    for child in children_handles:
        child_items = walk_node(child, seen_urls, parent_path)
        items.extend(child_items)

    return items


# ─────────────────────────────────────────────────────────────────────────────
# Step 3b – Alternative flat extraction (fallback / supplement)
# ─────────────────────────────────────────────────────────────────────────────
def extract_flat_links(page) -> list:
    """
    Simple, reliable extraction: grab every <a href*='/administration-guide/'>
    on the page, resolve to absolute URL, deduplicate, and return a flat list.
    Used to cross-check / supplement the hierarchical walk.
    """
    seen  = set()
    items = []

    links = page.query_selector_all(NAV_LINK_SEL)
    for link in links:
        href  = link.get_attribute("href") or ""
        title = (link.inner_text() or "").strip()
        if not href or not title:
            continue
        url = urljoin(BASE_URL, href)
        if url in seen:
            continue
        seen.add(url)
        items.append({"title": title, "url": url})

    return items


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 – Build hierarchy from a flat ordered list
# ─────────────────────────────────────────────────────────────────────────────
def build_hierarchy_from_flat(flat_items: list) -> dict:
    """
    Heuristic: infer parent–child relationships from indentation / nesting
    clues baked into the URL structure (path depth).

    URL depth examples:
        …/administration-guide/954635/…          depth 2  → top-level
        …/administration-guide/954635/12345/…    depth 3  → child of 954635

    Returns a tree dict with "title" + "children".
    """
    def depth(url: str) -> int:
        path = urlparse(url).path
        # Count segments after '/administration-guide/'
        idx  = path.find(GUIDE_PATH)
        if idx == -1:
            return 0
        sub  = path[idx + len(GUIDE_PATH):]
        return len([s for s in sub.split("/") if s])

    root = {"title": "Administration Guide", "children": []}
    stack = [root]  # stack[-1] is the current parent

    for item in flat_items:
        d = depth(item["url"])
        node = {
            "title":    item["title"],
            "url":      item["url"],
            "children": [],
        }

        # Pop the stack until we find a parent at depth d-1 (or root)
        while len(stack) > 1 and depth(stack[-1].get("url", "")) >= d:
            stack.pop()

        stack[-1]["children"].append(node)
        stack.append(node)

    return root


# ─────────────────────────────────────────────────────────────────────────────
# Step 5 – Flatten the hierarchy into a list with breadcrumb paths
# ─────────────────────────────────────────────────────────────────────────────
def flatten_tree(node: dict, path: str = "") -> list:
    """
    DFS walk of the hierarchy tree.
    Returns a list of:
        { "title": str, "url": str, "path": str }
    """
    flat  = []
    title = node.get("title", "")
    url   = node.get("url",   "")
    crumb = f"{path} > {title}" if path else title

    if url:
        flat.append({"title": title, "url": url, "path": crumb})

    for child in node.get("children", []):
        flat.extend(flatten_tree(child, crumb))

    return flat


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("[*] Launching Playwright ...")
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"],
        )
        context = browser.new_context(
            # Mimic a real desktop browser to avoid bot-detection blocks
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1440, "height": 900},
        )
        page = context.new_page()

        # ── Navigate ──────────────────────────────────────────────────────────
        print(f"[*] Navigating to:\n    {START_URL}\n")
        page.goto(START_URL, wait_until="domcontentloaded", timeout=90_000)

        # ── Wait for the sidebar link(s) to appear ────────────────────────────
        print("[*] Waiting for sidebar links to appear ...")
        try:
            page.wait_for_selector(NAV_LINK_SEL, timeout=60_000)
        except PlaywrightTimeout:
            print("   [!] Timed-out waiting for sidebar -- proceeding anyway.")

        # Extra buffer for JS hydration
        page.wait_for_timeout(3000)

        # ── Expand all collapsed sections ─────────────────────────────────────
        expand_all_sections(page)

        # ── Extract flat list (reliable fallback) ─────────────────────────────
        print("\n[*] Extracting all sidebar links (flat) ...")
        flat_links = extract_flat_links(page)
        print(f"   Found {len(flat_links)} unique links.")

        # ── Build hierarchical tree from URL depth heuristic ──────────────────
        print("\n[*] Building hierarchy from URL depth ...")
        tree = build_hierarchy_from_flat(flat_links)

        # ── Flatten with breadcrumb paths ─────────────────────────────────────
        flat_with_paths = flatten_tree(tree)

        # ── Save outputs ──────────────────────────────────────────────────────
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        with open(OUTPUT_TREE, "w", encoding="utf-8") as f:
            json.dump(tree, f, indent=2, ensure_ascii=False)
        print(f"\n[OK] Hierarchy tree   -> {OUTPUT_TREE}")

        with open(OUTPUT_FLAT, "w", encoding="utf-8") as f:
            json.dump(flat_with_paths, f, indent=2, ensure_ascii=False)
        print(f"[OK] Flat list        -> {OUTPUT_FLAT}")
        print(f"\n[*]  Total items in flat list: {len(flat_with_paths)}")

        # ── Quick preview ─────────────────────────────────────────────────────
        print("\n--------------  Preview (first 10 items)  --------------")
        for item in flat_with_paths[:10]:
            print(f"  > [{item['path']}]\n    {item['url']}")
        print("--------------------------------------------------------")

        browser.close()


if __name__ == "__main__":
    main()
