"""
requirements_detector.py
Extracts the Technical Requirements section from RFP/RFT PDFs.

Core insight from analysing real documents:
  - The TOC and procedural sections reference section names too, so keyword
    matching alone picks the wrong page.
  - A real section start page has DENSE technical content, not just a mention.
  - The actual header occupies a large fraction of the first non-blank lines.
  - End of section = start of next clearly non-technical named section.

  RFT-style (e.g. NTC Data Center) documents use:
    Annex-A1..A8  → Bill of Quantity  (financial but scoped to tech items)
    Annex-B1..B23 → Technical Specifications / Compliance Sheets
  Both Annex groups together constitute the technical requirements package.
  The detector handles this via a dedicated "RFT Annex sweep" that finds the
  earliest Annex-A/B page and the last Annex-B page as start/end boundaries.
"""

import os
import re
import json
import fitz  # PyMuPDF


# ---------------------------------------------------------------------------
# Patterns that identify the start of the tech-requirements section
# Matched against SHORT header-like lines only (< 120 chars, near top of page)
# ---------------------------------------------------------------------------
TECH_START_HEADERS = [
    # Explicit TSR/TSP labels (highest confidence)
    r"\bTSR[-\u2013\s]*\d*\b",
    r"TECHNICAL\s+SPECIFICATION\s+REQUIREMENTS?",
    r"TECHNICAL\s+SCRUTINY\s+PROFORMA",
    r"\bTSP\b",

    # Standard section names
    r"SECTION\s+V\b",
    r"SECTION\s+5\b",
    r"SCHEDULE\s+OF\s+REQUIREMENTS?",
    r"TECHNICAL\s+SPECIFICATIONS?\s*$",
    r"TECHNICAL\s+REQUIREMENTS?\s*$",
    r"TECHNICAL\s+CONDITIONS?\s*/\s*SPECIFICATIONS?",

    # Military/PAF style
    r"DP[-\u2013\s]*2.*PART[-\u2013\s]*III",
    r"PART[-\u2013\s]*III.*TECHNICAL",

    # Annex-based (RFT style) — BOQ summary page
    # Handles variants: "Annex-A", "Annex- A", "Annex-A1", "Annex-A 6" etc.
    r"ANNEX[-\s]*A\s*\d*\s*[:\-]?\s*BILL\s+OF\s+QUANTIT",
    r"ANNEX[-\s]*A\s*:\s*BOQ",
    r"ANNEX(?:URE)?\s*[-\u2013]?\s*A\s*$",
    r"ANNEX(?:URE)?\s*[-\u2013]?\s*1\s*$",

    # BOQ / Scope
    r"BILL\s+OF\s+QUANTITIES?\s*$",
    r"\bBOQ\b\s*$",
    r"SCOPE\s+OF\s+(?:WORK|SUPPLY|SERVICES?)\s*$",
]

# Patterns that definitively mark the END of the tech section
TECH_END_HEADERS = [
    r"SECTION\s+VI\b",
    r"SECTION\s+6\b",
    r"STANDARD\s+FORMS?\s*$",
    r"BID\s+FORMS?\s*$",
    r"PROPOSAL\s+FORMS?\s*$",
    r"GENERAL\s+CONDITIONS?\s+OF\s+(?:THE\s+)?CONTRACT",
    r"SPECIAL\s+CONDITIONS?\s+OF\s+(?:THE\s+)?CONTRACT",
    r"LETTER\s+OF\s+BID",
    r"FINANCIAL\s+PROPOSAL\s+FORM\s*$",
    r"SERVICE\s+LEVEL\s+AGREEMENT\s*$",
    # RFT: ANNEX-C onward are non-technical (SLA, compliance statements, bonds)
    r"ANNEX[-\u2013\s]*[:\-]?\s*C\b",
    r"ANNEX[-\u2013\s]*[:\-]?\s*D\b",
    r"ANNEX[-\u2013\s]*[:\-]?\s*E\b",
    r"ANNEX[-\u2013\s]*[:\-]?\s*F\b",
    r"ANNEX[-\u2013\s]*[:\-]?\s*G\b",
    r"CONTRACT\s+AGREEMENT\s*$",
    r"NON[-\u2013\s]DISCLOSURE\s+AGREEMENT",
    r"PERFORMANCE\s+GUARANTEE\s*$",
    r"BANK\s+GUARANTEE",
    r"EVALUATION\s+CRITERIA\s*$",
    r"RFP\s+FORMS?\s*$",
    r"RFP[-\u2013\s]*0?1\s*$",
    r"FORM\s+['\"]?A[-\u2013]?\d+",
    r"SECTION\s+VII\b",
    r"SECTION\s+VIII\b",
    r"UNDERTAKING\s*$",
    r"DP[-\u2013\s]*(?:PART[-\u2013\s]*)?II\b.*(?:LEGAL|ADMIN)",
    r"LEGAL\s*/\s*ADMINISTRATIVE",
    r"TERMS\s+AND\s+CONDITIONS\s+GOVERNING",
    r"SUPPLEMENT\s+TO\s+INDENT",
    r"FORM\s+DP[-\u2013]?3\b",
    r"FORM\s+DP[-\u2013]?2\s*,?\s*PART[-\u2013\s]*II\b",
]

# Keywords confirming real technical content
TECH_CONTENT_KEYWORDS = [
    "SPECIFICATION", "COMPLIANCE", "MAKE", "MODEL", "QTY", "QUANTITY",
    "PROCESSOR", "MEMORY", "STORAGE", "BANDWIDTH", "THROUGHPUT",
    "FIREWALL", "SWITCH", "ROUTER", "SERVER", "UPS", "RACK", "PDU",
    "RAM", "SSD", "HDD", "GHZ", "MBPS", "GBPS", "KVA", "WATT",
    "HARDWARE", "SOFTWARE", "COOLING", "NETWORK", "SECURITY",
    "FORTIGATE", "CISCO", "DELL", "HP", "JUNIPER",
    "IEC", "NFPA", "TIA", "ANSI", "IEEE",
    "CONTAINMENT", "DATA CENTER", "HVAC", "CCTV", "FIBER",
    "SSL", "VPN", "PDC", "SDC", "BOQ", "TSR",
    "REDUNDAN", "CONCURRENT", "SCALAB",
    "LICENSE", "FIRMWARE", "IPS", "UTM", "IPSEC", "ANTIVIRUS",
    "INSPECTION", "PROTOCOL", "FORTIANALYZER", "FORTIMANAGER",
    # RFT/BOQ specific
    "ANNEX-A", "ANNEX-B", "BILL OF QUANTITY", "COMPUTING NODE",
    "SAN", "NVME", "FLASH", "RACK MOUNT", "XEON", "GPU",
]

PROCEDURAL_KEYWORDS = [
    "TABLE OF CONTENTS", "INDEX OF CLAUSE", "LIST OF CLAUSE",
    "INSTRUCTION TO BIDDER", "INVITATION TO BID", "INVITATION FOR BID",
    "GRIEVANCE", "BID VALIDITY", "BID SECURITY", "PAYMENT SCHEDULE",
    "TERMS AND CONDITIONS", "GENERAL CONDITIONS", "SPECIAL CONDITIONS",
]

# ---------------------------------------------------------------------------
# RFT Annex-A/B sweep patterns
# Many RFT-style documents structure requirements as:
#   Annex-A (Bill of Quantity, sub-sections A1-A8) and
#   Annex-B (Technical Spec compliance sheets, sub-sections B1-B23+).
# We detect these explicitly and return the outer page range directly.
# ---------------------------------------------------------------------------
# Annex-A BOQ summary page: contains this phrase anywhere in its body text.
# fitz extracts the "Annex-A : Bill of Quantity" text from the page body,
# not as a standalone header line — so we search full page text, not just line[0].
_ANNEX_A_BODY_RE = re.compile(r"Annex[-\s]+A\s*[:\-=]\s*Bill\s+of\s+Quant", re.IGNORECASE)

# Annex-B spec pages: "Annex-B\d+" appears as a standalone first/early line.
# fitz reliably extracts this because it's in a text box, not a table cell.
_ANNEX_B_SPEC_RE = re.compile(r"^Annex[-\s]*B\d+\s*$", re.IGNORECASE)

# Annex-C marks end of technical section (SLA, compliance forms follow)
_ANNEX_C_END_RE  = re.compile(r"ANNEX[-\s]*[:\-]?\s*C\b", re.IGNORECASE)


def _detect_rft_annex_range(doc):
    """
    Sweep all pages looking for Annex-A BOQ and Annex-B spec pages.
    Returns (start_page_1based, end_page_1based, title) or None if not an RFT doc.

    KEY INSIGHT: fitz reads Annex-A table pages differently from pdftotext.
    The "Annex-A1 : Bill of Quantity" heading is part of a table header row, so
    fitz returns the column headers ("S# Description Qty A/U") as the first lines,
    not the section title. We therefore:

      - Detect the Annex-A START by finding the BOQ summary page whose BODY TEXT
        contains "Annex-A : Bill of Quantity" (page 26 in the NTC RFT).
      - Detect Annex-B pages normally (their header is a standalone text box).
      - Treat everything from the Annex-A start page up to the last Annex-B page
        as the technical requirements section.

    Also handles corrigendum documents that paste early Annex-B pages again at
    the end as Q&A context — a large gap in Annex-B page numbers triggers a cutoff.
    """
    num_pages    = len(doc)
    annex_a_start = None   # page number (1-based) of BOQ summary page
    annex_b_pages = []
    annex_c_first = None

    for i in range(num_pages):
        page_text = doc[i].get_text()
        lines = [l.strip() for l in page_text.split("\n") if l.strip()]
        if not lines:
            continue

        # ---- Annex-A: search full page body for the BOQ summary phrase ----
        if annex_a_start is None and _ANNEX_A_BODY_RE.search(page_text):
            annex_a_start = i + 1
            print(f"  Annex-A start found: p{annex_a_start}")
            continue   # this page is the BOQ summary; skip other checks

        # ---- Annex-B: header appears as standalone text in first 4 lines ----
        for line in lines[:4]:
            if _ANNEX_B_SPEC_RE.match(line):
                annex_b_pages.append(i + 1)
                break

        # ---- Annex-C end boundary: search first 4 lines ----
        if annex_b_pages and annex_c_first is None:
            for line in lines[:4]:
                if _ANNEX_C_END_RE.search(line):
                    annex_c_first = i + 1
                    break

    if not annex_b_pages:
        return None  # Not an RFT-Annex-B document

    # ------------------------------------------------------------------
    # Corrigendum gap detection
    # Corrigendum PDFs paste early Annex-B pages again at the end as Q&A
    # context. Detect a large jump in Annex-B page numbers and discard
    # everything after it.  Threshold = max(8 × median_gap, 30 pages).
    # ------------------------------------------------------------------
    if len(annex_b_pages) >= 4:
        gaps = [annex_b_pages[k+1] - annex_b_pages[k]
                for k in range(len(annex_b_pages) - 1)]
        first_half_gaps = sorted(gaps[:len(gaps)//2 + 1])
        median_gap = first_half_gaps[len(first_half_gaps) // 2]
        threshold  = max(median_gap * 8, 30)
        for k, g in enumerate(gaps):
            if g > threshold:
                cutoff_page = annex_b_pages[k]
                discarded   = annex_b_pages[k+1:]
                print(f"  Corrigendum gap detected after page {cutoff_page} "
                      f"(gap={g}). Discarding late pages: {discarded}")
                annex_b_pages = annex_b_pages[:k+1]
                break

    # Use Annex-A start if found; otherwise fall back to first Annex-B page
    start_page = annex_a_start if annex_a_start else min(annex_b_pages)
    end_page   = max(annex_b_pages)

    # Stop just before Annex-C if it follows the tech section
    if annex_c_first and annex_c_first > end_page:
        end_page = annex_c_first - 1

    num_b = len(annex_b_pages)
    print(f"  RFT Annex sweep: Annex-A start=p{annex_a_start}, "
          f"{num_b} Annex-B page(s), Annex-C boundary=p{annex_c_first}")
    print(f"  Annex-B pages: {annex_b_pages}")
    print(f"  => Range: {start_page} - {end_page}")

    # Sanity: must span at least 5 pages and have >=3 Annex-B sheets
    if (end_page - start_page + 1) >= 5 and num_b >= 3:
        first_b, last_b = min(annex_b_pages), max(annex_b_pages)
        return (start_page, end_page,
                f"Annex-A (BOQ, p{start_page}) + "
                f"Annex-B (Tech Specs, {num_b} sheets, pp{first_b}-{last_b})")

    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_lines(page):
    return [l.strip() for l in page.get_text().split("\n") if l.strip()]


def is_toc_page(lines, page_idx):
    text = " ".join(lines)
    if text.count("....") > 2 or text.count(". . . .") > 2:
        return True
    if page_idx < 15:
        num_endings = sum(1 for l in lines if re.search(r"\s+\d{1,3}\s*$", l))
        if num_endings > 6:
            return True
    return False


def is_header_line(line, pattern):
    if len(line) > 130:
        return False
    m = re.search(pattern, line.upper())
    if not m:
        return False
    coverage = (m.end() - m.start()) / max(len(line), 1)
    return coverage >= 0.30


def tech_density(lines):
    text = " ".join(lines).upper()
    score = 0
    for kw in TECH_CONTENT_KEYWORDS:
        score += min(text.count(kw), 6)
    return score


def has_procedural_signal(lines):
    text = " ".join(lines).upper()
    return any(p in text for p in PROCEDURAL_KEYWORDS)


# ---------------------------------------------------------------------------
# Pass 1 - collect candidate start pages
# ---------------------------------------------------------------------------

def find_start_candidates(doc):
    candidates = []
    num_pages = len(doc)

    for i in range(num_pages):
        lines = get_lines(doc[i])
        if not lines:
            continue
        if is_toc_page(lines, i):
            continue

        for pattern in TECH_START_HEADERS:
            for line in lines[:8]:
                if is_header_line(line, pattern):
                    density = tech_density(lines)
                    proc = has_procedural_signal(lines)
                    candidates.append({
                        "page_num": i + 1,
                        "page_idx": i,
                        "pattern": pattern,
                        "line": line,
                        "density": density,
                        "procedural": proc,
                    })
                    break
            else:
                continue
            break

    return candidates


# ---------------------------------------------------------------------------
# Pass 2 - score and pick best start page
# ---------------------------------------------------------------------------

def score_candidate(c, num_pages):
    score = 0.0
    pos = c["page_idx"] / num_pages
    pat = c["pattern"]

    if any(kw in pat for kw in ["TSR", "SCRUTINY", "TSP"]):
        score += 1000
    elif "SCHEDULE" in pat or "SECTION" in pat:
        score += 600
    elif "TECHNICAL" in pat:
        score += 500
    elif "DP" in pat or "PART" in pat:
        score += 450
    elif "ANNEX" in pat and "BILL" in pat:
        score += 700  # RFT BOQ+Spec Annex — high confidence
    elif "ANNEX" in pat:
        score += 300
    else:
        score += 200

    score += c["density"] * 8

    if c["procedural"]:
        score -= 800

    if pos < 0.08:
        score -= 500
    elif 0.10 < pos < 0.85:
        score += 100

    return score


def pick_start_page(candidates, num_pages):
    if not candidates:
        return None

    scored = [(score_candidate(c, num_pages), c) for c in candidates]
    scored.sort(key=lambda x: -x[0])

    print("\n  Candidate start pages (top 10, scored):")
    for s, c in scored[:10]:
        print(f"    p{c['page_num']:>4} score={s:>7.0f} density={c['density']:>4} "
              f"proc={c['procedural']} | {c['line'][:70]}")

    return scored[0][1]


# ---------------------------------------------------------------------------
# Pass 3 - find end page
# ---------------------------------------------------------------------------

def find_end_page(start_idx, doc):
    num_pages = len(doc)
    low_density_streak = 0

    for i in range(start_idx + 1, num_pages):
        lines = get_lines(doc[i])
        if not lines:
            continue

        for pattern in TECH_END_HEADERS:
            for line in lines[:10]:
                if is_header_line(line, pattern):
                    print(f"  End header at page {i+1}: '{line[:70]}'")
                    marker_pos = lines.index(line) / max(len(lines), 1)
                    return i if marker_pos < 0.55 else i + 1

        d = tech_density(lines)
        if d < 15:
            low_density_streak += 1
        else:
            low_density_streak = 0

        if low_density_streak >= 6:
            print(f"  Dead-zone end at page {i - 4}")
            return i - 4

    return num_pages


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def detect_requirements(pdf_path):
    doc = fitz.open(pdf_path)
    num_pages = len(doc)
    print(f"\nOpened: {os.path.basename(pdf_path)} ({num_pages} pages)")

    # -----------------------------------------------------------------------
    # Priority 0: RFT Annex-A/B sweep (handles NTC-style RFT documents)
    # -----------------------------------------------------------------------
    print("Pass 0: RFT Annex-A/B sweep...")
    rft_result = _detect_rft_annex_range(doc)
    if rft_result:
        start_page, end_page, title = rft_result
        start_page = max(1, min(start_page, num_pages))
        end_page   = max(start_page, min(end_page, num_pages))
        print(f"\nResult (RFT Annex sweep): pages {start_page}-{end_page} "
              f"({end_page - start_page + 1} pages)")
        return {"start_page": start_page, "end_page": end_page, "section_title": title}

    print("  No RFT Annex-B structure found — falling through to standard scan.")

    # -----------------------------------------------------------------------
    # Standard scan for RFP/tender documents
    # -----------------------------------------------------------------------
    print("Pass 1: Scanning for tech-section headers...")
    candidates = find_start_candidates(doc)
    print(f"  Found {len(candidates)} candidate(s)")

    print("Pass 2: Scoring candidates...")
    best = pick_start_page(candidates, num_pages)

    if best is None:
        print("WARNING: No section found, defaulting to page 1.")
        start_page, title = 1, "Fallback"
    else:
        start_page = best["page_num"]
        title = best["line"]
        print(f"  Selected start: page {start_page} - '{title}'")

    print("Pass 3: Finding end of section...")
    end_page = find_end_page(start_page - 1, doc)
    print(f"  End page: {end_page}")

    start_page = max(1, min(start_page, num_pages))
    end_page   = max(start_page, min(end_page, num_pages))

    print(f"\nResult: pages {start_page}-{end_page} ({end_page - start_page + 1} pages)")
    return {"start_page": start_page, "end_page": end_page, "section_title": title}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    from pdf_segmenter import extract_pages

    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output_dir", default=os.path.join("data", "Extracted Requirements Section"))
    args = parser.parse_args()

    result = detect_requirements(args.input)

    print(f"\n{'='*50}")
    print(f"Section : {result['section_title']}")
    print(f"Pages   : {result['start_page']} - {result['end_page']}")
    print(f"{'='*50}")

    os.makedirs(args.output_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(args.input))[0]
    out  = os.path.join(args.output_dir, f"{base}_Requirements.pdf")
    extract_pages(args.input, out, result["start_page"], result["end_page"])
    print(f"Saved: {out}")

    os.makedirs("output", exist_ok=True)
    with open("output/last_detected_range.json", "w") as f:
        json.dump(result, f, indent=2)