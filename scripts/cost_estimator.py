"""
cost_estimator.py
-----------------
Pre-processing API Cost Estimator for the RFP pipeline.

Usage:
    from cost_estimator import estimate_cost, confirm_execution

    cost_info = estimate_cost(pdf_path)
    confirm_execution(cost_info)   # raises AbortedByUser if user declines
"""

import os
import sys
from typing import Optional

from pypdf import PdfReader

# ---------------------------------------------------------------------------
# Pricing config (Gemini Flash 2.0 defaults — override via env vars)
# ---------------------------------------------------------------------------
# Price per 1,000 tokens in USD
PRICE_PER_1K_INPUT: float  = float(os.getenv("PRICE_PER_1K_INPUT",  "0.00010"))   # $0.10 / 1M tokens
PRICE_PER_1K_OUTPUT: float = float(os.getenv("PRICE_PER_1K_OUTPUT", "0.00040"))   # $0.40 / 1M tokens

# Output tokens are estimated as a fraction of input tokens
OUTPUT_TOKEN_RATIO: float = float(os.getenv("OUTPUT_TOKEN_RATIO", "0.30"))

# Characters per token — a safe approximation for multilingual/technical PDFs.
# tiktoken is Gemini-incompatible; Gemini uses ~3.5–4 chars/token for English text.
CHARS_PER_TOKEN: float = float(os.getenv("CHARS_PER_TOKEN", "3.8"))


class AbortedByUser(RuntimeError):
    """Raised when the user explicitly declines to proceed."""


def _extract_text_from_pdf(pdf_path: str) -> str:
    """Extract all text from a PDF file."""
    reader = PdfReader(pdf_path)
    pages_text = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            pages_text.append(text)
    return "\n".join(pages_text)


def estimate_cost(pdf_path: str, extra_prompt_chars: int = 4500) -> dict:
    """
    Estimate the LLM API cost for processing an RFP PDF.

    The estimate accounts for:
    - Full text extracted from the PDF
    - A fixed overhead for the system prompt (~4,500 chars by default)
    - Per-chunk overhead since the PDF is split into 10-page chunks

    Parameters
    ----------
    pdf_path : str
        Absolute path to the uploaded RFP PDF.
    extra_prompt_chars : int
        Estimated size of the system prompt injected per chunk in characters.

    Returns
    -------
    dict with keys:
        num_pages, num_chunks, total_input_chars, estimated_input_tokens,
        estimated_output_tokens, input_cost_usd, output_cost_usd, total_cost_usd
    """
    # Step 1 — Count pages to calculate chunking overhead
    reader = PdfReader(pdf_path)
    num_pages = len(reader.pages)
    # Each chunk processes up to 10 pages (mirrors chunk_pdf in gemini_extractor.py)
    PAGES_PER_CHUNK = 10
    num_chunks = max(1, -(-num_pages // PAGES_PER_CHUNK))  # ceiling division

    # Step 2 — Extract raw text and count characters
    raw_text = _extract_text_from_pdf(pdf_path)
    pdf_chars = len(raw_text)

    # Step 3 — Add prompt overhead per chunk
    total_input_chars = pdf_chars + (extra_prompt_chars * num_chunks)

    # Step 4 — Convert characters → tokens using our approximation ratio
    estimated_input_tokens = int(total_input_chars / CHARS_PER_TOKEN)
    estimated_output_tokens = int(estimated_input_tokens * OUTPUT_TOKEN_RATIO)

    # Step 5 — Calculate cost
    input_cost  = (estimated_input_tokens  / 1000) * PRICE_PER_1K_INPUT
    output_cost = (estimated_output_tokens / 1000) * PRICE_PER_1K_OUTPUT
    total_cost  = input_cost + output_cost

    return {
        "num_pages":               num_pages,
        "num_chunks":              num_chunks,
        "total_input_chars":       total_input_chars,
        "estimated_input_tokens":  estimated_input_tokens,
        "estimated_output_tokens": estimated_output_tokens,
        "input_cost_usd":          round(input_cost,  6),
        "output_cost_usd":         round(output_cost, 6),
        "total_cost_usd":          round(total_cost,  6),
    }


def confirm_execution(cost_info: dict) -> None:
    """
    Print a cost summary to the terminal and block until the operator confirms.

    Raises AbortedByUser if anything other than "yes" is entered.

    Parameters
    ----------
    cost_info : dict
        The dict returned by estimate_cost().
    """
    print("\n" + "=" * 60)
    print("  💰  API COST ESTIMATION")
    print("=" * 60)
    print(f"  PDF pages          : {cost_info['num_pages']}")
    print(f"  Processing chunks  : {cost_info['num_chunks']}")
    print(f"  Est. input tokens  : {cost_info['estimated_input_tokens']:,}")
    print(f"  Est. output tokens : {cost_info['estimated_output_tokens']:,}")
    print(f"  Input cost         : ${cost_info['input_cost_usd']:.6f}")
    print(f"  Output cost        : ${cost_info['output_cost_usd']:.6f}")
    print(f"  ─────────────────────────────────")
    print(f"  TOTAL ESTIMATED    : ${cost_info['total_cost_usd']:.6f} USD")
    print("=" * 60)

    try:
        answer = input(
            "\nThis is the total cost for processing the RFP. "
            "Would you like to proceed? (yes/no): "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        # Non-interactive environment (e.g., CI or piped stdin) — auto-abort
        print("\n[Cost Gate] Non-interactive environment detected. Aborting for safety.")
        raise AbortedByUser("Non-interactive environment — execution aborted automatically.")

    if answer != "yes":
        print("\n[Cost Gate] Execution cancelled by operator.")
        raise AbortedByUser(f"User declined to proceed (entered: '{answer}').")

    print("[Cost Gate] ✅ Operator confirmed. Proceeding with RFP processing...\n")
