"""
cost_estimator.py
-----------------
Pre-processing API Cost Estimator for the RFP pipeline.

Usage:
    from cost_estimator import estimate_cost, confirm_execution

    cost_info = estimate_cost(pdf_path, model_name="gemini-3-flash-preview")
    confirm_execution(cost_info)
"""

import os
import sys
from typing import Dict, Optional

from pypdf import PdfReader

# ---------------------------------------------------------------------------
# Pricing config. Paid-tier text/image/video prices are per 1M tokens in USD.
# Source checked 2026-06-10:
# - https://ai.google.dev/gemini-api/docs/models
# - https://ai.google.dev/gemini-api/docs/pricing
# These are text/document-capable Gemini models, excluding Live, TTS,
# image-generation, embedding, robotics, and deprecated/shut-down models.
# ---------------------------------------------------------------------------
DEFAULT_MODEL = os.getenv("GEMINI_MODEL", "gemini-3-flash-preview")

MODEL_PRICING: Dict[str, Dict[str, object]] = {
    "gemini-3-flash-preview": {
        "label": "Gemini 3 Flash Preview",
        "input_per_1m": 0.50,
        "output_per_1m": 3.00,
    },
    "gemini-3.5-flash": {
        "label": "Gemini 3.5 Flash",
        "input_per_1m": 1.50,
        "output_per_1m": 9.00,
    },
    "gemini-3.1-pro-preview": {
        "label": "Gemini 3.1 Pro Preview",
        "input_per_1m": 2.00,
        "output_per_1m": 12.00,
    },
    "gemini-3.1-flash-lite": {
        "label": "Gemini 3.1 Flash-Lite",
        "input_per_1m": 0.25,
        "output_per_1m": 1.50,
    },
    "gemini-2.5-pro": {
        "label": "Gemini 2.5 Pro",
        "input_per_1m": 1.25,
        "output_per_1m": 10.00,
    },
    "gemini-2.5-flash": {
        "label": "Gemini 2.5 Flash",
        "input_per_1m": 0.30,
        "output_per_1m": 2.50,
    },
    "gemini-2.5-flash-lite": {
        "label": "Gemini 2.5 Flash-Lite",
        "input_per_1m": 0.10,
        "output_per_1m": 0.40,
    },
    "gemini-2.5-flash-lite-preview-09-2025": {
        "label": "Gemini 2.5 Flash-Lite Preview 09-2025",
        "input_per_1m": 0.10,
        "output_per_1m": 0.40,
    },
}

# Output tokens are estimated as a fraction of input tokens.
OUTPUT_TOKEN_RATIO: float = float(os.getenv("OUTPUT_TOKEN_RATIO", "0.30"))

# Characters per token. Gemini uses roughly 3.5-4 chars/token for English text;
# this is only an estimate and actual billing may differ.
CHARS_PER_TOKEN: float = float(os.getenv("CHARS_PER_TOKEN", "3.8"))


class AbortedByUser(RuntimeError):
    """Raised when the user explicitly declines to proceed."""


def get_supported_models() -> list:
    """Return model choices for the UI/API."""
    return [
        {
            "id": model_id,
            "label": str(config["label"]),
            "input_per_1m": float(config["input_per_1m"]),
            "output_per_1m": float(config["output_per_1m"]),
        }
        for model_id, config in MODEL_PRICING.items()
    ]


def resolve_model_pricing(model_name: Optional[str]) -> Dict[str, object]:
    """Validate a selected model and return its pricing config."""
    selected = (model_name or DEFAULT_MODEL).strip()
    if selected not in MODEL_PRICING:
        valid = ", ".join(MODEL_PRICING)
        raise ValueError(f"Unsupported model '{selected}'. Choose one of: {valid}")
    pricing = dict(MODEL_PRICING[selected])
    pricing["id"] = selected
    return pricing


def _extract_text_from_pdf(pdf_path: str) -> str:
    """Extract all text from a PDF file."""
    reader = PdfReader(pdf_path)
    pages_text = []
    for page in reader.pages:
        text = page.extract_text()
        if text:
            pages_text.append(text)
    return "\n".join(pages_text)


def estimate_cost(pdf_path: str, extra_prompt_chars: int = 4500, model_name: Optional[str] = None) -> dict:
    """
    Estimate the LLM API cost for processing an RFP PDF.

    The estimate accounts for:
    - Full text extracted from the PDF
    - A fixed overhead for the system prompt, per chunk
    - 10-page chunking used by gemini_extractor.py
    """
    reader = PdfReader(pdf_path)
    num_pages = len(reader.pages)
    pages_per_chunk = 10
    num_chunks = max(1, -(-num_pages // pages_per_chunk))

    raw_text = _extract_text_from_pdf(pdf_path)
    pdf_chars = len(raw_text)
    total_input_chars = pdf_chars + (extra_prompt_chars * num_chunks)

    estimated_input_tokens = int(total_input_chars / CHARS_PER_TOKEN)
    estimated_output_tokens = int(estimated_input_tokens * OUTPUT_TOKEN_RATIO)

    pricing = resolve_model_pricing(model_name)
    input_per_1m = float(pricing["input_per_1m"])
    output_per_1m = float(pricing["output_per_1m"])
    input_cost = (estimated_input_tokens / 1_000_000) * input_per_1m
    output_cost = (estimated_output_tokens / 1_000_000) * output_per_1m
    total_cost = input_cost + output_cost

    return {
        "num_pages": num_pages,
        "num_chunks": num_chunks,
        "total_input_chars": total_input_chars,
        "estimated_input_tokens": estimated_input_tokens,
        "estimated_output_tokens": estimated_output_tokens,
        "model": pricing["id"],
        "model_label": pricing["label"],
        "input_price_per_1m": input_per_1m,
        "output_price_per_1m": output_per_1m,
        "input_cost_usd": round(input_cost, 6),
        "output_cost_usd": round(output_cost, 6),
        "total_cost_usd": round(total_cost, 6),
    }


def confirm_execution(cost_info: dict) -> None:
    """
    Log the cost summary. In web/Gunicorn mode there is no TTY, so this
    function simply prints the estimate and returns. The browser UI is
    responsible for obtaining user confirmation before calling /process.
    """
    print("\n" + "=" * 60)
    print("  API COST ESTIMATION")
    print("=" * 60)
    print(f"  Model              : {cost_info.get('model_label', cost_info.get('model', 'unknown'))}")
    print(f"  PDF pages          : {cost_info['num_pages']}")
    print(f"  Processing chunks  : {cost_info['num_chunks']}")
    print(f"  Est. input tokens  : {cost_info['estimated_input_tokens']:,}")
    print(f"  Est. output tokens : {cost_info['estimated_output_tokens']:,}")
    print(f"  Input cost         : ${cost_info['input_cost_usd']:.6f}")
    print(f"  Output cost        : ${cost_info['output_cost_usd']:.6f}")
    print("  ---------------------------------")
    print(f"  TOTAL ESTIMATED    : ${cost_info['total_cost_usd']:.6f} USD")
    print("=" * 60)
    print("[Cost Gate] Web mode - confirmation handled by browser UI.\n")


def confirm_execution_cli(cost_info: dict) -> None:
    """
    Interactive CLI confirmation gate. Prints the cost summary and blocks
    until the operator types 'yes'. Raises AbortedByUser otherwise.
    """
    confirm_execution(cost_info)

    try:
        answer = input(
            "\nThis is the total cost for processing the RFP. "
            "Would you like to proceed? (yes/no): "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt, OSError):
        print("\n[Cost Gate] Non-interactive environment detected. Aborting for safety.")
        raise AbortedByUser("Non-interactive environment - execution aborted automatically.")

    if answer != "yes":
        print("\n[Cost Gate] Execution cancelled by operator.")
        raise AbortedByUser(f"User declined to proceed (entered: '{answer}').")

    print("[Cost Gate] Operator confirmed. Proceeding with RFP processing...\n")
