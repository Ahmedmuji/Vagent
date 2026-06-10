import os
from typing import Optional


def get_gemini_api_key() -> Optional[str]:
    """Return the Gemini API key used across extraction and RAG stages."""
    return os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")


def describe_gemini_api_key_source() -> str:
    if os.getenv("GEMINI_API_KEY"):
        return "GEMINI_API_KEY"
    if os.getenv("GOOGLE_API_KEY"):
        return "GOOGLE_API_KEY"
    return "not set"
