from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple

from fortinet.reference_injector import FortinetReferenceInjector
from juniper.rag_matcher import JuniperRAGMatcher


class JuniperReferenceInjector(FortinetReferenceInjector):
    def __init__(self, catalog_dir: str):
        self.matcher = JuniperRAGMatcher(
            catalog_dir,
            top_k=int(os.getenv("JUNIPER_RAG_TOP_K", "8")),
            use_llm=False,
        )
        self.batch_candidate_limit = int(os.getenv("JUNIPER_RAG_BATCH_CANDIDATES", "3"))
        self.batch_llm_enabled = os.getenv("JUNIPER_RAG_USE_LLM", "1").lower() not in {"0", "false", "no", "off"}
        self.stats = {
            "rows_seen": 0,
            "sections_skipped": 0,
            "groups_seen": 0,
            "matched_rows": 0,
            "unmatched_rows": 0,
            "llm_batch_calls": 0,
            "llm_rows_sent": 0,
        }

    @staticmethod
    def _should_reference(text: str, metadata: Dict[str, Any]) -> bool:
        if metadata.get("requires_reference") is True:
            return True
        lowered = str(text or "").lower()
        terms = (
            "juniper", "srx", "ex series", "qfx", "mx series", "acx", "ptx",
            "firewall", "ngfw", "switch", "router", "routing platform",
            "leaf", "spine", "top of rack", "access point", "wireless",
            "wi-fi", "wifi", "mist", "apstra", "session smart router",
            "sfp", "qsfp", "interfaces", "ipsec", "ssl vpn",
        )
        return any(term in lowered for term in terms)


def inject_juniper_references(data: Dict[str, Any], catalog_dir: Optional[str] = None) -> Tuple[Dict[str, Any], Dict[str, int]]:
    if catalog_dir is None:
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        catalog_dir = os.path.join(project_root, "data", "product_catalogs")
    injector = JuniperReferenceInjector(catalog_dir)
    enriched = injector.inject(data)
    return enriched, injector.stats
