from __future__ import annotations

import json
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from fortinet.rag_matcher import FortinetCandidate, FortinetRAGMatcher, _norm
from product_matcher import ProductMatcher


JUNIPER_CATALOG = "juniper.json"
JUNIPER_EXTRA_CATEGORY_TERMS = {
    "WIRELESS_AP": ("wireless access point", "access point", "wi-fi", "wifi", "mist ap", "ap45", "ap47"),
    "SDWAN_ROUTER": ("session smart router", "sd-wan router", "ssr", "wan edge"),
    "SDN_AUTOMATION": ("apstra", "data center director", "intent-based networking"),
    "CENTRALIZED_MANAGEMENT": ("mist cloud", "wired assurance", "wireless assurance", "security director"),
}


class JuniperRAGMatcher(FortinetRAGMatcher):
    def __init__(self, catalog_dir: str, top_k: int = 8, use_llm: bool = True):
        super().__init__(catalog_dir, top_k=top_k, use_llm=use_llm, include_juniper=True)
        self.products = self._load_products()
        self.chunks = self._build_chunks(self.products)
        self._tfidf_vectorizer = None
        self._tfidf_matrix = None
        self._chunk_embeddings = None

    def match(self, requirement_text: str, metadata: Optional[Dict[str, Any]] = None, vendors: Optional[List[str]] = None) -> Dict[str, Any]:
        metadata = metadata or {}
        query = self._build_query(requirement_text, metadata)
        constraints = self._parse_constraints(query, metadata)
        result = self.match_vendor(query, constraints, "Juniper")
        return {
            "reference": result.get("reference", ""),
            "reasoning": result.get("reasoning", ""),
            "details": {
                "provider": "juniper-rag",
                "query": query,
                "constraints": constraints,
                "vendors": {"Juniper": result.get("details")},
            },
            "vendor_results": {"Juniper": result},
        }

    def _load_products(self) -> List[Dict[str, Any]]:
        path = self.catalog_dir / JUNIPER_CATALOG
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return []
        entries = data.get("products", data) if isinstance(data, dict) else data
        if not isinstance(entries, list):
            return []
        products: List[Dict[str, Any]] = []
        seen = set()
        for item in entries:
            if not isinstance(item, dict):
                continue
            product = dict(item)
            product["vendor"] = "Juniper"
            model = str(product.get("model") or "").strip()
            if not model:
                continue
            key = (model.lower(), str(product.get("category") or "").lower())
            if key in seen:
                continue
            seen.add(key)
            products.append(product)
        return products

    @staticmethod
    def _default_vendors(constraints: Dict[str, Any]) -> List[str]:
        return ["Juniper"]

    @staticmethod
    def _parse_constraints(text: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        normalized = FortinetRAGMatcher._parse_constraints(text, metadata)
        lowered = text.lower()
        for category, terms in JUNIPER_EXTRA_CATEGORY_TERMS.items():
            if any(term in lowered for term in terms):
                normalized["device_type"] = category
                break
        if normalized.get("device_type") == "WIRELESS_AP":
            uplink_match = re.search(r"(\d+(?:\.\d+)?)\s*g(?:be|bps)?\s+(?:uplink|port|interface)", lowered)
            if uplink_match:
                speed = float(uplink_match.group(1))
                interfaces = normalized.setdefault("interfaces", {})
                if isinstance(interfaces, dict):
                    if speed >= 10:
                        interfaces["10g_rj45"] = max(int(interfaces.get("10g_rj45", 0) or 0), 1)
                    elif speed >= 1:
                        interfaces["1g_rj45"] = max(int(interfaces.get("1g_rj45", 0) or 0), 1)
                if normalized.get("throughput_gbps") == speed:
                    normalized.pop("throughput_gbps", None)
        if "requirements" not in normalized:
            normalized["requirements"] = {
                key: value
                for key, value in normalized.items()
                if key not in {"device_type", "source_text", "requirements"}
            }
        else:
            normalized["requirements"] = {
                key: value
                for key, value in normalized["requirements"].items()
                if key in normalized or key == "interfaces"
            }
            if normalized.get("interfaces"):
                normalized["requirements"]["interfaces"] = normalized["interfaces"]
        return normalized

    @staticmethod
    def _category_is_compatible(required: str, candidate: str) -> bool:
        if required == candidate:
            return True
        if candidate in ProductMatcher._candidate_categories(required):
            return True
        compatible = [
            {"ROUTER", "SDWAN_ROUTER"},
            {"DATACENTER_SWITCH", "ACCESS_SWITCH", "SWITCH"},
            {"WIRELESS_AP", "CENTRALIZED_MANAGEMENT"},
        ]
        return any(required in group and candidate in group for group in compatible)

    @staticmethod
    def _passes_hard_constraints(product: Dict[str, Any], constraints: Dict[str, Any]) -> bool:
        category = constraints.get("device_type") or constraints.get("category")
        if category and not JuniperRAGMatcher._category_is_compatible(category, str(product.get("category") or "")):
            return False
        if not ProductMatcher._has_hard_constraints(constraints):
            return True
        ok, _, _, _ = ProductMatcher._passes_hard_filters(product, constraints)
        return ok

    def retrieve(self, query: str, constraints: Dict[str, Any], vendor: Optional[str] = None) -> List[FortinetCandidate]:
        candidates = super().retrieve(query, constraints, vendor="Juniper")
        query_lower = query.lower()
        category = constraints.get("device_type") or constraints.get("category")
        for candidate in candidates:
            model = str(candidate.product.get("model") or "").lower()
            category_text = str(candidate.product.get("category") or "")
            if category and self._category_is_compatible(category, category_text):
                candidate.score += 0.2
            if any(token in query_lower for token in ("srx", "firewall", "ngfw")) and model.startswith("srx"):
                candidate.score += 0.4
            if any(token in query_lower for token in ("qfx", "leaf", "spine", "tor", "data center switch")) and model.startswith("qfx"):
                candidate.score += 0.45
            if any(token in query_lower for token in ("ex", "access switch", "campus switch")) and model.startswith("ex"):
                candidate.score += 0.35
            if any(token in query_lower for token in ("mx", "ptx", "acx", "router")) and re.match(r"^(mx|ptx|acx)", model):
                candidate.score += 0.35
            if any(token in query_lower for token in ("mist", "wireless", "access point", "wi-fi", "wifi")) and model.startswith("ap"):
                candidate.score += 0.45
            if any(token in query_lower for token in ("wi-fi 7", "wifi 7", "802.11be")) and model == "ap47":
                candidate.score += 0.8
            if any(token in query_lower for token in ("wi-fi 6e", "wifi 6e", "6 ghz")) and model == "ap45":
                candidate.score += 0.6
        candidates.sort(key=lambda item: item.score, reverse=True)
        return candidates[: self.top_k]

    def _tfidf_scores(self, query: str):
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            if self._tfidf_vectorizer is None:
                self._tfidf_vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=20000)
                self._tfidf_matrix = self._tfidf_vectorizer.fit_transform([chunk["text"] for chunk in self.chunks])
            query_vec = self._tfidf_vectorizer.transform([query])
            return (self._tfidf_matrix @ query_vec.T).toarray().ravel()
        except Exception:
            query_terms = {term for term in re.findall(r"[a-z0-9]+", query.lower()) if len(term) > 2}
            scores = []
            for chunk in self.chunks:
                chunk_terms = set(re.findall(r"[a-z0-9]+", chunk["text"].lower()))
                if not query_terms or not chunk_terms:
                    scores.append(0.0)
                else:
                    scores.append(len(query_terms & chunk_terms) / math.sqrt(len(query_terms) * len(chunk_terms)))
            return self._array(scores)

    def _fallback_sort_key(self, candidate: FortinetCandidate, constraints: Dict[str, Any]):
        if (constraints.get("device_type") or constraints.get("category")) == "WIRELESS_AP":
            matched, _, _ = self._constraint_details(candidate.product, constraints)
            try:
                score = ProductMatcher._score_product(candidate.product, constraints, matched)
                return (
                    float(score.get("weighted_overprovision_penalty", 999)),
                    float(score.get("weighted_worst_overprovision", 999)),
                    float(score.get("overprovision_penalty", 999)),
                    -candidate.score,
                    float(score.get("hardware_scale", 999)),
                )
            except Exception:
                return (999.0, 999.0, 999.0, -candidate.score, 999.0)
        return super()._fallback_sort_key(candidate, constraints)

    @staticmethod
    def _format_reference(product: Dict[str, Any]) -> str:
        model = str(product.get("model") or "")
        url = str(product.get("datasheet_url") or product.get("product_url") or "").strip()
        return f"Juniper: {model} - {url}" if url else f"Juniper: {model}"

    def _format_result(
        self,
        selected: FortinetCandidate,
        query: str,
        constraints: Dict[str, Any],
        retrieved: List[FortinetCandidate],
        llm_result: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        result = super()._format_result(selected, query, constraints, retrieved, llm_result)
        result["reference"] = self._format_reference(selected.product)
        result["details"]["provider"] = "juniper-rag"
        return result
