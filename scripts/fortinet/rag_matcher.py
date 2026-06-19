from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import numpy as np
except Exception:  # pragma: no cover - fallback for minimal runtimes
    np = None

from product_matcher import ProductMatcher


FORTINET_RAG_CATALOGS = ("fortinet_scraped.json", "fortinet.json")
OPTIONAL_RAG_CATALOGS = ("juniper.json",)
CURATED_FALLBACK_PRODUCTS = (
    {
        "vendor": "Fortinet",
        "model": "FortiLogger",
        "category": "LOGGING",
        "product_url": "https://www.fortilogger.com/",
        "datasheet_url": "https://www.fortilogger.com/",
        "description": "Dedicated Fortinet-compatible hardware logging, reporting, and log backup appliance.",
        "use_case": "hardware logging solution, firewall logs, centralized logging, log reporting, log backup",
    },
    {
        "vendor": "Fortinet",
        "model": "FortiSwitch 1048E",
        "category": "DATACENTER_SWITCH",
        "switching_capacity_gbps": 1760,
        "interfaces": {
            "10g_sfp_plus": 48,
            "40g_qsfp_plus": 6,
        },
        "management_port": True,
        "product_url": "https://www.fortinet.com/products/ethernet-switches/fortiswitch",
        "datasheet_url": "https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/FortiSwitch_Data_Center_Series.pdf",
        "description": "FortiSwitch data-center switch family member for high-density 10G SFP+ switching requirements.",
    },
)
NETWORK_CATEGORIES = {
    "NGFW",
    "DATACENTER_SWITCH",
    "ACCESS_SWITCH",
    "SWITCH",
    "ROUTER",
    "CENTRALIZED_MANAGEMENT",
    "LOGGING",
    "SIEM_SOC",
    "NDR",
    "ENDPOINT_SECURITY",
    "IDENTITY_ACCESS",
    "PAM",
    "SANDBOX",
    "EMAIL_SECURITY",
    "NAC",
    "DECEPTION",
    "SOAR",
    "SASE",
    "SECURE_WEB_GATEWAY",
    "DDOS_MITIGATION",
    "DIGITAL_RISK_PROTECTION",
    "NETWORK_PERFORMANCE_MONITORING",
    "AI_NETWORK_OPERATIONS",
    "CLOUD_SECURITY",
    "WAN_EXTENDER",
    "VOIP_SECURITY",
    "VIDEO_SECURITY",
    "WAF",
    "ADC",
    "SDN_AUTOMATION",
}


@dataclass
class FortinetCandidate:
    product: Dict[str, Any]
    chunk: str
    score: float


def _clean_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _norm(value: Any) -> str:
    return _clean_text(value).lower()


class FortinetRAGMatcher:
    def __init__(
        self,
        catalog_dir: str,
        top_k: int = 8,
        use_llm: bool = True,
        include_juniper: bool = True,
    ):
        self.catalog_dir = Path(catalog_dir)
        self.top_k = top_k
        self.use_llm = use_llm
        self.include_juniper = include_juniper
        self.products = self._load_products()
        self.chunks = self._build_chunks(self.products)
        self._embedding_model = None
        self._chunk_embeddings = None
        self._tfidf_vectorizer = None
        self._tfidf_matrix = None
        self._llm_client = None

    def match(
        self,
        requirement_text: str,
        metadata: Optional[Dict[str, Any]] = None,
        vendors: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        metadata = metadata or {}
        query = self._build_query(requirement_text, metadata)
        constraints = self._parse_constraints(query, metadata)
        vendors = vendors or self._default_vendors(constraints)
        results = {
            vendor: self.match_vendor(query, constraints, vendor)
            for vendor in vendors
        }
        references = [
            result["reference"]
            for result in results.values()
            if result and result.get("reference")
        ]
        reasoning = "\n\n".join(
            result.get("reasoning", "")
            for result in results.values()
            if result and result.get("reasoning")
        )
        return {
            "reference": " | ".join(references),
            "reasoning": reasoning,
            "details": {
                "provider": "fortinet-rag",
                "query": query,
                "constraints": constraints,
                "vendors": {vendor: (result.get("details") if result else None) for vendor, result in results.items()},
            },
            "vendor_results": results,
        }

    def match_vendor(self, query: str, constraints: Dict[str, Any], vendor: str) -> Dict[str, Any]:
        constraints = self._adjust_solution_scale_constraints(query, constraints, vendor)
        if not self.has_matchable_product_intent(query, constraints):
            return {
                "reference": "",
                "reasoning": f"{vendor}: skipped because the row has no concrete hardware constraints or explicit product intent.",
                "details": {
                    "provider": "fortinet-rag",
                    "vendor": vendor,
                    "match_status": "not_a_hardware_reference_row",
                    "query": query,
                    "constraints": constraints,
                    "top_candidates": [],
                },
            }
        retrieved = self.retrieve(query, constraints, vendor=vendor)
        safe_candidates = [
            candidate for candidate in retrieved
            if self._passes_hard_constraints(candidate.product, constraints)
        ]
        candidates = self._merge_candidates(
            safe_candidates,
            self._safe_catalog_candidates(query, constraints, vendor),
            constraints,
        )
        llm_result = self._llm_rank(query, constraints, candidates, vendor) if self.use_llm else None
        if llm_result and llm_result.get("selected_model") and str(llm_result.get("match_status", "")).lower() != "no_safe_match":
            selected = self._candidate_by_model(candidates, str(llm_result["selected_model"])) or (candidates[0] if candidates else None)
            if selected:
                return self._format_result(selected, query, constraints, retrieved, llm_result)
        if not candidates:
            return {
                "reference": "",
                "reasoning": f"{vendor}: no catalog item met all hard constraints without being under-spec.",
                "details": {
                    "provider": "fortinet-rag",
                    "vendor": vendor,
                    "match_status": "no_safe_match",
                    "query": query,
                    "constraints": constraints,
                    "top_candidates": self._candidate_summaries(retrieved),
                },
            }
        selected = self._select_fallback(candidates, constraints)
        return self._format_result(selected, query, constraints, retrieved, None)

    def retrieve(self, query: str, constraints: Dict[str, Any], vendor: Optional[str] = None) -> List[FortinetCandidate]:
        category = constraints.get("device_type") or constraints.get("category")
        categories = set(ProductMatcher._candidate_categories(category)) if category else set()
        semantic_scores = self._semantic_scores(query)
        query_terms = {term for term in re.findall(r"[a-z0-9]+", query.lower()) if len(term) > 2}
        query_lower = query.lower()
        candidates: List[FortinetCandidate] = []
        for idx, chunk in enumerate(self.chunks):
            product = chunk["product"]
            if vendor and _norm(product.get("vendor")) != vendor.lower():
                continue
            product_category = str(product.get("category") or "")
            score = float(semantic_scores[idx]) if idx < len(semantic_scores) else 0.0
            chunk_text = chunk["text"].lower()
            overlap = sum(1 for term in query_terms if term in chunk_text)
            score += min(overlap / 28.0, 0.30)
            if category and product_category in categories:
                score += 0.35
            elif category and self._category_is_compatible(category, product_category):
                score += 0.12
            for model_key in self._model_keys(product.get("model")):
                model_tokens = [token for token in model_key.split() if len(token) > 1]
                if model_key and model_key in query_lower:
                    score += 0.85
                    break
                if len(model_tokens) >= 2 and all(token in query_terms for token in model_tokens):
                    score += 0.45
                    break
            score += self._fortinet_domain_boost(query_lower, product, chunk_text)
            candidates.append(FortinetCandidate(product=product, chunk=chunk["text"], score=score))
        candidates.sort(key=lambda item: item.score, reverse=True)
        deduped: List[FortinetCandidate] = []
        seen = set()
        for candidate in candidates:
            key = (_norm(candidate.product.get("vendor")), _norm(candidate.product.get("model")), candidate.product.get("datasheet_url"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(candidate)
            if len(deduped) >= self.top_k:
                break
        return deduped

    def _safe_catalog_candidates(self, query: str, constraints: Dict[str, Any], vendor: str) -> List[FortinetCandidate]:
        if not self.has_matchable_product_intent(query, constraints):
            return []
        category = constraints.get("device_type") or constraints.get("category")
        categories = set(ProductMatcher._candidate_categories(category)) if category else set()
        query_terms = {term for term in re.findall(r"[a-z0-9]+", query.lower()) if len(term) > 2}
        safe: List[FortinetCandidate] = []
        for chunk in self.chunks:
            product = chunk["product"]
            if _norm(product.get("vendor")) != vendor.lower():
                continue
            if categories and str(product.get("category") or "") not in categories:
                continue
            if not self._passes_hard_constraints(product, constraints):
                continue
            chunk_terms = set(re.findall(r"[a-z0-9]+", chunk["text"].lower()))
            overlap = len(query_terms & chunk_terms) / max(1.0, math.sqrt(max(1, len(query_terms)) * max(1, len(chunk_terms))))
            safe.append(FortinetCandidate(product=product, chunk=chunk["text"], score=overlap))
        return sorted(safe, key=lambda item: self._fallback_sort_key(item, constraints))[: self.top_k]

    def _merge_candidates(
        self,
        primary: List[FortinetCandidate],
        secondary: List[FortinetCandidate],
        constraints: Dict[str, Any],
    ) -> List[FortinetCandidate]:
        merged: List[FortinetCandidate] = []
        seen = set()
        for candidate in [*primary, *secondary]:
            key = (_norm(candidate.product.get("vendor")), _norm(candidate.product.get("model")), str(candidate.product.get("category") or ""))
            if key in seen:
                continue
            seen.add(key)
            merged.append(candidate)
        return sorted(merged, key=lambda item: self._fallback_sort_key(item, constraints))[: self.top_k]

    def _load_products(self) -> List[Dict[str, Any]]:
        products: List[Dict[str, Any]] = []
        seen = set()
        catalog_names = list(FORTINET_RAG_CATALOGS)
        if self.include_juniper:
            catalog_names.extend(OPTIONAL_RAG_CATALOGS)
        for filename in catalog_names:
            path = self.catalog_dir / filename
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            entries = data.get("products", data) if isinstance(data, dict) else data
            if not isinstance(entries, list):
                continue
            for item in entries:
                if not isinstance(item, dict):
                    continue
                item = dict(item)
                self._normalize_product_link(item)
                vendor = str(item.get("vendor") or "").strip()
                model = str(item.get("model") or "").strip()
                if not vendor or not model:
                    continue
                if vendor.lower() not in {"fortinet", "juniper"}:
                    continue
                key = (vendor.lower(), model.lower(), str(item.get("category") or "").lower())
                if key in seen:
                    continue
                seen.add(key)
                products.append(item)
        for item in CURATED_FALLBACK_PRODUCTS:
            key = (
                str(item.get("vendor") or "").lower(),
                str(item.get("model") or "").lower(),
                str(item.get("category") or "").lower(),
            )
            if key not in seen:
                seen.add(key)
                products.append(dict(item))
        return products

    @staticmethod
    def _normalize_product_link(product: Dict[str, Any]) -> None:
        vendor = _norm(product.get("vendor") or "")
        model = str(product.get("model") or "")
        url = str(product.get("datasheet_url") or "").lower()
        if vendor != "fortinet" or "infographic" not in url:
            return
        match = re.search(r"fortigate\s+(\d{3,4})([a-z])", model, flags=re.I)
        if not match:
            return
        series_number = (int(match.group(1)) // 100) * 100
        series_letter = match.group(2).lower()
        product["datasheet_url"] = (
            f"https://www.fortinet.com/content/dam/fortinet/assets/data-sheets/"
            f"fortigate-{series_number}{series_letter}-series.pdf"
        )

    @staticmethod
    def _build_chunks(products: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        chunks: List[Dict[str, Any]] = []
        for product in products:
            fields = []
            for key, value in product.items():
                if value in (None, "", {}, []):
                    continue
                value_text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
                fields.append(f"{key}: {value_text}")
            if fields:
                chunks.append({"product": product, "text": " | ".join(fields)})
        return chunks

    @staticmethod
    def _build_query(requirement_text: str, metadata: Dict[str, Any]) -> str:
        parts = [requirement_text]
        for key in ("device_type", "device_category", "category", "source_text"):
            if metadata.get(key):
                parts.append(str(metadata[key]))
        for key in ("detected_specs", "requirements", "interfaces"):
            if isinstance(metadata.get(key), dict):
                parts.append(json.dumps(metadata[key], ensure_ascii=False))
        deduped: List[str] = []
        seen = set()
        for part in parts:
            cleaned = _clean_text(part)
            if not cleaned:
                continue
            key = cleaned.lower()
            if key in seen:
                continue
            if any(key in existing.lower() for existing in deduped):
                continue
            seen.add(key)
            deduped.append(cleaned)
        return " | ".join(deduped)

    @staticmethod
    def _parse_constraints(text: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        extracted = ProductMatcher.extract_requirement_metadata(text)
        merged = dict(metadata or {})
        query_lower = str(text or "").lower()
        if re.search(r"\b(fortilogger|hardware logging|centralized logging|log reporting|log backup|logging appliance|firewall logs?)\b", query_lower):
            merged["device_category"] = "LOGGING"
            merged["device_type"] = "LOGGING"
        elif re.search(r"\b(perimeter firewall|next generation firewall|ngfw|firewall appliance|firewall throughput|threat protection throughput|ssl[-\s]?vpn\s+(?:throughput|users?|concurrent)|remote site firewall|central site firewall)\b", query_lower):
            merged["device_category"] = "NGFW"
            merged["device_type"] = "NGFW"
        elif re.search(r"\b(data\s*center|datacenter|core|access|distribution)\s+switch(?:es)?\b|\bswitching capacity\b", query_lower):
            merged["device_category"] = "DATACENTER_SWITCH"
            merged["device_type"] = "DATACENTER_SWITCH"
        for key, value in extracted.items():
            if key == "requirements" and isinstance(value, dict):
                existing = merged.setdefault("requirements", {})
                if isinstance(existing, dict):
                    existing.update({k: v for k, v in value.items() if v not in (None, "")})
            elif key == "interfaces" and isinstance(value, dict):
                existing_interfaces = merged.setdefault("interfaces", {})
                if isinstance(existing_interfaces, dict):
                    for name, count in value.items():
                        existing_interfaces[name] = max(int(existing_interfaces.get(name, 0) or 0), int(count))
            elif value not in (None, "") and not merged.get(key):
                merged[key] = value
        normalized = ProductMatcher.normalize_requirements(merged, source_text=text[:1000])
        if not normalized.get("device_type"):
            normalized["device_type"] = extracted.get("device_type")
        FortinetRAGMatcher._apply_explicit_throughput_labels(normalized, text)
        FortinetRAGMatcher._apply_explicit_interface_counts(normalized, text)
        FortinetRAGMatcher._apply_explicit_ssl_vpn_user_labels(normalized, text)
        FortinetRAGMatcher._sanitize_cross_product_constraints(normalized)
        return normalized

    @staticmethod
    def _apply_explicit_interface_counts(requirements: Dict[str, Any], text: str) -> None:
        explicit = ProductMatcher._extract_interfaces(ProductMatcher._normalize_text(text))
        if not explicit:
            return
        interfaces = dict(requirements.get("interfaces") or {})
        speed_by_name = {
            "1g_rj45": 1,
            "10g_rj45": 10,
            "1_10g_rj45": 10,
            "1g_sfp": 1,
            "10g_sfp_plus": 10,
            "25g_sfp28": 25,
            "40g_qsfp_plus": 40,
            "50g_sfp56": 50,
            "100g_qsfp28": 100,
            "200g_qsfp56": 200,
            "400g_qsfp_dd": 400,
        }
        corrected = {}
        for name, explicit_count in explicit.items():
            current = ProductMatcher._parse_catalog_number(interfaces.get(name))
            speed = speed_by_name.get(name)
            if current is None:
                interfaces[name] = explicit_count
                continue
            if speed and int(current) == int(explicit_count) * speed:
                interfaces[name] = explicit_count
                corrected[name] = {"from": int(current), "to": explicit_count}
            elif int(current) < int(explicit_count):
                interfaces[name] = explicit_count
        if interfaces:
            requirements["interfaces"] = interfaces
            nested = dict(requirements.get("requirements") or {})
            nested["interfaces"] = interfaces
            requirements["requirements"] = nested
        if corrected:
            notes = list(requirements.get("constraint_sanitization_notes") or [])
            notes.append(f"Corrected multiplied interface metadata from explicit text: {corrected}")
            requirements["constraint_sanitization_notes"] = notes

    @staticmethod
    def _sanitize_cross_product_constraints(requirements: Dict[str, Any]) -> None:
        category = requirements.get("device_type") or requirements.get("category")
        if category != "NGFW":
            return
        controller_or_service_fields = {
            "logs_per_day_gb",
            "analytic_rate_logs_sec",
            "collector_rate_logs_sec",
            "performance_eps",
            "email_routing_per_hour",
            "atp_per_hour",
            "email_domains",
            "server_mode_mailboxes",
            "max_devices_vdoms",
            "max_local_remote_users",
            "max_user_groups",
            "max_nas_devices",
            "max_fortitokens",
        }
        nested = dict(requirements.get("requirements") or {})
        removed = {}
        for field in controller_or_service_fields:
            if field in requirements:
                removed[field] = requirements.pop(field)
            nested.pop(field, None)
        if removed:
            requirements["requirements"] = nested
            notes = list(requirements.get("constraint_sanitization_notes") or [])
            notes.append(
                "Ignored controller/logging/service capacity fields while matching NGFW appliance hardware: "
                + ", ".join(sorted(removed))
            )
            requirements["constraint_sanitization_notes"] = notes

    @staticmethod
    def _apply_explicit_throughput_labels(requirements: Dict[str, Any], text: str) -> None:
        lowered = str(text or "").lower()

        def labeled_gbps(label_pattern: str) -> Optional[float]:
            match = re.search(
                rf"(?:{label_pattern})[^\d]{{0,80}}(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>tbps|gbps|mbps)\b",
                lowered,
                flags=re.I,
            )
            if not match:
                return None
            value = float(match.group("value"))
            unit = match.group("unit").lower()
            if unit == "tbps":
                return value * 1000
            if unit == "mbps":
                return value / 1000
            return value

        explicit_fields = {
            "ngfw_throughput_gbps": r"(?:next\s+generation\s+firewall|ngfw)\s+throughput",
            "firewall_throughput_gbps": r"(?<!generation\s)firewall\s+throughput",
            "ips_throughput_gbps": r"\bips\s+throughput",
            "threat_protection_gbps": r"threat\s+protection\s+throughput",
            "ssl_tls_inspection_gbps": r"ssl\s*/\s*tls\s+inspection\s+throughput|ssl\s+inspection\s+throughput|tls\s+inspection\s+throughput",
            "ssl_vpn_gbps": r"ssl[-\s]?vpn\s+throughput",
            "ipsec_vpn_throughput_gbps": r"ipsec\s+(?:vpn\s+)?throughput",
        }
        for field, pattern in explicit_fields.items():
            value = labeled_gbps(pattern)
            if value is not None:
                requirements[field] = value
        if requirements.get("ngfw_throughput_gbps") not in (None, ""):
            source = lowered[:1200]
            if "next generation firewall throughput" in source or "ngfw throughput" in source:
                requirements.pop("firewall_throughput_gbps", None)
                nested = dict(requirements.get("requirements") or {})
                nested.pop("firewall_throughput_gbps", None)
                nested["ngfw_throughput_gbps"] = requirements["ngfw_throughput_gbps"]
                requirements["requirements"] = nested

    @staticmethod
    def _apply_explicit_ssl_vpn_user_labels(requirements: Dict[str, Any], text: str) -> None:
        lowered = str(text or "").lower()

        def parse_int(value: str) -> float:
            return float(value.replace(",", ""))

        values: List[float] = []
        scalable_values: List[float] = []
        for match in re.finditer(r"(?:ssl[-\s]?vpn|vpn)[^\d]{0,80}(?P<value>\d[\d,]*)\s*(?:concurrent\s+)?users?\b", lowered):
            values.append(parse_int(match.group("value")))
        for match in re.finditer(r"\b(?:scalable|scale|handle)[^\d]{0,80}(?P<value>\d[\d,]*)\s*(?:concurrent\s+)?ssl[-\s]?vpn\s+users?\b", lowered):
            scalable_values.append(parse_int(match.group("value")))
        for match in re.finditer(r"\b(?:scalable|scale|handle)[^\d]{0,80}(?P<value>\d[\d,]*)\s*concurrent[^\|.;]{0,40}ssl\s+vpn\s+users?\b", lowered):
            scalable_values.append(parse_int(match.group("value")))

        if values or scalable_values:
            selected = max(values + scalable_values)
            requirements["ssl_vpn_users"] = selected
            requirements.pop("max_local_remote_users", None)
            requirements["device_type"] = "NGFW"
            if scalable_values and max(scalable_values) >= selected:
                requirements["solution_scale_ssl_vpn_users"] = max(scalable_values)
            nested = dict(requirements.get("requirements") or {})
            nested["ssl_vpn_users"] = selected
            nested.pop("max_local_remote_users", None)
            if requirements.get("solution_scale_ssl_vpn_users"):
                nested["solution_scale_ssl_vpn_users"] = requirements["solution_scale_ssl_vpn_users"]
            requirements["requirements"] = nested

    @staticmethod
    def _default_vendors(constraints: Dict[str, Any]) -> List[str]:
        category = constraints.get("device_type") or constraints.get("category")
        if category in {"NGFW", "SWITCH", "DATACENTER_SWITCH", "ACCESS_SWITCH", "ROUTER"}:
            return ["Fortinet", "Juniper"]
        return ["Fortinet"]

    @staticmethod
    def _category_is_compatible(required: str, candidate: str) -> bool:
        if required == candidate:
            return True
        return candidate in ProductMatcher._candidate_categories(required)

    def _semantic_scores(self, query: str):
        if not self.chunks:
            return self._array([])
        if os.getenv("FORTINET_USE_SENTENCE_EMBEDDINGS", "").lower() in {"1", "true", "yes"}:
            try:
                model = self._get_embedding_model()
                query_vec = model.encode([query], normalize_embeddings=True)
                chunk_vecs = self._get_chunk_embeddings(model)
                return chunk_vecs @ query_vec[0]
            except Exception:
                pass
        return self._tfidf_scores(query)

    def _get_embedding_model(self):
        if self._embedding_model is None:
            from sentence_transformers import SentenceTransformer
            model_name = os.getenv("FORTINET_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
            self._embedding_model = SentenceTransformer(model_name)
        return self._embedding_model

    def _get_chunk_embeddings(self, model):
        if self._chunk_embeddings is None:
            texts = [chunk["text"] for chunk in self.chunks]
            self._chunk_embeddings = self._array(model.encode(texts, normalize_embeddings=True))
        return self._chunk_embeddings

    def _tfidf_scores(self, query: str):
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            if self._tfidf_vectorizer is None:
                self._tfidf_vectorizer = TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=25000)
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
                    continue
                scores.append(len(query_terms & chunk_terms) / math.sqrt(len(query_terms) * len(chunk_terms)))
            return self._array(scores)

    @staticmethod
    def _array(values: List[float]):
        return np.array(values) if np is not None else values

    @staticmethod
    def _passes_hard_constraints(product: Dict[str, Any], constraints: Dict[str, Any]) -> bool:
        category = constraints.get("device_type") or constraints.get("category")
        if category and not FortinetRAGMatcher._category_is_compatible(category, str(product.get("category") or "")):
            return False
        if category == "LOGGING" and "fortilogger" in _norm(product.get("model")):
            return True
        if not ProductMatcher._has_hard_constraints(constraints):
            return True
        ok, _, _, _ = ProductMatcher._passes_hard_filters(product, constraints)
        return ok

    @staticmethod
    def has_matchable_product_intent(query: str, constraints: Dict[str, Any]) -> bool:
        if ProductMatcher._has_hard_constraints(constraints):
            return True

        query_lower = str(query or "").lower()
        if re.search(
            r"\b(procurement title|scope of work|delivery schedule|invitation to bid|bidder|eligibility|qualification|support, warranty|warranty, subscription|training|payment terms|general content|misc requirements|notes)\b",
            query_lower,
        ):
            return False

        explicit_patterns = (
            r"\b(?:fortigate|fortiswitch|fortimanager|fortianalyzer|fortilogger|fortisiem)\b",
            r"\bhardware\s+based\s+(?:next\s+generation\s+firewall|firewall|logging|management)\b",
            r"\b(?:firewall|ngfw)\s+(?:appliance|equipment|hardware|throughput)\b",
            r"\b(?:remote|central)\s+site\s+(?:equipment|firewall)s?\b",
            r"\b(?:ssl[-\s]?vpn)\s+(?:users?|throughput|appliance|concurrent)\b",
            r"\b(?:data\s*center|datacenter|core|access|distribution)\s+switch(?:es)?\b",
            r"\bswitching\s+capacity\b",
            r"\b(?:hardware\s+logging|logging\s+appliance|log\s+reporting|log\s+backup|firewall\s+logs?)\b",
            r"\b(?:centralized|network)\s+management\s+(?:appliance|hardware|solution)\b",
        )
        if any(re.search(pattern, query_lower) for pattern in explicit_patterns):
            return True

        category = constraints.get("device_type") or constraints.get("category")
        if category in {"LOGGING", "CENTRALIZED_MANAGEMENT"} and any(
            term in query_lower for term in ("hardware", "appliance", "device", "equipment", "logs", "management")
        ):
            return True
        return False

    def _adjust_solution_scale_constraints(self, query: str, constraints: Dict[str, Any], vendor: str) -> Dict[str, Any]:
        adjusted = dict(constraints or {})
        required = ProductMatcher._parse_catalog_number(adjusted.get("ssl_vpn_users"))
        if required is None:
            return adjusted
        query_lower = query.lower()
        if "ssl" not in query_lower or "vpn" not in query_lower:
            return adjusted
        if not re.search(r"\b(scalable|scale|license|licence|solution|pr\s+and\s+dr|pdc|sdc|redundant)\b", query_lower):
            return adjusted
        max_supported = self._vendor_max_numeric(vendor, "ssl_vpn_users", adjusted)
        if max_supported is None or required <= max_supported:
            return adjusted
        adjusted["solution_scale_ssl_vpn_users"] = required
        adjusted["ssl_vpn_users"] = max_supported
        requirements = dict(adjusted.get("requirements") or {})
        requirements["solution_scale_ssl_vpn_users"] = required
        requirements["ssl_vpn_users"] = max_supported
        adjusted["requirements"] = requirements
        adjusted["constraint_adjustment_note"] = (
            f"Requested SSL-VPN scale {int(required)} is treated as solution/license scale; "
            f"per-appliance hard filter capped at catalog maximum {int(max_supported)} for {vendor}."
        )
        return adjusted

    def _vendor_max_numeric(self, vendor: str, field: str, constraints: Dict[str, Any]) -> Optional[float]:
        category = constraints.get("device_type") or constraints.get("category")
        max_value: Optional[float] = None
        for product in self.products:
            if _norm(product.get("vendor")) != vendor.lower():
                continue
            if category and not self._category_is_compatible(category, str(product.get("category") or "")):
                continue
            value = ProductMatcher._product_numeric_value(product, field, None)
            if value is None:
                continue
            max_value = max(float(value), max_value or 0.0)
        return max_value

    @staticmethod
    def _constraint_details(product: Dict[str, Any], constraints: Dict[str, Any]) -> Tuple[List[str], List[str], Dict[str, Any]]:
        try:
            _, matched, missing, details = ProductMatcher._passes_hard_filters(product, constraints)
            return matched, missing, details
        except Exception:
            return [], [], {}

    def _select_fallback(self, candidates: List[FortinetCandidate], constraints: Dict[str, Any]) -> FortinetCandidate:
        return sorted(candidates, key=lambda candidate: self._fallback_sort_key(candidate, constraints))[0]

    def _fallback_sort_key(self, candidate: FortinetCandidate, constraints: Dict[str, Any]) -> Tuple[float, ...]:
        matched, _, _ = self._constraint_details(candidate.product, constraints)
        try:
            score = ProductMatcher._score_product(candidate.product, constraints, matched)
            url_penalty = self._datasheet_url_penalty(candidate.product)
            if constraints.get("solution_scale_ssl_vpn_users"):
                ssl_users = ProductMatcher._product_numeric_value(candidate.product, "ssl_vpn_users", None) or 0.0
                required_ssl_users = ProductMatcher._parse_catalog_number(constraints.get("ssl_vpn_users")) or ssl_users or 1.0
                ssl_user_gap = abs(float(ssl_users) - float(required_ssl_users)) / max(float(required_ssl_users), 1.0)
                return (
                    ssl_user_gap,
                    float(score.get("weighted_overprovision_penalty", 999)),
                    float(score.get("weighted_worst_overprovision", 999)),
                    float(score.get("hardware_scale", 999)),
                    url_penalty,
                    -candidate.score,
                )
            return (
                float(score.get("weighted_overprovision_penalty", 999)),
                float(score.get("weighted_worst_overprovision", 999)),
                float(score.get("overprovision_penalty", 999)),
                float(score.get("hardware_scale", 999)),
                url_penalty,
                -candidate.score,
            )
        except Exception:
            return (999.0, 999.0, 999.0, 999.0, -candidate.score)

    @staticmethod
    def _datasheet_url_penalty(product: Dict[str, Any]) -> float:
        url = str(product.get("datasheet_url") or "").lower()
        if "data-sheets" in url and "infographic" not in url and "product_matrix" not in url:
            return 0.0
        if url.endswith(".pdf"):
            return 0.5
        return 1.0

    def _llm_rank(
        self,
        query: str,
        constraints: Dict[str, Any],
        candidates: List[FortinetCandidate],
        vendor: str,
    ) -> Optional[Dict[str, Any]]:
        api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        if not self.use_llm or not api_key or not candidates:
            return None
        try:
            from google import genai
            client = self._llm_client or genai.Client(api_key=api_key)
            self._llm_client = client
            response = client.models.generate_content(
                model=os.getenv("FORTINET_RAG_LLM_MODEL", "gemini-3-flash-preview"),
                contents=self._rank_prompt(query, constraints, candidates, vendor),
            )
            text = getattr(response, "text", "") or ""
            match = re.search(r"\{.*\}", text, flags=re.S)
            if not match:
                return None
            parsed = json.loads(match.group(0))
            return parsed if isinstance(parsed, dict) else None
        except Exception:
            return None

    @staticmethod
    def _rank_prompt(query: str, constraints: Dict[str, Any], candidates: List[FortinetCandidate], vendor: str) -> str:
        payload = [
            {
                "model": c.product.get("model"),
                "vendor": c.product.get("vendor"),
                "category": c.product.get("category"),
                "datasheet_url": c.product.get("datasheet_url"),
                "retrieval_score": round(c.score, 4),
                "evidence": c.chunk[:1300],
            }
            for c in candidates
        ]
        return (
            f"You are selecting a {vendor} hardware reference for an RFP/BOQ compliance row.\n"
            "Only choose from the supplied candidates. Python hard filtering has already removed known under-spec candidates, "
            "but you must still avoid any candidate that appears below the stated requirement. Prefer the closest safe fit.\n\n"
            f"Requirement:\n{query}\n\n"
            f"Parsed hard constraints:\n{json.dumps(constraints, ensure_ascii=False, indent=2)}\n\n"
            f"Candidates:\n{json.dumps(payload, ensure_ascii=False, indent=2)}\n\n"
            "Return only JSON with keys: selected_model, match_status, confidence, reasoning, "
            "satisfied_requirements, uncertain_requirements."
        )

    @staticmethod
    def _candidate_by_model(candidates: List[FortinetCandidate], model: str) -> Optional[FortinetCandidate]:
        wanted = _norm(model)
        for candidate in candidates:
            if _norm(candidate.product.get("model")) == wanted:
                return candidate
        for candidate in candidates:
            if wanted and wanted in _norm(candidate.product.get("model")):
                return candidate
        return None

    @staticmethod
    def _format_reference(product: Dict[str, Any]) -> str:
        vendor = str(product.get("vendor") or "Fortinet")
        model = str(product.get("model") or "")
        url = str(product.get("datasheet_url") or product.get("product_url") or "").strip()
        return f"{vendor}: {model} - {url}" if url else f"{vendor}: {model}"

    @staticmethod
    def _model_keys(model: Any) -> List[str]:
        text = _norm(model)
        if not text:
            return []
        plain = re.sub(r"\b(fortinet|juniper|fortigate|fortiswitch)\b|\(tm\)|\(r\)|tm|registered", " ", text)
        plain = re.sub(r"[^a-z0-9]+", " ", plain).strip()
        keys = {text, re.sub(r"\s+", " ", plain)}
        return [key for key in keys if key]

    def _format_result(
        self,
        selected: FortinetCandidate,
        query: str,
        constraints: Dict[str, Any],
        retrieved: List[FortinetCandidate],
        llm_result: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        product = selected.product
        vendor = str(product.get("vendor") or "Fortinet")
        matched, missing, hard_details = self._constraint_details(product, constraints)
        if llm_result:
            reasoning = llm_result.get("reasoning") or f"{vendor}: selected {product.get('model')} after RAG retrieval and LLM verification."
            status = llm_result.get("match_status") or "rag_llm_match"
            confidence = llm_result.get("confidence")
        else:
            status = "rag_retrieval_match"
            confidence = round(max(0.5, min(0.98, selected.score)), 2)
            checks = []
            for key, detail in (hard_details.get("requirements") or {}).items():
                if detail.get("passes"):
                    checks.append(f"{key}: required {detail.get('required')}, candidate {detail.get('candidate')}")
            for key, detail in (hard_details.get("interfaces") or {}).items():
                if detail.get("passes"):
                    checks.append(f"interfaces.{key}: required {detail.get('required')}, candidate {detail.get('candidate')}")
            if constraints.get("device_type") == "LOGGING" and "fortilogger" in _norm(product.get("model")) and missing:
                status = "family_match"
                reasoning = (
                    f"{vendor}: selected {product.get('model')} because the requirement is for a dedicated hardware logging solution. "
                    "The catalog entry does not expose all EPS/log-volume capacity fields in structured form, so final sizing should be checked against the FortiLogger datasheet/configuration."
                )
            else:
                reasoning = (
                    f"{vendor}: selected {product.get('model')} from RAG-retrieved catalog candidates after hard constraint filtering. "
                    "The candidate was not below any parsed numeric/interface/HA constraints."
                )
            if constraints.get("constraint_adjustment_note"):
                reasoning += f" {constraints['constraint_adjustment_note']}"
            if checks:
                reasoning += f" Key checks: {'; '.join(checks[:6])}."
        details = {
            "provider": "fortinet-rag",
            "vendor": vendor,
            "match_status": status,
            "confidence": confidence,
            "query": query,
            "constraints": constraints,
            "selected_model": product.get("model"),
            "selected_category": product.get("category"),
            "selected_product_url": product.get("product_url", ""),
            "selected_datasheet_url": product.get("datasheet_url", ""),
            "matched_requirements": matched,
            "missing_requirements": missing,
            "hard_filter_details": hard_details,
            "top_candidates": self._candidate_summaries(retrieved),
        }
        if llm_result:
            details["llm_decision"] = llm_result
        return {
            "reference": self._format_reference(product),
            "reasoning": reasoning,
            "details": details,
        }

    def _candidate_summaries(self, candidates: List[FortinetCandidate]) -> List[Dict[str, Any]]:
        return [
            {
                "vendor": c.product.get("vendor"),
                "model": c.product.get("model"),
                "category": c.product.get("category"),
                "score": round(c.score, 4),
                "datasheet_url": c.product.get("datasheet_url", ""),
            }
            for c in candidates[: self.top_k]
        ]

    @staticmethod
    def _fortinet_domain_boost(query_lower: str, product: Dict[str, Any], chunk_text: str) -> float:
        model_text = _norm(product.get("model"))
        category = str(product.get("category") or "")
        score = 0.0
        if any(term in query_lower for term in ("firewall", "vpn", "ipsec", "ngfw")) and category == "NGFW":
            score += 0.35
            if "fortigate" in model_text:
                score += 0.25
        if any(term in query_lower for term in ("switch", "sfp", "qsfp", "ethernet", "port")) and category in {"SWITCH", "DATACENTER_SWITCH", "ACCESS_SWITCH"}:
            score += 0.25
        if any(term in query_lower for term in ("manager", "centralized", "fortimanager")) and "fortimanager" in model_text:
            score += 0.45
        if any(term in query_lower for term in ("fortilogger", "hardware logging", "log reporting", "logging appliance", "firewall logging", "log backup")):
            if "fortilogger" in model_text or category == "LOGGING":
                score += 0.75
            elif "fortianalyzer" in model_text:
                score -= 0.35
        if any(term in query_lower for term in ("siem", "soc", "eps")) and ("fortisiem" in model_text or category == "SIEM_SOC"):
            score += 0.45
        if "redundant" in query_lower and any(term in chunk_text for term in ("redundant", "dual power", "dual psu")):
            score += 0.15
        return score
