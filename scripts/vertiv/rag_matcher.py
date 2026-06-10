from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from gemini_config import get_gemini_api_key


VERTIV_CATEGORIES = {
    "UPS": ("ups", "uninterruptible", "battery", "runtime", "online", "double conversion"),
    "ENERGY_STORAGE": ("battery", "energy storage", "bess", "lithium"),
    "DC_POWER": ("dc power", "rectifier", "netSure", "48v"),
    "POWER_DISTRIBUTION": ("pdu", "power distribution", "busway", "rpp", "panelboard"),
    "TRANSFER_SWITCH": ("transfer switch", "static transfer", "sts", " ats", "ats-", "dc-ats"),
    "SWITCHGEAR": ("switchgear", "switchboard"),
    "BUSWAY": ("busway", "busduct"),
    "COOLING": ("cooling", "thermal", "in-row", "inrow", "room cooling", "chiller", "heat rejection", "crac", "crv"),
    "COOLING_CONTROL": ("controller", "thermal control", "monitoring"),
    "RACK": ("rack", "cabinet", "enclosure", "42u", "45u", "48u", "containment", "cable manager", "cable management", "blank panel"),
    "ENCLOSURE": ("outdoor enclosure", "enclosure", "cabinet"),
    "INTEGRATED_RACK_SOLUTION": ("integrated", "micro data center", "smartaisle", "smartrow", "smartcabinet"),
    "MONITORING": ("monitoring", "sensor", "environmental", "gateway", "rdu"),
    "SERIAL_CONSOLE": ("serial console", "console", "gateway"),
    "KVM": ("kvm", "lcd tray", "console", "switch"),
    "SOFTWARE": ("software", "platform", "management"),
}

DATASHEET_URL_OVERRIDES = {
    "liebert rdu501": "https://www.vertiv.com/48eef7/globalassets/products/monitoring-control-and-management/monitoring/liebert-rdu501/liebert-rdu501-datasheet.pdf",
    "rdu501": "https://www.vertiv.com/48eef7/globalassets/products/monitoring-control-and-management/monitoring/liebert-rdu501/liebert-rdu501-datasheet.pdf",
    "liebert crv4": "https://www.vertiv.com/49dd12/globalassets/products/thermal-management/in-row-cooling/liebert-crv4-brochure.pdf",
    "liebert spm": "https://www.vertiv.com/48ea64/globalassets/products/critical-power/power-distribution/liebert-spm-1.0/liebert-spm-1.0-brochure.pdf",
    "liebert spm 1 0": "https://www.vertiv.com/48ea64/globalassets/products/critical-power/power-distribution/liebert-spm-1.0/liebert-spm-1.0-brochure.pdf",
    "liebert spm 2 0": "https://www.vertiv.com/48ea64/globalassets/products/critical-power/power-distribution/liebert-spm-1.0/liebert-spm-1.0-brochure.pdf",
}

PDF_EXTRACTED_SPECS = Path(__file__).resolve().parents[2] / "output" / "json" / "vertiv_specs.json"

BAD_DATASHEET_URL_TERMS = (
    "code-of-conduct",
    "code_of_conduct",
    "ethics",
    "compliance",
    "foss-information",
    "obsolete",
)

UNSUPPORTED_REQUIREMENT_PATTERNS = (
    ("SPLIT_AC", r"\b(split\s*a/?c|split\s+ac|split\s+type\s+ac|split\s+air\s*condition(?:er|ing)?|a/?c\s+unit|air\s*condition(?:er|ing)?\s+unit|ton\s+split|t3\s+compressor|compressor\s+and\s+vendor|ashrae\s+requirement)\b"),
    ("VIDEO_WALL", r"\b(video\s*wall|display\s*wall|lcd\s*wall|noc\s+screen|screen\s+for\s+the\s+network\s+operations\s+room)\b"),
    ("CCTV", r"\b(ip\s*camera|dome\s*camera|bullet\s*camera|nvr|network\s+video\s+recorder|cctv)\b"),
    ("FIRE_SYSTEM", r"\b(fire\s+alarm|fire\s+detection|fire\s+suppression|smoke\s+detector|gas\s+cylinder|fk-5-1-12|clean\s+agent)\b"),
    ("ACCESS_CONTROL", r"\b(access\s+control|biometric|fingerprint|rfid|face\s+recognition|exit\s+button|magnetic\s+lock)\b"),
)


@dataclass
class VertivCandidate:
    product: Dict[str, Any]
    chunk: str
    score: float


def _clean_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _norm(value: Any) -> str:
    return _clean_text(value).lower()


def _parse_number(value: Any) -> Optional[float]:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dict):
        candidates = [value.get("max"), value.get("min")]
        for candidate in candidates:
            parsed = _parse_number(candidate)
            if parsed is not None:
                return parsed
        return None
    match = re.search(r"\d+(?:,\d{3})*(?:\.\d+)?", str(value or ""))
    if not match:
        return None
    return float(match.group(0).replace(",", ""))


class VertivRAGMatcher:
    def __init__(self, catalog_dir: str, top_k: int = 8, use_llm: bool = True):
        self.catalog_dir = Path(catalog_dir)
        self.top_k = top_k
        self.use_llm = use_llm
        self.products = self._load_products()
        self.chunks = self._build_chunks(self.products)
        self._embedding_model = None
        self._chunk_embeddings = None
        self._tfidf_vectorizer = None
        self._tfidf_matrix = None
        self._llm_client = None

    def match(self, requirement_text: str, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        metadata = metadata or {}
        query = self._build_query(requirement_text, metadata)
        constraints = self._parse_constraints(query, metadata)
        out_of_scope_reason = self._out_of_scope_reason(query, constraints)
        if out_of_scope_reason:
            return self._no_match_result(query, constraints, out_of_scope_reason)
        retrieved = self.retrieve(query, constraints)
        safe_candidates = [
            candidate for candidate in retrieved
            if self._passes_hard_constraints(candidate.product, constraints)
        ]
        candidates = safe_candidates or retrieved
        candidates_with_datasheets = [
            candidate for candidate in candidates
            if self._public_datasheet_url(candidate.product)
        ]
        if candidates_with_datasheets:
            candidates = candidates_with_datasheets
        llm_result = self._llm_rank(query, constraints, candidates) if self.use_llm else None
        if llm_result and llm_result.get("selected_model"):
            selected = self._candidate_by_model(candidates, llm_result["selected_model"]) or (candidates[0] if candidates else None)
            if selected:
                return self._format_result(selected, query, constraints, candidates, llm_result)
        if not candidates:
            return self._no_match_result(query, constraints, "no relevant catalog candidates were retrieved for this requirement")
        selected = self._select_fallback(candidates, constraints)
        return self._format_result(selected, query, constraints, candidates, None)

    def retrieve(self, query: str, constraints: Dict[str, Any]) -> List[VertivCandidate]:
        category_hint = constraints.get("category")
        query_embedding_scores = self._semantic_scores(query)
        keyword_terms = set(re.findall(r"[a-z0-9]+", query.lower()))
        candidates: List[VertivCandidate] = []
        for idx, chunk in enumerate(self.chunks):
            product = chunk["product"]
            score = float(query_embedding_scores[idx]) if idx < len(query_embedding_scores) else 0.0
            chunk_text = chunk["text"].lower()
            query_lower = query.lower()
            overlap = sum(1 for term in keyword_terms if len(term) > 2 and term in chunk_text)
            score += min(overlap / 25.0, 0.25)
            for model_key in self._model_keys(product.get("model")):
                model_tokens = [token for token in model_key.split() if len(token) > 2]
                if model_key and model_key in query_lower:
                    score += 0.75
                    break
                if len(model_tokens) >= 2 and all(token in keyword_terms for token in model_tokens):
                    score += 0.45
                    break
            if category_hint and product.get("category") == category_hint:
                score += 0.3
            elif category_hint and self._category_is_compatible(category_hint, str(product.get("category") or "")):
                score += 0.15
            if category_hint == "COOLING" and re.search(r"\bin[- ]?row\b", query_lower):
                subheading = str(product.get("subheading") or "").lower()
                if "in-row" in subheading or "in row" in subheading:
                    score += 0.25
            if category_hint == "COOLING" and re.search(r"\b300\s*mm\b", query_lower):
                model_text = f"{product.get('model') or ''} {product.get('subheading') or ''}".lower()
                if "crv" in model_text or "in-row" in model_text or "in row" in model_text:
                    score += 0.5
            if category_hint == "INTEGRATED_RACK_SOLUTION" and "smartaisle" in chunk_text:
                score += 0.6
                if "smartaisle 2" in chunk_text:
                    score += 0.2
            if category_hint == "UPS" and re.search(r"\b(power module|battery circuit|ground short|lithium-ion battery rack)\b", query_lower):
                model_text = str(product.get("model") or "").lower()
                if "apm" in model_text:
                    score += 0.6
            if category_hint == "UPS" and re.search(r"\b120\s*kw\b|\b(?:25|30)\s*kw\s+to\s+150\s*kw\b|hot swappable.*modular", query_lower):
                model_text = str(product.get("model") or "").lower()
                if "apm2" in model_text:
                    score += 0.7
            if category_hint == "ENERGY_STORAGE" and re.search(r"\b(lithium|battery rack|battery module)\b", query_lower):
                model_text = str(product.get("model") or "").lower()
                if "hpl p1" in model_text:
                    score += 2.0
                if "lithium-ion battery cabinet" in model_text or "lithium ion battery cabinet" in model_text:
                    score += 0.6
                if "energycore" in model_text or "battery" in model_text:
                    score += 0.5
            if category_hint == "POWER_DISTRIBUTION" and re.search(r"\b(modular power distribution|ups output|system capacity|hot plug mcb|touch screen|bms|modbus)\b", query_lower):
                model_text = str(product.get("model") or "").lower()
                if "spm" in model_text:
                    score += 1.2
                if "rack pdu" in model_text or "rpdu" in model_text or "geist" in model_text or "powergo" in model_text:
                    score -= 0.6
            if category_hint == "MONITORING" and "monitoring server" in query_lower:
                model_text = str(product.get("model") or "").lower()
                if "rdu501" in model_text:
                    score += 0.8
            if category_hint == "COOLING_CONTROL" and "water sensor" in query_lower:
                model_text = str(product.get("model") or "").lower()
                if "water sensing" in model_text or "water sensor" in model_text:
                    score += 0.8
            if category_hint == "COOLING_CONTROL" and ("temperature" in query_lower or "humidity" in query_lower):
                model_text = str(product.get("model") or "").lower()
                if "temperature" in model_text or "humidity" in model_text:
                    score += 0.5
            if constraints.get("rack_accessory") and str(product.get("category") or "") == "RACK":
                score += 0.25
                if any(term in chunk_text for term in ("cable management", "cable manager", "blank panel", "accessories")):
                    score += 0.25
            candidates.append(VertivCandidate(product=product, chunk=chunk["text"], score=score))
        candidates.sort(key=lambda item: item.score, reverse=True)
        deduped: List[VertivCandidate] = []
        seen = set()
        for candidate in candidates:
            key = (candidate.product.get("model"), candidate.product.get("product_url"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(candidate)
            if len(deduped) >= self.top_k:
                break
        return deduped

    def _load_products(self) -> List[Dict[str, Any]]:
        products: List[Dict[str, Any]] = []
        public_links_by_model: Dict[str, Dict[str, Any]] = {}
        public_link_products: List[Dict[str, Any]] = []
        for name in ("vertiv_scraped.json", "architecture_hardware.json"):
            path = self.catalog_dir / name
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(data, dict) and isinstance(data.get("products"), list):
                entries = [item for item in data["products"] if isinstance(item, dict)]
            elif isinstance(data, dict) and isinstance(data.get("items"), list):
                entries = [item for item in data["items"] if isinstance(item, dict)]
            else:
                entries = []
            entries = [self._normalize_catalog_product(item, f"data/product_catalogs/{name}") for item in entries]
            if name == "vertiv_scraped.json":
                for item in entries:
                    if _norm(item.get("vendor")) not in ("vertiv", ""):
                        continue
                    if self._public_datasheet_url(item) or self._public_product_url(item):
                        public_link_products.append(item)
                        for key in self._model_keys(item.get("model")):
                            existing = public_links_by_model.get(key)
                            if not existing or (self._public_datasheet_url(item) and not self._public_datasheet_url(existing)):
                                public_links_by_model[key] = item
            products.extend(entries)
        extracted_specs = self._load_extracted_pdf_specs()
        products = self._hydrate_extracted_specs(products, extracted_specs)
        products.extend(extracted_specs)
        hydrated = [self._hydrate_public_links(item, public_links_by_model, public_link_products) for item in products]
        vertiv_products = [item for item in hydrated if _norm(item.get("vendor")) in ("vertiv", "")]
        return self._merge_duplicate_products(vertiv_products)

    @staticmethod
    def _build_chunks(products: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        chunks: List[Dict[str, Any]] = []
        for product in products:
            fields = []
            for key, value in product.items():
                if value in (None, "", {}, []):
                    continue
                if isinstance(value, (dict, list)):
                    value_text = json.dumps(value, ensure_ascii=False)
                else:
                    value_text = str(value)
                fields.append(f"{key}: {value_text}")
            text = " | ".join(fields)
            if text:
                chunks.append({"product": product, "text": text})
        return chunks

    @classmethod
    def _load_extracted_pdf_specs(cls) -> List[Dict[str, Any]]:
        path = Path(os.getenv("VERTIV_EXTRACTED_SPECS_JSON", str(PDF_EXTRACTED_SPECS)))
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            return []
        if isinstance(data, dict) and isinstance(data.get("products"), list):
            entries = data["products"]
        elif isinstance(data, list):
            entries = data
        else:
            return []
        products: List[Dict[str, Any]] = []
        for item in entries:
            if not isinstance(item, dict):
                continue
            product = cls._normalize_catalog_product(item, str(path))
            product["vendor"] = product.get("vendor") or "Vertiv"
            if not product.get("model") and product.get("product_name"):
                product["model"] = product["product_name"]
            product.setdefault("source_catalog", str(path))
            products.append(product)
        return products

    @classmethod
    def _normalize_catalog_product(cls, product: Dict[str, Any], source_catalog: str = "") -> Dict[str, Any]:
        normalized = dict(product)
        if not normalized.get("model") and normalized.get("product_name"):
            normalized["model"] = normalized["product_name"]
        if not normalized.get("vendor"):
            normalized["vendor"] = "Vertiv"
        category = cls._canonical_category(normalized.get("category"))
        if category:
            normalized["category"] = category
        if source_catalog and not normalized.get("source_catalog"):
            normalized["source_catalog"] = source_catalog
        specs = normalized.get("technical_specifications")
        if isinstance(specs, dict):
            summary = specs.get("normalized_summary")
            if isinstance(summary, dict):
                for field, value in summary.items():
                    normalized.setdefault(field, value)
        return normalized

    @staticmethod
    def _canonical_category(category: Any) -> str:
        text = _norm(category)
        if not text:
            return ""
        if text in VERTIV_CATEGORIES:
            return text
        mapping = (
            ("ENERGY_STORAGE", ("energy storage", "bess", "battery energy")),
            ("POWER_DISTRIBUTION", ("power distribution", "rack pdu", "pdu")),
            ("COOLING", ("thermal management", "cooling", "in-row", "in row")),
            ("MONITORING", ("monitoring", "management")),
            ("RACK", ("rack", "enclosure")),
            ("INTEGRATED_RACK_SOLUTION", ("containment", "integrated data center", "smartaisle")),
            ("UPS", ("ups", "uninterruptible")),
        )
        for canonical, terms in mapping:
            if any(term in text for term in terms):
                return canonical
        compact = re.sub(r"[^a-z0-9]+", "_", text).strip("_").upper()
        return compact

    @classmethod
    def _hydrate_extracted_specs(
        cls,
        products: List[Dict[str, Any]],
        extracted_specs: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not extracted_specs:
            return products
        hydrated: List[Dict[str, Any]] = []
        for product in products:
            enriched = dict(product)
            match = cls._matching_extracted_spec(enriched, extracted_specs)
            if match and not enriched.get("technical_specifications"):
                enriched["technical_specifications"] = match.get("technical_specifications")
                enriched["extracted_spec_source"] = match.get("source_pdf") or match.get("source_catalog")
                if match.get("source_pages"):
                    enriched["extracted_spec_pages"] = match.get("source_pages")
                summary = (match.get("technical_specifications") or {}).get("normalized_summary")
                if isinstance(summary, dict):
                    for field, value in summary.items():
                        enriched.setdefault(field, value)
            hydrated.append(enriched)
        return hydrated

    @classmethod
    def _matching_extracted_spec(
        cls,
        product: Dict[str, Any],
        extracted_specs: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        product_keys = cls._model_keys(product.get("model"))
        product_tokens = [set(key.split()) for key in product_keys if key]
        product_category = str(product.get("category") or "")
        best: Optional[Tuple[int, Dict[str, Any]]] = None
        for spec in extracted_specs:
            spec_category = str(spec.get("category") or "")
            if product_category and spec_category and not cls._category_is_compatible(product_category, spec_category):
                continue
            for spec_key in cls._model_keys(spec.get("model")):
                spec_tokens = set(spec_key.split())
                if not spec_tokens:
                    continue
                for tokens in product_tokens:
                    if len(tokens) < 2:
                        continue
                    overlap = tokens & spec_tokens
                    if len(overlap) < min(2, len(spec_tokens)):
                        continue
                    if not (spec_tokens.issubset(tokens) or tokens.issubset(spec_tokens) or len(overlap) >= 2):
                        continue
                    score = len(overlap)
                    if spec_tokens.issubset(tokens) or tokens.issubset(spec_tokens):
                        score += 3
                    if best is None or score > best[0]:
                        best = (score, spec)
        return best[1] if best else None

    @staticmethod
    def _build_query(requirement_text: str, metadata: Dict[str, Any]) -> str:
        metadata_text = []
        for key in ("device_type", "device_category", "category", "source_text"):
            if metadata.get(key):
                metadata_text.append(str(metadata[key]))
        detected = metadata.get("detected_specs")
        if isinstance(detected, dict):
            metadata_text.append(json.dumps(detected, ensure_ascii=False))
        return " | ".join(part for part in [requirement_text, *metadata_text] if part).strip()

    def _parse_constraints(self, text: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        lowered = text.lower()
        constraints: Dict[str, Any] = {}
        unsupported = self._detect_unsupported_type(lowered)
        if unsupported:
            constraints["unsupported_type"] = unsupported
        category = self._infer_category(lowered, metadata)
        if category:
            constraints["category"] = category
        rack_accessory = bool(re.search(r"\b(cable manager|cable management|blank panel|brush strip|mounting plastic blank|rack accessory)\b", lowered))
        if rack_accessory:
            constraints["category"] = "RACK"
            constraints["rack_accessory"] = True
        if re.search(r"\b(dc-ats|ats-|ats\b|static transfer|transfer switch)\b", lowered):
            constraints["category"] = "TRANSFER_SWITCH"
        if re.search(r"\b(rpdu|rack pdu|pdu\b|power distribution)\b", lowered):
            constraints["category"] = "POWER_DISTRIBUTION"
        if re.search(r"\b(modular power distribution|rack based modular power distribution|ups output|hot plug mcb|bms,\s*modbus|touch screen)\b", lowered):
            constraints["category"] = "POWER_DISTRIBUTION"
            constraints["power_distribution_family"] = "SPM"
        if re.search(r"\b(containment|hot\s*/\s*cold aisle|hot aisle|cold aisle|aisle containment)\b", lowered):
            constraints["category"] = "INTEGRATED_RACK_SOLUTION"
        if re.search(r"\b(lithium[- ]ion battery|battery rack|battery module|battery cabinet)\b", lowered):
            constraints["category"] = "ENERGY_STORAGE"
        elif re.search(r"\b(power module|battery circuit|ground short)\b", lowered):
            constraints["category"] = "UPS"
        if "monitoring server" in lowered:
            constraints["category"] = "MONITORING"
        if re.search(r"\b(temperature.*sensor|humidity.*sensor|water sensor|environmental sensor)\b", lowered):
            constraints["category"] = "COOLING_CONTROL"
        for field, pattern in (
            ("power_capacity_kva", r"(\d+(?:\.\d+)?)\s*kva\b"),
            ("power_capacity_kw", r"(\d+(?:\.\d+)?)\s*kw\b"),
            ("cooling_capacity_kw", r"(\d+(?:\.\d+)?)\s*kw\b"),
            ("rack_units", r"\b(\d+)\s*u\b"),
            ("static_load_kg", r"([\d,]+)\s*kg\b"),
            ("outlet_count", r"(\d+)\s*(?:outlet|socket|receptacle)"),
        ):
            match = re.search(pattern, lowered)
            if match:
                if rack_accessory and field == "rack_units":
                    continue
                constraints[field] = _parse_number(match.group(1))
        if category == "COOLING" and "power_capacity_kw" in constraints:
            constraints.setdefault("cooling_capacity_kw", constraints.pop("power_capacity_kw"))
        elif category != "COOLING":
            constraints.pop("cooling_capacity_kw", None)
        if constraints.get("category") == "ENERGY_STORAGE":
            constraints["backup_load_kw"] = constraints.pop("power_capacity_kw", None)
        if re.search(r"\b(n\+1|redundan|dual power|active/passive|active-passive|ha\b|high availability)", lowered):
            constraints["redundancy_required"] = True
        return constraints

    @staticmethod
    def _detect_unsupported_type(lowered: str) -> str:
        for name, pattern in UNSUPPORTED_REQUIREMENT_PATTERNS:
            if re.search(pattern, lowered):
                return name
        return ""

    @staticmethod
    def _infer_category(lowered: str, metadata: Dict[str, Any]) -> str:
        explicit = _norm(metadata.get("device_type") or metadata.get("device_category") or metadata.get("category"))
        combined = f"{explicit} {lowered}"
        for category, terms in VERTIV_CATEGORIES.items():
            if any(term.lower() in combined for term in terms):
                return category
        return ""

    @staticmethod
    def _category_is_compatible(required: str, candidate: str) -> bool:
        if required == candidate:
            return True
        groups = [
            {"RACK", "ENCLOSURE", "INTEGRATED_RACK_SOLUTION"},
            {"COOLING", "COOLING_CONTROL"},
            {"POWER_DISTRIBUTION", "TRANSFER_SWITCH", "BUSWAY"},
            {"MONITORING", "SERIAL_CONSOLE", "KVM", "SOFTWARE"},
        ]
        return any(required in group and candidate in group for group in groups)

    def _semantic_scores(self, query: str) -> np.ndarray:
        if not self.chunks:
            return np.array([])
        if os.getenv("VERTIV_USE_SENTENCE_EMBEDDINGS", "").lower() not in {"1", "true", "yes"}:
            return self._tfidf_scores(query)
        try:
            model = self._get_embedding_model()
            query_vec = model.encode([query], normalize_embeddings=True)
            chunk_vecs = self._get_chunk_embeddings(model)
            return np.dot(chunk_vecs, query_vec[0])
        except Exception:
            return self._tfidf_scores(query)

    def _get_embedding_model(self):
        if self._embedding_model is None:
            from sentence_transformers import SentenceTransformer
            model_name = os.getenv("VERTIV_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
            self._embedding_model = SentenceTransformer(model_name)
        return self._embedding_model

    def _get_chunk_embeddings(self, model) -> np.ndarray:
        if self._chunk_embeddings is None:
            texts = [chunk["text"] for chunk in self.chunks]
            self._chunk_embeddings = np.array(model.encode(texts, normalize_embeddings=True))
        return self._chunk_embeddings

    def _tfidf_scores(self, query: str) -> np.ndarray:
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
                    continue
                overlap = len(query_terms & chunk_terms)
                scores.append(overlap / math.sqrt(len(query_terms) * len(chunk_terms)))
            return np.array(scores)

    def _passes_hard_constraints(self, product: Dict[str, Any], constraints: Dict[str, Any]) -> bool:
        if constraints.get("unsupported_type"):
            return False
        if constraints.get("category") and not self._category_is_compatible(constraints["category"], str(product.get("category") or "")):
            return False
        for field in ("power_capacity_kva", "power_capacity_kw", "cooling_capacity_kw", "rack_units", "static_load_kg", "outlet_count"):
            required = constraints.get(field)
            if required in (None, ""):
                continue
            candidate = _parse_number(product.get(field))
            if candidate is None:
                continue
            if candidate < float(required):
                return False
        if constraints.get("redundancy_required"):
            text = json.dumps(product, ensure_ascii=False).lower()
            if not any(term in text for term in ("redundan", "dual power", "n+1", "ha", "high availability", "hot_swappable")):
                return False
        return True

    def _out_of_scope_reason(self, query: str, constraints: Dict[str, Any]) -> str:
        unsupported = constraints.get("unsupported_type")
        if unsupported:
            labels = {
                "SPLIT_AC": "split AC / non-Vertiv packaged air-conditioning scope",
                "VIDEO_WALL": "video wall / display scope",
                "CCTV": "CCTV scope",
                "FIRE_SYSTEM": "fire detection or fire suppression scope",
                "ACCESS_CONTROL": "access control scope",
            }
            return f"requirement appears to be {labels.get(unsupported, unsupported)}, which is outside the Vertiv catalog scope used by this matcher"
        return ""

    @staticmethod
    def _no_match_result(
        query: str,
        constraints: Dict[str, Any],
        reason: str,
        candidates: Optional[List[VertivCandidate]] = None,
    ) -> Dict[str, Any]:
        return {
            "reference": "",
            "reasoning": f"Vertiv: no reference added because {reason}.",
            "details": {
                "provider": "vertiv",
                "match_status": "out_of_scope_or_no_safe_match",
                "query": query,
                "constraints": constraints,
                "top_candidates": [
                    {
                        "model": c.product.get("model"),
                        "category": c.product.get("category"),
                        "score": round(c.score, 4),
                        "datasheet_url": VertivRAGMatcher._public_datasheet_url(c.product),
                    }
                    for c in (candidates or [])[:8]
                ],
            },
        }

    def _select_fallback(self, candidates: List[VertivCandidate], constraints: Dict[str, Any]) -> VertivCandidate:
        def fit(candidate: VertivCandidate) -> Tuple[float, float]:
            over_sum = 0.0
            count = 0
            for field in ("power_capacity_kva", "power_capacity_kw", "cooling_capacity_kw", "rack_units", "static_load_kg", "outlet_count"):
                required = constraints.get(field)
                if required in (None, ""):
                    continue
                value = _parse_number(candidate.product.get(field))
                if value is None or float(required) <= 0:
                    continue
                over_sum += max(value / float(required), 1.0)
                count += 1
            return (over_sum / count if count else 999.0, -candidate.score)
        return sorted(candidates, key=fit)[0]

    def _llm_rank(self, query: str, constraints: Dict[str, Any], candidates: List[VertivCandidate]) -> Optional[Dict[str, Any]]:
        api_key = get_gemini_api_key()
        if not api_key or not candidates:
            return None
        try:
            from google import genai
            client = self._llm_client or genai.Client(api_key=api_key)
            self._llm_client = client
            prompt = self._rank_prompt(query, constraints, candidates)
            response = client.models.generate_content(
                model=os.getenv("VERTIV_RAG_LLM_MODEL", "gemini-3-flash-preview"),
                contents=prompt,
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
    def _rank_prompt(query: str, constraints: Dict[str, Any], candidates: List[VertivCandidate]) -> str:
        payload = [
            {
                "model": c.product.get("model"),
                "category": c.product.get("category"),
                "datasheet_url": c.product.get("datasheet_url"),
                "product_url": c.product.get("product_url"),
                "retrieval_score": round(c.score, 4),
                "evidence": c.chunk[:1400],
            }
            for c in candidates
        ]
        return (
            "You are selecting a Vertiv hardware reference for an RFP/BOQ compliance row.\n"
            "Use only the supplied candidate evidence. Do not select a model that is under-spec. "
            "Prefer candidates with a valid datasheet_url; do not choose a candidate with no datasheet_url when a safe datasheet candidate is available. "
            "Prefer the closest candidate that satisfies hard requirements. If no candidate is safe, return no_safe_match.\n\n"
            f"Requirement:\n{query}\n\n"
            f"Parsed hard constraints:\n{json.dumps(constraints, ensure_ascii=False, indent=2)}\n\n"
            f"Candidates:\n{json.dumps(payload, ensure_ascii=False, indent=2)}\n\n"
            "Return only JSON with keys: selected_model, match_status, confidence, reasoning, "
            "satisfied_requirements, uncertain_requirements."
        )

    @staticmethod
    def _candidate_by_model(candidates: List[VertivCandidate], model: str) -> Optional[VertivCandidate]:
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
        model = product.get("model")
        datasheet = VertivRAGMatcher._public_datasheet_url(product)
        return f"Vertiv: {model} - {datasheet}" if datasheet else f"Vertiv: {model}"

    @staticmethod
    def _model_keys(model: Any) -> List[str]:
        text = _norm(model)
        if not text:
            return []
        plain = re.sub(r"\bvertiv\b|\(tm\)|\(r\)|tm|registered", " ", text)
        plain = re.sub(r"[^a-z0-9]+", " ", plain).strip()
        compact = re.sub(r"\s+", " ", plain)
        keys = {text, compact}
        if compact.startswith("vertiv "):
            keys.add(compact[7:])
        return [key for key in keys if key]

    @staticmethod
    def _public_datasheet_url(product: Dict[str, Any]) -> str:
        for key in VertivRAGMatcher._model_keys(product.get("model")):
            if key in DATASHEET_URL_OVERRIDES:
                return DATASHEET_URL_OVERRIDES[key]
        url = str(product.get("datasheet_url") or "").strip()
        lowered = url.lower()
        if not lowered.startswith(("http://", "https://")):
            return ""
        if "partners.vertiv.com/english/directory" in lowered:
            return ""
        if any(term in lowered for term in BAD_DATASHEET_URL_TERMS):
            return ""
        if ".pdf" not in lowered:
            return ""
        return url

    @staticmethod
    def _public_product_url(product: Dict[str, Any]) -> str:
        url = str(product.get("product_url") or "").strip()
        lowered = url.lower()
        if not lowered.startswith(("http://", "https://")):
            return ""
        if "partners.vertiv.com/english/directory" in lowered:
            return ""
        return url

    @classmethod
    def _url_quality(cls, url: str, product: Dict[str, Any]) -> int:
        lowered = url.lower()
        model_tokens = [token for key in cls._model_keys(product.get("model")) for token in key.split() if len(token) > 2]
        score = 0
        if "/products/" in lowered or "/shared/" in lowered:
            score += 2
        if "datasheet" in lowered or "data-sheet" in lowered or "-ds-" in lowered:
            score += 4
        if "brochure" in lowered or "-br-" in lowered:
            score += 3
        if "obsolete" in lowered:
            score -= 4
        score += sum(1 for token in set(model_tokens) if token in lowered)
        return score

    @classmethod
    def _hydrate_public_links(
        cls,
        product: Dict[str, Any],
        public_links_by_model: Dict[str, Dict[str, Any]],
        public_link_products: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        public_datasheet = cls._public_datasheet_url(product)
        if public_datasheet:
            hydrated = dict(product)
            hydrated["datasheet_url"] = public_datasheet
            if not cls._public_product_url(hydrated):
                hydrated["product_url"] = ""
            return hydrated
        linked = cls._find_public_link(product, public_links_by_model, public_link_products)
        if not linked:
            return product
        hydrated = dict(product)
        if cls._public_datasheet_url(linked):
            hydrated["datasheet_url"] = linked.get("datasheet_url")
        if cls._public_product_url(linked):
            hydrated["product_url"] = linked.get("product_url")
        for key in ("main_heading", "subheading"):
            if not hydrated.get(key) and linked.get(key):
                hydrated[key] = linked.get(key)
        return hydrated

    @classmethod
    def _merge_duplicate_products(cls, products: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
        order: List[Tuple[str, str]] = []
        for product in products:
            keys = cls._model_keys(product.get("model"))
            key = (keys[0] if keys else _norm(product.get("model")), str(product.get("category") or ""))
            if key not in merged:
                merged[key] = dict(product)
                order.append(key)
                continue
            current = merged[key]
            for field, value in product.items():
                if value in (None, "", {}, []):
                    continue
                if field == "datasheet_url":
                    current_url = cls._public_datasheet_url(current)
                    candidate_url = cls._public_datasheet_url(product)
                    if candidate_url and (not current_url or cls._url_quality(candidate_url, current) > cls._url_quality(current_url, current)):
                        current[field] = candidate_url
                    continue
                if field == "product_url":
                    if not cls._public_product_url(current) and cls._public_product_url(product):
                        current[field] = product.get(field)
                    continue
                if current.get(field) in (None, "", {}, []):
                    current[field] = value
                elif isinstance(current.get(field), list) and isinstance(value, list):
                    seen = {str(item) for item in current[field]}
                    current[field].extend(item for item in value if str(item) not in seen)
                elif isinstance(current.get(field), dict) and isinstance(value, dict):
                    current[field] = {**value, **current[field]}
        return [merged[key] for key in order]

    @classmethod
    def _find_public_link(
        cls,
        product: Dict[str, Any],
        public_links_by_model: Dict[str, Dict[str, Any]],
        public_link_products: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        product_keys = cls._model_keys(product.get("model"))
        for key in product_keys:
            linked = public_links_by_model.get(key)
            if linked:
                return linked
        product_token_sets = [set(key.split()) for key in product_keys if key]
        product_category = str(product.get("category") or "")
        best: Optional[Tuple[int, Dict[str, Any]]] = None
        for candidate in public_link_products:
            if product_category and str(candidate.get("category") or "") != product_category:
                continue
            for candidate_key in cls._model_keys(candidate.get("model")):
                candidate_tokens = set(candidate_key.split())
                for product_tokens in product_token_sets:
                    if not product_tokens or len(product_tokens) < 2:
                        continue
                    if product_tokens.issubset(candidate_tokens):
                        score = len(product_tokens)
                        if cls._public_datasheet_url(candidate):
                            score += 5
                        if best is None or score > best[0]:
                            best = (score, candidate)
        return best[1] if best else None

    def _format_result(
        self,
        selected: VertivCandidate,
        query: str,
        constraints: Dict[str, Any],
        candidates: List[VertivCandidate],
        llm_result: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        product = selected.product
        if llm_result:
            reasoning = llm_result.get("reasoning") or ""
            status = llm_result.get("match_status") or "rag_llm_match"
            confidence = llm_result.get("confidence")
        else:
            status = "rag_retrieval_match"
            confidence = round(min(max(selected.score, 0.0), 1.0), 2)
            reasoning = (
                f"Vertiv: selected {product.get('model')} from the top retrieved catalog evidence. "
                "The candidate was not below any parsed numeric constraints available in the catalog."
            )
        details = {
            "provider": "vertiv",
            "match_status": status,
            "confidence": confidence,
            "query": query,
            "constraints": constraints,
            "selected_model": product.get("model"),
            "selected_category": product.get("category"),
            "selected_product_url": self._public_product_url(product),
            "selected_datasheet_url": self._public_datasheet_url(product),
            "top_candidates": [
                {
                    "model": c.product.get("model"),
                    "category": c.product.get("category"),
                    "score": round(c.score, 4),
                    "datasheet_url": self._public_datasheet_url(c.product),
                }
                for c in candidates[: self.top_k]
            ],
        }
        if llm_result:
            details["llm_decision"] = llm_result
        return {
            "reference": self._format_reference(product),
            "reasoning": reasoning,
            "details": details,
        }
