import json
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


NUMERIC_REQUIREMENT_FIELDS = (
    "ports",
    "max_ports",
    "ipsec_vpn_throughput_gbps",
    "ngfw_throughput_gbps",
    "ips_throughput_gbps",
    "ssl_tls_inspection_gbps",
    "ssl_vpn_gbps",
    "threat_protection_gbps",
    "switching_capacity_gbps",
    "firewall_throughput_gbps",
    "throughput_gbps",
    "concurrent_sessions",
    "ssl_vpn_users",
    "connections_per_second",
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
    "policies",
    "storage_tb",
)

PRODUCT_SPEC_ALIASES = {
    "ipsec_vpn_throughput_gbps": ("vpn_throughput_gbps",),
    "firewall_throughput_gbps": ("ngfw_throughput_gbps", "throughput_gbps"),
    "ngfw_throughput_gbps": ("firewall_throughput_gbps", "throughput_gbps"),
    "switching_capacity_gbps": ("throughput_gbps",),
    "throughput_gbps": ("switching_capacity_gbps", "ngfw_throughput_gbps"),
    "connections_per_second": ("cps",),
    "performance_eps": ("analytic_rate_logs_sec", "collector_rate_logs_sec"),
    "max_ports": ("ports",),
}

INTERFACE_METADATA_FIELDS = {
    "interfaces_1g": "1g_rj45",
    "interfaces_10g": "10g_sfp_plus",
    "interfaces_25g": "25g_sfp28",
    "interfaces_40g": "40g_qsfp_plus",
    "interfaces_100g": "100g_qsfp28",
}

INTERFACE_COMPATIBILITY = {
    "1g_rj45": ("1g_rj45", "1_10g_rj45"),
    "10g_rj45": ("10g_rj45", "1_10g_rj45"),
    "1_10g_rj45": ("1_10g_rj45",),
    "1g_sfp": ("1g_sfp",),
    "10g_sfp_plus": ("10g_sfp_plus", "10g_rj45", "1_10g_rj45"),
    "25g_sfp28": ("25g_sfp28",),
    "40g_qsfp_plus": ("40g_qsfp_plus",),
    "100g_qsfp28": ("100g_qsfp28",),
}

DEVICE_CATEGORY_MAP = {
    "ngfw": "NGFW",
    "next_generation_firewall": "NGFW",
    "firewall": "NGFW",
    "datacenter_switch": "DATACENTER_SWITCH",
    "data_center_switch": "DATACENTER_SWITCH",
    "access_switch": "ACCESS_SWITCH",
    "switch": "SWITCH",
    "switching": "SWITCH",
    "adc": "ADC",
    "waf": "WAF",
    "centralized_management": "CENTRALIZED_MANAGEMENT",
    "management": "CENTRALIZED_MANAGEMENT",
    "siem_soc": "SIEM_SOC",
    "siem": "SIEM_SOC",
    "soc": "SIEM_SOC",
    "ndr": "NDR",
    "endpoint_security": "ENDPOINT_SECURITY",
    "endpoint": "ENDPOINT_SECURITY",
    "identity_access": "IDENTITY_ACCESS",
    "identity_and_access": "IDENTITY_ACCESS",
    "pam": "PAM",
    "sandbox": "SANDBOX",
    "fortisandbox": "SANDBOX",
    "email_security": "EMAIL_SECURITY",
    "email": "EMAIL_SECURITY",
    "mail_security": "EMAIL_SECURITY",
    "nac": "NAC",
    "network_access_control": "NAC",
    "deception": "DECEPTION",
    "soar": "SOAR",
    "sase": "SASE",
    "secure_web_gateway": "SECURE_WEB_GATEWAY",
    "swg": "SECURE_WEB_GATEWAY",
    "ddos_mitigation": "DDOS_MITIGATION",
    "ddos": "DDOS_MITIGATION",
    "digital_risk_protection": "DIGITAL_RISK_PROTECTION",
    "network_performance_monitoring": "NETWORK_PERFORMANCE_MONITORING",
    "ai_network_operations": "AI_NETWORK_OPERATIONS",
    "cloud_security": "CLOUD_SECURITY",
    "wan_extender": "WAN_EXTENDER",
    "voip_security": "VOIP_SECURITY",
    "video_security": "VIDEO_SECURITY",
    "routing": "ROUTER",
    "router": "ROUTER",
    "sdn_automation": "SDN_AUTOMATION",
    "automation": "SDN_AUTOMATION",
}

INTERFACE_PATTERNS = {
    "100g_qsfp28": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:100\s*g|100gbe|100\s*gbps|hundred\s* Gigabit).*?(?:qsfp28|qsfp)?",
    "40g_qsfp_plus": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:40\s*g|40gbe|40\s*gbps).*?(?:qsfp\+|qsfp)?",
    "25g_sfp28": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:25\s*g|25gbe|25\s*gbps).*?(?:sfp28)?",
    "10g_sfp_plus": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:10\s*g|10gbe|10\s*gbps).*?(?:sfp\+|sfp plus|sfp)?",
    "1_10g_rj45": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:1/10\s*g|1g/10g|10\s*g|10gbe).*?(?:rj45|base-t|copper)",
    "1g_rj45": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:1\s*g|1gbe|gigabit).*?(?:rj45|base-t|copper)",
}

INTERFACE_REVERSE_PATTERNS = {
    "100g_qsfp28": r"(?:interfaces?|ports?).{0,50}(?:100\s*(?:g|gig|gbe|gbps)|hundred\s*gigabit).{0,35}(?:qsfp28|qsfp)?.{0,15}(?:=|:|qty|quantity|count)\s*(?P<count>\d+)",
    "40g_qsfp_plus": r"(?:interfaces?|ports?).{0,50}40\s*(?:g|gig|gbe|gbps).{0,35}(?:qsfp\+|qsfp)?.{0,15}(?:=|:|qty|quantity|count)\s*(?P<count>\d+)",
    "25g_sfp28": r"(?:interfaces?|ports?).{0,50}25\s*(?:g|gig|gbe|gbps).{0,35}(?:sfp28)?.{0,15}(?:=|:|qty|quantity|count)\s*(?P<count>\d+)",
    "10g_sfp_plus": r"(?:interfaces?|ports?).{0,50}10\s*(?:g|gig|gbe|gbps).{0,35}(?:sfp\+|sfp plus|sfp)?.{0,15}(?:=|:|qty|quantity|count)\s*(?P<count>\d+)",
    "1_10g_rj45": r"(?:interfaces?|ports?).{0,50}(?:1/10\s*g|1g/10g).{0,35}(?:rj45|base-t|copper)?.{0,15}(?:=|:|qty|quantity|count)\s*(?P<count>\d+)",
    "1g_rj45": r"(?:interfaces?|ports?).{0,50}(?:copper|rj45|base-t).{0,25}(?:1\s*(?:g|gig|gbe|gbps)|gigabit).{0,15}(?:=|:|qty|quantity|count)\s*(?P<count>\d+)",
}

CATEGORY_KEYWORDS = {
    "CENTRALIZED_MANAGEMENT": ("fortimanager", "centralized management", "firewall manager", "security management"),
    "SIEM_SOC": ("fortisiem", " siem ", "soc platform", "security information and event management"),
    "NDR": ("fortindr", "ndr", "network detection and response"),
    "ENDPOINT_SECURITY": ("fortiedr", "fortixdr", "forticlient", "endpoint security", "edr", "xdr"),
    "IDENTITY_ACCESS": ("fortiauthenticator", "identity access", "identity and access", "radius server", "authentication appliance"),
    "PAM": ("fortipam", "privileged access", "pam"),
    "SANDBOX": ("fortisandbox", "sandbox", "malware analysis", "file analysis"),
    "EMAIL_SECURITY": ("fortimail", "email security", "mail security", "secure email gateway"),
    "NAC": ("fortinac", "network access control", " nac ", "control and application server"),
    "DECEPTION": ("fortideceptor", "deception"),
    "SOAR": ("fortisoar", "soar", "orchestration automation response"),
    "SASE": ("fortisase", "sase"),
    "SECURE_WEB_GATEWAY": ("fortiproxy", "secure web gateway", "web proxy", "swg"),
    "DDOS_MITIGATION": ("fortiddos", "ddos"),
    "DIGITAL_RISK_PROTECTION": ("fortirecon", "digital risk protection", "external attack surface"),
    "NETWORK_PERFORMANCE_MONITORING": ("fortimonitor", "network performance monitoring", "monitoring"),
    "AI_NETWORK_OPERATIONS": ("fortiaiops", "aiops", "ai network operations"),
    "CLOUD_SECURITY": ("forticnapp", "cnapp", "cloud security"),
    "WAN_EXTENDER": ("fortiextender", "wan extender", "lte wan", "5g wan"),
    "VOIP_SECURITY": ("fortivoice", "voip", "voice security"),
    "VIDEO_SECURITY": ("fortirecorder", "video security", "nvr"),
    "SDN_AUTOMATION": ("apstra", "sdn", "automation", "intent-based networking"),
    "WAF": ("web application firewall", " waf ", "fortiweb"),
    "ADC": ("load balancer", "application delivery", " adc ", "fortiadc"),
    "DATACENTER_SWITCH": ("data center switch", "datacenter switch", "tor", "top of rack", "leaf", "spine", "core network", "qfx", "fortiswitch 1048", "fortiswitch 3032"),
    "ACCESS_SWITCH": ("access switch", "campus switch", "edge switch", "fortiswitch 448", "ex4400"),
    "SWITCH": ("switch", "switching"),
    "ROUTER": ("router", "routing platform", "edge routing", "wan router"),
    "NGFW": ("ngfw", "next generation firewall", "firewall", "security gateway", "ssl-vpn", "ssl vpn", "vpn appliance"),
}

EXCLUDED_KEYWORDS = (
    "ups", "generator", "cooling", "hvac", "fire suppression", "cctv", "camera",
    "rack", "cabinet", "pdu", "patch cord", "cabling", "civil work", "electrical",
    "storage array", "san switch", "gpu", "license only", "subscription only",
)


@dataclass
class ProductMatch:
    vendor: str
    model: str
    category: str
    confidence: float
    product_url: str
    datasheet_url: str
    matched_requirements: List[str]
    missing_requirements: List[str]
    score_breakdown: Dict[str, float]
    match_details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor": self.vendor,
            "matched_product": self.model,
            "category": self.category,
            "confidence": self.confidence,
            "product_url": self.product_url,
            "datasheet_url": self.datasheet_url,
            "matched_requirements": self.matched_requirements,
            "missing_requirements": self.missing_requirements,
            "score_breakdown": self.score_breakdown,
            "match_details": self.match_details,
        }


class ProductCatalog:
    def __init__(self, catalog_dir: str):
        self.catalog_dir = catalog_dir
        self.products = self._load_catalogs(catalog_dir)

    @staticmethod
    def _load_catalogs(catalog_dir: str) -> List[Dict[str, Any]]:
        products: List[Dict[str, Any]] = []
        if not os.path.isdir(catalog_dir):
            raise FileNotFoundError(f"Product catalog directory not found: {catalog_dir}")
        for filename in sorted(os.listdir(catalog_dir)):
            if not filename.lower().endswith(".json"):
                continue
            path = os.path.join(catalog_dir, filename)
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                entries = data.get("products", [])
            elif isinstance(data, list):
                entries = data
            else:
                entries = []
            for entry in entries:
                if isinstance(entry, dict):
                    products.append(entry)
        return products

    def by_vendor(self, vendor: str) -> List[Dict[str, Any]]:
        return [p for p in self.products if str(p.get("vendor", "")).lower() == vendor.lower()]


class ProductMatcher:
    def __init__(self, catalog_dir: str):
        self.catalog = ProductCatalog(catalog_dir)

    def match_text(self, text: str, vendors: Optional[List[str]] = None) -> Dict[str, Any]:
        metadata = self.extract_requirement_metadata(text)
        return self.match(metadata, vendors=vendors)

    def match(self, requirements: Dict[str, Any], vendors: Optional[List[str]] = None) -> Dict[str, Any]:
        requirements = self.normalize_requirements(requirements)
        vendors = vendors or ["Fortinet", "Juniper"]
        results: Dict[str, Any] = {"requirements": requirements, "matches": {}}
        for vendor in vendors:
            match = self._match_vendor(requirements, vendor)
            results["matches"][vendor] = match.to_dict() if match else None
        return results

    @classmethod
    def normalize_requirements(cls, metadata: Dict[str, Any], source_text: str = "") -> Dict[str, Any]:
        if not isinstance(metadata, dict):
            metadata = {}
        normalized: Dict[str, Any] = {
            "device_type": cls._normalize_category(
                metadata.get("device_type") or metadata.get("category") or metadata.get("device_category")
            ),
            "source_text": source_text or str(metadata.get("source_text") or "")[:1000],
        }
        detected_specs = metadata.get("detected_specs") if isinstance(metadata.get("detected_specs"), dict) else {}
        nested_requirements = metadata.get("requirements") if isinstance(metadata.get("requirements"), dict) else {}
        for field in NUMERIC_REQUIREMENT_FIELDS:
            value = metadata.get(field, detected_specs.get(field, nested_requirements.get(field)))
            if value not in (None, ""):
                parsed_value = cls._parse_catalog_number(value)
                if parsed_value is not None:
                    normalized[field] = parsed_value
        if detected_specs.get("switching_capacity_tbps") not in (None, ""):
            parsed_tbps = cls._parse_catalog_number(detected_specs["switching_capacity_tbps"])
            if parsed_tbps is not None:
                normalized["switching_capacity_gbps"] = parsed_tbps * 1000
        throughput_mbps = metadata.get("throughput_mbps", detected_specs.get("throughput_mbps", nested_requirements.get("throughput_mbps")))
        if throughput_mbps not in (None, "") and "throughput_gbps" not in normalized:
            parsed_mbps = cls._parse_catalog_number(throughput_mbps)
            if parsed_mbps is not None:
                normalized["throughput_gbps"] = parsed_mbps / 1000
        storage_gb = metadata.get("storage_gb", metadata.get("local_storage_gb", detected_specs.get("storage_gb", detected_specs.get("local_storage_gb", nested_requirements.get("storage_gb", nested_requirements.get("local_storage_gb"))))))
        if storage_gb not in (None, "") and "storage_tb" not in normalized:
            parsed_storage_gb = cls._parse_catalog_number(storage_gb)
            if parsed_storage_gb is not None:
                normalized["storage_tb"] = parsed_storage_gb / 1024
        if detected_specs.get("cps", nested_requirements.get("cps")) not in (None, ""):
            normalized["connections_per_second"] = detected_specs.get("cps", nested_requirements.get("cps"))
        interfaces: Dict[str, int] = {}
        raw_interfaces = metadata.get("interfaces") or nested_requirements.get("interfaces")
        if isinstance(raw_interfaces, dict):
            for key, value in raw_interfaces.items():
                if value not in (None, ""):
                    parsed_value = cls._parse_catalog_number(value)
                    if parsed_value is not None:
                        interfaces[key] = int(parsed_value)
        for source_key, target_key in INTERFACE_METADATA_FIELDS.items():
            value = metadata.get(source_key, detected_specs.get(source_key))
            if value not in (None, ""):
                parsed_value = cls._parse_catalog_number(value)
                if parsed_value is not None:
                    interfaces[target_key] = max(interfaces.get(target_key, 0), int(parsed_value))
        if interfaces:
            normalized["interfaces"] = interfaces
        ports = metadata.get("ports", detected_specs.get("ports", nested_requirements.get("ports")))
        if ports not in (None, ""):
            parsed_ports = cls._parse_catalog_number(ports)
            if parsed_ports is not None:
                normalized["ports"] = int(parsed_ports)
        feature_candidates = metadata.get("fortinet_feature_candidates")
        if isinstance(feature_candidates, list):
            normalized["fortinet_feature_candidates"] = [str(item) for item in feature_candidates if str(item).strip()]
        for field in ("ha_port", "management_port", "console_port"):
            if metadata.get(field) is True:
                normalized[field] = True
        requirements = {k: v for k, v in normalized.items() if k not in ("device_type", "source_text", "fortinet_feature_candidates")}
        normalized["requirements"] = requirements
        return normalized

    @staticmethod
    def _normalize_category(category: Any) -> Optional[str]:
        if category in (None, "", "unknown"):
            return None
        raw = str(category).strip()
        if raw in set(DEVICE_CATEGORY_MAP.values()):
            return raw
        return DEVICE_CATEGORY_MAP.get(raw.lower().replace(" ", "_").replace("-", "_"), raw.upper())

    def _match_vendor(self, requirements: Dict[str, Any], vendor: str) -> Optional[ProductMatch]:
        category = requirements.get("device_type") or requirements.get("category")
        if not category:
            return None
        categories = self._candidate_categories(category)
        candidates = [p for p in self.catalog.by_vendor(vendor) if p.get("category") in categories]

        # ----------------------------------------------------------------
        # STRICT PHASE: only consider products that meet ALL hard constraints.
        # A hard constraint fails when candidate_spec < required_spec.
        # We NEVER fall back to under-spec hardware.
        # ----------------------------------------------------------------
        viable: List[Tuple[Dict[str, Any], List[str], Dict[str, float], Dict[str, Any]]] = []
        rejected: List[Dict[str, Any]] = []
        for product in candidates:
            ok, matched, missing, details = self._passes_hard_filters(product, requirements)
            if ok:
                score = self._score_product(product, requirements, matched)
                viable.append((product, matched, score, details))
            elif missing:
                rejected.append({
                    "model": product.get("model"),
                    "missing_or_under_spec": missing[:8],
                })

        if not viable:
            # No product satisfies all requirements → return None rather than
            # silently selecting an under-spec device.
            return None

        # ----------------------------------------------------------------
        # RANKING PHASE: among all valid candidates, prefer the closest fit
        # (minimise over-provisioning) using fit_quality score.
        # ----------------------------------------------------------------
        viable.sort(key=lambda item: item[2]["fit_quality"], reverse=True)
        product, matched, breakdown, details = viable[0]
        details["selected_model"] = product.get("model")
        details["valid_candidates_considered"] = len(viable)
        details["rejected_candidates_sample"] = rejected[:8]
        details["selection_reason"] = (
            "Selected closest valid candidate after hard filtering. "
            "Every listed matched constraint has candidate value >= required value."
        )
        confidence = round(max(0.5, min(0.99, breakdown["total"])), 2)
        return ProductMatch(
            vendor=str(product.get("vendor", vendor)),
            model=str(product.get("model", "")),
            category=str(product.get("category", category)),
            confidence=confidence,
            product_url=str(product.get("product_url", "")),
            datasheet_url=str(product.get("datasheet_url", "")),
            matched_requirements=matched,
            missing_requirements=[],
            score_breakdown={k: round(v, 4) for k, v in breakdown.items()},
            match_details=details,
        )

    @staticmethod
    def _candidate_categories(category: str) -> List[str]:
        if category == "SWITCH":
            return ["DATACENTER_SWITCH", "ACCESS_SWITCH", "SWITCH"]
        if category in ("DATACENTER_SWITCH", "ACCESS_SWITCH"):
            return [category, "SWITCH"]
        if category == "CENTRALIZED_MANAGEMENT":
            return ["CENTRALIZED_MANAGEMENT", "SIEM_SOC"]
        return [category]

    @staticmethod
    def _passes_hard_filters(product: Dict[str, Any], requirements: Dict[str, Any]) -> Tuple[bool, List[str], List[str], Dict[str, Any]]:
        matched: List[str] = []
        missing: List[str] = []
        details: Dict[str, Any] = {
            "device_type": requirements.get("device_type") or requirements.get("category"),
            "requirements": {},
            "interfaces": {},
        }
        for field in NUMERIC_REQUIREMENT_FIELDS:
            required = requirements.get(field)
            if required in (None, ""):
                continue
            available = ProductMatcher._product_numeric_value(product, field, required)
            details["requirements"][field] = {
                "required": required,
                "candidate": available,
                "passes": False,
            }
            if available is None:
                missing.append(field)
                continue
            required_value = ProductMatcher._parse_catalog_number(required)
            available_value = ProductMatcher._parse_catalog_number(available)
            if required_value is None or available_value is None:
                missing.append(field)
                continue
            if available_value < required_value:
                missing.append(field)
            else:
                matched.append(field)
                details["requirements"][field]["passes"] = True
        required_interfaces = requirements.get("interfaces") or {}
        product_interfaces = product.get("interfaces") or {}
        for name, required_count in required_interfaces.items():
            if required_count in (None, ""):
                continue
            available_count = ProductMatcher._compatible_interface_count(product, name, required_count)
            details["interfaces"][name] = {
                "required": required_count,
                "candidate": available_count,
                "passes": int(available_count) >= int(required_count),
            }
            if int(available_count) < int(required_count):
                missing.append(f"interfaces.{name}")
            else:
                matched.append(f"interfaces.{name}")
        for field in ("ha_port", "management_port", "console_port"):
            if requirements.get(field) is True:
                details["requirements"][field] = {
                    "required": True,
                    "candidate": product.get(field),
                    "passes": product.get(field) is True,
                }
                if product.get(field) is True:
                    matched.append(field)
                else:
                    missing.append(field)
        details["requirements"] = {k: v for k, v in details["requirements"].items() if v.get("required") not in (None, "")}
        details["interfaces"] = {k: v for k, v in details["interfaces"].items() if v.get("required") not in (None, "")}
        return not missing, matched, missing, details

    @staticmethod
    def _score_product(product: Dict[str, Any], requirements: Dict[str, Any], matched: List[str]) -> Dict[str, float]:
        """
        Score a product that has already passed all hard constraints.

        Two key sub-scores:
        - closeness  : ratio of required / available for every numeric field.
                       1.0 = exact match; lower = over-provisioned.
                       Closer to 1.0 is better (less wasteful).
        - coverage   : fraction of required fields that are matched.
        - affinity   : textual overlap between product model name and requirement text.
        - fit_quality: composite score used as the primary sort key to prefer
                       the tightest fit without under-sizing.
        """
        fit_scores: List[float] = []
        required_count = 0

        for field in NUMERIC_REQUIREMENT_FIELDS:
            required = requirements.get(field)
            available = ProductMatcher._product_numeric_value(product, field, required)
            if required in (None, "") or available in (None, ""):
                continue
            required_count += 1
            required_float = ProductMatcher._parse_catalog_number(required)
            available_float = ProductMatcher._parse_catalog_number(available)
            if required_float is None or available_float is None:
                continue
            if required_float <= 0 or available_float <= 0:
                continue
            # ratio = required / available:  1.0 = perfect, <1.0 = over-provisioned.
            # Since we already passed hard filters, available >= required, so ratio ∈ (0, 1].
            ratio = required_float / available_float
            fit_scores.append(ratio)

        required_interfaces = requirements.get("interfaces") or {}
        product_interfaces = product.get("interfaces") or {}
        for name, required_interface_count in required_interfaces.items():
            required_count += 1
            available_count = ProductMatcher._compatible_interface_count(product, name, required_interface_count)
            if not required_interface_count or not available_count:
                continue
            ratio = int(required_interface_count) / int(available_count)
            fit_scores.append(ratio)

        for field in ("ha_port", "management_port", "console_port"):
            if requirements.get(field) is True:
                required_count += 1

        # closeness: average ratio — 1.0 means every spec is exactly met
        closeness = sum(fit_scores) / len(fit_scores) if fit_scores else 0.75
        coverage  = min(1.0, len(matched) / max(1, required_count))

        context = " ".join([
            str(requirements.get("source_text") or ""),
            " ".join(requirements.get("fortinet_feature_candidates") or []),
        ]).lower()
        model_tokens = [token for token in re.findall(r"[a-z0-9]+", str(product.get("model", "")).lower()) if len(token) > 2]
        affinity = 1.0 if any(token in context for token in model_tokens) else 0.0

        # Composite total (unchanged weights keep backwards compatibility)
        total = (0.64 * closeness) + (0.18 * coverage) + (0.08 * affinity) + 0.10

        # fit_quality is the primary sort key: maximise closeness (i.e. prefer
        # the product that is just enough without over-provisioning), with
        # coverage as a tie-breaker.
        fit_quality = (0.80 * closeness) + (0.20 * coverage)

        return {
            "closeness":   closeness,
            "coverage":    coverage,
            "affinity":    affinity,
            "total":       total,
            "fit_quality": fit_quality,
        }

    @staticmethod
    def _total_interfaces(product: Dict[str, Any]) -> Optional[int]:
        interfaces = product.get("interfaces")
        if not isinstance(interfaces, dict):
            return None
        total = 0
        for value in interfaces.values():
            if value not in (None, ""):
                parsed_value = ProductMatcher._parse_catalog_number(value)
                total += int(parsed_value or 0)
        return total

    @staticmethod
    def _product_numeric_value(product: Dict[str, Any], field: str, required: Any = None) -> Optional[float]:
        if field == "ports":
            return ProductMatcher._available_port_count(product, required)
        if field == "max_ports":
            value = product.get("max_ports")
            if value not in (None, ""):
                return ProductMatcher._parse_catalog_number(value)
            return ProductMatcher._available_port_count(product, required)
        if field == "storage_tb":
            return ProductMatcher._product_storage_tb(product)
        if field == "throughput_gbps":
            mbps = product.get("throughput_mbps")
            if mbps not in (None, ""):
                parsed_mbps = ProductMatcher._parse_catalog_number(mbps)
                return parsed_mbps / 1000 if parsed_mbps is not None else None
        value = product.get(field)
        if value not in (None, ""):
            return ProductMatcher._parse_catalog_number(value)
        for alias in PRODUCT_SPEC_ALIASES.get(field, ()):
            alias_value = product.get(alias)
            if alias_value not in (None, ""):
                return ProductMatcher._parse_catalog_number(alias_value)
        return None

    @staticmethod
    def _available_port_count(product: Dict[str, Any], required: Any = None) -> Optional[int]:
        direct_ports = product.get("ports") or product.get("max_ports")
        if direct_ports not in (None, ""):
            parsed_ports = ProductMatcher._parse_catalog_number(direct_ports)
            return int(parsed_ports) if parsed_ports is not None else None
        options = product.get("main_port_options")
        if isinstance(options, list) and options:
            numeric_options = sorted(
                int(parsed)
                for option in options
                if (parsed := ProductMatcher._parse_catalog_number(option)) is not None
            )
            if not numeric_options:
                return None
            if required not in (None, ""):
                required_count = int(required)
                for option in numeric_options:
                    if option >= required_count:
                        return option
            return max(numeric_options)
        return ProductMatcher._total_interfaces(product)

    @staticmethod
    def _product_storage_tb(product: Dict[str, Any]) -> Optional[float]:
        for field in ("storage_tb", "storage_gb", "local_storage_gb"):
            value = product.get(field)
            if value in (None, ""):
                continue
            parsed_value = ProductMatcher._parse_catalog_number(value)
            if parsed_value is None:
                continue
            return parsed_value if field == "storage_tb" else parsed_value / 1024
        return None

    @staticmethod
    def _compatible_interface_count(product: Dict[str, Any], required_name: str, required_count: Any = None) -> int:
        product_interfaces = product.get("interfaces") or {}
        if not isinstance(product_interfaces, dict):
            product_interfaces = {}
        compatible_names = INTERFACE_COMPATIBILITY.get(required_name, (required_name,))
        total = 0
        for name in compatible_names:
            value = product_interfaces.get(name, 0)
            if value not in (None, ""):
                parsed_value = ProductMatcher._parse_catalog_number(value)
                total += int(parsed_value or 0)
        if total:
            return total

        main_speed = ProductMatcher._max_speed_gbps(product.get("main_port_speed"))
        required_speed = ProductMatcher._interface_speed_gbps(required_name)
        if main_speed is None or required_speed is None or main_speed < required_speed:
            return 0
        port_count = ProductMatcher._available_port_count(product, required_count)
        return int(port_count or 0)

    @staticmethod
    def _parse_catalog_number(value: Any) -> Optional[float]:
        if value in (None, ""):
            return None
        if isinstance(value, (int, float)):
            return float(value)
        text = str(value).strip().replace(",", "")
        if not text:
            return None
        matches = [float(match) for match in re.findall(r"\d+(?:\.\d+)?", text)]
        if not matches:
            return None
        if re.search(r"\bto\b|-", text, re.IGNORECASE) and len(matches) >= 2:
            return max(matches)
        return matches[0]

    @staticmethod
    def _interface_speed_gbps(interface_name: str) -> Optional[float]:
        match = re.match(r"(?P<num>\d+)(?:_(?P<num2>\d+))?g", str(interface_name).lower())
        if not match:
            return None
        if match.group("num2"):
            return float(match.group("num2"))
        return float(match.group("num"))

    @staticmethod
    def _max_speed_gbps(raw_speed: Any) -> Optional[float]:
        if raw_speed in (None, ""):
            return None
        speeds = [float(match.group(1)) for match in re.finditer(r"(\d+(?:\.\d+)?)\s*G(?:bps)?", str(raw_speed), re.IGNORECASE)]
        return max(speeds) if speeds else None
        return total

    @classmethod
    def extract_requirement_metadata(cls, text: str) -> Dict[str, Any]:
        normalized = f" {cls._normalize_text(text)} "
        if any(keyword in normalized for keyword in EXCLUDED_KEYWORDS):
            return {"device_type": None, "requirements": {}, "excluded": True}
        category = cls._detect_category(normalized)
        metadata: Dict[str, Any] = {"device_type": category, "requirements": {}, "source_text": text[:1000]}
        if not category:
            return metadata
        flat = cls._extract_numeric_requirements(normalized, category)
        interfaces = cls._extract_interfaces(normalized)
        if interfaces:
            flat["interfaces"] = interfaces
        if re.search(r"\bha\s+(?:port|interface)\b|(?:port|interface)\s+(?:for\s+)?ha\b|dedicated\s+ha\b", normalized):
            flat["ha_port"] = True
        if " management port" in normalized or "mgmt port" in normalized:
            flat["management_port"] = True
        if " console port" in normalized:
            flat["console_port"] = True
        metadata.update(flat)
        metadata["requirements"] = {k: v for k, v in flat.items() if k != "interfaces"}
        if interfaces:
            metadata["requirements"]["interfaces"] = interfaces
        return metadata

    @staticmethod
    def _normalize_text(text: str) -> str:
        text = text.lower().replace("≥", ">=").replace("—", "-").replace("–", "-")
        return re.sub(r"\s+", " ", text)

    @staticmethod
    def _detect_category(text: str) -> Optional[str]:
        for category, keywords in CATEGORY_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                return category
        return None

    @classmethod
    def _extract_numeric_requirements(cls, text: str, category: str) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        speed_matches = list(re.finditer(r"(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>tbps|gbps|mbps|tbit/s|gbit/s|mbit/s|g\b|t\b)", text))
        for match in speed_matches:
            prefix = text[max(0, match.start() - 12):match.start()]
            if re.search(r"\d+\s*(?:x|×)\s*$", prefix):
                continue
            value = cls._to_gbps(float(match.group("num")), match.group("unit"))
            window = text[max(0, match.start() - 80): min(len(text), match.end() + 80)]
            local_start = max(text.rfind(",", 0, match.start()), text.rfind(";", 0, match.start()), text.rfind("|", 0, match.start())) + 1
            local_end_candidates = [idx for idx in (text.find(",", match.end()), text.find(";", match.end()), text.find("|", match.end())) if idx != -1]
            local_end = min(local_end_candidates) if local_end_candidates else min(len(text), match.end() + 60)
            local_clause = text[local_start:local_end]
            if any(k in local_clause for k in ("ipsec", "vpn")) and category == "NGFW":
                values["ipsec_vpn_throughput_gbps"] = max(values.get("ipsec_vpn_throughput_gbps", 0), value)
            elif any(k in local_clause for k in ("ssl", "tls", "inspection", "decrypt")) and category == "NGFW":
                values["ssl_tls_inspection_gbps"] = max(values.get("ssl_tls_inspection_gbps", 0), value)
            elif re.search(r"\bips\b|intrusion prevention", local_clause):
                values["ips_throughput_gbps"] = max(values.get("ips_throughput_gbps", 0), value)
            elif any(k in window for k in ("switching", "backplane", "fabric")) or category in ("SWITCH", "DATACENTER_SWITCH", "ACCESS_SWITCH"):
                values["switching_capacity_gbps"] = max(values.get("switching_capacity_gbps", 0), value)
            elif category == "NGFW":
                values["ngfw_throughput_gbps"] = max(values.get("ngfw_throughput_gbps", 0), value)
            else:
                values["throughput_gbps"] = max(values.get("throughput_gbps", 0), value)
        cls._extract_count(text, values, "concurrent_sessions", ("concurrent sessions", "sessions"))
        cls._extract_count(text, values, "ssl_vpn_users", ("ssl vpn users", "ssl-vpn users", "vpn users", "concurrent users"))
        cls._extract_count(text, values, "connections_per_second", ("connections per second", "cps", "new sessions per second"))
        cls._extract_count(text, values, "policies", ("policies", "firewall policies"))
        cls._extract_count(text, values, "logs_per_day_gb", ("gb logs per day", "gb/day", "logs per day"))
        cls._extract_count(text, values, "analytic_rate_logs_sec", ("analytics logs/sec", "analytic logs/sec", "analytics rate"))
        cls._extract_count(text, values, "collector_rate_logs_sec", ("collector logs/sec", "collection logs/sec", "collector rate"))
        cls._extract_count(text, values, "performance_eps", ("eps", "events per second"))
        cls._extract_count(text, values, "email_routing_per_hour", ("email routing per hour", "messages per hour", "emails per hour"))
        cls._extract_count(text, values, "atp_per_hour", ("atp per hour", "atp scans per hour"))
        cls._extract_count(text, values, "email_domains", ("email domains", "domains"))
        cls._extract_count(text, values, "server_mode_mailboxes", ("mailboxes", "server mode mailboxes"))
        cls._extract_count(text, values, "max_ports", ("managed ports", "ports"))
        cls._extract_count(text, values, "max_devices_vdoms", ("devices", "vdoms", "managed devices"))
        cls._extract_count(text, values, "max_local_remote_users", ("local users", "remote users", "users"))
        cls._extract_count(text, values, "max_user_groups", ("user groups", "groups"))
        cls._extract_count(text, values, "max_nas_devices", ("nas devices", "radius clients"))
        cls._extract_count(text, values, "max_fortitokens", ("fortitokens", "tokens"))
        storage = re.search(r"(?:(?:storage|ssd|disk|hdd)\s*(?:of|:)?\s*)?(\d+(?:\.\d+)?)\s*(tb|gb)\s*(?:storage|ssd|disk|hdd)", text)
        if storage:
            number = float(storage.group(1))
            values["storage_tb"] = number if storage.group(2) == "tb" else number / 1024
        return values

    @staticmethod
    def _to_gbps(value: float, unit: str) -> float:
        unit = unit.lower()
        if unit.startswith("t"):
            return value * 1000
        if unit.startswith("m"):
            return value / 1000
        return value

    @staticmethod
    def _extract_count(text: str, values: Dict[str, Any], field: str, labels: Tuple[str, ...]) -> None:
        for label in labels:
            pattern_before = rf"(?P<num>\d[\d,]*(?:\.\d+)?)\s*(?:k|m|million|thousand)?\s+{re.escape(label)}"
            pattern_after = rf"{re.escape(label)}\s*(?:of|:|>=|>|at least|minimum|min)?\s*(?P<num>\d[\d,]*(?:\.\d+)?)\s*(?P<suffix>k|m|million|thousand)?"
            for pattern in (pattern_before, pattern_after):
                match = re.search(pattern, text)
                if match:
                    suffix = match.groupdict().get("suffix") or ""
                    values[field] = ProductMatcher._parse_count(match.group("num"), suffix)
                    return

    @staticmethod
    def _parse_count(raw: str, suffix: str = "") -> int:
        number = float(raw.replace(",", ""))
        suffix = suffix.lower()
        if suffix in ("m", "million"):
            number *= 1_000_000
        elif suffix in ("k", "thousand"):
            number *= 1_000
        return int(number)

    @staticmethod
    def _extract_interfaces(text: str) -> Dict[str, int]:
        interfaces: Dict[str, int] = {}
        for name, pattern in INTERFACE_PATTERNS.items():
            total = 0
            for match in re.finditer(pattern, text):
                total += int(match.group("count"))
            for match in re.finditer(INTERFACE_REVERSE_PATTERNS.get(name, ""), text):
                total += int(match.group("count"))
            if total:
                interfaces[name] = total
        return interfaces


def format_reference(matches: Dict[str, Any]) -> str:
    parts: List[str] = []
    for vendor in ("Fortinet", "Juniper"):
        match = (matches.get("matches") or {}).get(vendor)
        if not match:
            continue
        model = match.get("matched_product", "")
        url = match.get("datasheet_url") or match.get("product_url", "")
        if model and url:
            parts.append(f"{vendor}: {model} — {url}")
    return " | ".join(parts)
