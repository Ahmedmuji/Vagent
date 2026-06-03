import json
import math
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
    "power_capacity_kw",
    "power_capacity_kva",
    "cooling_capacity_kw",
    "rack_units",
    "static_load_kg",
    "dynamic_load_kg",
    "sensor_capacity",
    "outlet_count",
    "backup_runtime_minutes",
    "voltage_v",
    "phase_count",
)

PRODUCT_SPEC_ALIASES = {
    "ipsec_vpn_throughput_gbps": ("vpn_throughput_gbps",),
    "firewall_throughput_gbps": ("ngfw_throughput_gbps", "throughput_gbps"),
    "ngfw_throughput_gbps": ("firewall_throughput_gbps", "throughput_gbps"),
    "switching_capacity_gbps": ("throughput_gbps",),
    "throughput_gbps": ("switching_capacity_gbps", "ngfw_throughput_gbps"),
    "connections_per_second": ("cps",),
    "ssl_vpn_users": ("ssl_vpn_concurrent_users", "concurrent_ssl_vpn_users"),
    "performance_eps": ("analytic_rate_logs_sec", "collector_rate_logs_sec"),
    "max_ports": ("ports",),
}

GENERIC_SPEC_ALIASES = {
    "ipsec_vpn_throughput_gbps": ("ipsec vpn throughput", "ipsec_vpn_throughput", "vpn throughput"),
    "ngfw_throughput_gbps": ("ngfw throughput", "next generation firewall throughput"),
    "firewall_throughput_gbps": ("firewall throughput", "fw throughput"),
    "ips_throughput_gbps": ("ips throughput", "intrusion prevention throughput"),
    "threat_protection_gbps": ("threat protection throughput", "threat throughput"),
    "ssl_tls_inspection_gbps": ("ssl inspection throughput", "tls inspection throughput", "ssl/tls inspection"),
    "scalable_ssl_vpn_concurrent_users": ("scalable ssl vpn concurrent users", "scalable ssl-vpn concurrent users", "scale to ssl vpn users"),
    "ssl_vpn_gbps": ("ssl vpn throughput", "ssl-vpn throughput"),
    "ssl_vpn_users": ("ssl vpn concurrent users", "ssl-vpn concurrent users", "ssl vpn users", "concurrent ssl vpn users"),
    "switching_capacity_gbps": ("switching capacity", "fabric capacity", "switch capacity"),
    "concurrent_sessions": ("concurrent sessions", "sessions"),
    "connections_per_second": ("connections per second", "cps", "new sessions per second"),
    "ports": ("ports", "interfaces"),
    "policies": ("policies", "firewall policies"),
    "storage_tb": ("storage", "local storage"),
    "power_capacity_kw": ("kw", "power capacity", "active power"),
    "power_capacity_kva": ("kva", "ups capacity", "apparent power"),
    "cooling_capacity_kw": ("cooling capacity", "net sensible cooling", "sensible cooling"),
    "rack_units": ("rack units", "rack height", "u height"),
    "static_load_kg": ("static load", "static load capacity"),
    "dynamic_load_kg": ("dynamic load", "dynamic load capacity"),
    "outlet_count": ("outlets", "outlet count", "sockets"),
    "backup_runtime_minutes": ("backup runtime", "runtime", "backup time"),
    "voltage_v": ("voltage", "input voltage", "output voltage"),
    "phase_count": ("phase", "phases"),
}

INTERFACE_METADATA_FIELDS = {
    "interfaces_1g": "1g_rj45",
    "interfaces_10g": "10g_sfp_plus",
    "interfaces_25g": "25g_sfp28",
    "interfaces_40g": "40g_qsfp_plus",
    "interfaces_50g": "50g_sfp56",
    "interfaces_100g": "100g_qsfp28",
    "interfaces_200g": "200g_qsfp56",
    "interfaces_400g": "400g_qsfp_dd",
}

INTERFACE_COMPATIBILITY = {
    "1g_rj45": ("1g_rj45", "1_10g_rj45"),
    "10g_rj45": ("10g_rj45", "1_10g_rj45"),
    "1_10g_rj45": ("1_10g_rj45",),
    "1g_sfp": ("1g_sfp",),
    "10g_sfp_plus": ("10g_sfp_plus", "25g_sfp28"),
    "25g_sfp28": ("25g_sfp28", "50g_sfp56"),
    "40g_qsfp_plus": ("40g_qsfp_plus", "100g_qsfp28"),
    "100g_qsfp28": ("100g_qsfp28", "200g_qsfp56", "400g_qsfp_dd"),
    "200g_qsfp56": ("200g_qsfp56", "400g_qsfp_dd"),
    "400g_qsfp_dd": ("400g_qsfp_dd",),
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
    "ups": "UPS",
    "uninterruptible_power_supply": "UPS",
    "battery_energy_storage": "BATTERY_ENERGY_STORAGE",
    "battery_storage": "BATTERY_ENERGY_STORAGE",
    "lithium_ion_battery": "BATTERY_ENERGY_STORAGE",
    "cooling": "COOLING",
    "cooling_control": "COOLING",
    "precision_cooling": "COOLING",
    "row_cooling": "COOLING",
    "pdu": "RACK_PDU",
    "rack_pdu": "RACK_PDU",
    "power_distribution": "POWER_DISTRIBUTION",
    "transfer_switch": "TRANSFER_SWITCH",
    "busway": "BUSWAY",
    "containment": "CONTAINMENT",
    "rack": "RACK",
    "rack_accessory": "RACK_ACCESSORY",
    "monitoring": "MONITORING",
    "kvm": "KVM",
    "serial_console": "SERIAL_CONSOLE",
    "fire_suppression": "FIRE_SUPPRESSION",
    "fire_detection": "FIRE_DETECTION",
    "fire_alarm": "FIRE_ALARM",
    "camera": "CAMERA",
    "display": "DISPLAY",
}

INTERFACE_PATTERNS = {
    "400g_qsfp_dd": r"(?P<count>\d+)\s*(?:x|Ã—)?\s*(?:400\s*g|400gbe|400\s*gbps).*?(?:qsfp-dd|qsfpdd)?",
    "200g_qsfp56": r"(?P<count>\d+)\s*(?:x|Ã—)?\s*(?:200\s*g|200gbe|200\s*gbps).*?(?:qsfp56|qsfp)?",
    "50g_sfp56": r"(?P<count>\d+)\s*(?:x|Ã—)?\s*(?:50\s*g|50gbe|50\s*gbps).*?(?:sfp56)?",
    "100g_qsfp28": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:100\s*g|100gbe|100\s*gbps|hundred\s* Gigabit).*?(?:qsfp28|qsfp)?",
    "40g_qsfp_plus": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:40\s*g|40gbe|40\s*gbps).*?(?:qsfp\+|qsfp)?",
    "25g_sfp28": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:25\s*g|25gbe|25\s*gbps).*?(?:sfp28)?",
    "10g_sfp_plus": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:10\s*g|10gbe|10\s*gbps).*?(?:sfp\+|sfp plus|sfp)?",
    "1_10g_rj45": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:1/10\s*g|1g/10g|10\s*g|10gbe).*?(?:rj45|base-t|copper)",
    "1g_rj45": r"(?P<count>\d+)\s*(?:x|×)?\s*(?:1\s*g|1gbe|gigabit).*?(?:rj45|base-t|copper)",
}

INTERFACE_REVERSE_PATTERNS = {
    "400g_qsfp_dd": r"(?:interfaces?|ports?).{0,50}400\s*(?:g|gig|gbe|gbps).{0,35}(?:qsfp-dd|qsfpdd)?.{0,15}(?:=|:|qty|quantity|count)\s*(?P<count>\d+)",
    "200g_qsfp56": r"(?:interfaces?|ports?).{0,50}200\s*(?:g|gig|gbe|gbps).{0,35}(?:qsfp56|qsfp)?.{0,15}(?:=|:|qty|quantity|count)\s*(?P<count>\d+)",
    "50g_sfp56": r"(?:interfaces?|ports?).{0,50}50\s*(?:g|gig|gbe|gbps).{0,35}(?:sfp56)?.{0,15}(?:=|:|qty|quantity|count)\s*(?P<count>\d+)",
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
    "DATACENTER_SWITCH": ("data center switch", "datacenter switch", " tor ", "top of rack", "leaf", "spine", "core network", "qfx", "fortiswitch 1048", "fortiswitch 3032"),
    "ACCESS_SWITCH": ("access switch", "campus switch", "edge switch", "fortiswitch 448", "ex4400"),
    "SWITCH": ("switch", "switching"),
    "ROUTER": ("router", "routing platform", "edge routing", "wan router"),
    "NGFW": ("ngfw", "next generation firewall", "firewall", "security gateway", "ssl-vpn", "ssl vpn", "vpn appliance"),
    "UPS": ("ups", "uninterruptible power", "battery backup", "kva ups", "kw ups", "liebert apm", "liebert mtp"),
    "BATTERY_ENERGY_STORAGE": ("lithium-ion battery", "lithium ion battery", "battery cabinet", "battery energy storage", "battery rack"),
    "COOLING": ("precision cooling", "row cooling", "cooling unit", "thermal management", "crv4", "computer room air"),
    "POWER_DISTRIBUTION": ("power distribution", "server power distribution", "spm", "distribution panel"),
    "TRANSFER_SWITCH": ("transfer switch", "static transfer", "sts", "ats"),
    "BUSWAY": ("busway", "busduct", "bus duct"),
    "RACK_PDU": ("rack pdu", "rpdu", "geist", "power distribution unit"),
    "CONTAINMENT": ("containment", "cold aisle", "hot aisle", "smartaisle"),
    "RACK": ("rack enclosure", "server rack", "ve rack", "42u rack", "48u rack"),
    "RACK_ACCESSORY": ("rack accessory", "cable manager", "blank panel", "brush strip"),
    "MONITORING": ("infrastructure monitoring", "environmental monitoring", "rdu501", "monitoring gateway"),
    "KVM": ("kvm", "keyboard video mouse", "console tray"),
    "SERIAL_CONSOLE": ("serial console", "console server"),
    "FIRE_SUPPRESSION": ("fire suppression", "extinguishing", "fk-5-1-12", "nozzle", "check valve", "releasing control"),
    "FIRE_DETECTION": ("smoke detector", "fire detection", "airsense", "truealarm", "aspirating smoke"),
    "FIRE_ALARM": ("fire alarm", "manual station", "nac extender", "horn", "bacpac"),
    "CAMERA": ("camera", "cctv", "ip camera", "image sensor"),
    "DISPLAY": ("display", "video wall", "lcd panel", "narrow bezel"),
}

EXCLUDED_KEYWORDS = (
    "generator", "hvac", "patch cord", "cabling", "civil work", "electrical",
    "storage array", "san switch", "gpu", "license only", "subscription only",
)

SPEC_FIT_WEIGHTS = {
    "firewall_throughput_gbps": 1.45,
    "ngfw_throughput_gbps": 1.55,
    "ips_throughput_gbps": 1.35,
    "threat_protection_gbps": 1.35,
    "ipsec_vpn_throughput_gbps": 1.25,
    "ssl_tls_inspection_gbps": 1.25,
    "ssl_vpn_gbps": 1.15,
    "switching_capacity_gbps": 1.45,
    "throughput_gbps": 1.35,
    "concurrent_sessions": 1.15,
    "connections_per_second": 1.10,
    "ports": 1.20,
    "max_ports": 1.20,
    "interfaces": 1.35,
    "storage_tb": 0.90,
}

BOOLEAN_REQUIREMENT_FIELDS = (
    "ha_supported",
    "ha_port",
    "management_port",
    "console_port",
    "redundant_power",
)

ARCHITECTURE_CATEGORIES = (
    "UPS", "COOLING", "POWER_DISTRIBUTION", "RACK_PDU", "CONTAINMENT", "RACK",
    "MONITORING", "FIRE_SUPPRESSION", "FIRE_DETECTION", "FIRE_ALARM", "CAMERA", "DISPLAY",
)

HA_MODE_PATTERNS = (
    ("active-passive", r"active\s*[-/ ]\s*passive|\ba-p\b"),
    ("active-active", r"active\s*[-/ ]\s*active|\ba-a\b"),
    ("fgcp", r"\bfgcp\b"),
    ("fgsp", r"\bfgsp\b"),
    ("virtual clustering", r"virtual\s+cluster(?:ing)?"),
    ("clustering", r"cluster(?:ing)?"),
)

GENERIC_HA_MODES = {"active-passive", "active-active", "clustering"}


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
        seen_keys: set = set()
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
                    # Deduplicate by (vendor, model) - keep first occurrence.
                    dedup_key = (
                        str(entry.get("vendor", "")).lower(),
                        str(entry.get("model", "")).lower(),
                    )
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
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
        vendors = vendors or self._default_vendors(requirements)
        results: Dict[str, Any] = {"requirements": requirements, "matches": {}}
        for vendor in vendors:
            match = self._match_vendor(requirements, vendor)
            results["matches"][vendor] = match.to_dict() if match else None
        return results

    def _default_vendors(self, requirements: Dict[str, Any]) -> List[str]:
        category = requirements.get("device_type") or requirements.get("category")
        if category in {"NGFW", "SWITCH", "DATACENTER_SWITCH", "ACCESS_SWITCH", "ROUTER"}:
            return ["Fortinet", "Juniper"]
        vendors = sorted({str(product.get("vendor")) for product in self.catalog.products if product.get("vendor")})
        return vendors or ["Fortinet", "Juniper"]

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
        detected_specs = dict(metadata.get("detected_specs")) if isinstance(metadata.get("detected_specs"), dict) else {}
        nested_requirements = dict(metadata.get("requirements")) if isinstance(metadata.get("requirements"), dict) else {}
        for key, value in cls._extract_generic_specs(metadata.get("specs")).items():
            detected_specs.setdefault(key, value)
            nested_requirements.setdefault(key, value)
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
            parsed_cps = cls._parse_catalog_number(detected_specs.get("cps", nested_requirements.get("cps")))
            if parsed_cps is not None:
                normalized["connections_per_second"] = parsed_cps
        ssl_users = detected_specs.get("ssl_vpn_concurrent_users", nested_requirements.get("ssl_vpn_concurrent_users"))
        if ssl_users not in (None, "") and "ssl_vpn_users" not in normalized:
            parsed_ssl_users = cls._parse_catalog_number(ssl_users)
            if parsed_ssl_users is not None:
                normalized["ssl_vpn_users"] = parsed_ssl_users
        scalable_ssl_users = detected_specs.get(
            "scalable_ssl_vpn_concurrent_users",
            nested_requirements.get("scalable_ssl_vpn_concurrent_users"),
        )
        if scalable_ssl_users not in (None, "") and "scalable_ssl_vpn_concurrent_users" not in normalized:
            parsed_scalable_ssl_users = cls._parse_catalog_number(scalable_ssl_users)
            if parsed_scalable_ssl_users is not None:
                normalized["scalable_ssl_vpn_concurrent_users"] = parsed_scalable_ssl_users
                normalized["solution_scale_ssl_vpn_users"] = parsed_scalable_ssl_users
        for range_field in ("power_capacity_kw", "power_capacity_kva", "cooling_capacity_kw"):
            if range_field in normalized:
                continue
            value = metadata.get(range_field, detected_specs.get(range_field, nested_requirements.get(range_field)))
            parsed_range = cls._parse_capacity_requirement(value)
            if parsed_range is not None:
                normalized[range_field] = parsed_range
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
        for field in BOOLEAN_REQUIREMENT_FIELDS:
            if (
                metadata.get(field) is True
                or detected_specs.get(field) is True
                or nested_requirements.get(field) is True
            ):
                normalized[field] = True
        ha_modes = cls._normalize_ha_modes(
            metadata.get("ha_modes")
            or detected_specs.get("ha_modes")
            or nested_requirements.get("ha_modes")
        )
        if ha_modes:
            normalized["ha_supported"] = True
            normalized["ha_modes"] = ha_modes
        # Promote generic throughput_gbps to the right hardware-specific field
        # once the device type is known from row, sheet, or parent context.
        if normalized.get("throughput_gbps") and normalized.get("device_type") == "NGFW":
            src = (normalized.get("source_text") or "").lower()
            tput = normalized.pop("throughput_gbps")
            if any(k in src for k in ("ipsec", "ipsec vpn", "ipsec vpn throughput")) and "ipsec_vpn_throughput_gbps" not in normalized:
                normalized["ipsec_vpn_throughput_gbps"] = tput
            elif any(k in src for k in ("ssl vpn", "ssl-vpn")) and "ssl_vpn_gbps" not in normalized:
                normalized["ssl_vpn_gbps"] = tput
            elif any(k in src for k in ("ssl", "tls", "inspection", "decrypt")) and "ssl_tls_inspection_gbps" not in normalized:
                normalized["ssl_tls_inspection_gbps"] = tput
            elif any(k in src for k in ("ips", "intrusion prevention")) and "ips_throughput_gbps" not in normalized:
                normalized["ips_throughput_gbps"] = tput
            elif any(k in src for k in ("threat",)) and "threat_protection_gbps" not in normalized:
                normalized["threat_protection_gbps"] = tput
            elif "ngfw_throughput_gbps" not in normalized and "firewall_throughput_gbps" not in normalized:
                normalized["ngfw_throughput_gbps"] = tput
        requirements = {k: v for k, v in normalized.items() if k not in ("device_type", "source_text", "fortinet_feature_candidates")}
        normalized["requirements"] = requirements
        return normalized

    @classmethod
    def _extract_generic_specs(cls, specs: Any) -> Dict[str, Any]:
        extracted: Dict[str, Any] = {}
        if not isinstance(specs, list):
            return extracted
        for item in specs:
            if not isinstance(item, dict):
                continue
            target = cls._generic_spec_target(str(item.get("name") or ""))
            if not target:
                continue
            value = item.get("value")
            if value in (None, ""):
                value = item.get("raw_text")
            parsed = cls._parse_catalog_number(value)
            if parsed is None:
                continue
            extracted[target] = cls._convert_generic_spec_units(target, parsed, item.get("unit"))
        if "ssl_vpn_users" in extracted and "ssl_vpn_concurrent_users" not in extracted:
            extracted["ssl_vpn_concurrent_users"] = extracted["ssl_vpn_users"]
        if "scalable_ssl_vpn_concurrent_users" in extracted and "ssl_vpn_users" not in extracted:
            extracted["ssl_vpn_users"] = extracted["scalable_ssl_vpn_concurrent_users"]
        return extracted

    @staticmethod
    def _generic_spec_target(name: str) -> Optional[str]:
        normalized_name = re.sub(r"[^a-z0-9]+", " ", str(name or "").lower()).strip()
        compact_name = normalized_name.replace(" ", "_")
        for target, aliases in GENERIC_SPEC_ALIASES.items():
            if compact_name == target:
                return target
            for alias in aliases:
                normalized_alias = re.sub(r"[^a-z0-9]+", " ", alias.lower()).strip()
                if normalized_alias and normalized_alias in normalized_name:
                    return target
        return None

    @staticmethod
    def _convert_generic_spec_units(target: str, value: float, unit: Any) -> float:
        unit_text = str(unit or "").lower()
        if target.endswith("_gbps") and "mbps" in unit_text:
            return value / 1000
        if target.endswith("_gbps") and "tbps" in unit_text:
            return value * 1000
        if target == "storage_tb" and re.search(r"\bgb\b|gbyte|gigabyte", unit_text):
            return value / 1024
        if target == "backup_runtime_minutes" and re.search(r"\bhours?\b|\bhr\b", unit_text):
            return value * 60
        if target == "voltage_v" and re.search(r"\bkv\b|kilovolt", unit_text):
            return value * 1000
        return value

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
        if not self._has_hard_constraints(requirements):
            return None

        # ----------------------------------------------------------------
        # STRICT PHASE: only consider products that meet ALL hard constraints.
        # A hard constraint fails when candidate_spec < required_spec.
        # We NEVER fall back to under-spec hardware.
        # ----------------------------------------------------------------
        viable: List[Tuple[Dict[str, Any], List[str], Dict[str, Any], Dict[str, Any]]] = []
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
        viable.sort(
            key=lambda item: (
                item[2]["weighted_overprovision_penalty"],
                item[2]["weighted_worst_overprovision"],
                item[2]["overprovision_penalty"],
                -item[2]["coverage"],
                -item[2]["affinity"],
                item[2]["hardware_scale"],
            )
        )
        product, matched, breakdown, details = viable[0]
        details["selected_model"] = product.get("model")
        details["valid_candidates_considered"] = len(viable)
        details["rejected_candidates_sample"] = rejected[:8]
        details["top_valid_candidates"] = [
            {
                "model": item[0].get("model"),
                "weighted_overprovision_penalty": round(float(item[2]["weighted_overprovision_penalty"]), 4),
                "weighted_closeness": round(float(item[2]["weighted_closeness"]), 4),
                "max_overprovision": round(float(item[2]["max_overprovision"]), 4),
            }
            for item in viable[:5]
        ]
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
            score_breakdown=self._rounded_score_breakdown(breakdown),
            match_details=details,
        )

    @staticmethod
    def _rounded_score_breakdown(breakdown: Dict[str, Any]) -> Dict[str, Any]:
        rounded: Dict[str, Any] = {}
        for key, value in breakdown.items():
            if isinstance(value, (int, float)):
                rounded[key] = round(float(value), 4)
            elif key == "fit_details" and isinstance(value, dict):
                rounded[key] = {
                    detail_key: {
                        detail_field: round(float(detail_value), 4)
                        for detail_field, detail_value in detail.items()
                        if isinstance(detail_value, (int, float))
                    }
                    for detail_key, detail in value.items()
                    if isinstance(detail, dict)
                }
            else:
                rounded[key] = value
        return rounded

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
    def _has_hard_constraints(requirements: Dict[str, Any]) -> bool:
        for field in NUMERIC_REQUIREMENT_FIELDS:
            if requirements.get(field) not in (None, "", 0):
                return True
        if requirements.get("interfaces"):
            return True
        if requirements.get("ha_modes"):
            return True
        return any(requirements.get(field) is True for field in BOOLEAN_REQUIREMENT_FIELDS)

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
        for field in BOOLEAN_REQUIREMENT_FIELDS:
            if requirements.get(field) is True:
                candidate = ProductMatcher._product_boolean_value(product, field)
                details["requirements"][field] = {
                    "required": True,
                    "candidate": candidate,
                    "passes": candidate is True,
                }
                if candidate is True:
                    matched.append(field)
                else:
                    missing.append(field)
        required_ha_modes = ProductMatcher._normalize_ha_modes(requirements.get("ha_modes"))
        if required_ha_modes:
            candidate_modes = ProductMatcher._normalize_ha_modes(product.get("ha_modes"))
            modes_pass = ProductMatcher._product_supports_ha_modes(product, required_ha_modes, candidate_modes)
            missing_modes = [] if modes_pass else [mode for mode in required_ha_modes if mode not in candidate_modes]
            details["requirements"]["ha_modes"] = {
                "required": required_ha_modes,
                "candidate": candidate_modes,
                "passes": modes_pass,
            }
            if missing_modes:
                missing.append("ha_modes")
            else:
                matched.append("ha_modes")
        details["requirements"] = {k: v for k, v in details["requirements"].items() if v.get("required") not in (None, "")}
        details["interfaces"] = {k: v for k, v in details["interfaces"].items() if v.get("required") not in (None, "")}
        return not missing, matched, missing, details

    @staticmethod
    def _score_product(product: Dict[str, Any], requirements: Dict[str, Any], matched: List[str]) -> Dict[str, Any]:
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
        weighted_fit_total = 0.0
        total_weight = 0.0
        overprovision_factors: List[float] = []
        weighted_overprovision_total = 0.0
        weighted_worst_overprovision = 0.0
        fit_details: Dict[str, Dict[str, float]] = {}
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
            factor = max(1.0, available_float / required_float)
            weight = ProductMatcher._constraint_weight(field)
            fit_scores.append(ratio)
            weighted_fit_total += ratio * weight
            total_weight += weight
            overprovision_factors.append(factor)
            weighted_overprovision_total += math.log(factor) * weight
            weighted_worst_overprovision = max(weighted_worst_overprovision, math.log(factor) * weight)
            fit_details[field] = {
                "required": required_float,
                "candidate": available_float,
                "fit_ratio": ratio,
                "overprovision_factor": factor,
                "weight": weight,
            }

        required_interfaces = requirements.get("interfaces") or {}
        for name, required_interface_count in required_interfaces.items():
            required_count += 1
            available_count = ProductMatcher._compatible_interface_count(product, name, required_interface_count)
            if not required_interface_count or not available_count:
                continue
            ratio = int(required_interface_count) / int(available_count)
            factor = max(1.0, int(available_count) / int(required_interface_count))
            weight = ProductMatcher._constraint_weight(f"interfaces.{name}")
            fit_scores.append(ratio)
            weighted_fit_total += ratio * weight
            total_weight += weight
            overprovision_factors.append(factor)
            weighted_overprovision_total += math.log(factor) * weight
            weighted_worst_overprovision = max(weighted_worst_overprovision, math.log(factor) * weight)
            fit_details[f"interfaces.{name}"] = {
                "required": float(required_interface_count),
                "candidate": float(available_count),
                "fit_ratio": ratio,
                "overprovision_factor": factor,
                "weight": weight,
            }

        for field in BOOLEAN_REQUIREMENT_FIELDS:
            if requirements.get(field) is True:
                required_count += 1
        if requirements.get("ha_modes"):
            required_count += 1

        # closeness: average ratio — 1.0 means every spec is exactly met
        closeness = sum(fit_scores) / len(fit_scores) if fit_scores else 0.75
        weighted_closeness = weighted_fit_total / total_weight if total_weight else closeness
        coverage  = min(1.0, len(matched) / max(1, required_count))
        overprovision_penalty = (
            sum(math.log(factor) for factor in overprovision_factors) / len(overprovision_factors)
            if overprovision_factors else 0.0
        )
        weighted_overprovision_penalty = weighted_overprovision_total / total_weight if total_weight else overprovision_penalty
        max_overprovision = max(overprovision_factors) if overprovision_factors else 1.0
        hardware_scale = ProductMatcher._product_scale_score(product)

        context = " ".join([
            str(requirements.get("source_text") or ""),
            " ".join(requirements.get("fortinet_feature_candidates") or []),
        ]).lower()
        model_tokens = [token for token in re.findall(r"[a-z0-9]+", str(product.get("model", "")).lower()) if len(token) > 2]
        affinity = 1.0 if any(token in context for token in model_tokens) else 0.0

        # Higher confidence for tight, complete matches; sorting still uses the
        # overprovision penalties above to prefer the closest compliant model.
        total = (0.68 * weighted_closeness) + (0.16 * coverage) + (0.06 * affinity) + 0.10

        # fit_quality is the primary sort key: maximise closeness (i.e. prefer
        # the product that is just enough without over-provisioning), with
        # coverage as a tie-breaker.
        fit_quality = (0.84 * weighted_closeness) + (0.16 * coverage)

        return {
            "closeness":   closeness,
            "weighted_closeness": weighted_closeness,
            "coverage":    coverage,
            "affinity":    affinity,
            "total":       total,
            "fit_quality": fit_quality,
            "overprovision_penalty": overprovision_penalty,
            "weighted_overprovision_penalty": weighted_overprovision_penalty,
            "max_overprovision": max_overprovision,
            "weighted_worst_overprovision": weighted_worst_overprovision,
            "hardware_scale": hardware_scale,
            "fit_details": fit_details,
        }

    @staticmethod
    def _constraint_weight(field: str) -> float:
        if field.startswith("interfaces."):
            return SPEC_FIT_WEIGHTS["interfaces"]
        return SPEC_FIT_WEIGHTS.get(field, 1.0)

    @staticmethod
    def _normalize_ha_modes(value: Any) -> List[str]:
        if value in (None, ""):
            return []
        if isinstance(value, str):
            candidates = re.split(r"[,;/|]+", value)
        elif isinstance(value, (list, tuple, set)):
            candidates = [str(item) for item in value]
        else:
            candidates = [str(value)]

        modes: List[str] = []
        for candidate in candidates:
            normalized = ProductMatcher._normalize_text(candidate)
            for mode, pattern in HA_MODE_PATTERNS:
                if re.search(pattern, normalized) and mode not in modes:
                    modes.append(mode)
        return modes

    @staticmethod
    def _extract_ha_modes(text: str) -> List[str]:
        return [
            mode
            for mode, pattern in HA_MODE_PATTERNS
            if re.search(pattern, text)
        ]

    @staticmethod
    def _product_boolean_value(product: Dict[str, Any], field: str) -> bool:
        if product.get(field) is True:
            return True
        if field == "ha_supported":
            return bool(product.get("ha_port") is True or ProductMatcher._normalize_ha_modes(product.get("ha_modes")))
        return False

    @staticmethod
    def _product_supports_ha_modes(product: Dict[str, Any], required_modes: List[str], candidate_modes: Optional[List[str]] = None) -> bool:
        candidate_modes = candidate_modes if candidate_modes is not None else ProductMatcher._normalize_ha_modes(product.get("ha_modes"))
        if candidate_modes:
            return all(mode in candidate_modes for mode in required_modes)
        if not ProductMatcher._product_boolean_value(product, "ha_supported"):
            return False
        return all(mode in GENERIC_HA_MODES for mode in required_modes)

    @staticmethod
    def _product_scale_score(product: Dict[str, Any]) -> float:
        model = str(product.get("model") or "")
        numbers = [float(match) for match in re.findall(r"\d+", model)]
        if numbers:
            return max(numbers)
        numeric_values: List[float] = []
        for field in (
            "firewall_throughput_gbps", "ipsec_vpn_throughput_gbps",
            "ngfw_throughput_gbps", "ips_throughput_gbps",
            "concurrent_sessions", "ssl_vpn_users",
        ):
            value = ProductMatcher._parse_catalog_number(product.get(field))
            if value is not None:
                numeric_values.append(value)
        return sum(math.log(max(1.0, value)) for value in numeric_values)

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
            if isinstance(value, dict):
                for key in ("max", "value", "required", "min"):
                    if value.get(key) not in (None, ""):
                        return ProductMatcher._parse_catalog_number(value[key])
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
        suffixed = re.search(r"(?P<num>\d+(?:\.\d+)?)\s*(?P<suffix>k|m|million|thousand)\b", text, re.IGNORECASE)
        if suffixed:
            number = float(suffixed.group("num"))
            suffix = suffixed.group("suffix").lower()
            if suffix in ("m", "million"):
                return number * 1_000_000
            return number * 1_000
        matches = [float(match) for match in re.findall(r"\d+(?:\.\d+)?", text)]
        if not matches:
            return None
        if re.search(r"\bto\b|-", text, re.IGNORECASE) and len(matches) >= 2:
            return max(matches)
        return matches[0]

    @staticmethod
    def _parse_capacity_requirement(value: Any) -> Optional[float]:
        if isinstance(value, dict):
            for key in ("min", "required", "value"):
                if value.get(key) not in (None, ""):
                    return ProductMatcher._parse_catalog_number(value[key])
            if value.get("max") not in (None, ""):
                return ProductMatcher._parse_catalog_number(value["max"])
        return ProductMatcher._parse_catalog_number(value)

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
        flat = cls._extract_numeric_requirements(normalized, category or "")
        interfaces = cls._extract_interfaces(normalized)
        if interfaces:
            flat["interfaces"] = interfaces
        if re.search(r"\bha\s+(?:configuration|mode|pair|cluster)\b|high availability|active[\s/-]*passive|active[\s/-]*active|\bfgcp\b|\bfgsp\b|virtual\s+cluster", normalized):
            flat["ha_supported"] = True
        ha_modes = cls._extract_ha_modes(normalized)
        if ha_modes:
            flat["ha_supported"] = True
            flat["ha_modes"] = ha_modes
        if cls.text_explicitly_requires_ha_port(normalized):
            flat["ha_port"] = True
        if re.search(r"redundant\s+power(?:\s+supply)?|dual\s+(?:ac\s+)?power|dual\s+psu|1\+1\s+redundancy", normalized):
            flat["redundant_power"] = True
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
    def text_explicitly_requires_ha_port(text: str) -> bool:
        return bool(re.search(
            r"\bha\s+(?:ports?|interfaces?)\b|\b(?:ports?|interfaces?)\s+(?:for\s+)?ha\b|dedicated\s+ha\b",
            text,
        ))

    @staticmethod
    def _detect_category(text: str) -> Optional[str]:
        for category in ARCHITECTURE_CATEGORIES:
            keywords = CATEGORY_KEYWORDS.get(category, ())
            if any(keyword in text for keyword in keywords):
                return category
        for category, keywords in CATEGORY_KEYWORDS.items():
            if any(keyword in text for keyword in keywords):
                return category
        return None

    @classmethod
    def _extract_numeric_requirements(cls, text: str, category: str) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        cat = (category or "").upper()
        ngfw_categories = {"NGFW", ""}
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
            classification_clause = f"{local_clause} {window}"
            if "ssl vpn" in classification_clause and cat in ngfw_categories:
                values["ssl_vpn_gbps"] = max(values.get("ssl_vpn_gbps", 0), value)
            elif any(k in classification_clause for k in ("ipsec", "ipsec vpn", "ipsec vpn throughput")) and cat in ngfw_categories:
                values["ipsec_vpn_throughput_gbps"] = max(values.get("ipsec_vpn_throughput_gbps", 0), value)
            elif any(k in classification_clause for k in ("ssl", "tls", "inspection", "decrypt")) and cat in ngfw_categories:
                values["ssl_tls_inspection_gbps"] = max(values.get("ssl_tls_inspection_gbps", 0), value)
            elif re.search(r"\bips\b|intrusion prevention", classification_clause):
                values["ips_throughput_gbps"] = max(values.get("ips_throughput_gbps", 0), value)
            elif "threat protection" in classification_clause:
                values["threat_protection_gbps"] = max(values.get("threat_protection_gbps", 0), value)
            elif any(k in window for k in ("switching", "backplane", "fabric")) or cat in ("SWITCH", "DATACENTER_SWITCH", "ACCESS_SWITCH"):
                values["switching_capacity_gbps"] = max(values.get("switching_capacity_gbps", 0), value)
            elif cat == "NGFW":
                values["ngfw_throughput_gbps"] = max(values.get("ngfw_throughput_gbps", 0), value)
            elif cat == "":
                values["throughput_gbps"] = max(values.get("throughput_gbps", 0), value)
            else:
                values["throughput_gbps"] = max(values.get("throughput_gbps", 0), value)
        cls._extract_count(text, values, "concurrent_sessions", ("concurrent sessions", "sessions"))
        cls._extract_count(text, values, "ssl_vpn_users", (
            "ssl vpn users", "ssl-vpn users",
            "ssl vpn concurrent users", "ssl-vpn concurrent users",
            "ssl vpn concurrent user", "ssl-vpn concurrent user",
            "ssl vpn user license", "ssl-vpn user license",
            "ssl vpn concurrent user license", "ssl-vpn concurrent user license",
            "vpn users", "concurrent users",
        ))
        cls._extract_count(text, values, "connections_per_second", ("connections per second", "connections per seconds", "cps", "new sessions per second"))
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
        storage_after_label = re.search(r"(?:storage|ssd|disk|hdd).{0,80}?(\d+(?:\.\d+)?)\s*(tb|gb)\b", text)
        if storage_after_label:
            number = float(storage_after_label.group(1))
            values["storage_tb"] = max(values.get("storage_tb", 0), number if storage_after_label.group(2) == "tb" else number / 1024)
        if cat == "UPS":
            cls._extract_capacity(text, values, "power_capacity_kva", ("kva",))
            cls._extract_capacity(text, values, "power_capacity_kw", ("kw",))
        elif cat == "COOLING":
            cls._extract_capacity(text, values, "cooling_capacity_kw", ("kw",))
        elif cat == "POWER_DISTRIBUTION":
            cls._extract_capacity(text, values, "power_capacity_kva", ("kva",))
        elif cat == "RACK":
            cls._extract_count(text, values, "rack_units", ("u rack", "rack units", "u enclosure"))
            cls._extract_count(text, values, "static_load_kg", ("kg static load", "kg load", "static load"))
        elif cat == "MONITORING":
            cls._extract_count(text, values, "sensor_capacity", ("sensors", "sensor"))
        elif cat == "RACK_PDU":
            cls._extract_count(text, values, "outlet_count", ("outlets", "sockets", "socket"))
        return values

    @staticmethod
    def _extract_capacity(text: str, values: Dict[str, Any], field: str, units: Tuple[str, ...]) -> None:
        found: List[float] = []
        unit_pattern = "|".join(re.escape(unit) for unit in units)
        for match in re.finditer(rf"(?P<num>\d+(?:\.\d+)?)\s*(?P<unit>{unit_pattern})\b", text):
            prefix = text[max(0, match.start() - 12):match.start()]
            if re.search(r"\d+\s*(?:x|×)\s*$", prefix):
                continue
            found.append(float(match.group("num")))
        if found:
            values[field] = max(values.get(field, 0), max(found))

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
        found: List[int] = []
        for label in labels:
            pattern_before = rf"(?P<num>\d[\d,]*(?:\.\d+)?)\s*(?P<suffix>k|m|million|thousand)?\s+{re.escape(label)}"
            pattern_after = rf"{re.escape(label)}(?:\s|\||:|=|-|>|of|at least|minimum|min)*?(?P<num>\d[\d,]*(?:\.\d+)?)\s*(?P<suffix>k|m|million|thousand)?"
            for pattern in (pattern_before, pattern_after):
                for match in re.finditer(pattern, text):
                    suffix = match.groupdict().get("suffix") or ""
                    found.append(ProductMatcher._parse_count(match.group("num"), suffix))
        if found:
            values[field] = max(values.get(field, 0), max(found))

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
    for vendor, match in (matches.get("matches") or {}).items():
        if not match:
            continue
        model = match.get("matched_product", "")
        url = match.get("datasheet_url") or match.get("product_url", "")
        if model and url:
            parts.append(f"{vendor}: {model} — {url}")
    return " | ".join(parts)
