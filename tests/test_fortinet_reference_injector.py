import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from fortinet.rag_matcher import FortinetRAGMatcher  # noqa: E402
from fortinet.reference_injector import inject_fortinet_references  # noqa: E402


CATALOG_DIR = str(ROOT / "data" / "product_catalogs")


def _reference_index(sheet):
    return sheet["headers"].index("References")


class FortinetReferenceInjectorTests(unittest.TestCase):
    def setUp(self):
        self.previous_include_juniper = os.environ.get("FORTINET_RAG_INCLUDE_JUNIPER")
        os.environ["FORTINET_RAG_INCLUDE_JUNIPER"] = "0"
        os.environ["FORTINET_RAG_USE_LLM"] = "0"

    def tearDown(self):
        if self.previous_include_juniper is None:
            os.environ.pop("FORTINET_RAG_INCLUDE_JUNIPER", None)
        else:
            os.environ["FORTINET_RAG_INCLUDE_JUNIPER"] = self.previous_include_juniper

    def test_single_firewall_section_references_only_anchor_row(self):
        data = {
            "sheets": [{
                "title": "Technical Requirements",
                "headers": ["Section", "SN", "Requirement", "Required Value / Spec"],
                "rows": [
                    ["Perimeter Firewalls", "", "", ""],
                    ["", "1.", "Next Generation Firewall Throughput", "20Gbps"],
                    ["", "2.", "IPS Throughput", "20Gbps"],
                    ["", "3.", "Concurrent sessions", "12 Million"],
                    ["", "4.", "Connections Per Seconds", "500,000"],
                    ["", "5.", "Policies", "100,000"],
                    ["", "6.", "Storage Support (Usable)", "1TB"],
                    ["", "7.", "Threat protection throughput", "20Gbps"],
                    ["", "8.", "SSL/TLS Inspection throughput", "15Gbps"],
                    ["", "9.", "SSL VPN Throughput", "15Gbps"],
                    ["Interfaces", "1.", "25 GE SFP28 interfaces with matched transceivers", "4"],
                    ["", "2.", "10 GE SFP+ interfaces with matched transceivers", "8"],
                    ["", "3.", "1/10 GE RJ45", "2"],
                    ["Features", "1.", "High Availability", "Active/Active, Active/Passive, Clustering"],
                    ["", "34.", "All hardware equipment must be Dual Power Supply", "Yes"],
                ],
            }]
        }

        enriched, stats = inject_fortinet_references(data, CATALOG_DIR)
        sheet = enriched["sheets"][0]
        ref_idx = _reference_index(sheet)

        self.assertEqual(stats["matched_rows"], 1)
        self.assertEqual(sheet["rows"][0][ref_idx], "")
        self.assertIn("Fortinet: FortiGate", sheet["rows"][1][ref_idx])
        self.assertIn("fortigate-", sheet["rows"][1][ref_idx].lower())
        self.assertTrue(all(row[ref_idx] == "" for row in sheet["rows"][2:]))

    def test_firewall_fit_prefers_closest_safe_model_over_oversized_model(self):
        matcher = FortinetRAGMatcher(CATALOG_DIR, top_k=20, use_llm=False, include_juniper=False)
        requirement = (
            "Perimeter Firewalls Next Generation Firewall Throughput 20Gbps "
            "IPS Throughput 20Gbps Concurrent sessions 12 Million "
            "Connections Per Seconds 500,000 Policies 100,000 "
            "Storage Support (Usable) 1TB Threat protection throughput 20Gbps "
            "SSL/TLS Inspection throughput 15Gbps SSL VPN Throughput 15Gbps "
            "Interfaces 25 GE SFP28 interfaces with matched transceivers 4 "
            "10 GE SFP+ interfaces with matched transceivers 8 "
            "1/10 GE RJ45 2 HA Port Yes Console Port Yes Management Port RJ-45 Yes "
            "High Availability Active/Active, Active/Passive, Clustering"
        )

        constraints = matcher._parse_constraints(requirement, {})
        result = matcher.match_vendor(requirement, constraints, "Fortinet")

        self.assertEqual(constraints["interfaces"]["1_10g_rj45"], 2)
        self.assertIn("Fortinet: FortiGate 2601F", result["reference"])
        self.assertNotIn("FortiGate 3501F", result["reference"])

    def test_mixed_sdwan_controller_text_does_not_pollute_firewall_constraints(self):
        matcher = FortinetRAGMatcher(CATALOG_DIR, top_k=20, use_llm=False, include_juniper=False)
        requirement = (
            "Bidder should propose complete SD-WAN solution for 200x remote sites. "
            "PR Site Aggregation Firewalls (Hardware) Qty 2, DR Site Aggregation Firewalls Qty 2, "
            "PR Site Controllers Qty 2, DR Site Controllers Qty 2. "
            "1.2.1 Aggregation Firewalls for PR & DR must comply: "
            "IPSec VPN throughput with all features 10 Gbps; Equipment must support 2000+ IPSec VPNs; "
            "Minimum 8x 10Gig Interfaces other than HA; Concurrent Sessions 20Million; "
            "Redundant Power Supplies. 1.2.2 Redundant Controllers for PR & DR Sites must provide "
            "licenses for 200x Firewalls and centrally manage SDWAN feature sets."
        )
        gemini_metadata = {
            "device_type": "NGFW",
            "detected_specs": {
                "ipsec_vpn_throughput_gbps": 10,
                "concurrent_sessions": 20_000_000,
                "interfaces_10g": 8,
                "redundant_power": True,
                "max_devices_vdoms": 200,
            },
        }

        constraints = matcher._parse_constraints(requirement, gemini_metadata)
        result = matcher.match_vendor(requirement, constraints, "Fortinet")

        self.assertNotIn("max_devices_vdoms", constraints)
        self.assertIn("Fortinet: FortiGate 700G", result["reference"])
        self.assertNotIn("no catalog item met", result["reasoning"].lower())

    def test_multiplied_40g_metadata_is_corrected_from_text(self):
        matcher = FortinetRAGMatcher(CATALOG_DIR, top_k=20, use_llm=False, include_juniper=False)
        requirement = "Core switch must provide minimum 3x 40G interfaces and 1 Tbps switching capacity."
        gemini_metadata = {
            "device_type": "DATACENTER_SWITCH",
            "detected_specs": {
                "interfaces_40g": 120,
                "switching_capacity_gbps": 1000,
            },
        }

        constraints = matcher._parse_constraints(requirement, gemini_metadata)

        self.assertEqual(constraints["interfaces"]["40g_qsfp_plus"], 3)
        self.assertNotEqual(constraints["interfaces"]["40g_qsfp_plus"], 120)

    def test_inferred_firewall_block_overrides_bad_gemini_continuation_flags(self):
        data = {
            "sheets": [{
                "title": "Hardware Based Next Generation Firewall",
                "headers": ["SN", "Requirement", "Required Value / Spec"],
                "rows": [
                    {"row_type": "data", "data": ["Perimeter Firewalls", "", ""], "metadata": {"requires_reference": False, "product_group_primary_row": False}},
                    {"row_type": "data", "data": ["1.", "Next Generation Firewall Throughput", "20Gbps"], "metadata": {"requires_reference": False, "product_group_primary_row": False}},
                    {"row_type": "data", "data": ["2.", "IPS Throughput", "20Gbps"], "metadata": {"is_product_spec_continuation": True}},
                    {"row_type": "data", "data": ["3.", "SSL VPN Throughput", "15Gbps"], "metadata": {"is_product_spec_continuation": True}},
                    {"row_type": "data", "data": ["4.", "25 GE SFP28 interfaces with matched transceivers", "4"], "metadata": {"is_product_spec_continuation": True}},
                    {"row_type": "data", "data": ["5.", "10 GE SFP+ interfaces with matched transceivers", "8"], "metadata": {"is_product_spec_continuation": True}},
                    {"row_type": "data", "data": ["6.", "All hardware equipment must be Dual Power Supply", "Yes"], "metadata": {"is_product_spec_continuation": True}},
                ],
            }]
        }

        enriched, stats = inject_fortinet_references(data, CATALOG_DIR)
        sheet = enriched["sheets"][0]
        ref_idx = _reference_index(sheet)

        self.assertEqual(stats["matched_rows"], 1)
        self.assertIn("Fortinet: FortiGate", sheet["rows"][1]["data"][ref_idx])
        self.assertTrue(all(row["data"][ref_idx] == "" for row in sheet["rows"][2:]))

    def test_firewall_sheet_still_references_when_model_marks_rows_as_sections(self):
        data = {
            "sheets": [{
                "title": "Hardware Based Next Generation Firewall",
                "headers": ["SN", "Requirement", "Required Value / Spec"],
                "rows": [
                    {"row_type": "section", "data": ["", "Perimeter Firewalls", ""], "metadata": {"requires_reference": False}},
                    {"row_type": "section", "data": ["1.", "Next Generation Firewall Throughput", "20Gbps"], "metadata": {"requires_reference": False}},
                    {"row_type": "section", "data": ["2.", "IPS Throughput", "20Gbps"], "metadata": {"requires_reference": False}},
                    {"row_type": "section", "data": ["3.", "Concurrent sessions", "12 Million"], "metadata": {"requires_reference": False}},
                    {"row_type": "section", "data": ["4.", "Storage Support (Usable)", "1TB"], "metadata": {"requires_reference": False}},
                    {"row_type": "section", "data": ["5.", "SSL VPN Throughput", "15Gbps"], "metadata": {"requires_reference": False}},
                    {"row_type": "section", "data": ["6.", "10 GE SFP+ interfaces with matched transceivers", "8"], "metadata": {"requires_reference": False}},
                    {"row_type": "section", "data": ["7.", "1/10 GE RJ45", "2"], "metadata": {"requires_reference": False}},
                ],
            }]
        }

        enriched, stats = inject_fortinet_references(data, CATALOG_DIR)
        sheet = enriched["sheets"][0]
        ref_idx = _reference_index(sheet)

        self.assertEqual(stats["matched_rows"], 1)
        self.assertIn("Fortinet: FortiGate", sheet["rows"][1]["data"][ref_idx])
        self.assertTrue(all(row["data"][ref_idx] == "" for idx, row in enumerate(sheet["rows"]) if idx != 1))

    def test_multi_product_sheet_references_each_product_anchor(self):
        data = {
            "sheets": [{
                "title": "Network Hardware",
                "headers": ["Section", "SN", "Requirement", "Required Value / Spec"],
                "rows": [
                    ["Perimeter Firewalls", "", "", ""],
                    ["", "1.", "Next Generation Firewall Throughput", "20Gbps"],
                    ["", "2.", "IPS Throughput", "20Gbps"],
                    ["", "3.", "Concurrent sessions", "12 Million"],
                    ["", "4.", "Connections Per Seconds", "500,000"],
                    ["", "5.", "Policies", "100,000"],
                    ["", "6.", "Storage Support (Usable)", "1TB"],
                    ["", "7.", "Threat protection throughput", "20Gbps"],
                    ["", "8.", "SSL/TLS Inspection throughput", "15Gbps"],
                    ["", "9.", "SSL VPN Throughput", "15Gbps"],
                    ["Interfaces", "1.", "25 GE SFP28 interfaces with matched transceivers", "4"],
                    ["", "2.", "10 GE SFP+ interfaces with matched transceivers", "8"],
                    ["", "3.", "1/10 GE RJ45", "2"],
                    ["Features", "1.", "High Availability", "Active/Passive"],
                    ["", "2.", "All hardware equipment must be Dual Power Supply", "Yes"],
                    ["Data Center Switches", "", "", ""],
                    ["", "1.", "Switching Capacity", "1Tbps"],
                    ["", "2.", "10 GE SFP+ interfaces", "24"],
                    ["", "3.", "Management Port", "Yes"],
                ],
            }]
        }

        enriched, stats = inject_fortinet_references(data, CATALOG_DIR)
        sheet = enriched["sheets"][0]
        ref_idx = _reference_index(sheet)

        self.assertEqual(stats["matched_rows"], 2)
        self.assertIn("Fortinet: FortiGate", sheet["rows"][1][ref_idx])
        self.assertIn("Fortinet: FortiSwitch", sheet["rows"][16][ref_idx])
        self.assertTrue(all(sheet["rows"][idx][ref_idx] == "" for idx in (0, 2, 10, 15, 17, 18)))

    def test_self_contained_remote_firewall_row_does_not_absorb_feature_rows(self):
        data = {
            "sheets": [{
                "title": "Technical Compliance Sheet",
                "headers": ["S#", "Description", "Compliance"],
                "rows": [
                    ["2.", "Total Remote Sites Firewalls = 196x Remote Site Equipment Hardware Capacity: a) IPSec VPN throughput with all features 200 Mbps b) Interfaces Copper 1Gig = 5", ""],
                    ["4.", "Provided equipment must load balance, load sharing and fail-over between network links.", ""],
                    ["5.", "Proposed equipment must provide SDWAN features including link bundling and traffic steering.", ""],
                ],
            }]
        }

        enriched, stats = inject_fortinet_references(data, CATALOG_DIR)
        sheet = enriched["sheets"][0]
        ref_idx = _reference_index(sheet)
        reason_idx = sheet["headers"].index("Hardware_Reference_Reasoning")

        self.assertEqual(stats["matched_rows"], 1)
        self.assertIn("Fortinet: FortiGate 40F", sheet["rows"][0][ref_idx])
        self.assertNotIn("ha_modes", sheet["rows"][0][reason_idx].lower())
        self.assertTrue(all(row[ref_idx] == "" for row in sheet["rows"][1:]))

    def test_hardware_logging_uses_fortilogger_not_fortianalyzer(self):
        data = {
            "sheets": [{
                "title": "Logging Hardware",
                "headers": ["SN", "Requirement", "Required Value / Spec"],
                "rows": [
                    ["1.", "Hardware logging appliance for firewall logs, log reporting and log backup", "Yes"],
                ],
            }]
        }

        enriched, stats = inject_fortinet_references(data, CATALOG_DIR)
        sheet = enriched["sheets"][0]
        ref = sheet["rows"][0][_reference_index(sheet)]

        self.assertEqual(stats["matched_rows"], 1)
        self.assertIn("Fortinet: FortiLogger", ref)
        self.assertNotIn("FortiAnalyzer", ref)

    def test_procurement_narrative_does_not_get_hardware_reference(self):
        data = {
            "sheets": [{
                "title": "General Content",
                "headers": ["Description"],
                "rows": [
                    ["Procurement Title: Supply, Installation, Configuration and Maintenance of SSL-VPN Solution"],
                    ["Scope of Work: The bidder shall provide services, support, warranty and documentation."],
                ],
            }]
        }

        enriched, stats = inject_fortinet_references(data, CATALOG_DIR)
        sheet = enriched["sheets"][0]
        ref_idx = _reference_index(sheet)

        self.assertEqual(stats["matched_rows"], 0)
        self.assertEqual(sheet["rows"][0][ref_idx], "")
        self.assertEqual(sheet["rows"][1][ref_idx], "")

    def test_generic_ssl_vpn_scope_without_specs_is_not_fallback_matched(self):
        data = {
            "sheets": [{
                "title": "Connectivity Requirements",
                "headers": ["SN", "Requirement", "Required Value / Spec"],
                "rows": [
                    ["1.", "SSL-VPN solution shall be provided for remote users as part of project scope", "Yes"],
                ],
            }]
        }

        enriched, stats = inject_fortinet_references(data, CATALOG_DIR)
        sheet = enriched["sheets"][0]
        ref = sheet["rows"][0][_reference_index(sheet)]

        self.assertEqual(stats["matched_rows"], 0)
        self.assertEqual(ref, "")

    def test_ssl_vpn_user_sheet_groups_scale_rows_into_one_firewall_reference(self):
        data = {
            "sheets": [{
                "title": "SSL-VPN Users",
                "headers": ["SN", "Requirement", "Required Value / Spec"],
                "rows": [
                    ["Deployment and Hardware", "", ""],
                    ["1.", "All solution and its components must be deployed on-prem", "Yes"],
                    ["2.", "All proposed hardware must have minimum 4 x 10/25 fiber and 4 x 10G fiber ready to use interfaces", "Yes"],
                    ["Scalability", "", ""],
                    ["1.", "Fully licensed SSL-VPN concurrent users", "17,000"],
                    ["2.", "Hardware must be scalable to handle 47,000 concurrent SSL VPN users", "Yes"],
                    ["Security", "", ""],
                    ["1.", "MFA and access control policies must be supported", "Yes"],
                ],
            }]
        }

        enriched, stats = inject_fortinet_references(data, CATALOG_DIR)
        sheet = enriched["sheets"][0]
        ref_idx = _reference_index(sheet)

        self.assertEqual(stats["matched_rows"], 1)
        self.assertIn("Fortinet: FortiGate", sheet["rows"][4][ref_idx])
        self.assertIn("data-sheets", sheet["rows"][4][ref_idx])
        self.assertTrue(all(row[ref_idx] == "" for idx, row in enumerate(sheet["rows"]) if idx != 4))

    def test_logging_sheet_groups_rows_and_quotes_fortilogger_once(self):
        data = {
            "sheets": [{
                "title": "Hardware Based Logging Solution",
                "headers": ["No.", "Requirement Description", "Compliance"],
                "rows": [
                    ["1.", "Reporting", "Yes"],
                    ["2.", "Logging", "Yes"],
                    ["3.", "Must support 100GB Per day Or 10,000EPS and quote the solution accordingly.", "100GB Logs Per day Or 10,000 EPS"],
                    ["4.", "Centralized logging", "Yes"],
                    ["5.", "Must provide all type of logs including firewall logs, traffic logs, attack and audit logs.", "Yes"],
                ],
            }]
        }

        enriched, stats = inject_fortinet_references(data, CATALOG_DIR)
        sheet = enriched["sheets"][0]
        ref_idx = _reference_index(sheet)

        self.assertEqual(stats["matched_rows"], 1)
        self.assertIn("Fortinet: FortiLogger", sheet["rows"][2][ref_idx])
        self.assertTrue(all(row[ref_idx] == "" for idx, row in enumerate(sheet["rows"]) if idx != 2))


if __name__ == "__main__":
    unittest.main()
