import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

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


if __name__ == "__main__":
    unittest.main()
