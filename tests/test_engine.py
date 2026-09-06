#!/usr/bin/env python3
import os
import sys
import json
import shutil
import subprocess
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "firmware"))
from net_forensics import (
    PCAPParser, FlowReconstructor, ProtocolAnalyzer, IoCExtractor, NetworkForensics,
)

HERE = os.path.dirname(__file__)
FIXTURE = os.path.join(HERE, "fixtures", "network_traffic.pcap")


class TestPCAPParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = PCAPParser(FIXTURE)
        cls.parser.load()

    def test_parses_packets(self):
        self.assertGreaterEqual(len(self.parser.packets), 120)

    def test_link_type_ethernet(self):
        self.assertEqual(self.parser.link_type, 1)

    def test_magic(self):
        self.assertEqual(self.parser.data[:4], b"\xd4\xc3\xb2\xa1")

    def test_ether_frames(self):
        frames = self.parser.get_ethernet_frames()
        self.assertTrue(all(f["eth_type"] == "0x0800" for f in frames))


class TestIPExtraction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = PCAPParser(FIXTURE)
        cls.parser.load()
        cls.ip = cls.parser.get_ip_packets()

    def test_ip_packets_extracted(self):
        self.assertGreaterEqual(len(self.ip), 120)

    def test_protocols_present(self):
        protos = {p["protocol"] for p in self.ip}
        self.assertIn("TCP", protos)
        self.assertIn("UDP", protos)

    def test_dns_destination_port(self):
        udp = [p for p in self.ip if p["protocol"] == "UDP"]
        self.assertTrue(len(udp) >= 4)
        for p in udp:
            dport = struct_dport(p["payload"])
            self.assertEqual(dport, 53)


def struct_dport(payload):
    import struct
    return struct.unpack_from(">H", payload, 2)[0] if len(payload) >= 4 else 0


class TestFlows(unittest.TestCase):
    def setUp(self):
        parser = PCAPParser(FIXTURE)
        parser.load()
        self.ip = parser.get_ip_packets()

    def test_flows_reconstructed(self):
        fr = FlowReconstructor(self.ip)
        flows = fr.build_flows()
        self.assertGreaterEqual(flows["total_flows"], 2)

    def test_flow_has_ports(self):
        fr = FlowReconstructor(self.ip)
        flows = fr.build_flows()
        dports = {f["dport"] for f in flows["flows"]}
        self.assertGreater(len(dports), 2)

    def test_dns_port_seen_in_analysis(self):
        proto = ProtocolAnalyzer(self.ip).analyze()
        port_entries = {p["port"] for p in proto["top_ports"]}
        self.assertIn(53, port_entries)


class TestProtocolAnalysis(unittest.TestCase):
    def setUp(self):
        parser = PCAPParser(FIXTURE)
        parser.load()
        self.proto = ProtocolAnalyzer(parser.get_ip_packets()).analyze()

    def test_dns_queries_found(self):
        queries = [d.get("query", "") for d in self.proto["dns_queries"]]
        self.assertIn("google.com", queries)
        self.assertIn("malware-cnc.evil.com", queries)

    def test_http_requests_found(self):
        reqs = self.proto["http_requests"]
        methods = {r["method"] for r in reqs}
        self.assertIn("GET", methods)
        self.assertIn("POST", methods)
        self.assertTrue(any("/cmd.exe" in r["uri"] for r in reqs))


class TestIoC(unittest.TestCase):
    def setUp(self):
        parser = PCAPParser(FIXTURE)
        parser.load()
        self.ip = parser.get_ip_packets()
        proto = ProtocolAnalyzer(self.ip).analyze()
        self.iocs = IoCExtractor(self.ip, proto["dns_queries"]).extract()

    def test_suspicious_domain_detected(self):
        values = [i["value"] for i in self.iocs["iocs"] if i["type"] == "suspicious_domain"]
        self.assertIn("malware-cnc.evil.com", values)

    def test_suspicious_payload_detected(self):
        values = [i["value"] for i in self.iocs["iocs"] if i["type"] == "suspicious_payload"]
        self.assertIn("cmd.exe", values)

    def test_ioc_count(self):
        self.assertGreaterEqual(self.iocs["total_iocs"], 2)


class TestFullAnalysis(unittest.TestCase):
    def setUp(self):
        self.nf = NetworkForensics(FIXTURE)
        self.nf.load()

    def test_report_structure(self):
        r = self.nf.full_analysis()
        self.assertIn("total_packets", r)
        self.assertIn("flows", r)
        self.assertIn("iocs", r)
        self.assertGreaterEqual(r["total_packets"], 120)


class TestCLIDemo(unittest.TestCase):
    def test_demo_exit_zero_and_report(self):
        repo = os.path.dirname(HERE)
        proc = subprocess.run([sys.executable, "cli.py", "--demo"],
                              cwd=repo, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = os.path.join(repo, "reports", "d4_report.json")
        self.assertTrue(os.path.isfile(report))
        with open(report) as f:
            data = json.load(f)
        self.assertGreaterEqual(len(data["protocol_analysis"]["dns_queries"]), 4)
        self.assertGreaterEqual(data["iocs"]["total_iocs"], 2)


class TestFixtureRegenerable(unittest.TestCase):
    def test_fixture_regenerates_identical(self):
        with open(FIXTURE, "rb") as f:
            before = f.read()
        tmp = tempfile.mkdtemp()
        try:
            orig_path = os.path.join(tmp, "network_traffic.pcap")
            nf = NetworkForensics(orig_path)
            nf.generate_test_pcap(orig_path)
            with open(orig_path, "rb") as f:
                regen = f.read()
        finally:
            shutil.rmtree(tmp)
        self.assertEqual(before[:4], regen[:4])
        self.assertEqual(len(before), len(regen))


if __name__ == "__main__":
    unittest.main()
