#!/usr/bin/env python3
"""
D4 — Network Forensics Suite
PCAP parsing, flow reconstruction, protocol analysis, IoC extraction.
Uses scapy for packet parsing.
"""

import struct
import os
import sys
import json
import hashlib
import math
from datetime import datetime, timedelta
from collections import defaultdict, Counter

try:
    from scapy.all import (
        rdpcap, TCP, UDP, ICMP, IP, IPv6, DNS, Raw,
        ARP, Ether, DNSQR, DNSRR, ICMPv6EchoRequest,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PCAPParser:
    """Low-level PCAP file parser using struct (no scapy needed)."""

    PCAP_MAGIC = 0xa1b2c3d4
    PCAP_MAGIC_SWAPPED = 0xd4c3b2a1

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.data = None
        self.file_size = 0
        self.link_type = 0
        self.packets = []

    def load(self) -> bool:
        """Load and parse PCAP file using struct."""
        if not os.path.exists(self.pcap_path):
            print(f"[ERROR] File not found: {self.pcap_path}")
            return False
        self.file_size = os.path.getsize(self.pcap_path)
        if self.file_size < 24:
            print(f"[ERROR] File too small for PCAP header")
            return False
        with open(self.pcap_path, "rb") as f:
            self.data = f.read()
        return self._parse_pcap()

    def _parse_pcap(self) -> bool:
        """Parse PCAP global header and packets."""
        magic = struct.unpack_from("<I", self.data, 0)[0]
        if magic == self.PCAP_MAGIC:
            endian = "<"
        elif magic == self.PCAP_MAGIC_SWAPPED:
            endian = ">"
        else:
            print(f"[ERROR] Not a valid PCAP file (magic: 0x{magic:08x})")
            return False

        _, _, _, _, _, self.link_type, _ = struct.unpack_from(endian + "IHHiiII", self.data, 0)

        offset = 24
        while offset < len(self.data) - 16:
            try:
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(endian + "IIII", self.data, offset)
                offset += 16
                if incl_len > len(self.data) - offset or incl_len == 0:
                    break
                packet_data = self.data[offset:offset + incl_len]
                ts = datetime.fromtimestamp(ts_sec + ts_usec / 1_000_000)
                self.packets.append({
                    "timestamp": ts,
                    "length": orig_len,
                    "data": packet_data,
                    "raw": packet_data.hex(),
                })
                offset += incl_len
            except struct.error:
                break

        print(f"[+] Parsed {len(self.packets)} packets from {self.pcap_path}")
        return True

    def get_ethernet_frames(self) -> list:
        """Parse Ethernet frames."""
        frames = []
        for pkt in self.packets:
            if len(pkt["data"]) < 14:
                continue
            dst_mac = ":".join(f"{b:02x}" for b in pkt["data"][0:6])
            src_mac = ":".join(f"{b:02x}" for b in pkt["data"][6:12])
            eth_type = struct.unpack_from(">H", pkt["data"], 12)[0]
            frames.append({
                "timestamp": pkt["timestamp"],
                "dst_mac": dst_mac,
                "src_mac": src_mac,
                "eth_type": f"0x{eth_type:04x}",
                "length": pkt["length"],
                "data": pkt["data"][14:],
            })
        return frames

    def get_ip_packets(self) -> list:
        """Parse IP packets from Ethernet frames."""
        frames = self.get_ethernet_frames()
        packets = []
        for frame in frames:
            eth_type = int(frame["eth_type"], 16)
            if eth_type == 0x0800 and len(frame["data"]) >= 20:
                ip_data = frame["data"]
                version = (ip_data[0] >> 4) & 0xF
                if version != 4:
                    continue
                ihl = (ip_data[0] & 0xF) * 4
                protocol = ip_data[9]
                src_ip = ".".join(str(b) for b in ip_data[12:16])
                dst_ip = ".".join(str(b) for b in ip_data[16:20])
                total_len = struct.unpack_from(">H", ip_data, 2)[0]

                proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol, str(protocol))
                payload = ip_data[ihl:] if ihl < len(ip_data) else b""

                packets.append({
                    "timestamp": frame["timestamp"],
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": proto_name,
                    "protocol_num": protocol,
                    "total_length": total_len,
                    "payload": payload,
                    "payload_hex": payload[:200].hex(),
                })
            elif eth_type == 0x0806:
                if len(frame["data"]) >= 28:
                    arp_data = frame["data"]
                    op = struct.unpack_from(">H", arp_data, 6)[0]
                    sender_ip = ".".join(str(b) for b in arp_data[14:18])
                    target_ip = ".".join(str(b) for b in arp_data[24:28])
                    packets.append({
                        "timestamp": frame["timestamp"],
                        "src_ip": sender_ip,
                        "dst_ip": target_ip,
                        "protocol": "ARP",
                        "protocol_num": 0,
                        "total_length": len(frame["data"]),
                        "payload": b"",
                        "payload_hex": "",
                        "arp_op": "request" if op == 1 else "reply",
                    })

        # If no Ethernet frames found, try parsing as raw IP
        if not frames:
            packets = self._parse_raw_ip_packets()

        return packets

    def _parse_raw_ip_packets(self) -> list:
        """Parse raw IP packets (no Ethernet header)."""
        packets = []
        for pkt in self.packets:
            if len(pkt["data"]) < 20:
                continue
            ip_data = pkt["data"]
            version = (ip_data[0] >> 4) & 0xF
            if version != 4:
                continue
            ihl = (ip_data[0] & 0xF) * 4
            protocol = ip_data[9]
            src_ip = ".".join(str(b) for b in ip_data[12:16])
            dst_ip = ".".join(str(b) for b in ip_data[16:20])
            total_len = struct.unpack_from(">H", ip_data, 2)[0]

            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(protocol, str(protocol))
            payload = ip_data[ihl:] if ihl < len(ip_data) else b""

            packets.append({
                "timestamp": pkt["timestamp"],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto_name,
                "protocol_num": protocol,
                "total_length": total_len,
                "payload": payload,
                "payload_hex": payload[:200].hex(),
            })
        return packets


class FlowReconstructor:
    """Reconstruct network flows from parsed packets."""

    def __init__(self, packets: list):
        self.packets = packets
        self.flows = defaultdict(list)

    def build_flows(self) -> dict:
        """Group packets into flows by 5-tuple."""
        for pkt in self.packets:
            if pkt["protocol"] in ("TCP", "UDP"):
                key = (
                    pkt.get("src_ip", ""),
                    pkt.get("dst_ip", ""),
                    pkt["protocol"],
                    self._get_sport(pkt),
                    self._get_dport(pkt),
                )
                self.flows[key].append(pkt)

        flow_list = []
        for key, pkts in self.flows.items():
            if len(pkts) < 2:
                continue
            src_ip, dst_ip, proto, sport, dport = key
            durations = [p["timestamp"] for p in pkts]
            start = min(durations)
            end = max(durations)
            duration = (end - start).total_seconds()

            flow_list.append({
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": proto,
                "sport": sport,
                "dport": dport,
                "packets": len(pkts),
                "start_time": start.isoformat(),
                "end_time": end.isoformat(),
                "duration_s": round(duration, 3),
                "bytes": sum(p.get("total_length", 0) for p in pkts),
            })

        flow_list.sort(key=lambda x: x["start_time"])
        return {
            "total_flows": len(flow_list),
            "flows": flow_list,
        }

    def _get_sport(self, pkt: dict) -> int:
        """Extract source port from TCP/UDP payload."""
        payload = pkt.get("payload", b"")
        if len(payload) >= 2:
            return struct.unpack_from(">H", payload, 0)[0]
        return 0

    def _get_dport(self, pkt: dict) -> int:
        """Extract destination port from TCP/UDP payload."""
        payload = pkt.get("payload", b"")
        if len(payload) >= 4:
            return struct.unpack_from(">H", payload, 2)[0]
        return 0


class ProtocolAnalyzer:
    """Analyze protocols and extract protocol-specific data."""

    WELL_KNOWN_PORTS = {
        80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH",
        21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
        3389: "RDP", 445: "SMB", 139: "NetBIOS",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        5060: "SIP", 123: "NTP", 67: "DHCP-S", 68: "DHCP-C",
    }

    def __init__(self, packets: list):
        self.packets = packets
        self.protocol_stats = Counter()
        self.port_stats = defaultdict(lambda: {"count": 0, "bytes": 0})
        self.dns_queries = []
        self.http_requests = []

    def analyze(self) -> dict:
        """Run protocol analysis on packets."""
        for pkt in self.packets:
            proto = pkt.get("protocol", "unknown")
            self.protocol_stats[proto] += 1

            if proto in ("TCP", "UDP"):
                payload = pkt.get("payload", b"")
                sport = self._extract_sport(payload)
                dport = self._extract_dport(payload)

                for port in [sport, dport]:
                    if port > 0:
                        self.port_stats[port]["count"] += 1
                        self.port_stats[port]["bytes"] += pkt.get("total_length", 0)

                if dport == 53:
                    self._parse_dns_query(pkt, payload)
                elif sport == 53:
                    self._parse_dns_response(pkt, payload)

                if dport in (80, 8080) and len(payload) > 20:
                    self._parse_http(pkt, payload)

        return {
            "protocol_distribution": dict(self.protocol_stats),
            "top_ports": self._top_ports(20),
            "dns_queries": self.dns_queries[:50],
            "http_requests": self.http_requests[:30],
        }

    def _extract_sport(self, payload: bytes) -> int:
        if len(payload) >= 2:
            return struct.unpack_from(">H", payload, 0)[0]
        return 0

    def _extract_dport(self, payload: bytes) -> int:
        if len(payload) >= 4:
            return struct.unpack_from(">H", payload, 2)[0]
        return 0

    def _parse_dns_query(self, pkt: dict, payload: bytes):
        """Parse DNS query packet."""
        if len(payload) < 12:
            return
        qdcount = struct.unpack_from(">H", payload, 4)[0]
        if qdcount == 0:
            return
        offset = 12
        name = self._read_dns_name(payload, offset)
        if name and offset + len(name) < len(payload):
            qtype = struct.unpack_from(">H", payload, offset + len(name.split(".")[-1]) + 2)[0] if offset + len(name) + 4 <= len(payload) else 0
            self.dns_queries.append({
                "timestamp": pkt["timestamp"].isoformat(),
                "src_ip": pkt["src_ip"],
                "query": name,
                "type": self._dns_type_name(qtype),
            })

    def _parse_dns_response(self, pkt: dict, payload: bytes):
        """Parse DNS response packet."""
        if len(payload) < 12:
            return
        ancount = struct.unpack_from(">H", payload, 6)[0]
        if ancount > 0 and len(payload) > 12:
            offset = 12
            name = self._read_dns_name(payload, offset)
            self.dns_queries.append({
                "timestamp": pkt["timestamp"].isoformat(),
                "src_ip": pkt["src_ip"],
                "response": name,
                "answers": ancount,
            })

    def _read_dns_name(self, data: bytes, offset: int) -> str:
        """Read a DNS name from packet data."""
        parts = []
        jumps = 0
        while offset < len(data) and jumps < 20:
            length = data[offset]
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:
                break
            offset += 1
            if offset + length > len(data):
                break
            parts.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length
            jumps += 1
        return ".".join(parts)

    def _dns_type_name(self, qtype: int) -> str:
        return {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}.get(qtype, str(qtype))

    def _parse_http(self, pkt: dict, payload: bytes):
        """Parse HTTP request from TCP payload."""
        try:
            text = payload.decode("ascii", errors="replace")
            lines = text.split("\r\n")
            if lines and " " in lines[0]:
                parts = lines[0].split(" ", 2)
                if len(parts) >= 2:
                    method = parts[0]
                    uri = parts[1]
                    host = ""
                    for line in lines[1:]:
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                            break
                    self.http_requests.append({
                        "timestamp": pkt["timestamp"].isoformat(),
                        "src_ip": pkt["src_ip"],
                        "method": method,
                        "uri": uri,
                        "host": host,
                    })
        except Exception:
            pass

    def _top_ports(self, n: int) -> list:
        sorted_ports = sorted(self.port_stats.items(), key=lambda x: x[1]["count"], reverse=True)
        result = []
        for port, stats in sorted_ports[:n]:
            result.append({
                "port": port,
                "service": self.WELL_KNOWN_PORTS.get(port, "unknown"),
                "count": stats["count"],
                "bytes": stats["bytes"],
            })
        return result


class IoCExtractor:
    """Extract Indicators of Compromise from network traffic."""

    SUSPICIOUS_DOMAINS = [
        "malware", "phish", "exploit", "payload", "cnc",
        "command", "control", "exfil", "backdoor", "trojan",
    ]

    SUSPICIOUS_IPS = [
        "0.0.0.0", "255.255.255.255",
    ]

    def __init__(self, packets: list, dns_queries: list):
        self.packets = packets
        self.dns_queries = dns_queries
        self.iocs = []

    def extract(self) -> dict:
        """Extract all IoCs."""
        self._check_dns_suspicious()
        self._check_suspicious_ips()
        self._check_payload_patterns()
        self._check_port_scanning()
        self._check_data_exfiltration()

        unique_iocs = []
        seen = set()
        for ioc in self.iocs:
            key = (ioc["type"], ioc["value"])
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return {
            "total_iocs": len(unique_iocs),
            "iocs": unique_iocs,
        }

    def _check_dns_suspicious(self):
        """Check DNS queries for suspicious domains."""
        for q in self.dns_queries:
            query_name = q.get("query", "").lower()
            for pattern in self.SUSPICIOUS_DOMAINS:
                if pattern in query_name:
                    self.iocs.append({
                        "type": "suspicious_domain",
                        "value": query_name,
                        "severity": "high",
                        "detail": f"Contains suspicious keyword: {pattern}",
                        "timestamp": q.get("timestamp"),
                    })
                    break

    def _check_suspicious_ips(self):
        """Check for known suspicious IP patterns."""
        ip_counter = Counter()
        for pkt in self.packets:
            src = pkt.get("src_ip", "")
            dst = pkt.get("dst_ip", "")
            if src:
                ip_counter[src] += 1
            if dst:
                ip_counter[dst] += 1

        for ip, count in ip_counter.most_common(50):
            if ip in self.SUSPICIOUS_IPS:
                self.iocs.append({
                    "type": "suspicious_ip",
                    "value": ip,
                    "severity": "medium",
                    "detail": f"Broadcast/null address with {count} packets",
                })

    def _check_payload_patterns(self):
        """Check packet payloads for suspicious patterns."""
        patterns = [
            (b"cmd.exe", "Windows command execution"),
            (b"/bin/sh", "Shell execution"),
            (b"mimikatz", "Credential dumping tool"),
            (b"powershell", "PowerShell execution"),
            (b"base64", "Base64 encoding"),
            (b"eval(", "Code evaluation"),
            (b"UNION SELECT", "SQL injection"),
            (b"<script>", "XSS payload"),
            (b"../", "Path traversal"),
        ]
        for pkt in self.packets:
            payload = pkt.get("payload", b"")
            if not payload:
                continue
            for pattern, desc in patterns:
                if pattern in payload:
                    self.iocs.append({
                        "type": "suspicious_payload",
                        "value": pattern.decode("ascii", errors="replace"),
                        "severity": "high",
                        "detail": desc,
                        "src_ip": pkt.get("src_ip", ""),
                        "dst_ip": pkt.get("dst_ip", ""),
                        "timestamp": pkt.get("timestamp", "").isoformat() if hasattr(pkt.get("timestamp"), "isoformat") else "",
                    })

    def _check_port_scanning(self):
        """Detect potential port scanning."""
        dst_ports = defaultdict(set)
        for pkt in self.packets:
            payload = pkt.get("payload", b"")
            if len(payload) >= 4:
                dport = struct.unpack_from(">H", payload, 2)[0]
                dst_ports[pkt.get("src_ip", "")].add(dport)

        for src_ip, ports in dst_ports.items():
            if len(ports) > 20:
                self.iocs.append({
                    "type": "port_scan",
                    "value": src_ip,
                    "severity": "high",
                    "detail": f"Scanned {len(ports)} unique ports",
                })

    def _check_data_exfiltration(self):
        """Check for large data transfers that could indicate exfiltration."""
        flow_bytes = defaultdict(int)
        for pkt in self.packets:
            key = (pkt.get("src_ip", ""), pkt.get("dst_ip", ""))
            flow_bytes[key] += pkt.get("total_length", 0)

        threshold = 10 * 1024 * 1024  # 10MB
        for (src, dst), total in flow_bytes.items():
            if total > threshold:
                self.iocs.append({
                    "type": "possible_exfiltration",
                    "value": f"{src} -> {dst}",
                    "severity": "medium",
                    "detail": f"Large transfer: {total:,} bytes ({total/1024/1024:.1f} MB)",
                })


class NetworkForensics:
    """Main network forensics engine combining all components."""

    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.parser = PCAPParser(pcap_path)
        self.packets = []
        self.flows = {}
        self.protocol_analysis = {}
        self.iocs = {}
        self.scapy_packets = None

    def load(self) -> bool:
        """Load and parse the PCAP file."""
        if not self.parser.load():
            return False
        self.packets = self.parser.get_ip_packets()
        print(f"[+] Extracted {len(self.packets)} IP packets")
        return True

    def load_scapy(self) -> bool:
        """Load PCAP using scapy for deeper analysis."""
        if not SCAPY_AVAILABLE:
            print("[!] Scapy not available, using raw parser only")
            return False
        try:
            self.scapy_packets = rdpcap(self.pcap_path)
            print(f"[+] Scapy loaded {len(self.scapy_packets)} packets")
            return True
        except Exception as e:
            print(f"[!] Scapy error: {e}")
            return False

    def full_analysis(self) -> dict:
        """Run complete network forensics analysis."""
        print("[*] Running network forensics analysis...")

        print("[*] Reconstructing flows...")
        flow_reconstructor = FlowReconstructor(self.packets)
        self.flows = flow_reconstructor.build_flows()

        print("[*] Analyzing protocols...")
        proto_analyzer = ProtocolAnalyzer(self.packets)
        self.protocol_analysis = proto_analyzer.analyze()

        print("[*] Extracting IoCs...")
        ioc_extractor = IoCExtractor(self.packets, self.protocol_analysis.get("dns_queries", []))
        self.iocs = ioc_extractor.extract()

        print("[*] Building summary...")
        result = self._build_summary()
        self._print_summary(result)
        return result

    def _build_summary(self) -> dict:
        """Build analysis summary."""
        ip_counter = Counter()
        for pkt in self.packets:
            src = pkt.get("src_ip", "")
            dst = pkt.get("dst_ip", "")
            if src:
                ip_counter[src] += 1
            if dst:
                ip_counter[dst] += 1

        return {
            "file": self.pcap_path,
            "total_packets": len(self.packets),
            "flows": self.flows,
            "protocol_analysis": self.protocol_analysis,
            "iocs": self.iocs,
            "top_talkers": ip_counter.most_common(20),
            "timestamp_range": self._get_time_range(),
        }

    def _get_time_range(self) -> dict:
        """Get the time range of captured packets."""
        if not self.packets:
            return {}
        timestamps = [p["timestamp"] for p in self.packets if "timestamp" in p]
        if not timestamps:
            return {}
        return {
            "start": min(timestamps).isoformat(),
            "end": max(timestamps).isoformat(),
            "duration_s": (max(timestamps) - min(timestamps)).total_seconds(),
        }

    def _print_summary(self, result: dict):
        """Print analysis summary."""
        print("\n" + "=" * 60)
        print("  D4 — Network Forensics Suite — Analysis Report")
        print("=" * 60)
        print(f"  File: {result['file']}")
        print(f"  Total Packets: {result['total_packets']}")
        print(f"  Total Flows: {result['flows']['total_flows']}")

        proto_dist = result["protocol_analysis"].get("protocol_distribution", {})
        if proto_dist:
            print("\n  --- Protocol Distribution ---")
            for proto, count in proto_dist.items():
                print(f"    {proto:>10}: {count}")

        top_ports = result["protocol_analysis"].get("top_ports", [])
        if top_ports:
            print("\n  --- Top Ports ---")
            for p in top_ports[:10]:
                print(f"    {p['port']:>5} ({p['service']:>12}): {p['count']} packets, {p['bytes']:,} bytes")

        dns = result["protocol_analysis"].get("dns_queries", [])
        if dns:
            print(f"\n  --- DNS Queries ({len(dns)}) ---")
            for d in dns[:10]:
                q = d.get("query") or d.get("response", "")
                print(f"    {q}")

        http = result["protocol_analysis"].get("http_requests", [])
        if http:
            print(f"\n  --- HTTP Requests ({len(http)}) ---")
            for h in http[:10]:
                print(f"    {h['method']} {h['uri']} -> {h['host']}")

        iocs = result["iocs"]
        if iocs["total_iocs"] > 0:
            print(f"\n  --- IoCs ({iocs['total_iocs']}) ---")
            for ioc in iocs["iocs"][:15]:
                print(f"    [{ioc['severity'].upper()}] {ioc['type']}: {ioc['value']}")
                if ioc.get("detail"):
                    print(f"             {ioc['detail']}")

        if result["top_talkers"]:
            print("\n  --- Top Talkers ---")
            for ip, count in result["top_talkers"][:10]:
                print(f"    {ip:>20}: {count} packets")

        print("=" * 60)

    def export_json(self, output_path: str):
        """Export analysis to JSON."""
        result = self.full_analysis()
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"[+] Results exported to {output_path}")

    def generate_test_pcap(self, output_path: str):
        """Generate a synthetic test PCAP for testing."""
        print(f"[*] Generating test PCAP file...")
        packets = []

        base_time = datetime(2024, 1, 15, 10, 0, 0)

        # DNS queries
        for i, domain in enumerate(["google.com", "malware-cnc.evil.com", "github.com", "phishing-site.net"]):
            ts = base_time + timedelta(seconds=i)
            dns_q = self._make_dns_packet(domain, ts, "192.168.1." + str(100 + i))
            packets.append(dns_q)

        # HTTP requests
        for i, (method, uri, host) in enumerate([
            ("GET", "/index.html", "google.com"),
            ("POST", "/login", "phishing-site.net"),
            ("GET", "/cmd.exe", "malware-cnc.evil.com"),
        ]):
            ts = base_time + timedelta(seconds=10 + i)
            http_pkt = self._make_http_packet(method, uri, host, ts, "192.168.1.100")
            packets.append(http_pkt)

        # TCP SYN scan pattern (port scanning)
        scan_ts = base_time + timedelta(seconds=30)
        for port in [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443,
                      135, 139, 143, 993, 995, 1433, 3306, 3389, 5432, 5900]:
            pkt = self._make_tcp_packet("10.0.0.50", "192.168.1.10", port, scan_ts, b"")
            packets.append(pkt)
            scan_ts += timedelta(milliseconds=5)

        # Large data transfer (exfiltration simulation)
        exfil_ts = base_time + timedelta(seconds=60)
        payload = b"\x00" * 1500
        for i in range(100):
            pkt = self._make_tcp_packet("192.168.1.100", "185.100.87.200", 443, exfil_ts, payload)
            packets.append(pkt)
            exfil_ts += timedelta(milliseconds=10)

        # Suspicious payload
        sus_ts = base_time + timedelta(seconds=100)
        sus_payload = b"cmd.exe /c whoami && net user"
        pkt = self._make_tcp_packet("192.168.1.100", "10.0.0.5", 4444, sus_ts, sus_payload)
        packets.append(pkt)

        self._write_pcap(packets, output_path)
        print(f"[+] Test PCAP written: {output_path}")
        return output_path

    def _make_dns_packet(self, domain: str, ts: datetime, src_ip: str) -> dict:
        """Create a synthetic DNS query packet."""
        query = self._encode_dns_query(domain)
        ip_payload = self._make_ip_header(src_ip, "8.8.8.8", 17, query)
        return {
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": "8.8.8.8",
            "protocol": "UDP",
            "protocol_num": 17,
            "total_length": len(ip_payload),
            "payload": query,
            "payload_hex": query.hex(),
        }

    def _make_http_packet(self, method: str, uri: str, host: str, ts: datetime, src_ip: str) -> dict:
        """Create a synthetic HTTP request packet."""
        http = f"{method} {uri} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        payload = http.encode("ascii")
        ip_payload = self._make_ip_header(src_ip, "93.184.216.34", 6, payload)
        return {
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": "93.184.216.34",
            "protocol": "TCP",
            "protocol_num": 6,
            "total_length": len(ip_payload),
            "payload": payload,
            "payload_hex": payload.hex(),
        }

    def _make_tcp_packet(self, src_ip: str, dst_ip: str, dport: int, ts: datetime, payload: bytes) -> dict:
        """Create a synthetic TCP packet."""
        sport = 40000 + (hash((src_ip, dst_ip, dport)) % 10000)
        tcp_header = struct.pack(">HH", sport, dport) + b"\x00" * 16
        return {
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "TCP",
            "protocol_num": 6,
            "total_length": 20 + len(payload),
            "payload": tcp_header + payload,
            "payload_hex": (tcp_header + payload).hex(),
        }

    def _make_ip_header(self, src_ip: str, dst_ip: str, protocol: int, payload: bytes) -> bytes:
        """Create a minimal IP header."""
        src = bytes(int(x) for x in src_ip.split("."))
        dst = bytes(int(x) for x in dst_ip.split("."))
        total_len = 20 + len(payload)
        ip = struct.pack(">BBHHHBB", 0x45, 0, total_len, 0, 0, 64, protocol) + b"\x00\x00" + src + dst
        return ip + payload

    def _encode_dns_query(self, domain: str) -> bytes:
        """Encode a domain name into DNS query format."""
        parts = domain.split(".")
        query = b""
        for part in parts:
            query += bytes([len(part)]) + part.encode("ascii")
        query += b"\x00"
        query += struct.pack(">HH", 1, 1)  # Type A, Class IN
        return query

    def _write_pcap(self, packets: list, output_path: str):
        """Write packets to a PCAP file."""
        with open(output_path, "wb") as f:
            # Global header
            header = struct.pack("<IHHiIII",
                                 0xa1b2c3d4,  # magic
                                 2, 4,  # version
                                 0,  # timezone
                                 0,  # sigfigs
                                 65535,  # snaplen
                                 1)  # link type = Ethernet
            f.write(header)

            for pkt in packets:
                ts = pkt["timestamp"]
                ts_sec = int(ts.timestamp())
                ts_usec = int((ts.timestamp() - ts_sec) * 1_000_000)
                pkt_data = pkt["data"] if "data" in pkt else self._raw_packet(pkt)
                pkt_len = len(pkt_data)

                pcap_pkt = struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)
                f.write(pcap_pkt)
                f.write(pkt_data)

    def _raw_packet(self, pkt: dict) -> bytes:
        """Create raw packet bytes from packet dict with Ethernet header."""
        src_mac = b"\x00" * 6
        dst_mac = b"\x00" * 6
        eth_type = struct.pack(">H", 0x0800)  # IPv4

        src_ip = bytes(int(x) for x in pkt["src_ip"].split("."))
        dst_ip = bytes(int(x) for x in pkt["dst_ip"].split("."))

        protocol = pkt.get("protocol_num", 6)
        if protocol == 17:
            total_len = 20 + 8 + len(pkt.get("payload", b""))
        else:
            total_len = 20 + len(pkt.get("payload", b""))

        ip_header = struct.pack(">BBHHHBB", 0x45, 0, total_len, 0, 0, 64, protocol)
        ip_header += b"\x00\x00"
        ip_header += src_ip + dst_ip

        return dst_mac + src_mac + eth_type + ip_header + pkt.get("payload", b"")


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="D4 — Network Forensics Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: python3 net_forensics.py --pcap capture.pcap --output report.json"
    )
    parser.add_argument("--pcap", "-p", help="Path to PCAP file")
    parser.add_argument("--output", "-o", help="Export results to JSON file")
    parser.add_argument("--generate-test", "-g", help="Generate a test PCAP", metavar="PATH")
    parser.add_argument("--flows", "-f", action="store_true", help="Show flows only")
    parser.add_argument("--dns", action="store_true", help="Show DNS queries only")
    parser.add_argument("--iocs", action="store_true", help="Extract IoCs only")
    args = parser.parse_args()

    if args.generate_test:
        forensics = NetworkForensics(args.generate_test)
        forensics.generate_test_pcap(args.generate_test)
        forensics.load()
        forensics.full_analysis()
        return

    if not args.pcap:
        parser.print_help()
        sys.exit(1)

    forensics = NetworkForensics(args.pcap)

    if args.flows:
        forensics.load()
        flows = FlowReconstructor(forensics.packets).build_flows()
        for flow in flows["flows"]:
            print(f"  {flow['src_ip']:>15} -> {flow['dst_ip']:<15} {flow['protocol']:>4} {flow['dport']:>5} | {flow['packets']} pkts, {flow['bytes']:,} bytes")
        return

    if args.dns:
        forensics.load()
        proto = ProtocolAnalyzer(forensics.packets)
        result = proto.analyze()
        for q in result["dns_queries"]:
            print(f"  {q['timestamp']} {q.get('query', '') or q.get('response', '')} ({q.get('type', '')})")
        return

    if args.iocs:
        forensics.load()
        proto = ProtocolAnalyzer(forensics.packets)
        result = proto.analyze()
        ioc_extractor = IoCExtractor(forensics.packets, result["dns_queries"])
        iocs = ioc_extractor.extract()
        for ioc in iocs["iocs"]:
            print(f"  [{ioc['severity'].upper():>6}] {ioc['type']}: {ioc['value']}")
            if ioc.get("detail"):
                print(f"          {ioc['detail']}")
        return

    if args.output:
        forensics.export_json(args.output)
    else:
        forensics.full_analysis()


if __name__ == "__main__":
    main()
