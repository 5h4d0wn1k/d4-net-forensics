# D4 — Network Forensics Suite

PCAP parsing, flow reconstruction, protocol analysis, IoC extraction.

## Overview

This project implements a network forensics analysis suite that:
- Parses PCAP files using both raw struct parsing and scapy
- Reconstructs network flows from packet captures
- Analyzes protocols (TCP, UDP, DNS, HTTP, ARP)
- Extracts Indicators of Compromise (IoCs)
- Detects port scanning and data exfiltration
- Identifies suspicious DNS queries and payloads

## Features

- **Dual parsing**: Raw struct-based PCAP parser + scapy for deep analysis
- **Flow reconstruction**: 5-tuple flow grouping and analysis
- **Protocol analysis**: TCP, UDP, DNS, HTTP, ARP parsing
- **IoC extraction**: DNS, IP, payload, and behavioral IoCs
- **Port scan detection**: Identify scanning patterns
- **Exfiltration detection**: Large transfer identification
- **Test mode**: Generate synthetic PCAP files with attack patterns

## Installation

```bash
pip install scapy
```

## Usage

```bash
# Full analysis
python3 net_forensics.py --pcap capture.pcap

# Generate test PCAP and analyze
python3 net_forensics.py --generate-test test_capture.pcap

# Show flows only
python3 net_forensics.py --pcap capture.pcap --flows

# Show DNS queries only
python3 net_forensics.py --pcap capture.pcap --dns

# Extract IoCs only
python3 net_forensics.py --pcap capture.pcap --iocs

# Export to JSON
python3 net_forensics.py --pcap capture.pcap --output report.json
```

## Example Output

```
============================================================
  D4 — Network Forensics Suite — Analysis Report
============================================================
  File: capture.pcap
  Total Packets: 150
  Total Flows: 12

  --- Protocol Distribution ---
           TCP: 120
           UDP: 25
           ARP: 5

  --- Top Ports ---
       53 (         DNS): 25 packets, 2,500 bytes
      80 (         HTTP): 30 packets, 15,000 bytes
     443 (        HTTPS): 20 packets, 10,000 bytes

  --- IoCs (3) ---
    [HIGH] suspicious_domain: malware-cnc.evil.com
    [HIGH] port_scan: 10.0.0.50
             Scanned 20 unique ports
    [MEDIUM] possible_exfiltration: 192.168.1.100 -> 185.100.87.200
             Large transfer: 150,000 bytes (0.1 MB)

  --- Top Talkers ---
         192.168.1.100: 120 packets
            10.0.0.50: 30 packets
============================================================
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Network data may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
