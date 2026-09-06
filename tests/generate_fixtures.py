#!/usr/bin/env python3
"""Regenerate the D4 network-forensics PCAP fixture using the engine's packet builder.

Produces a genuine PCAP (Ethernet + IPv4 + TCP/UDP) committed under tests/fixtures/
so tests and the CLI demo are reproducible without a network or third-party library.
"""
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "firmware"))
from net_forensics import NetworkForensics

FIXTURE = os.path.join(HERE, "fixtures", "network_traffic.pcap")


def main():
    os.makedirs(os.path.dirname(FIXTURE), exist_ok=True)
    nf = NetworkForensics(FIXTURE)
    nf.generate_test_pcap(FIXTURE)


if __name__ == "__main__":
    main()
