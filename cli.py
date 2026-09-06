#!/usr/bin/env python3
"""CLI entry point for D4 Network Forensics Suite."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "firmware"))
from net_forensics import main

if __name__ == "__main__":
    main()
