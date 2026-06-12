#!/usr/bin/env python3
"""edo — CTF infrastructure orchestrator entrypoint.

Bridges WireGuard and Docker so a single operator can deploy isolated,
per-challenge containers reachable only over the VPN.

Run with root privileges (iptables and WireGuard cannot be touched otherwise).
"""
from __future__ import annotations

import sys

from src.cli import main


if __name__ == "__main__":
    sys.exit(main())
