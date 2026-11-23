#!/usr/bin/env python3
"""cuttedbydiar — entry point.

Usage:
    python -m cuttedbydiar.cli [--iface IFACE] <command>
    python -m cuttedbydiar.gui     (GTK 3 desktop GUI)

Commands:
    scan                              ARP scan + gateway detection
    block <ip> <mac>                  Block a device (runs until Ctrl+C)
    unblock [--ip <ip>]               Unblock a specific IP
    whitelist show|add|remove [mac]   Manage whitelist
"""

from __future__ import annotations

from . import cli

if __name__ == "__main__":
    raise SystemExit(cli.main())