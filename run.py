#!/usr/bin/env python3
"""cuttedbydiar — entry point.

Usage:
    python -m cuttedbydiar.cli [--iface IFACE] <command>
    python -m cuttedbydiar.gui    (GTK 3 desktop GUI)

Commands:
    scan                       ARP scan + gateway detection
    block <ip> <mac>           Block a device (runs until Ctrl+C)
    unblock --ip <ip>          Unblock a specific IP
    whitelist show|add|remove  Manage whitelist
"""

from __future__ import annotations

import sys
from cuttedbydiar import cli, gui

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "gui":
        raise SystemExit(gui.main())
    raise SystemExit(cli.main())