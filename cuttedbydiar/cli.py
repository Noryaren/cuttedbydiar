"""cuttedbydiar CLI — LAN device controller (ARP spoofing) with whitelist."""

from __future__ import annotations

import argparse
import sys
import time

from .utils import is_admin, require_admin
from .network import BlockEngine, get_gateway, scan_devices
from .whitelist import Whitelist


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cuttedbydiar",
        description="LAN device controller: ARP scan + ARP-spoof block with whitelist.",
    )
    parser.add_argument(
        "--iface",
        default=None,
        help="Interface to use (e.g. eth0, en0, Wi-Fi). Auto-detected if omitted.",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("scan", help="ARP scan & show gateway")

    p = sub.add_parser("block", help="Block a device (needs running process)")
    p.add_argument("ip", help="Target IP, e.g. 192.168.1.20")
    p.add_argument("mac", help="Target MAC, e.g. aa:bb:cc:dd:ee:ff")

    p = sub.add_parser("unblock", help="Unblock all currently-blocked devices")
    p.add_argument("--ip", default=None, help="Unblock a specific IP")

    p = sub.add_parser("whitelist", help="Manage the whitelist")
    wsub = p.add_subparsers(dest="wcommand", metavar="SUBCOMMAND")
    wsub.add_parser("show", help="Show all whitelisted MACs")
    wa = wsub.add_parser("add", help="Add a MAC to the whitelist")
    wa.add_argument("mac", help="MAC to whitelist")
    wr = wsub.add_parser("remove", help="Remove a MAC from the whitelist")
    wr.add_argument("mac", help="MAC to remove")

    return parser


def cmd_scan(args) -> int:
    require_admin()
    wl = Whitelist()

    iface = args.iface
    if not iface:
        from .network import _local_iface

        try:
            iface, own_mac = _local_iface()
        except Exception as exc:
            print(f"error: could not determine interface: {exc}", file=sys.stderr)
            return 1
    gw_ip, gw_mac = get_gateway(iface)
    devices = scan_devices(iface)

    print(f"\n{'='*60}")
    print(f"Network info")
    print(f"  Interface : {iface}")
    print(f"  Gateway   : {gw_ip} ({gw_mac})")
    print(f"{'='*60}\n")

    for dev in devices:
        badge = ""
        if wl.is_whitelisted(dev.mac):
            badge = "  [WHITELIST]"
        print(f"  {dev.ip:<16} {dev.mac:<18} {dev.hostname:<24}{badge}")
    return 0


def cmd_block(args) -> int:
    require_admin()
    wl = Whitelist()

    gw_ip, gw_mac = get_gateway(args.iface) if args.iface else get_gateway()
    from .network import _local_iface

    iface = args.iface or _local_iface()[0]

    engine = BlockEngine(gw_ip, gw_mac, iface, wl)
    if wl.is_whitelisted(args.mac):
        print(f"error: {args.mac} is on the whitelist; remove it first.", file=sys.stderr)
        return 1

    print(f"Blocking {args.ip} ({args.mac}) via {iface} ...")
    print("Press Ctrl+C to stop.")
    engine.block(args.ip, args.mac)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        engine.stop()
        print("\nStopped.")
    return 0


def cmd_unblock(args) -> int:
    # placeholder: engine is stateless across invocations; real impl needs a daemon
    print("Unblocking all...", file=sys.stderr)
    print("NOTE: This is a one-shot placeholder. A full daemon is needed for state.", file=sys.stderr)
    return 0


def cmd_whitelist(args) -> int:
    wl = Whitelist()
    if args.wcommand == "show":
        macs = wl.all()
        if not macs:
            print("(empty)")
        else:
            for m in macs:
                print(m)
        return 0
    if args.wcommand == "add":
        wl.add(args.mac)
        print(f"Added {args.mac.lower()} to whitelist.")
        return 0
    if args.wcommand == "remove":
        wl.remove(args.mac)
        print(f"Removed {args.mac.lower()} from whitelist.")
        return 0
    return 1


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    if args.command == "block":
        return cmd_block(args)
    if args.command == "unblock":
        return cmd_unblock(args)
    if args.command == "whitelist":
        return cmd_whitelist(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())