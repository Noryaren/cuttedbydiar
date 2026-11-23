"""Whitelist persistence.

A whitelist entry protects a device: it is never targeted by the block engine,
and if used as a defender it is re-announced as trusted on the network.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Iterable

from .utils import config_dir, normalize_mac


class Whitelist:
    """Thread-safe whitelist stored as JSON on disk."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (config_dir() / "whitelist.json")
        # RLock: add()/remove() take the lock and then call save(), which locks too.
        self._lock = threading.RLock()
        self._macs: set[str] = set()
        self.load()

    # -- persistence -------------------------------------------------------
    def load(self) -> None:
        with self._lock:
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self._macs = {normalize_mac(m) for m in data.get("macs", [])}
            except (FileNotFoundError, json.JSONDecodeError, OSError):
                self._macs = set()

    def save(self) -> None:
        with self._lock:
            payload = {"macs": sorted(self._macs)}
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(self.path)

    # -- queries -----------------------------------------------------------
    def is_whitelisted(self, mac: str) -> bool:
        with self._lock:
            return normalize_mac(mac) in self._macs

    def all(self) -> list[str]:
        with self._lock:
            return sorted(self._macs)

    # -- mutations ---------------------------------------------------------
    def add(self, mac: str) -> None:
        with self._lock:
            self._macs.add(normalize_mac(mac))
        self.save()

    def remove(self, mac: str) -> None:
        with self._lock:
            self._macs.discard(normalize_mac(mac))
        self.save()

    def update(self, macs: Iterable[str]) -> None:
        with self._lock:
            self._macs = {normalize_mac(m) for m in macs}
        self.save()
