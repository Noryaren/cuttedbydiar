"""Small platform / privilege helpers."""

from __future__ import annotations

import os
import platform
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"


def is_admin() -> bool:
    """True if the process can open raw sockets (root on Linux, admin on Windows)."""
    if IS_WINDOWS:
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def config_dir() -> Path:
    """Per-user config directory for whitelist etc."""
    if IS_WINDOWS:
        base = os.environ.get("APPDATA") or str(Path.home())
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    path = Path(base) / "cuttedbydiar"
    path.mkdir(parents=True, exist_ok=True)
    return path


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address to lowercase colon form."""
    return mac.strip().lower().replace("-", ":")


def require_admin() -> None:
    if is_admin():
        return
    if IS_WINDOWS:
        raise PermissionError(
            "cuttedbydiar needs Administrator rights. Run the terminal as Administrator."
        )
    raise PermissionError(
        "cuttedbydiar needs root (raw sockets). Try: sudo python -m cuttedbydiar ..."
    )
