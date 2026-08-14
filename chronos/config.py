"""Configuration handling.

The default config is kept in code so the tool works out of the box; a
`--config` TOML file can override any section.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:  # pragma: no cover
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

DEFAULT_TIMEOUT = 20.0
DEFAULT_IO_CAPTURE = True
MAX_PATH_LEN = 4096
MAX_IO_PREVIEW = 64

# Sinkhole defaults. Ports >1024 so the tool runs as a normal user; bind 53/80
# only if running as root (loopback-only anyway).
SINKHOLE_DNS_PORT = 5353
SINKHOLE_HTTP_PORT = 8080
SINKHOLE_HTTP_PREVIEW = 256
SINKHOLE_RESOLVE_IP = "127.0.0.1"

# Linux paths commonly abused for persistence / autostart.
PERSISTENCE_PATHS = [
    ".config/autostart",
    ".bashrc",
    ".bash_profile",
    ".profile",
    ".zshrc",
    ".ssh/authorized_keys",
    "/etc/cron.d",
    "/etc/crontab",
    "/etc/systemd/system",
    "/etc/rc.local",
    "/etc/profile.d",
    "/etc/xdg/autostart",
]

# Read patterns typical of sandbox / debugger detection.
ANTI_DEBUG_READS = ["/proc/self/status", "/proc/self/stat", "/proc/self/wchan"]


@dataclass(slots=True)
class Config:
    timeout: float = DEFAULT_TIMEOUT
    capture_io: bool = DEFAULT_IO_CAPTURE
    io_preview: int = MAX_IO_PREVIEW
    persistence_paths: list[str] = field(default_factory=lambda: list(PERSISTENCE_PATHS))
    anti_debug_reads: list[str] = field(default_factory=lambda: list(ANTI_DEBUG_READS))
    # Beaconing: N+ connections to the same host within the window = C2 signal.
    beacon_min: int = 3
    beacon_window: float = 10.0
    # Memory: flag RWX anonymous regions (potential injected/obfuscated code).
    rwx_anon: bool = True
    # Loopback sinkhole: intercept DNS/HTTP so C2 traffic stays on the host.
    sinkhole_enabled: bool = False
    sinkhole_dns_port: int = SINKHOLE_DNS_PORT
    sinkhole_http_port: int = SINKHOLE_HTTP_PORT
    sinkhole_http_preview: int = SINKHOLE_HTTP_PREVIEW
    sinkhole_resolve_ip: str = SINKHOLE_RESOLVE_IP

    @classmethod
    def default(cls) -> Config:
        return cls()

    @classmethod
    def load(cls, path: str | None = None) -> Config:
        cfg = cls.default()
        if not path:
            return cfg
        data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
        for key in (
            "timeout",
            "capture_io",
            "io_preview",
            "beacon_min",
            "beacon_window",
            "rwx_anon",
            "sinkhole_enabled",
            "sinkhole_dns_port",
            "sinkhole_http_port",
            "sinkhole_http_preview",
            "sinkhole_resolve_ip",
        ):
            if key in data:
                setattr(cfg, key, data[key])
        if "persistence_paths" in data:
            cfg.persistence_paths = list(data["persistence_paths"])
        if "anti_debug_reads" in data:
            cfg.anti_debug_reads = list(data["anti_debug_reads"])
        return cfg


def _platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    return "unknown"


def default_runtime(platform: str | None = None) -> str:
    plat = platform or _platform()
    if plat == "linux":
        return "linux-ptrace"
    if plat == "windows":
        return "windows-frida"
    return "simulated"


def expand_user(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))
