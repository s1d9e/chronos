"""Runtime selection."""

from __future__ import annotations

from chronos import config as cfg

from .base import Runtime, RuntimeResult
from .linux_ptrace import LinuxPTraceRuntime
from .simulated import SimulatedRuntime


def get_runtime(name: str | None = None) -> Runtime:
    chosen = name or cfg.default_runtime()
    if chosen == "linux-ptrace":
        return LinuxPTraceRuntime()
    if chosen == "simulated":
        return SimulatedRuntime()
    if chosen == "windows-frida":
        from .windows_frida import WindowsFridaRuntime

        return WindowsFridaRuntime()
    raise ValueError(f"unknown runtime: {chosen} (try linux-ptrace, simulated, windows-frida)")


def list_runtimes() -> list[str]:
    return ["linux-ptrace", "simulated", "windows-frida"]


__all__ = ["Runtime", "RuntimeResult", "get_runtime", "list_runtimes"]
