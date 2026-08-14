"""Simulated runtime.

Emits scripted ``SyscallEvent`` streams so the whole pipeline (monitors,
analysis, reporting) can be exercised and tested without OS-level tracing.
This is what the ``chronos simulate`` command and the test-suite use.
"""

from __future__ import annotations

import time

from chronos.events import SyscallEvent

from .base import Runtime, RuntimeResult


def _base(seq: int, name: str, ts: float, args: dict, nr: int = 0) -> SyscallEvent:
    return SyscallEvent(seq=seq, pid=1000, tid=1000, ts=ts, syscall=name, nr=nr, args=args)


SCENARIOS: dict[str, list[dict]] = {
    "benign": [
        {"s": "openat", "a": {"dirfd": -100, "path": "/etc/hostname", "flags": "RDONLY", "mode": 0}},
        {"s": "read", "a": {"fd": 3, "buf": "0x7fff...", "count": 128}},
        {"s": "close", "a": {"fd": 3}},
        {"s": "write", "a": {"fd": 1, "buf": "0x7fff...", "count": 24}},
        {"s": "exit_group", "a": {}},
    ],
    "benign_network": [
        {"s": "socket", "a": {"domain": "2 (inet)", "type": "1 (stream)", "protocol": 0}},
        {"s": "connect", "a": {"fd": 4, "len": 16, "sockaddr": "inet 93.184.216.34:443"}},
        {"s": "write", "a": {"fd": 4, "count": 96}},
        {"s": "recvfrom", "a": {"fd": 4, "len": 1024}},
        {"s": "close", "a": {"fd": 4}},
    ],
    "evil": [
        {"s": "openat", "a": {"dirfd": -100, "path": "/proc/self/status", "flags": "RDONLY", "mode": 0}},
        {"s": "read", "a": {"fd": 3, "count": 2048}},
        {"s": "close", "a": {"fd": 3}},
        {"s": "mmap", "a": {"addr": "0x0", "length": 4096, "prot": "RWX", "flags": "PRIVATE|ANON", "fd": -1, "offset": 0}},
        {"s": "mprotect", "a": {"addr": "0x700000000000", "length": 4096, "prot": "NONE"}},
        {"s": "mprotect", "a": {"addr": "0x700000000000", "length": 4096, "prot": "RX"}},
        {"s": "socket", "a": {"domain": "2 (inet)", "type": "1 (stream)", "protocol": 0}},
        {"s": "connect", "a": {"fd": 5, "len": 16, "sockaddr": "inet 203.0.113.7:4444"}},
        {"s": "connect", "a": {"fd": 6, "len": 16, "sockaddr": "inet 203.0.113.7:4444"}},
        {"s": "connect", "a": {"fd": 7, "len": 16, "sockaddr": "inet 203.0.113.7:4444"}},
        {"s": "openat", "a": {"dirfd": -100, "path": "/tmp/drop", "flags": "WRONLY|CREAT", "mode": 0x1A4}},
        {"s": "write", "a": {"fd": 8, "count": 128}},
        {"s": "close", "a": {"fd": 8}},
        {"s": "unlink", "a": {"path": "/tmp/drop"}},
        {"s": "openat", "a": {"dirfd": -100, "path": "/home/u/.config/autostart/p.service", "flags": "WRONLY|CREAT", "mode": 0x1A4}},
        {"s": "write", "a": {"fd": 9, "count": 320}},
        {"s": "close", "a": {"fd": 9}},
        {"s": "execve", "a": {"path": "/bin/sh", "argv": "0x..."}},
        {"s": "exit_group", "a": {}},
    ],
}


def _apply_info(event: SyscallEvent, raw: dict) -> None:
    if event.syscall == "connect":
        event.info["sock"] = raw["a"].get("sockaddr", "")
    if event.syscall in ("openat", "open"):
        event.info["path"] = raw["a"].get("path", "")
    if event.syscall == "mmap":
        event.info["region"] = "0x0 len=4096 prot=RWX"
        event.info["anon"] = "ANON" in raw["a"].get("flags", "")
    if event.syscall == "mprotect":
        event.info["region"] = f"{raw['a'].get('addr', '')} len={raw['a'].get('length', 0)} prot={raw['a'].get('prot', '')}"
    if event.syscall in ("write", "read") and "io_preview" not in raw:
        event.info["io_preview"] = ""


class SimulatedRuntime(Runtime):
    name = "simulated"
    description = "Emit a scripted event stream (offline demo / tests)."

    def run(self, config) -> RuntimeResult:  # type: ignore[no-untyped-def]
        scenario = getattr(self, "scenario", None) or "benign"
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario: {scenario} (available: {', '.join(SCENARIOS)})")

        start = time.monotonic()
        events: list[SyscallEvent] = []
        ts = start
        for i, raw in enumerate(SCENARIOS[scenario]):
            ts += 0.001
            ev = _base(i + 1, raw["s"], ts, dict(raw["a"]))
            _apply_info(ev, raw)
            events.append(ev)

        return RuntimeResult(
            sample=f"simulated:{scenario}",
            events=events,
            exit_code=0,
            duration=time.monotonic() - start,
        )


def list_scenarios() -> list[str]:
    return list(SCENARIOS)
