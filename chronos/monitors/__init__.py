"""Monitor package."""

from __future__ import annotations

from chronos import config as cfg
from chronos.events import BehaviorEvent, SyscallEvent

from .base import Monitor
from .filesystem import FilesystemMonitor
from .memory import MemoryMonitor
from .network import NetworkMonitor
from .process import ProcessMonitor


def all_monitors(conf: cfg.Config | None = None) -> list[Monitor]:
    conf = conf or cfg.Config.default()
    return [
        ProcessMonitor(),
        FilesystemMonitor(conf),
        NetworkMonitor(conf),
        MemoryMonitor(conf),
    ]


def run_monitors(events: list[SyscallEvent], monitors: list[Monitor]) -> list[BehaviorEvent]:
    behaviors: list[BehaviorEvent] = []
    for event in events:
        for mon in monitors:
            behaviors.extend(mon.handle(event))
    behaviors.sort(key=lambda b: b.seq)
    return behaviors


__all__ = ["Monitor", "all_monitors", "run_monitors", "BehaviorEvent", "SyscallEvent"]
