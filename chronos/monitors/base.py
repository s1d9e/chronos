"""Monitors: fold raw syscall events into semantic behavioral events."""

from __future__ import annotations

from chronos.events import BehaviorEvent, SyscallEvent


class Monitor:
    name = "base"

    def handle(self, event: SyscallEvent) -> list[BehaviorEvent]:
        return []


__all__ = ["Monitor"]
