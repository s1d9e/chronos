"""Persistence heuristics: writes to autostart / cron / systemd paths."""

from __future__ import annotations

from chronos.events import BehaviorEvent, SyscallEvent
from chronos.models import Indicator

from ..base import Analyzer, bev_by_op, mk


class PersistenceAnalyzer(Analyzer):
    name = "persistence"
    mitre = "T1547"
    description = "Autostart / scheduled-execution writes surviving reboot."

    def analyze(self, behaviors: list[BehaviorEvent], events: list[SyscallEvent]) -> list[Indicator]:
        found: list[Indicator] = []

        writes = [b for b in bev_by_op(behaviors, "persistence_write")]
        if writes:
            found.append(mk(
                "Write to autostart / scheduler path", self.mitre,
                "HIGH", 0.85,
                [f"[{b.seq}] pid {b.pid} write -> {b.target}" for b in writes[:8]],
                count=len(writes),
            ))

        # chmod +x on a path we just wrote = runnable dropped component
        chmodded = {b.target for b in behaviors if b.op == "chmod"}
        if chmodded:
            written = {b.target for b in behaviors if b.op in ("write", "open_write", "rename")}
            overlap = written & chmodded
            if overlap:
                found.append(mk(
                    "Executable bit set on written file", self.mitre,
                    "MEDIUM", 0.6,
                    [f"chmod +x on {p}" for p in list(overlap)[:6]],
                    count=len(overlap),
                ))

        return found
