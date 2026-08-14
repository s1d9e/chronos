"""Trace erasure and timestomping heuristics."""

from __future__ import annotations

from chronos.events import BehaviorEvent, SyscallEvent
from chronos.models import Indicator

from ..base import Analyzer, bev_in, mk


class TraceErasureAnalyzer(Analyzer):
    name = "trace_erasure"
    mitre = "T1070"
    description = "Self-cleanup of artifacts (deletes in temp, timestomping)."

    def analyze(self, behaviors: list[BehaviorEvent], events: list[SyscallEvent]) -> list[Indicator]:
        found: list[Indicator] = []

        dels = bev_in(behaviors, {"delete", "rmdir"})
        tmp_dels = [b for b in dels if any(t in b.target for t in ("/tmp", "/var/tmp", "/dev/shm"))]
        if tmp_dels:
            found.append(mk(
                "Deletion of files in temp", self.mitre, "MEDIUM", 0.55,
                [f"[{b.seq}] {b.op} {b.target}" for b in tmp_dels[:6]],
                count=len(tmp_dels),
            ))

        # drop-then-delete: a file written and later deleted by the same process
        writes = {b.target for b in behaviors if b.op == "write" and b.category == "filesystem"}
        deletes = {b.target for b in behaviors if b.op == "delete"}
        dropped = writes & deletes
        if dropped:
            found.append(mk(
                "Write-then-delete (artifacts removed)", self.mitre,
                "MEDIUM", 0.65,
                [f"file removed after write: {p}" for p in list(dropped)[:6]],
                count=len(dropped),
            ))

        timestomp = [e for e in events if e.syscall in ("utimensat", "futimesat", "utime")]
        if timestomp:
            found.append(mk(
                "Timestamp manipulation", self.mitre, "LOW", 0.5,
                [f"[{e.seq}] {e.syscall}" for e in timestomp[:6]],
                count=len(timestomp),
            ))

        return found
