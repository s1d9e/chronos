"""Evasion heuristics: API unhooking, self-modification, indirect resolution."""

from __future__ import annotations

from chronos.events import BehaviorEvent, SyscallEvent
from chronos.models import Indicator

from ..base import Analyzer, ev_by_syscall, mk


class EvasionAnalyzer(Analyzer):
    name = "evasion"
    mitre = "T1562"
    description = "Impair-defenses signals (unhooking / self-modifying code / dynamic API resolution)."

    def analyze(self, behaviors: list[BehaviorEvent], events: list[SyscallEvent]) -> list[Indicator]:
        found: list[Indicator] = []

        self_mem = [e for e in events if e.syscall == "open"
                    and str(e.args.get("path", "")) in ("/proc/self/mem", "/proc/self/exe")]
        if self_mem:
            found.append(mk(
                "Self-memory write path opened", self.mitre, "HIGH", 0.7,
                [f"[{e.seq}] pid {e.pid} open {e.args.get('path')}" for e in self_mem[:6]],
            ))

        poke = [e for e in ev_by_syscall(events, "ptrace")
                if "POKEDATA" in str(e.args.get("request", ""))]
        if poke:
            found.append(mk(
                "POKEDATA (manual code patching)", self.mitre, "HIGH", 0.8,
                [f"[{e.seq}] ptrace POKEDATA target pid={e.args.get('pid')}" for e in poke[:6]],
            ))

        rwx_write = [
            b for b in behaviors
            if b.op in ("rwx_protect", "rwx_alloc")
            and any(x.op == "write" and x.pid == b.pid for x in behaviors)
        ]
        if rwx_write:
            found.append(mk(
                "Write-after-RWX (hook removal pattern)", self.mitre, "MEDIUM", 0.6,
                [f"[{b.seq}] pid {b.pid} {b.op} {b.target}" for b in rwx_write[:6]],
            ))

        resolve = [b for b in behaviors if b.op == "resolve_api"]
        if len(resolve) >= 10:
            found.append(mk(
                "Heavy GetProcAddress resolution", self.mitre, "LOW", 0.4,
                [f"[{resolve[0].seq}] {resolve[0].op} x{len(resolve)}"],
                count=len(resolve),
            ))

        return found
