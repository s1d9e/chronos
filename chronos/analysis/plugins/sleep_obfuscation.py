"""Sleep obfuscation heuristics: regions cycled through PROT_NONE."""

from __future__ import annotations

from dataclasses import dataclass, field

from chronos.events import BehaviorEvent, SyscallEvent
from chronos.models import Indicator

from ..base import Analyzer, mk


@dataclass
class _Region:
    addr: str
    events: list[BehaviorEvent] = field(default_factory=list)
    prots: list[str] = field(default_factory=list)


class SleepObfuscationAnalyzer(Analyzer):
    name = "sleep_obfuscation"
    mitre = "T1027.001"
    description = "Memory set non-readable during sleep (encrypted/masked-resident code)."

    def analyze(self, behaviors: list[BehaviorEvent], events: list[SyscallEvent]) -> list[Indicator]:
        regions: dict[str, _Region] = {}
        for b in behaviors:
            if b.category != "memory":
                continue
            if b.op in ("protect", "protect_none", "rwx_protect", "alloc", "free"):
                r = regions.setdefault(b.target, _Region(addr=b.target))
                r.events.append(b)
                r.prots.append(str(b.data.get("prot", "?")))

        cycled = []
        for r in regions.values():
            prot_seq = [p for p in r.prots if p not in ("?",)]
            if "NONE" in prot_seq and len(prot_seq) >= 2:
                cycled.append(r)

        if not cycled:
            return []

        evidence = []
        for r in cycled[:6]:
            seqs = ", ".join(f"{b.seq}:{b.op}" for b in r.events)
            evidence.append(f"region {r.addr} — {seqs}")
        found = mk(
            "Memory hidden then restored (sleep obfuscation pattern)", self.mitre,
            "HIGH", 0.75, evidence, count=len(cycled),
        )
        return [found]
