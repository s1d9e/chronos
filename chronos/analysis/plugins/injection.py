"""Process injection heuristics (observation only)."""

from __future__ import annotations

from chronos.events import BehaviorEvent, SyscallEvent
from chronos.models import Indicator

from ..base import Analyzer, bev_in, ev_by_syscall, mk


class InjectionAnalyzer(Analyzer):
    name = "injection"
    mitre = "T1055"
    description = "Process injection staging (RWX regions, remote writes, memfd + exec)."

    def analyze(self, behaviors: list[BehaviorEvent], events: list[SyscallEvent]) -> list[Indicator]:
        found: list[Indicator] = []

        rwx = bev_in(behaviors, {"rwx_alloc", "rwx_protect"})
        if rwx:
            evidence = [f"[{b.seq}] pid {b.pid} {b.op} {b.target} prot={b.data.get('prot')}" for b in rwx[:6]]
            found.append(mk(
                "RWX executable memory region", self.mitre, "HIGH", 0.7,
                evidence, count=len(rwx),
            ))

        remote = bev_in(behaviors, {"remote_thread", "write_remote"})
        if remote:
            found.append(mk(
                "Cross-process write / remote thread", self.mitre, "CRITICAL", 0.9,
                [f"[{b.seq}] pid {b.pid} {b.op} {b.target}" for b in remote[:6]],
                count=len(remote),
            ))

        pvm_write = [e for e in events if e.syscall == "process_vm_writev"]
        if pvm_write:
            found.append(mk(
                "process_vm_writev into another process", self.mitre, "CRITICAL", 0.9,
                [f"[{e.seq}] pid {e.pid} -> target pid={e.args.get('pid')}" for e in pvm_write[:6]],
                count=len(pvm_write),
            ))

        memfd_exec = [e for e in ev_by_syscall(events, "execve")
                      if any(b.op == "memfd" and b.pid == e.pid for b in behaviors)]
        if memfd_exec:
            found.append(mk(
                "Fileless execution (memfd + exec)", self.mitre, "HIGH", 0.8,
                [f"[{e.seq}] execve of memfd-backed path" for e in memfd_exec[:6]],
            ))

        return found
