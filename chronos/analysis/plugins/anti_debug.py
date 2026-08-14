"""Anti-debug / sandbox-detection heuristics."""

from __future__ import annotations

from chronos.events import BehaviorEvent, SyscallEvent
from chronos.models import Indicator

from ..base import Analyzer, bev_in, ev_by_syscall, mk


class AntiDebugAnalyzer(Analyzer):
    name = "anti_debug"
    mitre = "T1622"
    description = "Debugger / sandbox environment probing."

    def analyze(self, behaviors: list[BehaviorEvent], events: list[SyscallEvent]) -> list[Indicator]:
        found: list[Indicator] = []

        probes = [
            e for e in events
            if e.syscall in ("open", "openat", "openat2")
            and any(p in str(e.args.get("path", "")) for p in self.conf.anti_debug_reads)
        ]
        if probes:
            found.append(mk(
                "Trace-state probing (/proc/self/status, TracerPid)", self.mitre,
                "MEDIUM", 0.7,
                [f"[{e.seq}] open {e.args.get('path')}" for e in probes[:6]],
                count=len(probes),
            ))

        ptrace_calls = [e for e in ev_by_syscall(events, "ptrace")]
        if ptrace_calls:
            found.append(mk(
                "ptrace() usage (self-debug / anti-tracing)", self.mitre,
                "MEDIUM", 0.6,
                [f"[{e.seq}] ptrace {e.args.get('request')} pid={e.args.get('pid')}" for e in ptrace_calls[:6]],
                count=len(ptrace_calls),
            ))

        dbg = bev_in(behaviors, {"is_debugger_present", "query_debug"})
        if dbg:
            found.append(mk(
                "IsDebuggerPresent / debug-port query", self.mitre,
                "LOW", 0.6,
                [f"[{b.seq}] {b.op}" for b in dbg[:6]],
                count=len(dbg),
            ))

        timing = [
            e for e in events
            if e.syscall in ("clock_gettime", "gettimeofday")
            and len([b for b in behaviors if b.op == "sleep" and b.pid == e.pid]) >= 3
        ]
        if timing:
            found.append(mk(
                "Timing checks near sleeps (CPU timing evasion)", self.mitre,
                "LOW", 0.5, [f"[{e.seq}] {e.syscall}" for e in timing[:6]],
            ))

        return found
