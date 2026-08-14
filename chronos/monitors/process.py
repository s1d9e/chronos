"""Process lifecycle monitoring (spawn / exec / exit)."""

from __future__ import annotations

from chronos.events import PROC, BehaviorEvent, SyscallEvent

from .base import Monitor

_SPAWN = {"fork", "vfork", "clone", "clone3"}
_EXIT = {"exit", "exit_group"}


class ProcessMonitor(Monitor):
    name = "process"

    def handle(self, event: SyscallEvent) -> list[BehaviorEvent]:
        out: list[BehaviorEvent] = []
        name = event.syscall

        if name in _SPAWN:
            flags = event.args.get("flags", "")
            child = event.ret if event.ret is not None else "?"
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=PROC, op="spawn", target=str(child),
                    data={"flags": str(flags)}, syscall=name, backref=event.seq,
                )
            )
        elif name == "execve":
            target = event.args.get("path", "?") or event.info.get("argv0", "?")
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=PROC, op="exec", target=target,
                    data={"argv0": event.info.get("argv0", "")}, syscall=name,
                    backref=event.seq,
                )
            )
        elif name in _EXIT:
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=PROC, op="exit", target=str(event.pid),
                    data={"code": event.ret if event.ret is not None else -1},
                    syscall=name, backref=event.seq,
                )
            )
        return out
