"""Memory behavior monitoring (allocation / protection / free)."""

from __future__ import annotations

from chronos import config as cfg
from chronos.events import MEM, BehaviorEvent, SyscallEvent

from .base import Monitor

_PROT_NONE = "NONE"
_PROT_RWX = "RWX"


class MemoryMonitor(Monitor):
    name = "memory"

    def __init__(self, conf: cfg.Config) -> None:
        self.conf = conf

    def handle(self, event: SyscallEvent) -> list[BehaviorEvent]:
        name = event.syscall
        out: list[BehaviorEvent] = []

        if name == "mmap":
            prot = str(event.args.get("prot", "?"))
            flags = str(event.args.get("flags", ""))
            anon = "ANON" in flags
            data = {
                "length": event.args.get("length", 0),
                "prot": prot,
                "flags": flags,
                "anon": anon,
            }
            fd_path = event.info.get("fd_path")
            if fd_path:
                data["fd_path"] = fd_path
            addr = str(event.args.get("addr", "0x0"))
            op = "alloc"
            if anon and prot == _PROT_RWX and self.conf.rwx_anon:
                op = "rwx_alloc"
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=MEM, op=op, target=addr, data=data,
                    syscall=name, backref=event.seq,
                )
            )
        elif name == "mprotect":
            prot = str(event.args.get("prot", "?"))
            addr = str(event.args.get("addr", "0x0"))
            data = {"length": event.args.get("length", 0), "prot": prot}
            op = "protect"
            if prot == _PROT_NONE:
                op = "protect_none"
            elif prot == _PROT_RWX:
                op = "rwx_protect"
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=MEM, op=op, target=addr, data=data,
                    syscall=name, backref=event.seq,
                )
            )
        elif name == "munmap":
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=MEM, op="free", target=str(event.args.get("addr", "0x0")),
                    data={"length": event.args.get("length", 0)},
                    syscall=name, backref=event.seq,
                )
            )
        elif name == "brk":
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=MEM, op="brk", target=str(event.args.get("addr", "0x0")),
                    data={}, syscall=name, backref=event.seq,
                )
            )
        return out
