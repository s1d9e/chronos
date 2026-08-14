"""Network behavior monitoring."""

from __future__ import annotations

from chronos import config as cfg
from chronos.events import NET, BehaviorEvent, SyscallEvent

from .base import Monitor

_SOCK = {"socket"}
_CONNECT = {"connect"}
_SEND = {"sendto", "sendmsg", "writev"}
_RECV = {"recvfrom", "recvmsg"}
_LISTEN = {"bind", "listen", "accept", "accept4"}


class NetworkMonitor(Monitor):
    name = "network"

    def __init__(self, conf: cfg.Config) -> None:
        self.conf = conf

    def handle(self, event: SyscallEvent) -> list[BehaviorEvent]:
        name = event.syscall
        out: list[BehaviorEvent] = []

        if name in _SOCK:
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=NET, op="socket",
                    target=f"domain={event.args.get('domain', '?')} type={event.args.get('type', '?')}",
                    data={"protocol": event.args.get("protocol", 0)},
                    syscall=name, backref=event.seq,
                )
            )
        elif name in _CONNECT:
            dst = event.info.get("sock") or event.args.get("sockaddr") or "?"
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=NET, op="connect", target=str(dst), data={},
                    syscall=name, backref=event.seq,
                )
            )
        elif name in _SEND:
            dst = event.info.get("sock")
            target = str(dst) if dst else f"fd={event.args.get('fd', '?')}"
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=NET, op="sendto", target=target,
                    data={"length": event.args.get("len", 0)},
                    syscall=name, backref=event.seq,
                )
            )
        elif name in _RECV:
            dst = event.info.get("sock")
            target = str(dst) if dst else f"fd={event.args.get('fd', '?')}"
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=NET, op="recvfrom", target=target,
                    data={"length": event.args.get("len", 0)},
                    syscall=name, backref=event.seq,
                )
            )
        elif name in _LISTEN:
            dst = event.info.get("sock")
            target = str(dst) if dst else f"fd={event.args.get('fd', '?')}"
            out.append(
                BehaviorEvent(
                    seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
                    category=NET, op=name, target=str(target), data={},
                    syscall=name, backref=event.seq,
                )
            )
        return out
