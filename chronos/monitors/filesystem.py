"""Filesystem behavior monitoring."""

from __future__ import annotations

from chronos import config as cfg
from chronos.events import FS, BehaviorEvent, SyscallEvent

from .base import Monitor

_OPEN = {"open", "openat", "openat2"}
_WRITE = {"write", "pwrite64", "writev"}
_DELETE = {"unlink", "unlinkat"}
_RENAME = {"rename", "renameat"}
_MKDIR = {"mkdir", "mkdirat"}
_RMDIR = {"rmdir"}
_MEMFD = {"memfd_create"}


def _path_of(event: SyscallEvent, name: str) -> str | None:
    if name in ("openat", "mkdirat", "unlinkat", "renameat", "faccessat", "readlinkat"):
        path = event.args.get("path")
    else:
        path = event.args.get("oldpath") or event.args.get("path")
    return path if isinstance(path, str) else None


class FilesystemMonitor(Monitor):
    name = "filesystem"

    def __init__(self, conf: cfg.Config) -> None:
        self.persist_paths = tuple(conf.persistence_paths)

    def handle(self, event: SyscallEvent) -> list[BehaviorEvent]:
        name = event.syscall
        out: list[BehaviorEvent] = []

        if name in _OPEN:
            path = _path_of(event, name)
            if path is None:
                return out
            flags = str(event.args.get("flags", ""))
            op = "open_write" if ("WRONLY" in flags or "RDWR" in flags or "CREAT" in flags) else "open_read"
            out.append(self._bev(event, op, path, {"flags": flags}, name))
        elif name in _WRITE:
            fd_path = event.info.get("fd_path")
            target = fd_path or f"fd={event.args.get('fd', '?')}"
            data = {"length": event.args.get("count", 0)}
            preview = event.info.get("io_preview")
            if preview:
                data["preview"] = str(preview)[:cfg.MAX_IO_PREVIEW]
            out.append(self._bev(event, "write", target, data, name))
        elif name in _DELETE:
            path = _path_of(event, name)
            if path:
                out.append(self._bev(event, "delete", path, {}, name))
        elif name in _RENAME:
            old = event.args.get("oldpath", "?")
            new = event.args.get("newpath", "?")
            out.append(self._bev(event, "rename", f"{old} -> {new}", {}, name))
        elif name in _MKDIR:
            path = _path_of(event, name)
            if path:
                out.append(self._bev(event, "mkdir", path, {}, name))
        elif name in _RMDIR:
            path = _path_of(event, name)
            if path:
                out.append(self._bev(event, "rmdir", path, {}, name))
        elif name == "chmod":
            path = event.args.get("path")
            if path:
                out.append(self._bev(event, "chmod", str(path), {"mode": event.args.get("mode", 0)}, name))
        elif name in _MEMFD:
            target = event.args.get("name", "?")
            out.append(self._bev(event, "memfd", str(target), {}, name))

        # persistence-path hint (feeds the persistence analyzer)
        for b in list(out):
            if b.category != FS:
                continue
            if any(p in b.target for p in self.persist_paths):
                out.append(
                    BehaviorEvent(
                        seq=b.seq, pid=b.pid, tid=b.tid, ts=b.ts, category=FS,
                        op="persistence_write", target=b.target, data=b.data,
                        syscall=b.syscall, backref=b.backref,
                    )
                )
        return out

    @staticmethod
    def _bev(event: SyscallEvent, op: str, target: str, data: dict, name: str) -> BehaviorEvent:
        return BehaviorEvent(
            seq=event.seq, pid=event.pid, tid=event.tid, ts=event.ts,
            category=FS, op=op, target=target, data=data, syscall=name,
            backref=event.seq,
        )
