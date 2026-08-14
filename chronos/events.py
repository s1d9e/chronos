"""Event model shared across runtimes, monitors and analysis.

The syscall event is the lowest-level, backend-agnostic primitive emitted by a
runtime. Monitors fold raw events into behavioral events that analysis
plugins consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Behavioral categories
FS = "filesystem"
NET = "network"
PROC = "process"
MEM = "memory"
REG = "registry"
DBG = "debugger"
IO = "io"
CRYPTO = "crypto"

CATEGORIES = (FS, NET, PROC, MEM, REG, DBG, IO, CRYPTO)


@dataclass(slots=True)
class SyscallEvent:
    """A single (optionally decoded) system call crossing."""

    seq: int
    pid: int
    tid: int
    ts: float
    syscall: str
    nr: int
    args: dict[str, Any] = field(default_factory=dict)
    ret: int | None = None
    err: str | None = None
    info: dict[str, Any] = field(default_factory=dict)
    arch: str = "unknown"

    @property
    def is_error(self) -> bool:
        return self.err is not None


@dataclass(slots=True)
class BehaviorEvent:
    """A semantic, canonical observation derived from raw events."""

    seq: int
    pid: int
    tid: int
    ts: float
    category: str
    op: str
    target: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    syscall: str = ""
    backref: int = -1

    def line(self) -> str:
        parts = [self.op, self.target]
        extra = self.data
        if "fd_path" in extra:
            parts.append(f"fd={extra['fd_path']}")
        if "length" in extra:
            parts.append(f"len={extra['length']}")
        if "prot" in extra:
            parts.append(f"prot={extra['prot']}")
        return " ".join(p for p in parts if p)
