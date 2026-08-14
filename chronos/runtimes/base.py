"""Runtime abstraction: how a sample is executed and instrumented."""

from __future__ import annotations

from dataclasses import dataclass, field

from chronos.events import BehaviorEvent, SyscallEvent


@dataclass(slots=True)
class RuntimeResult:
    sample: str
    events: list[SyscallEvent] = field(default_factory=list)
    behaviors: list[BehaviorEvent] = field(default_factory=list)
    exit_code: int | None = None
    signals: list[str] = field(default_factory=list)
    timed_out: bool = False
    duration: float = 0.0


class Runtime:
    """Base class. Subclasses run + instrument a sample."""

    name = "base"
    description = ""

    def run(self, config) -> RuntimeResult:  # type: ignore[no-untyped-def]
        raise NotImplementedError
