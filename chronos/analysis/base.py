"""Analysis engine and plugin base."""

from __future__ import annotations

from chronos import config as cfg
from chronos.events import BehaviorEvent, SyscallEvent
from chronos.models import Indicator


class Analyzer:
    """An analyzer observes behavior and reports indicators (never advice)."""

    name = "analyzer"
    mitre = ""
    description = ""

    def __init__(self, conf: cfg.Config | None = None) -> None:
        self.conf = conf or cfg.Config.default()

    def analyze(self, behaviors: list[BehaviorEvent], events: list[SyscallEvent]) -> list[Indicator]:
        return []


def ev_by_syscall(events: list[SyscallEvent], name: str) -> list[SyscallEvent]:
    return [e for e in events if e.syscall == name]


def ev_in(events: list[SyscallEvent], names: set[str]) -> list[SyscallEvent]:
    return [e for e in events if e.syscall in names]


def bev_by_op(behaviors: list[BehaviorEvent], op: str) -> list[BehaviorEvent]:
    return [b for b in behaviors if b.op == op]


def bev_in(behaviors: list[BehaviorEvent], ops: set[str]) -> list[BehaviorEvent]:
    return [b for b in behaviors if b.op in ops]


def mk(technique: str, mitre: str, severity: str, confidence: float, evidence: list[str], count: int = 1) -> Indicator:
    ind = Indicator(
        technique=technique, mitre=mitre, severity=severity,
        confidence=confidence, evidence=evidence, count=count,
    )
    ind.validate()
    return ind
