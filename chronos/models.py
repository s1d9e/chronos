"""Analysis result models: indicators, timeline and the final report."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from chronos.events import BehaviorEvent, SyscallEvent

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_WEIGHT = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass(slots=True)
class Indicator:
    """A detected technique, as observation (never as guidance to act)."""

    technique: str
    mitre: str
    severity: str = "LOW"
    confidence: float = 0.5
    evidence: list[str] = field(default_factory=list)
    count: int = 1

    @property
    def score(self) -> int:
        return SEVERITY_WEIGHT.get(self.severity, 1) * self.count

    def validate(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity}")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")


@dataclass(slots=True)
class TimelineEntry:
    ts: float
    pid: int
    category: str
    op: str
    detail: str


@dataclass(slots=True)
class Report:
    """Structured analysis result."""

    sample: str
    started: float
    duration: float
    timed_out: bool = False
    exit_code: int | None = None
    signals: list[str] = field(default_factory=list)
    events: list[SyscallEvent] = field(default_factory=list)
    behaviors: list[BehaviorEvent] = field(default_factory=list)
    timeline: list[TimelineEntry] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)

    def total_score(self) -> int:
        return sum(ind.score for ind in self.indicators)

    def severity_histogram(self) -> dict[str, int]:
        hist = {s: 0 for s in SEVERITIES}
        for ind in self.indicators:
            hist[ind.severity] += 1
        return hist

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample": self.sample,
            "started": self.started,
            "duration": round(self.duration, 4),
            "timed_out": self.timed_out,
            "exit_code": self.exit_code,
            "signals": self.signals,
            "summary": {
                "score": self.total_score(),
                "histogram": self.severity_histogram(),
            },
            "indicators": [asdict(i) for i in self.indicators],
            "timeline": [
                {
                    "ts": round(t.ts, 4),
                    "pid": t.pid,
                    "category": t.category,
                    "op": t.op,
                    "detail": t.detail,
                }
                for t in self.timeline
            ],
        }
