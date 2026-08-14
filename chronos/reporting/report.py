"""Human- and machine-readable reporting."""

from __future__ import annotations

import json
from pathlib import Path

from chronos.events import BehaviorEvent, SyscallEvent
from chronos.models import Indicator, Report, TimelineEntry

# ANSI
_RED = "\033[91m"
_YEL = "\033[93m"
_CYN = "\033[96m"
_GRN = "\033[92m"
_BLD = "\033[1m"
_RST = "\033[0m"

_SEV_COLOR = {"CRITICAL": _RED, "HIGH": _RED, "MEDIUM": _YEL, "LOW": _CYN}


def build_report(
    sample: str,
    started: float,
    duration: float,
    timed_out: bool,
    exit_code: int | None,
    signals: list[str],
    events: list[SyscallEvent],
    behaviors: list[BehaviorEvent],
    indicators: list[Indicator],
) -> Report:
    report = Report(
        sample=sample, started=started, duration=duration, timed_out=timed_out,
        exit_code=exit_code, signals=signals, events=events, behaviors=behaviors,
        indicators=indicators,
    )
    report.timeline = [
        TimelineEntry(
            ts=b.ts, pid=b.pid, category=b.category, op=b.op,
            detail=b.line(),
        )
        for b in behaviors
    ]
    return report


def _score_bar(score: int) -> str:
    if score >= 20:
        severity = "CRITICAL"
        color = _RED
    elif score >= 10:
        severity = "HIGH"
        color = _RED
    elif score >= 5:
        severity = "MEDIUM"
        color = _YEL
    else:
        severity = "LOW"
        color = _GRN
    filled = max(0, min(40, score))
    bar = "█" * filled + "░" * (40 - filled)
    return f"{color}{_BLD}Threat Score:  {bar}  ({score}) [{severity}]{_RST}"


def render(report: Report) -> str:
    lines: list[str] = []
    hist = report.severity_histogram()

    lines.append("=" * 70)
    lines.append("  CHRONOS — dynamic analysis report")
    lines.append("=" * 70)
    lines.append(f"  Sample:      {report.sample}")
    lines.append(f"  Duration:    {report.duration:.3f}s")
    lines.append(f"  Exit code:   {report.exit_code if report.exit_code is not None else 'n/a'}")
    if report.timed_out:
        lines.append(f"  {_YEL}  Note: analysis timed out — sample killed.{_RST}")
    for sig in report.signals:
        lines.append(f"  {_YEL}  signal: {sig}{_RST}")
    lines.append("")

    lines.append(_score_bar(report.total_score()))
    lines.append("")
    lines.append("  Indicators:  "
                 f"{_RED}{hist['CRITICAL']} critical{_RST} | "
                 f"{_RED}{hist['HIGH']} high{_RST} | "
                 f"{_YEL}{hist['MEDIUM']} medium{_RST} | "
                 f"{_CYN}{hist['LOW']} low{_RST}")
    lines.append("")

    if report.indicators:
        lines.append("  [ INDICATORS ]")
        for ind in report.indicators:
            color = _SEV_COLOR.get(ind.severity, _RST)
            lines.append(f"  {color}[{ind.severity:8s}]{_RST} {ind.technique} "
                         f"({ind.mitre}) conf={ind.confidence:.0%} x{ind.count}")
            for ev in ind.evidence[:4]:
                lines.append(f"      {ev}")
        lines.append("")

    lines.append(f"  [ TIMELINE ]  ({len(report.timeline)} events)")
    for t in report.timeline:
        lines.append(f"  {t.ts:8.3f}  pid {t.pid:<6d} {t.category:<10s} {t.op:<14s} {t.detail}")
    lines.append("")
    lines.append("  Behaviors classified as indicators are observations, not "
                 "attribution.")
    lines.append("=" * 70)
    return "\n".join(lines)


def write_json(report: Report, path: str) -> None:
    Path(path).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
