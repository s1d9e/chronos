"""Analysis engine and plugins."""

from __future__ import annotations

from chronos import config as cfg
from chronos.events import BehaviorEvent, SyscallEvent
from chronos.models import Indicator

from .base import Analyzer
from .plugins.anti_debug import AntiDebugAnalyzer
from .plugins.c2 import C2NetworkAnalyzer
from .plugins.evasion import EvasionAnalyzer
from .plugins.injection import InjectionAnalyzer
from .plugins.persistence import PersistenceAnalyzer
from .plugins.sleep_obfuscation import SleepObfuscationAnalyzer
from .plugins.trace_erasure import TraceErasureAnalyzer


class AnalysisEngine:
    def __init__(self, conf: cfg.Config | None = None, analyzers: list[Analyzer] | None = None) -> None:
        conf = conf or cfg.Config.default()
        self.analyzers = analyzers or [
            InjectionAnalyzer(conf),
            EvasionAnalyzer(conf),
            SleepObfuscationAnalyzer(conf),
            AntiDebugAnalyzer(conf),
            PersistenceAnalyzer(conf),
            C2NetworkAnalyzer(conf),
            TraceErasureAnalyzer(conf),
        ]

    def analyze(
        self,
        behaviors: list[BehaviorEvent],
        events: list[SyscallEvent],
        conf: cfg.Config,
    ) -> list[Indicator]:
        indicators: list[Indicator] = []
        for analyzer in self.analyzers:
            indicators.extend(analyzer.analyze(behaviors, events))
        indicators.sort(key=lambda i: i.score, reverse=True)
        return indicators


__all__ = ["AnalysisEngine"]
