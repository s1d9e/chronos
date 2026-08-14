"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from chronos import config as cfg  # noqa: E402
from chronos.analysis import AnalysisEngine  # noqa: E402
from chronos.monitors import all_monitors, run_monitors  # noqa: E402
from chronos.runtimes import get_runtime  # noqa: E402


def analyze_scenario(name: str, conf: cfg.Config | None = None):
    conf = conf or cfg.Config.default()
    runtime = get_runtime("simulated")
    runtime.scenario = name  # type: ignore[attr-defined]
    result = runtime.run(conf)
    behaviors = run_monitors(result.events, all_monitors(conf))
    engine = AnalysisEngine(conf=conf)
    indicators = engine.analyze(behaviors, result.events, conf)
    return result.events, behaviors, indicators
