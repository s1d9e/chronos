"""Report construction and serialization tests."""

from __future__ import annotations

import json

from chronos import config as cfg
from chronos.analysis import AnalysisEngine
from chronos.monitors import all_monitors, run_monitors
from chronos.reporting.report import build_report, write_json
from chronos.runtimes import get_runtime


def test_report_json_roundtrip(tmp_path):
    conf = cfg.Config.default()
    runtime = get_runtime("simulated")
    runtime.scenario = "evil"  # type: ignore[attr-defined]
    result = runtime.run(conf)
    behaviors = run_monitors(result.events, all_monitors(conf))
    indicators = AnalysisEngine(conf=conf).analyze(behaviors, result.events, conf)

    report = build_report(
        sample="simulated:evil", started=0.0, duration=1.0,
        timed_out=False, exit_code=0, signals=[],
        events=result.events, behaviors=behaviors, indicators=indicators,
    )
    assert report.total_score() >= 10
    assert len(report.timeline) == len(behaviors)

    out = tmp_path / "report.json"
    write_json(report, str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["sample"] == "simulated:evil"
    assert data["summary"]["score"] == report.total_score()
    assert all("mitre" in i for i in data["indicators"])
