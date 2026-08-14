"""Sandbox orchestrator: runtime -> monitors -> analysis -> report -> storage."""

from __future__ import annotations

import time

from chronos import config as cfg
from chronos.analysis import AnalysisEngine
from chronos.events import BehaviorEvent, SyscallEvent
from chronos.models import Report
from chronos.monitors import all_monitors, run_monitors
from chronos.net import Sinkhole
from chronos.reporting.report import build_report
from chronos.runtimes import Runtime, RuntimeResult, get_runtime
from chronos.storage.sqlite import TraceStore


def _sinkhole_behaviors(sinkhole: Sinkhole, start_seq: int) -> list[BehaviorEvent]:
    """Fold captured DNS/HTTP records into behavioral events."""
    out: list[BehaviorEvent] = []
    for i, rec in enumerate(sinkhole.dns_records):
        out.append(BehaviorEvent(
            seq=start_seq + i, pid=0, tid=0, ts=rec.ts,
            category="network", op="dns", target=rec.qname,
            data={"qtype": rec.qtype_name, "src": rec.src}, syscall="", backref=-1,
        ))
    base = start_seq + len(sinkhole.dns_records)
    for i, hit in enumerate(sinkhole.http_records):
        out.append(BehaviorEvent(
            seq=base + i, pid=0, tid=0, ts=hit.ts,
            category="network", op="http", target=hit.uri,
            data={"method": hit.method, "src": hit.src, "body": hit.body}, syscall="", backref=-1,
        ))
    return out


class Sandbox:
    """Coordinate a single analysis run."""

    def __init__(self, conf: cfg.Config | None = None, store_path: str | None = None) -> None:
        self.conf = conf or cfg.Config.default()
        self.engine = AnalysisEngine(conf=self.conf)
        self.store_path = store_path

    def run_runtime(self, runtime: Runtime) -> Report:
        sinkhole: Sinkhole | None = None
        if self.conf.sinkhole_enabled:
            sinkhole = Sinkhole(
                dns_port=self.conf.sinkhole_dns_port,
                http_port=self.conf.sinkhole_http_port,
                resolve_ip=self.conf.sinkhole_resolve_ip,
                http_preview=self.conf.sinkhole_http_preview,
            )
            sinkhole.start()

        try:
            result: RuntimeResult = runtime.run(self.conf)
        finally:
            if sinkhole:
                sinkhole.stop()

        behaviors = result.behaviors
        if not behaviors and result.events:
            behaviors = run_monitors(result.events, all_monitors(self.conf))
        if sinkhole:
            start_seq = max((e.seq for e in result.events), default=-1) + 1
            behaviors = list(behaviors) + _sinkhole_behaviors(sinkhole, start_seq)

        indicators = self.engine.analyze(behaviors, result.events, self.conf)
        report = build_report(
            sample=result.sample,
            started=time.monotonic() - result.duration,
            duration=result.duration,
            timed_out=result.timed_out,
            exit_code=result.exit_code,
            signals=result.signals,
            events=result.events,
            behaviors=behaviors,
            indicators=indicators,
        )

        if self.store_path:
            store = TraceStore(self.store_path)
            store.save(
                sample=result.sample,
                started=time.monotonic() - result.duration,
                duration=result.duration,
                timed_out=result.timed_out,
                exit_code=result.exit_code,
                events=result.events,
                behaviors=behaviors,
            )
            store.close()
        return report

    def run(
        self,
        argv: list[str] | None = None,
        *,
        runtime_name: str | None = None,
        scenario: str | None = None,
    ) -> Report:
        runtime = get_runtime(runtime_name)
        if argv is not None:
            runtime.argv = argv  # type: ignore[attr-defined]
        if scenario is not None:
            runtime.scenario = scenario  # type: ignore[attr-defined]
        return self.run_runtime(runtime)

    def replay(self, store_path: str, run_id: int | None = None) -> Report:
        store = TraceStore(store_path)
        events: list[SyscallEvent] = store.load_events(run_id)
        behaviors: list[BehaviorEvent] = store.load_behaviors(run_id)
        if not behaviors:
            behaviors = run_monitors(events, all_monitors(self.conf))
        indicators = self.engine.analyze(behaviors, events, self.conf)
        report = build_report(
            sample=store_path,
            started=time.time() - 1.0,
            duration=0.0,
            timed_out=False,
            exit_code=None,
            signals=[],
            events=events,
            behaviors=behaviors,
            indicators=indicators,
        )
        store.close()
        return report


__all__ = ["Sandbox"]
