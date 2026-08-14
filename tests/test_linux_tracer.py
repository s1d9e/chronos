"""Real ptrace tracer test (Linux only; skipped elsewhere)."""

from __future__ import annotations

import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "fork"),
    reason="ptrace tracer requires Linux",
)


def test_tracer_captures_syscalls():
    from chronos.core.tracer import LinuxTracer

    tracer = LinuxTracer(["/bin/echo", "hi"], timeout=10)
    events, exit_code, signals, timed_out = tracer.run()
    assert not timed_out
    assert exit_code == 0
    assert len(events) > 5
    syscalls = {e.syscall for e in events}
    assert "write" in syscalls or "openat" in syscalls or "newfstatat" in syscalls


def test_tracer_decodes_paths_and_fd_resolution():
    from chronos.core.tracer import LinuxTracer

    tracer = LinuxTracer(["/bin/cat", "/etc/hostname"], timeout=10)
    events, _, _, _ = tracer.run()
    assert any(
        e.syscall == "openat" and "hostname" in str(e.args.get("path", ""))
        for e in events
    )
    assert any("fd_path" in e.info for e in events if e.syscall == "read")


def test_tracer_timeout_kills_tracee():
    from chronos.core.tracer import LinuxTracer

    tracer = LinuxTracer(["/bin/sleep", "30"], timeout=1.0)
    events, _, _, timed_out = tracer.run()
    assert timed_out
