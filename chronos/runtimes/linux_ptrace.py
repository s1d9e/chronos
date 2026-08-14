"""Linux runtime backed by the built-in ptrace syscall tracer."""

from __future__ import annotations

import time

from chronos.core.tracer import LinuxTracer

from .base import Runtime, RuntimeResult


class LinuxPTraceRuntime(Runtime):
    name = "linux-ptrace"
    description = "Run a Linux command and trace its syscalls with ptrace(2)."

    def run(self, config) -> RuntimeResult:  # type: ignore[no-untyped-def]
        argv = getattr(self, "argv", None)
        if not argv:
            raise ValueError("linux-ptrace runtime requires an argv (e.g. -- /path/to/sample)")

        tracer = LinuxTracer(
            argv,
            cwd=getattr(self, "cwd", None),
            env=getattr(self, "env", None),
            timeout=config.timeout,
            capture_io=config.capture_io,
            io_preview=config.io_preview,
        )
        start = time.monotonic()
        events, exit_code, signals, timed_out = tracer.run()
        return RuntimeResult(
            sample=argv[0],
            events=events,
            exit_code=exit_code,
            signals=signals,
            timed_out=timed_out,
            duration=time.monotonic() - start,
        )
