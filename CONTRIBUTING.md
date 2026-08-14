# Contributing

Thanks for helping improve Chronos. This is a **defensive security tool**: the
project only accepts contributions that observe and analyze. No exploit,
injection or evasion payloads — ever.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Commands

```bash
make lint       # ruff check .
make typecheck  # mypy chronos/
make test       # pytest
make probe      # compile the C behaviour probe
make demo       # probe + full sandbox run
```

All three quality gates must pass before a PR is merged:

```bash
ruff check .
mypy chronos/
pytest
```

## Guidelines

- Keep changes **observation-only**: the tracer and sinkhole must never patch
  the traced process, serve payloads, or relay traffic off-loopback.
- Follow the existing style: Python 3.10+ target, `dataclasses(slots=True)`,
  type annotations, `from __future__ import annotations`, line length 100.
- Monitors emit semantic `BehaviorEvent`s; analyzers consume only those and
  return `Indicator`s with a MITRE ATT&CK ID. Raw-syscall parsing lives in
  the runtime layer (`chronos/core/tracer.py`).
- Add tests: pipeline tests live in `tests/`, the real ptrace tests in
  `tests/test_linux_tracer.py` (skipped on non-Linux), sinkhole tests in
  `tests/test_sinkhole.py`.

## Pull requests

1. Branch from `main` with a short descriptive name.
2. One logical change per PR.
3. Update the relevant docs (`README.md`, `docs/`, `CHANGELOG.md`).
4. Reference the issue/feature your PR addresses.

## Security

Do not open issues for security vulnerabilities — follow
[SECURITY.md](SECURITY.md).
