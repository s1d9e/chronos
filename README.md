# Chronos — Dynamic Analysis Engine & Private Sandbox

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/s1d9e/chronos/ci.yml?branch=main&label=CI&logo=github" alt="CI">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Ruff-0_errors-000000.svg" alt="Ruff">
  <img src="https://img.shields.io/badge/Mypy-0_errors-964EE8.svg" alt="Mypy">
  <img src="https://img.shields.io/badge/Tests-16_passing-2ECC71.svg" alt="Tests">
  <img src="https://img.shields.io/github/stars/s1d9e/chronos?style=social&label=Stars" alt="Stars">
</p>

**Chronos observes what a binary actually does** by executing it under
instrumentation and folding the raw observation stream into behavior, then
into technique indicators — for blue team, DFIR and malware research.

**Observation only.** Chronos never patches the traced process, never modifies
its memory or control flow, serves no payloads, relays no traffic, and emits
no guidance about how to act. See [LEGAL.md](LEGAL.md).

---

## Features

- **Real syscall tracing** — pure `ptrace(2)` on Linux (no strace binary), with
  argument decoding: paths, open flags, socket addresses, memory protections
  and I/O previews. x86_64 + aarch64, full process-tree following.
- **Network sinkhole** — loopback DNS + HTTP servers that intercept C2 traffic
  so it never leaves the host. Every query and request is recorded; responses
  are empty.
- **Behavioral monitoring** — filesystem, process, network and memory behavior
  folded from raw events.
- **MITRE-mapped analysis** — plugin analyzers flag techniques (T1055, T1562,
  T1027.001, T1622, T1547, T1071, T1070…) with severity, confidence and
  evidence.
- **Replay-first storage** — every run persists to SQLite; re-analyze later
  with new plugins or configs without re-running the sample.
- **Portable reporting** — terminal and JSON, threat scoring included.
- **Windows backend** — optional Frida hooks (`pip install "chronos[windows]"`).

## Quick start

```bash
pip install -e .
# Trace a real binary (Linux): compile the probe first
gcc -O0 -o /tmp/probe examples/behaviour_probe.c
chronos run -- /tmp/probe
# Sinkhole demo: intercept DNS + HTTP C2 traffic on loopback
chronos run --sinkhole --dns-port 5353 --http-port 8080 -- \
    python3 examples/sinkhole_probe.py
# Offline demo:
chronos simulate --scenario evil
# Replay a saved trace (pick a run with --run N):
chronos run --db trace.db -- /bin/true && chronos replay --db trace.db
```

## Demo

`chronos simulate --scenario evil`:

```
  THREAT SCORE:  ██████████████████████████████░░░░░░░░░░  (30) [CRITICAL]

  [ INDICATORS ]
  [HIGH] Beaconing to 203.0.113.7:4444 (T1071) conf=80% x3
  [HIGH] RWX executable memory region (T1055) conf=70%
  [HIGH] Memory hidden then restored (sleep obfuscation) (T1027.001)
  [HIGH] Write to autostart / scheduler path (T1547)
  [MED]  Trace-state probing (/proc/self/status) (T1622)
  [MED]  Write-then-delete (artifacts removed) (T1070)

  [ TIMELINE ]
    0.001  pid 1000  filesystem  open_read    /proc/self/status
    0.004  pid 1000  memory      rwx_alloc    0x0 len=4096 prot=RWX
    0.005  pid 1000  memory      protect_none 0x700000000000 prot=NONE
    ...
```

The real Linux run (`chronos run -- ./probe`) feeds the exact same pipeline
with a live traced process — see `examples/behaviour_probe.c`. With the
sinkhole enabled, a sample that resolves a DGA-looking domain and beacons over
HTTP yields:

```
  [HIGH] Periodic HTTP callback (beaconing) (T1071) conf=75% x3
      3x /img/upd?c=1/ gaps=[0.224, 0.224]
  [HIGH] DGA-like DNS queries (sinkhole) (T1071) conf=75% x1
      [989] deadbeef1234.example.com (A)
```

## Architecture

| Layer | What |
|-------|------|
| **Instrumentation** | Usermode syscall tracing on Linux (pure `ptrace(2)`). Windows backend via Frida native API hooks. |
| **Sandbox / isolation** | Runs the sample as a controlled child process with timeout kill; structured event stream recorded. |
| **Sinkhole** | Loopback DNS + HTTP servers that intercept outbound C2 traffic so it never leaves the host. |
| **Monitoring** | Filesystem, process, network, memory behaviors folded from raw events. |
| **Analysis** | Plugin analyzers detect techniques as **observation** (injection, unhooking, sleep obfuscation, anti-debug, persistence, C2, trace erasure). |
| **Reporting** | Timeline + indicators + MITRE ATT&CK mapping, terminal and JSON. |
| **Storage** | Raw traces persisted to SQLite — replay the analysis without re-running the sample. |

See [docs/architecture.md](docs/architecture.md) for the data flow and design
decisions.

## Configuration

```bash
chronos run --config examples/sandbox.toml -- ./sample
```

Tunables: timeout, persistence paths, anti-debug reads, beacon thresholds,
RWX flagging, I/O capture, sinkhole ports. See `chronos/config.py`.

## Backends

| Backend | Platform | Method |
|---------|----------|--------|
| `linux-ptrace` (default on Linux) | Linux | `ptrace(2)` syscall tracing |
| `windows-frida` | Windows | Frida hooks on `kernel32` / `ntdll` / `ws2_32` / `advapi32` |
| `simulated` | any | Scripted event stream for demos and tests |

## Development

```bash
pip install -e ".[dev]"
make lint && make typecheck && make test
```

All quality gates are enforced in CI. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- Restricted-token / AppContainer profile for the Windows backend.
- `chronos serve` — FastAPI server for headless analysis pipelines.
- Sandbox networking policy (per-process allowlist, egress control).

## Security

Found a vulnerability? Do **not** open a public issue — follow
[SECURITY.md](SECURITY.md).

## Legal

**For authorized security research, blue team and DFIR use only.** Analyze
only binaries you own or are explicitly authorized to analyze. See
[LEGAL.md](LEGAL.md).

## License

[MIT](LICENSE). Built by [s1d9e](https://github.com/s1d9e).
