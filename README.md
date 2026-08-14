# Chronos — Dynamic Analysis Engine & Private Sandbox

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB.svg?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Ruff-0_errors-000000.svg" alt="Ruff">
  <img src="https://img.shields.io/badge/Mypy-0_errors-964EE8.svg" alt="Mypy">
  <img src="https://img.shields.io/badge/Tests-pytest-2ECC71.svg" alt="Tests">
</p>

Chronos observes **what a binary actually does** by executing it under
instrumentation and folding the raw observation stream into behavior, then
into technique indicators — for blue team, DFIR and malware research.

Observation only. Chronos never patches the traced process, never modifies
its memory or control flow, and emits no guidance about how to act.

---

## What it does

| Layer | What |
|-------|------|
| **Instrumentation** | Usermode syscall tracing on Linux (pure-`ptrace(2)`, no strace). Windows backend via Frida native API hooks. |
| **Sandbox / isolation** | Runs the sample as a controlled child process with timeout kill; structured event stream recorded. |
| **Sinkhole** | Loopback DNS + HTTP servers that intercept outbound C2 traffic so it never leaves the host. |
| **Monitoring** | Filesystem, process, network, memory behaviors folded from raw events. |
| **Analysis** | Plugin analyzers detect techniques (injection, unhooking, sleep obfuscation, anti-debug, persistence, C2, trace erasure) **as observation**. |
| **Reporting** | Timeline + indicators + MITRE ATT&CK mapping, terminal and JSON. |
| **Storage** | Raw traces persisted to SQLite — replay the analysis without re-running the sample. |

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
# Replay a saved trace (pick a specific run with --run N):
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
with a live traced process — see `examples/behaviour_probe.c`.

## Sinkhole

`--sinkhole` starts a loopback DNS (UDP+TCP) and HTTP sinkhole. DNS queries
are answered with `127.0.0.1` so the sample's HTTP callbacks land on the
local sinkhole instead of reaching a real host; every query and request is
recorded and analyzed (DGA-looking names, periodic beaconing, POST bodies).
**Observation only**: responses are empty, nothing is relayed and nothing is
served back to the sample. Defaults: `--dns-port 5353`, `--http-port 8080`
(bind 53/80 only as root). See `chronos/net/sinkhole.py`.

## Linux backend

`chronos run -- /path/to/sample` forks the sample, applies `PTRACE_TRACEME`,
then walks the process tree (fork/clone/exec/exit events) decoding ~90
syscalls on x86_64 (aarch64 supported subset): paths, open flags, socket
addresses, mmap/mprotect protections, I/O buffer previews. See
`chronos/core/tracer.py`.

## Windows backend

Install `pip install "chronos[windows]"` and run on a Windows host (ideally a
disposable VM). `windows-frida` spawns the sample under Frida and hooks
`kernel32` / `advapi32` / `ws2_32` / `ntdll` primitives (VirtualAlloc,
VirtualProtect, WriteProcessMemory, CreateRemoteThread, CreateFile, registry,
connect/sendto, debugger queries...). Run it from a dedicated low-privilege
account.

## Configuration

```bash
chronos run --config sandbox.toml -- ./sample
```

See `chronos/config.py` for tunables (timeout, persistence paths, beacon
thresholds, RWX flagging, I/O capture, sinkhole ports).

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy chronos/
```

## Legal

**For authorized security research, blue team and DFIR use only.** Analyze
only binaries you own or are explicitly authorized to analyze. See
`LEGAL.md`.

## License

MIT. Built by [s1d9e](https://github.com/s1d9e).
