# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-14

### Added

- Linux syscall tracer in pure `ptrace(2)` (no strace): x86_64 and aarch64
  syscall tables, process-tree following (fork/clone/exec/exit), argument
  decoding (paths, open flags, socket addresses, mmap/mprotect protections,
  I/O previews), hard-timeout kill of the whole tracee tree.
- Loopback DNS + HTTP sinkhole (`--sinkhole`): intercepts C2 traffic so it
  never leaves the host. Observation only — empty responses, no relay.
- Behavioral monitors: filesystem, process, network, memory.
- Technique analyzers mapped to MITRE ATT&CK: process injection, evasion /
  unhooking, sleep obfuscation, anti-debug, persistence, C2 beaconing, trace
  erasure — including DGA and periodic-HTTP-callback detection.
- SQLite trace storage with per-run replay (`chronos replay --db x --run N`).
- Terminal and JSON reporting with threat scoring.
- Windows backend via Frida (optional extra), simulated scenarios for offline
  demos and tests.
- Examples: C behaviour probe, sinkhole probe, sample TOML configuration.
