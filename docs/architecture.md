# Architecture

```
                    +----------------------------------------------+
                    |                 chronos run                    |
                    +----------------------------------------------+
        +-----------------+   +----------------+   +--------------+
        |    runtime       |   |    monitors    |   |   analysis   |
        |                  |   |                |   |              |
        | linux-ptrace     |   | process        |   | injection    |
        | windows-frida    |   | filesystem     |   | evasion      |
        | simulated        |   | network        |   | sleep_obf    |
        |                  |   | memory         |   | anti_debug   |
        +------------------+   +----------------+   | persistence |
               |  SyscallEvent      | BehaviorEvent | c2_network  |
               v                    v               | trace_eras  |
        +------------------+   +----------------+   +-------------+
        |   sinkhole       |   |   reporting    |        | Indicator
        | DNS+HTTP loopback|   | terminal/JSON  |        v
        | -> net behaviors |   +----------------+   +-------------+
        +------------------+                          |  Report     |
        |    storage       |                          +-------------+
        |   SQLite (replay)|
        +------------------+
```

## Data flow

1. **Runtime** executes the sample and emits `SyscallEvent`s (backend-agnostic
   raw syscalls with decoded args) — or `BehaviorEvent`s directly for
   hook-based backends (Frida).
2. **Sinkhole** (loopback DNS + HTTP) records outbound queries/requests; its
   captures are injected as `network/dns` and `network/http` behaviors.
3. **Monitors** fold raw events into canonical `BehaviorEvent`s:
   `filesystem`, `process`, `network`, `memory`, `registry`, `debugger`.
4. **AnalysisEngine** runs plugin analyzers over behaviors (+ raw events).
   Each emits `Indicator`s with severity, confidence, MITRE ID and evidence.
5. **Report** = timeline (ordered behaviors) + indicators + aggregate score.
   **Storage** persists the raw trace for replay (per-run partitionning).

## Design decisions

- **ptrace, not strace**: real argument decoding (paths, sockaddrs, memory
  protections, I/O previews), process-tree following, no external binary.
- **Monitors stay semantic**: analyzers never parse raw syscalls, so the same
  plugin set works for Linux ptrace and Windows Frida data.
- **Plugins are passive**: they produce observations with confidence, never
  "next steps". Attribution is left to the analyst.
- **Replay-first**: every run can be stored; re-analysis with new plugins or
  configs is a `chronos replay --db` away.

## Isolation model

- Sample runs as a child of the tracer; a hard timeout SIGKILLs the whole
  tracee tree (`PTRACE_O_EXITKILL`).
- On Windows, run the Frida backend inside a low-privilege dedicated account
  in a disposable VM. (Roadmap: restricted token + AppContainer profile.)
- Do not give the sandbox host credentials or broad network egress; pair with
  the network sinkhole of your choice.
