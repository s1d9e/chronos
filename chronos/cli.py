"""Chronos CLI.

Examples
--------
Trace a real binary on Linux:
    chronos run -- ./probe /tmp/ct

Offline demo with a scripted scenario:
    chronos simulate --scenario evil

Re-run analysis on a saved trace:
    chronos replay trace.db

JSON export:
    chronos run --json report.json -- ./sample
"""

from __future__ import annotations

import argparse
import sys

from chronos import __version__
from chronos import config as cfg
from chronos.reporting.report import render, write_json
from chronos.runtimes.simulated import list_scenarios
from chronos.sandbox import Sandbox


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chronos",
        description="Private dynamic analysis engine and sandbox for malware research.",
    )
    parser.add_argument("--version", action="version", version=f"chronos {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Trace and analyze a command/binary.")
    run.add_argument("--config", default=None, help="TOML config path")
    run.add_argument("--runtime", default=None, choices=["linux-ptrace", "simulated", "windows-frida"])
    run.add_argument("--timeout", type=float, default=None, help="override analysis timeout (s)")
    run.add_argument("--json", default=None, help="write machine-readable report to path")
    run.add_argument("--db", default=None, help="persist raw trace to SQLite path")
    run.add_argument("--no-io", action="store_true", help="disable I/O buffer capture")
    run.add_argument("--sinkhole", action="store_true",
                     help="intercept DNS/HTTP on loopback (observation only)")
    run.add_argument("--dns-port", type=int, default=None, help="sinkhole DNS port (default 5353)")
    run.add_argument("--http-port", type=int, default=None, help="sinkhole HTTP port (default 8080)")
    run.add_argument("argv", nargs="+", metavar="CMD", help="command to execute (-- /path/to/sample ...)")

    sim = sub.add_parser("simulate", help="Run a scripted scenario end-to-end (offline).")
    sim.add_argument("--scenario", default="benign", choices=list_scenarios())
    sim.add_argument("--json", default=None)
    sim.add_argument("--db", default=None)

    rep = sub.add_parser("replay", help="Re-run analysis on a saved SQLite trace.")
    rep.add_argument("--db", required=True, help="SQLite trace path")
    rep.add_argument("--run", type=int, default=None, help="run id to replay (default: latest)")
    rep.add_argument("--json", default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    conf = cfg.Config.load(getattr(args, "config", None))
    if getattr(args, "timeout", None):
        conf.timeout = args.timeout
    if getattr(args, "no_io", False):
        conf.capture_io = False
    if getattr(args, "sinkhole", False):
        conf.sinkhole_enabled = True
    if getattr(args, "dns_port", None):
        conf.sinkhole_dns_port = args.dns_port
    if getattr(args, "http_port", None):
        conf.sinkhole_http_port = args.http_port

    sandbox = Sandbox(conf=conf, store_path=getattr(args, "db", None))

    if args.command == "run":
        report = sandbox.run(args.argv, runtime_name=args.runtime)
    elif args.command == "simulate":
        report = sandbox.run(scenario=args.scenario, runtime_name="simulated")
    elif args.command == "replay":
        report = sandbox.replay(args.db, run_id=args.run)
    else:  # pragma: no cover
        parser.error(f"unknown command: {args.command}")

    if getattr(args, "json", None):
        write_json(report, args.json)
    else:
        sys.stdout.write(render(report) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
