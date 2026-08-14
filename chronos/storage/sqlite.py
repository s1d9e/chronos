"""SQLite-backed trace storage with replay support.

A raw trace is persisted so the analysis pass can be re-run later with new
plugins or updated configs — no need to re-execute the sample.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from chronos.events import BehaviorEvent, SyscallEvent


class TraceStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sample TEXT, started REAL, duration REAL,
                timed_out INTEGER, exit_code INTEGER
            );
            CREATE TABLE IF NOT EXISTS events (
                run_id INTEGER, seq INTEGER, pid INTEGER, tid INTEGER, ts REAL,
                syscall TEXT, nr INTEGER, args TEXT, ret INTEGER,
                err TEXT, info TEXT, arch TEXT
            );
            CREATE TABLE IF NOT EXISTS behaviors (
                run_id INTEGER, seq INTEGER, pid INTEGER, tid INTEGER, ts REAL,
                category TEXT, op TEXT, target TEXT, data TEXT,
                syscall TEXT, backref INTEGER
            );
            """
        )
        # migrate schemas written before per-run partitioning
        cols = {r["name"] for r in self.conn.execute("PRAGMA table_info(events)")}
        if "run_id" not in cols:
            self.conn.executescript("DROP TABLE events; DROP TABLE behaviors;")
            self.conn.executescript(
                """
                CREATE TABLE events (
                    run_id INTEGER, seq INTEGER, pid INTEGER, tid INTEGER, ts REAL,
                    syscall TEXT, nr INTEGER, args TEXT, ret INTEGER,
                    err TEXT, info TEXT, arch TEXT
                );
                CREATE TABLE behaviors (
                    run_id INTEGER, seq INTEGER, pid INTEGER, tid INTEGER, ts REAL,
                    category TEXT, op TEXT, target TEXT, data TEXT,
                    syscall TEXT, backref INTEGER
                );
                """
            )
        self.conn.commit()

    def save(
        self,
        sample: str,
        started: float,
        duration: float,
        timed_out: bool,
        exit_code: int | None,
        events: list[SyscallEvent],
        behaviors: list[BehaviorEvent],
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO runs(sample, started, duration, timed_out, exit_code) VALUES(?,?,?,?,?)",
            (sample, started, duration, int(timed_out), exit_code),
        )
        run_id = int(cur.lastrowid or 0)
        self.conn.executemany(
            "INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    run_id, e.seq, e.pid, e.tid, e.ts, e.syscall, e.nr,
                    json.dumps(e.args), e.ret, e.err, json.dumps(e.info), e.arch,
                )
                for e in events
            ],
        )
        self.conn.executemany(
            "INSERT INTO behaviors VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    run_id, b.seq, b.pid, b.tid, b.ts, b.category, b.op, b.target,
                    json.dumps(b.data), b.syscall, b.backref,
                )
                for b in behaviors
            ],
        )
        self.conn.commit()
        return run_id

    def _latest_run_id(self) -> int | None:
        row = self.conn.execute("SELECT MAX(id) AS m FROM runs").fetchone()
        return int(row["m"]) if row and row["m"] is not None else None

    def load_events(self, run_id: int | None = None) -> list[SyscallEvent]:
        if run_id is None:
            run_id = self._latest_run_id()
        if run_id is None:
            return []
        rows = self.conn.execute(
            "SELECT * FROM events WHERE run_id = ? ORDER BY seq", (run_id,)
        ).fetchall()
        return [
            SyscallEvent(
                seq=r["seq"], pid=r["pid"], tid=r["tid"], ts=r["ts"],
                syscall=r["syscall"], nr=r["nr"],
                args=json.loads(r["args"]),
                ret=r["ret"] if r["ret"] is not None else None,
                err=r["err"],
                info=json.loads(r["info"]), arch=r["arch"],
            )
            for r in rows
        ]

    def load_behaviors(self, run_id: int | None = None) -> list[BehaviorEvent]:
        if run_id is None:
            run_id = self._latest_run_id()
        if run_id is None:
            return []
        rows = self.conn.execute(
            "SELECT * FROM behaviors WHERE run_id = ? ORDER BY seq", (run_id,)
        ).fetchall()
        return [
            BehaviorEvent(
                seq=r["seq"], pid=r["pid"], tid=r["tid"], ts=r["ts"],
                category=r["category"], op=r["op"], target=r["target"],
                data=json.loads(r["data"]), syscall=r["syscall"], backref=r["backref"],
            )
            for r in rows
        ]

    def runs(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM runs ORDER BY id DESC")]

    def close(self) -> None:
        self.conn.close()
