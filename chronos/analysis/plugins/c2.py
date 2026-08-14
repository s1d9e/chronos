"""Network heuristics: outbound contacts, beaconing, sinkhole captures."""

from __future__ import annotations

import math
import re
from collections import defaultdict

from chronos.events import BehaviorEvent, SyscallEvent
from chronos.models import Indicator

from ..base import Analyzer, bev_by_op, mk

_SUSPICIOUS_PORTS = {4444, 1337, 31337, 5555, 6666, 7777, 8888, 9999, 8080, 8443}


class C2NetworkAnalyzer(Analyzer):
    name = "c2_network"
    mitre = "T1071"
    description = "Command & control beaconing and suspicious outbound contacts."

    def analyze(self, behaviors: list[BehaviorEvent], events: list[SyscallEvent]) -> list[Indicator]:
        found: list[Indicator] = []
        connects = bev_by_op(behaviors, "connect")

        if connects:
            # 1) suspicious ports
            odd = [b for b in connects if _port(b.target) in _SUSPICIOUS_PORTS]
            if odd:
                found.append(mk(
                    "Connection to suspicious port", self.mitre, "MEDIUM", 0.6,
                    [f"[{b.seq}] pid {b.pid} connect {b.target}" for b in odd[:6]],
                    count=len(odd),
                ))

            # 2) private / documentation range destinations (no external sinkhole)
            localish = [b for b in connects if _is_odd_dest(b.target)]
            if localish:
                found.append(mk(
                    "Connection to non-routable / doc-range address", self.mitre,
                    "LOW", 0.4,
                    [f"[{b.seq}] {b.target}" for b in localish[:6]],
                    count=len(localish),
                ))

            # 3) beaconing: repeated connections to the same host
            per_host: dict[str, list[BehaviorEvent]] = defaultdict(list)
            for b in connects:
                host = _host(b.target)
                if host:
                    per_host[host].append(b)
            for host, hits in per_host.items():
                if len(hits) >= self.conf.beacon_min and (hits[-1].ts - hits[0].ts) <= self.conf.beacon_window:
                    found.append(mk(
                        f"Beaconing to {host}", self.mitre, "HIGH", 0.8,
                        [f"[{b.seq}] connect {b.target}" for b in hits[:8]],
                        count=len(hits),
                    ))

            # 4) exfil-ish large sends
            sends = bev_by_op(behaviors, "sendto")
            big = [b for b in sends if int(b.data.get("length", 0)) > 4096]
            if big:
                found.append(mk(
                    "Large outbound transfers", self.mitre, "MEDIUM", 0.5,
                    [f"[{b.seq}] send len={b.data.get('length')} -> {b.target}" for b in big[:6]],
                    count=len(big),
                ))

        # 5) sinkhole DNS captures
        dns = bev_by_op(behaviors, "dns")
        if dns:
            dga = [b for b in dns if _looks_dga(b.target)]
            if dga:
                found.append(mk(
                    "DGA-like DNS queries (sinkhole)", self.mitre, "HIGH", 0.75,
                    [f"[{b.seq}] {b.target} ({b.data.get('qtype', '?')})" for b in dga[:6]],
                    count=len(dga),
                ))
            else:
                distinct = sorted({b.target for b in dns})
                found.append(mk(
                    "DNS queries observed (sinkhole)", self.mitre, "MEDIUM", 0.5,
                    [f"[{b.seq}] {b.target} ({b.data.get('qtype', '?')})" for b in dns[:6]],
                    count=len(dns),
                ))
                if len(distinct) >= 4:
                    found.append(mk(
                        f"High number of distinct DNS names ({len(distinct)})", self.mitre,
                        "MEDIUM", 0.55,
                        [f"{n}" for n in distinct[:8]],
                        count=len(distinct),
                    ))

        # 6) sinkhole HTTP captures
        http = bev_by_op(behaviors, "http")
        if http:
            beacon = _http_beacons(http)
            if beacon:
                found.append(mk(
                    "Periodic HTTP callback (beaconing)", self.mitre, "HIGH", 0.75,
                    beacon,
                    count=len(http),
                ))
            else:
                found.append(mk(
                    "HTTP callbacks captured (sinkhole)", self.mitre, "MEDIUM", 0.5,
                    [f"[{b.seq}] {b.data.get('method', '?')} {b.target}" for b in http[:6]],
                    count=len(http),
                ))
            posts = [b for b in http if b.data.get("method", "").upper() == "POST"]
            if posts:
                evidence = [f"[{b.seq}] POST {b.target}" for b in posts[:6]]
                if posts[0].data.get("body"):
                    evidence[0] += f" body={posts[0].data['body'][:80]!r}"
                found.append(mk(
                    "HTTP POST with body (possible exfil)", self.mitre, "MEDIUM", 0.55,
                    evidence,
                    count=len(posts),
                ))

        return found


def _http_beacons(hits: list[BehaviorEvent]) -> list[str]:
    """Return evidence lines if the same path is hit repeatedly at regular gaps."""
    per_key: dict[tuple[str, str], list[float]] = defaultdict(list)
    for b in hits:
        host = _host_from_uri(b.target)
        path = _path_from_uri(b.target)
        per_key[(host, path)].append(b.ts)
    evidence: list[str] = []
    for (host, path), stamps in per_key.items():
        stamps.sort()
        if len(stamps) < 3:
            continue
        gaps = [round(stamps[i + 1] - stamps[i], 3) for i in range(len(stamps) - 1)]
        if max(gaps) - min(gaps) <= 1.0 and gaps:
            evidence.append(f"{len(stamps)}x {host}{path} gaps={gaps[:5]}")
    return evidence[:6]


def _host_from_uri(uri: str) -> str:
    m = re.match(r"https?://([^/:]+)", uri)
    return m.group(1) if m else uri


def _path_from_uri(uri: str) -> str:
    m = re.match(r"https?://[^/]*(/[^?]*)", uri)
    return m.group(1) if m else "/"


def _looks_dga(name: str) -> bool:
    """Heuristic: a long leading label with high digit density or high entropy
    (typical of algorithmically generated domain names)."""
    label = name.split(".")[0] if "." in name else name
    if len(label) < 8 or not re.fullmatch(r"[a-z0-9]{8,}", label):
        return False
    digits = sum(c.isdigit() for c in label)
    if digits >= 3:
        return True
    entropy = 0.0
    for c in set(label):
        p = label.count(c) / len(label)
        entropy -= p * math.log2(p)
    return entropy >= 3.1


def _port(target: str) -> int | None:
    m = re.search(r":(\d+)$", target)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _host(target: str) -> str | None:
    m = re.match(r"^(?:inet |inet6 |unix:)?([0-9a-fA-F:.\[]+)", target)
    return m.group(1) if m else None


def _is_odd_dest(target: str) -> bool:
    ip = re.match(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", target)
    if not ip:
        return False
    a, b, c, _ = (int(g) for g in ip.groups())
    return (
        a == 127 or a == 0 or a == 10
        or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31)
        or (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113))
    )
