"""Loopback sinkhole tests: DNS wire parsing, HTTP capture, analyzer integration."""

from __future__ import annotations

import socket
import struct

from chronos.config import Config
from chronos.events import BehaviorEvent


def _dns_query(qname: str, qid: int = 0x1234, qtype: int = 1) -> bytes:
    out = bytearray()
    for label in qname.rstrip(".").split("."):
        b = label.encode("ascii")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    return header + bytes(out) + struct.pack("!HH", qtype, 1)


def _start_sinkhole():
    from chronos.net import Sinkhole

    sh = Sinkhole(dns_port=0, http_port=0)
    sh.start()
    return sh


def test_dns_answers_a_record_and_records_query():
    sh = _start_sinkhole()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        q = _dns_query("deadbeef1234.example.com")
        sock.sendto(q, ("127.0.0.1", sh.dns_port))
        resp = sock.recvfrom(512)[0]
        sock.close()

        qid = struct.unpack("!H", resp[:2])[0]
        ancount = struct.unpack("!H", resp[6:8])[0]
        assert qid == 0x1234
        assert ancount == 1
        assert socket.inet_aton("127.0.0.1") in resp  # resolves to loopback
        assert sh.dns_records and sh.dns_records[0].qname == "deadbeef1234.example.com"
    finally:
        sh.stop()


def test_dns_aaaa_query_gets_no_answer():
    sh = _start_sinkhole()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(_dns_query("www.example.com", qtype=28), ("127.0.0.1", sh.dns_port))
        resp = sock.recvfrom(512)[0]
        sock.close()
        assert struct.unpack("!H", resp[6:8])[0] == 0
    finally:
        sh.stop()


def test_http_captures_request_and_serves_empty_response():
    sh = _start_sinkhole()
    try:
        s = socket.create_connection(("127.0.0.1", sh.http_port), timeout=3)
        s.sendall(b"GET /img/upd HTTP/1.0\r\nHost: stage.example\r\n\r\n")
        data = s.recv(512)
        s.close()
        assert data.startswith(b"HTTP/1.0 200")
        assert len(sh.http_records) == 1
        rec = sh.http_records[0]
        assert rec.method == "GET"
        assert rec.uri == "/img/upd"
        assert rec.headers.get("Host") == "stage.example"
    finally:
        sh.stop()


def test_analyzer_flags_dga_dns_and_http_callbacks():
    from chronos.analysis.plugins.c2 import C2NetworkAnalyzer

    analyzer = C2NetworkAnalyzer(Config.default())
    behaviors = [
        BehaviorEvent(1, 0, 0, 0.0, "network", "dns", "deadbeef1234.example.com", data={"qtype": "A"}),
        BehaviorEvent(2, 0, 0, 0.1, "network", "http", "http://stage.example/img/upd", data={"method": "GET"}),
    ]
    indicators = analyzer.analyze(behaviors, [])
    names = {i.technique for i in indicators}
    assert "DGA-like DNS queries (sinkhole)" in names
    assert "HTTP callbacks captured (sinkhole)" in names


def test_analyzer_detects_periodic_http_beacon():
    from chronos.analysis.plugins.c2 import C2NetworkAnalyzer

    analyzer = C2NetworkAnalyzer(Config.default())
    behaviors = [
        BehaviorEvent(i, 0, 0, float(i), "network", "http",
                      "http://stage.example/img/upd", data={"method": "GET"})
        for i in range(1, 5)
    ]
    indicators = analyzer.analyze(behaviors, [])
    assert any("Periodic HTTP callback" in i.technique for i in indicators)


def test_sandbox_integration_appends_sinkhole_behaviors():
    from chronos.analysis import AnalysisEngine
    from chronos.monitors import run_monitors
    from chronos.sandbox import _sinkhole_behaviors

    sh = _start_sinkhole()
    try:
        # one DNS query through the real server
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(_dns_query("cnc.example.net"), ("127.0.0.1", sh.dns_port))
        sock.recvfrom(512)[0]
        sock.close()

        behs = _sinkhole_behaviors(sh, start_seq=99)
        assert any(b.op == "dns" and b.target == "cnc.example.net" for b in behs)
        # and the full pipeline consumes them
        engine = AnalysisEngine(Config.default())
        inds = engine.analyze(behs, [], Config.default())
        assert any("DNS queries observed" in i.technique for i in inds)
        run_monitors([], [])  # no-op guard: behaviors are already semantic
    finally:
        sh.stop()
