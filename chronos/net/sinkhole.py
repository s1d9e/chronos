"""Loopback DNS + HTTP sinkhole servers (observation only).

Design constraints:
- bound to 127.0.0.1 only, never exposed to the network;
- DNS answers resolve to the loopback address so HTTP callbacks are captured
  locally instead of reaching a real host;
- HTTP responses are empty (Content-Length: 0): no payload is ever served,
  no redirect, no JavaScript, no binary data;
- every query / request is recorded for analysis.

This mirrors the behaviour of tools like INetSim or FakeNet-NG but is
explicitly read-only for the sample: nothing is relayed, nothing is executed.
"""

from __future__ import annotations

import http.server
import socket
import struct
import threading
import time
from dataclasses import dataclass

MAX_DNS_NAME = 253
QTYPE_NAMES = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 33: "SRV"}
_RESOLVE_TTL = 60


@dataclass(slots=True)
class DNSRecord:
    """A DNS query captured by the sinkhole."""

    qname: str
    qtype: int
    qtype_name: str
    ts: float
    src: str


@dataclass(slots=True)
class HTTPRecord:
    """An HTTP request captured by the sinkhole."""

    method: str
    uri: str
    headers: dict[str, str]
    body: str
    ts: float
    src: str


class Sinkhole:
    """Start/stop loopback DNS and HTTP sinkhole servers."""

    def __init__(
        self,
        dns_port: int = 5353,
        http_port: int = 8080,
        resolve_ip: str = "127.0.0.1",
        http_preview: int = 256,
    ) -> None:
        self.dns_port = dns_port
        self.http_port = http_port
        self.resolve_ip = resolve_ip
        self.http_preview = http_preview
        self.dns_records: list[DNSRecord] = []
        self.http_records: list[HTTPRecord] = []
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._http: http.server.ThreadingHTTPServer | None = None
        self._running = False

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._running:
            return
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp.bind(("127.0.0.1", self.dns_port))
        self.dns_port = self._udp.getsockname()[1]

        self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp.bind(("127.0.0.1", self.dns_port))
        self._tcp.listen(16)

        handler = _make_handler(self)
        self._http = http.server.ThreadingHTTPServer(("127.0.0.1", self.http_port), handler)
        self.http_port = self._http.server_address[1]

        self._running = True
        for target in (self._serve_udp, self._serve_tcp, self._serve_http):
            t = threading.Thread(target=target, daemon=True, name=f"sinkhole-{target.__name__}")
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._running = False
        if self._udp:
            self._udp.close()
        if self._tcp:
            self._tcp.close()
        if self._http:
            self._http.shutdown()
            self._http.server_close()
        for t in self._threads:
            t.join(timeout=2)
        self._threads.clear()

    # -- record collection ----------------------------------------------------

    def _record_dns(self, qname: str, qtype: int, src: str) -> None:
        with self._lock:
            self.dns_records.append(DNSRecord(
                qname=qname,
                qtype=qtype,
                qtype_name=QTYPE_NAMES.get(qtype, f"qtype{qtype}"),
                ts=time.monotonic(),
                src=src,
            ))

    def _record_http(self, method: str, uri: str, headers: dict[str, str], body: str, src: str) -> None:
        with self._lock:
            self.http_records.append(HTTPRecord(
                method=method, uri=uri, headers=dict(headers),
                body=body, ts=time.monotonic(), src=src,
            ))

    # -- DNS servers ------------------------------------------------------------

    def _serve_udp(self) -> None:
        assert self._udp is not None
        while self._running:
            try:
                data, addr = self._udp.recvfrom(4096)
            except OSError:
                if self._running:
                    continue
                break
            try:
                qname, qtype, _, _ = _parse_query(data)
            except ValueError:
                continue
            self._record_dns(qname, qtype, f"{addr[0]}:{addr[1]}")
            resp = _dns_respond(data, self.resolve_ip)
            if resp:
                try:
                    self._udp.sendto(resp, addr)
                except OSError:
                    continue

    def _serve_tcp(self) -> None:
        assert self._tcp is not None
        self._tcp.settimeout(1.0)
        while self._running:
            try:
                conn, _ = self._tcp.accept()
            except (TimeoutError, OSError):
                continue
            conn.settimeout(5.0)
            try:
                length = struct.unpack("!H", _recv_exact(conn, 2))[0]
                data = _recv_exact(conn, length)
                qname, qtype, _, _ = _parse_query(data)
                self._record_dns(qname, qtype, f"{conn.getpeername()[0]}:{conn.getpeername()[1]}")
                resp = _dns_respond(data, self.resolve_ip)
                if resp:
                    conn.sendall(struct.pack("!H", len(resp)) + resp)
            except (OSError, ValueError):
                pass
            finally:
                conn.close()

    # -- HTTP server ---------------------------------------------------------------

    def _serve_http(self) -> None:
        assert self._http is not None
        self._http.serve_forever(poll_interval=0.1)


def _make_handler(sinkhole: Sinkhole) -> type[http.server.BaseHTTPRequestHandler]:
    class _Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"
        server_version = "ChronosSinkhole/1.0"

        def _capture(self) -> None:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = ""
            if length > 0:
                raw = self.rfile.read(min(length, sinkhole.http_preview))
                body = raw.decode("utf-8", "replace")
            sinkhole._record_http(
                self.command, self.path, dict(self.headers), body,
                f"{self.client_address[0]}:{self.client_address[1]}",
            )

        def _respond_empty(self) -> None:
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            self._capture()
            self._respond_empty()

        def do_POST(self) -> None:  # noqa: N802
            self._capture()
            self._respond_empty()

        def do_PUT(self) -> None:  # noqa: N802
            self._capture()
            self._respond_empty()

        def do_PATCH(self) -> None:  # noqa: N802
            self._capture()
            self._respond_empty()

        def do_DELETE(self) -> None:  # noqa: N802
            self._capture()
            self._respond_empty()

        def do_HEAD(self) -> None:  # noqa: N802
            self._capture()
            self._respond_empty()

        def do_OPTIONS(self) -> None:  # noqa: N802
            self._capture()
            self._respond_empty()

        def log_message(self, *args: object) -> None:  # silence
            pass

    return _Handler


# -- DNS wire protocol helpers -------------------------------------------------

def _recv_exact(conn: socket.socket, n: int) -> bytes:
    data = bytearray()
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            raise OSError("eof")
        data.extend(chunk)
    return bytes(data)


def _parse_query(data: bytes) -> tuple[str, int, int, int]:
    """Parse a DNS query header + first question. Returns (qname, qtype, qclass, id)."""
    if len(data) < 12:
        raise ValueError("short dns header")
    qid, flags, qdcount = struct.unpack("!HHH", data[:6])
    if qdcount < 1:
        raise ValueError("no question")
    labels: list[str] = []
    pos = 12
    total = 0
    while True:
        if pos >= len(data):
            raise ValueError("truncated name")
        ln = data[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0:
            raise ValueError("compression in query name")
        if pos + 1 + ln > len(data):
            raise ValueError("name overruns")
        labels.append(data[pos + 1:pos + 1 + ln].decode("ascii", "replace"))
        pos += 1 + ln
        total += ln + 1
        if total > MAX_DNS_NAME:
            raise ValueError("name too long")
    if pos + 4 > len(data):
        raise ValueError("no type/class")
    qtype, qclass = struct.unpack("!HH", data[pos:pos + 4])
    return ".".join(labels) or ".", qtype, qclass, qid


def _dns_respond(data: bytes, resolve_ip: str) -> bytes | None:
    """Build a DNS response for a query, or None if it cannot be parsed."""
    qname, qtype, qclass, qid = _parse_query(data)
    _ = qclass  # answered regardless of class
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    question = _encode_name(qname) + struct.pack("!HH", qtype, qclass)
    ip = socket.inet_aton(resolve_ip)
    answer = _encode_name_pointer(12) + struct.pack("!HHIH", 1, 1, _RESOLVE_TTL, 4) + ip
    if qtype == 28:  # AAAA: no answer, let the client fall back to A
        header = struct.pack("!HHHHHH", qid, 0x8180, 1, 0, 0, 0)
        return header + question
    if qtype != 1:
        header = struct.pack("!HHHHHH", qid, 0x8180, 1, 0, 0, 0)
        return header + question
    return header + question + answer


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii", "replace")
        out.append(len(b) & 0x3F)
        out.extend(b)
    out.append(0)
    return bytes(out)


def _encode_name_pointer(offset: int) -> bytes:
    return struct.pack("!H", 0xC000 | offset)


__all__ = ["DNSRecord", "HTTPRecord", "Sinkhole"]
