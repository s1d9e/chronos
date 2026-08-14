"""Benign demo sample for the Chronos loopback sinkhole.

Sends a raw DNS query for a DGA-looking name to the sinkhole DNS server, then
performs three HTTP callbacks to the sinkhole HTTP server (beaconing pattern).
Everything stays on 127.0.0.1. Usage:
    chronos run --sinkhole --dns-port 5353 --http-port 8080 -- \
        python3 examples/sinkhole_probe.py
"""

from __future__ import annotations

import contextlib
import socket
import struct
import sys
import time

DNS_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5353
HTTP_PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
QNAME = b"\x0cdeadbeef1234\x07example\x03com\x00"


def _dns_query() -> bytes:
    header = struct.pack("!HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
    return header + QNAME + struct.pack("!HH", 1, 1)


def main() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.sendto(_dns_query(), ("127.0.0.1", DNS_PORT))
    with contextlib.suppress(OSError):
        sock.recvfrom(512)
    sock.close()

    for _ in range(3):
        conn = socket.create_connection(("127.0.0.1", HTTP_PORT), timeout=3)
        conn.sendall(b"GET /img/upd?c=1 HTTP/1.0\r\nHost: stage.example\r\n\r\n")
        with contextlib.suppress(OSError):
            conn.recv(512)
        conn.close()
        time.sleep(0.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
