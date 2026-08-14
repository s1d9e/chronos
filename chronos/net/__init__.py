"""Sinkhole: loopback-only DNS + HTTP servers that observe outbound traffic.

Observation only: no payload is served and no traffic is relayed outside the
loopback interface. DNS queries are answered with a loopback address so the
sample's HTTP callbacks are captured by the local HTTP sinkhole instead of
leaving the host.
"""

from __future__ import annotations

from chronos.net.sinkhole import DNSRecord, HTTPRecord, Sinkhole

__all__ = ["DNSRecord", "HTTPRecord", "Sinkhole"]
