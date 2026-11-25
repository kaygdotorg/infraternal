#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Interactive TCP round trip under bulk load, for run.sh.

A ping is the wrong probe for a userspace tunnel: it busy-waits at 100 Hz (it costs the
engines 1 to 9% of throughput) and it travels as a small non-TCP packet, which an engine
may schedule differently from a keystroke. A keystroke is a TCP segment that carries data.
This tool measures that case.

    rr.py serve IP PORT
        Echo server: each 64-byte request names its reply length; the reply carries the
        request's sequence number first and is padded to that length.
    rr.py client IP PORT REPLY_LEN INTERVAL_MS SECONDS OUT.json
        Open loop: one 64-byte request every interval on an absolute schedule
        (TCP_NODELAY), whether or not earlier replies came back, so one slow reply never
        hides the next. A reader thread stamps each reply by sequence number. Writes
        p50/p99/p999 of the round trip in ms; unanswered requests count as infinite.
"""

import json
import math
import socket
import struct
import sys
import threading
import time

REQ = 64
HDR = struct.Struct("!IH")


def recv_exact(sock, n):
    """Read exactly n bytes, or return None when the peer closed the connection."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return bytes(buf)


def serve(ip, port):
    """Answer requests forever, one thread per connection."""
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((ip, port))
    lsock.listen(16)

    def handle(conn):
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with conn:
            while True:
                req = recv_exact(conn, REQ)
                if req is None:
                    return
                seq, rlen = HDR.unpack_from(req)
                conn.sendall(
                    HDR.pack(seq, rlen) + b"\0" * (max(rlen, HDR.size) - HDR.size)
                )

    while True:
        conn, _ = lsock.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def pct(values, q):
    """Nearest-rank percentile of a sorted copy; NaN when empty."""
    if not values:
        return math.nan
    s = sorted(values)
    return s[max(1, math.ceil(q * len(s))) - 1]


def client(ip, port, rlen, interval_ms, seconds, out):
    """Send requests on a fixed schedule and write the round-trip summary to `out`."""
    sock = socket.create_connection((ip, port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(None)
    n = int(seconds * 1000 / interval_ms)
    sent = [0] * n
    rtt = [math.inf] * n
    done = threading.Event()

    def reader():
        for _ in range(n):
            rep = recv_exact(sock, max(rlen, HDR.size))
            if rep is None:
                break
            seq, _ = HDR.unpack_from(rep)
            if seq < n and sent[seq]:
                rtt[seq] = (time.monotonic_ns() - sent[seq]) / 1e6
        done.set()

    threading.Thread(target=reader, daemon=True).start()
    pad = b"\0" * (REQ - HDR.size)
    start = time.monotonic_ns()
    for seq in range(n):
        wait = (start + seq * interval_ms * 1_000_000 - time.monotonic_ns()) / 1e9
        if wait > 0:
            time.sleep(wait)  # the open-loop schedule between requests
        sent[seq] = time.monotonic_ns()
        sock.sendall(HDR.pack(seq, rlen) + pad)
    done.wait(timeout=3)
    got = [r for r in rtt if r != math.inf]
    res = {
        "reply_len": rlen,
        "interval_ms": interval_ms,
        "sent": n,
        "lost": n - len(got),
        "p50_ms": pct(got, 0.5),
        "p99_ms": pct(rtt, 0.99),
        "p999_ms": pct(rtt, 0.999),
        "max_ms": max(got, default=math.nan),
    }
    with open(out, "w") as f:
        json.dump(res, f)
    sock.close()


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "serve":
        serve(sys.argv[2], int(sys.argv[3]))
    elif len(sys.argv) == 8 and sys.argv[1] == "client":
        client(
            sys.argv[2],
            int(sys.argv[3]),
            int(sys.argv[4]),
            float(sys.argv[5]),
            float(sys.argv[6]),
            sys.argv[7],
        )
    else:
        sys.exit(__doc__)
