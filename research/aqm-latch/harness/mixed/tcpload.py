#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""The TCP side of the mixed flood-plus-TCP measurement (#260, J1249).

Our own small tools instead of a benchmark client, because a client with a separate control
connection can fail under a flood and take its result with it. Everything runs inside the job's
network namespaces.

    tcpload.py sink <ip> <bulk-port> <echo-port> <stats-file>
        Receiver on the hub: counts the bytes each bulk connection delivers (goodput, as the
        application sees it) and echoes the probes. Appends one JSON line every 0.25 s with the
        cumulative bytes per source address.
    tcpload.py bulk <src-ip> <dst-ip> <port> <until-epoch>
        One bulk upload from <src-ip> that sends as fast as TCP allows until <until-epoch>.
    tcpload.py probe <src-ip> <dst-ip> <port> <start-epoch> <stop-epoch> <interval-ms>
        A 64-byte request on an absolute schedule (never waiting for replies). Requests sent in
        [start, stop) are reported on stdout as one JSON object with their round trips in ms;
        a request unanswered 3 s after <stop-epoch> counts as lost.
"""
import json
import socket
import struct
import sys
import threading
import time

#: Size of every probe request and reply: small, like a keystroke, and under the engine's
#: 256-byte "sparse" exemption.
SIZE = 64
#: Request header: the sequence number.
HEAD = struct.Struct("!I")


def connect(src, dst, port, give_up):
    """Connect from `src` to `dst:port`, retrying until the epoch `give_up`."""
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind((src, 0))
            sock.settimeout(3)
            sock.connect((dst, port))
            sock.settimeout(None)
            return sock
        except OSError:
            sock.close()
            if time.time() > give_up:
                raise
            time.sleep(0.2)


def read_exact(conn, length):
    """Read exactly `length` bytes, or return None once the peer has closed."""
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return bytes(data)


def sink(ip, bulk_port, echo_port, stats_path):
    """Serve bulk uploads and probe echoes until killed; write the delivered-byte counters."""
    totals = {}

    def listener(port):
        """A listening socket on the hub's inner address."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((ip, port))
        sock.listen(64)
        return sock

    def drain(conn, source):
        """Count one bulk connection's delivered bytes."""
        buf = bytearray(1 << 20)
        while True:
            got = conn.recv_into(buf)
            if not got:
                return
            totals[source] = totals.get(source, 0) + got

    def echo(conn, _source):
        """Return every probe request unchanged."""
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while (request := read_exact(conn, SIZE)) is not None:
            conn.sendall(request)

    def accept(sock, handler):
        """Give every accepted connection its own thread."""
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=handler, args=(conn, addr[0]), daemon=True).start()

    for port, handler in ((bulk_port, drain), (echo_port, echo)):
        threading.Thread(target=accept, args=(listener(port), handler), daemon=True).start()
    with open(stats_path, "a", buffering=1) as out:
        while True:
            out.write(json.dumps({"t": time.time(), "bytes": dict(totals)}) + "\n")
            # sleep: the sampling period of the delivered-byte counters.
            time.sleep(0.25)


def bulk(src, dst, port, until):
    """Upload zeros as fast as TCP lets us until `until`."""
    sock = connect(src, dst, port, until)
    sock.settimeout(max(1.0, until - time.time() + 2))
    block = bytes(256 * 1024)
    try:
        while time.time() < until:
            sock.send(block)
    except OSError:
        pass
    sock.close()


def probe(src, dst, port, start, stop, interval_ms):
    """Send requests on a fixed schedule and report the round trips of those sent in the window."""
    sock = connect(src, dst, port, start)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sent, answered = {}, {}

    def reader():
        """Stamp each echoed request as it returns."""
        try:
            while (reply := read_exact(sock, SIZE)) is not None:
                answered[HEAD.unpack_from(reply)[0]] = time.time()
        except OSError:
            pass

    threading.Thread(target=reader, daemon=True).start()
    seq, due = 0, time.time()
    while due < stop:
        delay = due - time.time()
        if delay > 0:
            # sleep: the open-loop send schedule.
            time.sleep(delay)
        # The round trip counts from the scheduled time, so a send that was held back (a full
        # window after loss) is not hidden.
        sent[seq] = due
        try:
            sock.sendall(HEAD.pack(seq) + bytes(SIZE - HEAD.size))
        except OSError:
            break
        seq += 1
        due += interval_ms / 1000
    deadline = stop + 3
    wanted = [s for s, at in sent.items() if at >= start]
    while time.time() < deadline and any(s not in answered for s in wanted):
        # sleep: wait for the last replies.
        time.sleep(0.05)
    scheduled = int(round((stop - start) * 1000 / interval_ms))
    rtts = [round((answered[s] - sent[s]) * 1000, 3) for s in wanted if s in answered]
    # Requests the schedule never reached (the connection stalled for good) are lost too.
    print(json.dumps({"src": src, "rtts": rtts, "lost": max(scheduled, len(wanted)) - len(rtts)}))


def main():
    """Dispatch on the subcommand (see the module documentation)."""
    command, args = sys.argv[1], sys.argv[2:]
    if command == "sink":
        sink(args[0], int(args[1]), int(args[2]), args[3])
    elif command == "bulk":
        bulk(args[0], args[1], int(args[2]), float(args[3]))
    elif command == "probe":
        probe(args[0], args[1], int(args[2]), float(args[3]), float(args[4]), float(args[5]))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
