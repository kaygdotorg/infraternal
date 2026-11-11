"""Send fixed-rate mesh probes with monotonic timestamps and explicit missing replies."""

from __future__ import annotations

import argparse
import json
import select
import socket
import struct
import time
from pathlib import Path
from typing import TextIO

_PROBE = struct.Struct("!QQ")


def encode_probe(sequence: int, sent_ns: int) -> bytes:
    """Encode a probe sequence and its monotonic send timestamp for an echo peer."""
    if sequence < 1 or sent_ns < 0:
        raise ValueError("probe sequence must be positive and timestamp non-negative")
    return _PROBE.pack(sequence, sent_ns)


def decode_probe(payload: bytes) -> tuple[int, int] | None:
    """Return a valid probe identity, or `None` for a malformed datagram."""
    if len(payload) != _PROBE.size:
        return None
    sequence, sent_ns = _PROBE.unpack(payload)
    return (sequence, sent_ns) if sequence > 0 else None


def _write_probe(
    output: TextIO,
    *,
    sequence: int,
    scheduled_ns: int,
    sent_ns: int,
    rtt_ms: float | None,
    sender_stalled: bool,
) -> None:
    """Write one completed probe or missed scheduled slot as a JSON line."""
    output.write(
        json.dumps(
            {
                "sequence": sequence,
                "scheduled_ns": scheduled_ns,
                "sent_ns": sent_ns,
                "rtt_ms": rtt_ms,
                "sender_stalled": sender_stalled,
            },
            separators=(",", ":"),
        )
        + "\n"
    )
    output.flush()


def echo_server(bind: str, port: int) -> None:
    """Echo valid mesh probe datagrams until the process is stopped."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind((bind, port))
        while True:
            payload, address = listener.recvfrom(256)
            if decode_probe(payload) is not None:
                listener.sendto(payload, address)


def probe_client(
    target: str,
    port: int,
    seconds: int,
    interval_ms: int,
    timeout_ms: int,
    output_path: Path,
) -> None:
    """Probe one mesh peer at a fixed cadence and retain replies and missed slots."""
    if seconds < 1 or interval_ms < 1 or timeout_ms < 1 or not 1 <= port <= 65535:
        raise ValueError("duration, probe interval, timeout, and port must be positive")
    destination = socket.getaddrinfo(target, port, socket.AF_INET, socket.SOCK_DGRAM)[0][4]
    interval_ns = interval_ms * 1_000_000
    timeout_ns = timeout_ms * 1_000_000
    started_ns = time.monotonic_ns()
    ends_ns = started_ns + seconds * 1_000_000_000
    next_scheduled_ns = started_ns
    next_sequence = 1
    pending: dict[int, tuple[int, int, int]] = {}
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, output_path.open(
        "w", encoding="utf-8"
    ) as output:
        client.setblocking(False)
        while time.monotonic_ns() < ends_ns or pending:
            now_ns = time.monotonic_ns()
            if now_ns < ends_ns and now_ns >= next_scheduled_ns:
                missed_slots = (now_ns - next_scheduled_ns) // interval_ns
                for _ in range(missed_slots):
                    _write_probe(
                        output,
                        sequence=next_sequence,
                        scheduled_ns=next_scheduled_ns,
                        sent_ns=next_scheduled_ns,
                        rtt_ms=None,
                        sender_stalled=True,
                    )
                    next_sequence += 1
                    next_scheduled_ns += interval_ns

                scheduled_ns = next_scheduled_ns
                sent_ns = time.monotonic_ns()
                sequence = next_sequence
                payload = encode_probe(sequence, sent_ns)
                try:
                    client.sendto(payload, destination)
                except OSError:
                    _write_probe(
                        output,
                        sequence=sequence,
                        scheduled_ns=scheduled_ns,
                        sent_ns=sent_ns,
                        rtt_ms=None,
                        sender_stalled=False,
                    )
                else:
                    pending[sequence] = (scheduled_ns, sent_ns, sent_ns + timeout_ns)
                next_sequence += 1
                next_scheduled_ns += interval_ns

            now_ns = time.monotonic_ns()
            deadlines = [entry[2] for entry in pending.values()]
            wake_at_ns = min(deadlines, default=ends_ns)
            if now_ns < ends_ns:
                wake_at_ns = min(wake_at_ns, next_scheduled_ns)
            readable, _, _ = select.select(
                [client], [], [], max(0.0, (wake_at_ns - now_ns) / 1_000_000_000)
            )
            if readable:
                while True:
                    try:
                        payload, address = client.recvfrom(256)
                    except BlockingIOError:
                        break
                    identity = decode_probe(payload)
                    if address[0] != destination[0] or identity is None:
                        continue
                    sequence, original_sent_ns = identity
                    pending_entry = pending.get(sequence)
                    if pending_entry is None or original_sent_ns != pending_entry[1]:
                        continue
                    scheduled_ns, sent_ns, _ = pending_entry
                    pending.pop(sequence)
                    received_ns = time.monotonic_ns()
                    _write_probe(
                        output,
                        sequence=sequence,
                        scheduled_ns=scheduled_ns,
                        sent_ns=sent_ns,
                        rtt_ms=round((received_ns - sent_ns) / 1_000_000, 4),
                        sender_stalled=False,
                    )

            now_ns = time.monotonic_ns()
            expired = [
                sequence
                for sequence, (_, _, deadline_ns) in pending.items()
                if now_ns >= deadline_ns
            ]
            for sequence in expired:
                scheduled_ns, sent_ns, _ = pending.pop(sequence)
                _write_probe(
                    output,
                    sequence=sequence,
                    scheduled_ns=scheduled_ns,
                    sent_ns=sent_ns,
                    rtt_ms=None,
                    sender_stalled=False,
                )


def main() -> None:
    """Run the UDP echo endpoint or the monotonic fixed-rate mesh probe client."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    server = subparsers.add_parser("serve", help="echo valid mesh probes")
    server.add_argument("--bind", default="0.0.0.0")
    server.add_argument("--port", type=int, default=5202)
    client = subparsers.add_parser("probe", help="record RTTs and missed probe slots")
    client.add_argument("--target", required=True)
    client.add_argument("--port", type=int, default=5202)
    client.add_argument("--seconds", type=int, required=True)
    client.add_argument("--interval-ms", type=int, default=50)
    client.add_argument("--timeout-ms", type=int, default=2_000)
    client.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.mode == "serve":
        echo_server(arguments.bind, arguments.port)
    else:
        probe_client(
            arguments.target,
            arguments.port,
            arguments.seconds,
            arguments.interval_ms,
            arguments.timeout_ms,
            arguments.output,
        )


if __name__ == "__main__":
    main()
