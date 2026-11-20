"""Move one verifiable TCP stream through a mesh route and publish live byte progress."""

from __future__ import annotations

import argparse
from collections.abc import Mapping
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import time
from typing import Any

_READ_BYTES = 256 * 1024
_BLOCK_BYTES = 64 * 1024


def transfer_integrity_ok(sender: Mapping[str, Any], receiver: Mapping[str, Any]) -> bool:
    """Return true only when both endpoints verified the same nonempty stream."""

    sent = sender.get("bytes")
    received = receiver.get("bytes")
    sent_hash = sender.get("sha256")
    received_hash = receiver.get("sha256")
    return (
        type(sent) is int
        and type(received) is int
        and sent > 0
        and sent == received
        and isinstance(sent_hash, str)
        and bool(sent_hash)
        and sent_hash == received_hash
    )


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    """Publish a progress snapshot atomically so readers never see partial JSON."""

    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, separators=(",", ":")) + "\n", encoding="utf-8")
    temporary.replace(path)


def serve(bind: str, port: int, progress_path: Path, result_path: Path) -> None:
    """Receive one stream, hash its payload, and publish cumulative receiver progress."""

    progress_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    received = 0
    digest = hashlib.sha256()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((bind, port))
        listener.listen(1)
        listener.settimeout(30)
        _write_json(progress_path, {"bytes": received, "sha256": digest.hexdigest()})
        print(json.dumps({"ready": True, "port": port}), flush=True)
        connection, _ = listener.accept()
        with connection:
            while True:
                payload = connection.recv(_READ_BYTES)
                if not payload:
                    break
                digest.update(payload)
                received += len(payload)
                _write_json(
                    progress_path,
                    {"bytes": received, "sha256": digest.copy().hexdigest()},
                )
    result = {"bytes": received, "sha256": digest.hexdigest()}
    _write_json(progress_path, result)
    _write_json(result_path, result)
    print(json.dumps(result, separators=(",", ":")), flush=True)


def send(
    target: str,
    port: int,
    duration_seconds: int,
    rate_mbit: int,
    progress_path: Path,
    result_path: Path,
) -> None:
    """Send deterministic payload at a bounded rate and publish cumulative sender progress."""

    if not 1 <= port <= 65535:
        raise ValueError("TCP port must be between 1 and 65535")
    if duration_seconds < 1:
        raise ValueError("TCP load duration must be positive")
    if not 1 <= rate_mbit <= 10_000:
        raise ValueError("TCP load rate must be between 1 and 10000 Mbit/s")
    progress_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    block = bytes(range(256)) * (_BLOCK_BYTES // 256)
    digest = hashlib.sha256()
    sent = 0
    last_reported = 0
    _write_json(progress_path, {"bytes": sent, "sha256": digest.hexdigest()})

    with socket.create_connection((target, port), timeout=10) as connection:
        # Seed the stream before starting a short load window. A delayed process
        # must not wake after the requested duration and publish an empty run.
        connection.sendall(block)
        digest.update(block)
        sent += len(block)
        _write_json(progress_path, {"bytes": sent, "sha256": digest.hexdigest()})
        last_reported = sent
        connection.setblocking(False)
        # Start the requested load window after the first payload reaches TCP.
        started_ns = time.monotonic_ns()
        ends_ns = started_ns + duration_seconds * 1_000_000_000
        while time.monotonic_ns() < ends_ns:
            now_ns = time.monotonic_ns()
            next_allowed_ns = started_ns + (
                sent * 8_000_000_000 // (rate_mbit * 1_000_000)
            )
            if next_allowed_ns > now_ns:
                select.select(
                    [], [], [], min((next_allowed_ns - now_ns) / 1_000_000_000, 0.05)
                )
                continue
            _, writable, _ = select.select([], [connection], [], 0.05)
            if not writable:
                continue
            try:
                count = connection.send(block)
            except BlockingIOError:
                continue
            if count <= 0:
                break
            digest.update(block[:count])
            sent += count
            if sent - last_reported >= _BLOCK_BYTES:
                _write_json(
                    progress_path,
                    {"bytes": sent, "sha256": digest.copy().hexdigest()},
                )
                last_reported = sent
        try:
            connection.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    ended_ns = time.monotonic_ns()
    result = {
        "bytes": sent,
        "sha256": digest.hexdigest(),
        "duration_ms": round((ended_ns - started_ns) / 1_000_000, 3),
        "rate_mbit": rate_mbit,
    }
    _write_json(progress_path, result)
    _write_json(result_path, result)
    print(json.dumps(result, separators=(",", ":")), flush=True)


def main() -> None:
    """Run the single-connection receiver or the bounded deterministic sender."""

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    receiver = commands.add_parser("serve", help="receive and hash one TCP stream")
    receiver.add_argument("--bind", default="0.0.0.0")
    receiver.add_argument("--port", type=int, default=5201)
    receiver.add_argument("--progress", required=True, type=Path)
    receiver.add_argument("--result", required=True, type=Path)
    sender = commands.add_parser("send", help="send deterministic bounded-rate TCP traffic")
    sender.add_argument("--target", required=True)
    sender.add_argument("--port", type=int, default=5201)
    sender.add_argument("--seconds", type=int, default=15)
    sender.add_argument("--rate-mbit", type=int, default=100)
    sender.add_argument("--progress", required=True, type=Path)
    sender.add_argument("--result", required=True, type=Path)
    arguments = parser.parse_args()
    if arguments.mode == "serve":
        serve(arguments.bind, arguments.port, arguments.progress, arguments.result)
    else:
        send(
            arguments.target,
            arguments.port,
            arguments.seconds,
            arguments.rate_mbit,
            arguments.progress,
            arguments.result,
        )


if __name__ == "__main__":
    main()
