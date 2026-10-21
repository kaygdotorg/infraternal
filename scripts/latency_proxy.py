#!/usr/bin/env python3
"""Rootless stream latency relay shared by browser and agent test fixtures [#55, D122, D130].

The relay delays bytes in both directions while preserving their TCP stream order.
One-way delay is half the configured RTT; independent half-jitter samples make
the total round-trip jitter stay within the configured bound. A TCP stream proxy
cannot emulate packet loss without corrupting application bytes, so loss remains
disabled for these HTTP, WebSocket, and agent-protocol streams.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import os
from pathlib import Path
import random
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time


DEFAULT_RTT_MS = 300
DEFAULT_JITTER_MS = 30
BURST_IDLE_SECONDS = 0.200
MAX_QUEUED_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class LatencyConfig:
    """The shared test-link RTT and full round-trip jitter bound."""

    rtt_ms: int
    jitter_ms: int = DEFAULT_JITTER_MS

    @classmethod
    def from_environment(cls) -> "LatencyConfig":
        raw = os.environ.get("INFRATERNAL_TEST_RTT", str(DEFAULT_RTT_MS))
        try:
            rtt_ms = int(raw, 10)
        except ValueError as error:
            raise ValueError("INFRATERNAL_TEST_RTT must be a non-negative integer in milliseconds") from error
        if not 0 <= rtt_ms <= 60_000:
            raise ValueError("INFRATERNAL_TEST_RTT must be between 0 and 60000 milliseconds")
        return cls(rtt_ms=rtt_ms, jitter_ms=0 if rtt_ms == 0 else DEFAULT_JITTER_MS)

    def one_way_delay(self, generator: random.Random) -> float:
        """Return seconds of one-way delay; two independent halves bound RTT jitter."""
        half_rtt = self.rtt_ms / 2
        half_jitter = self.jitter_ms / 2
        delay_ms = half_rtt + generator.uniform(-half_jitter, half_jitter)
        return max(0.0, delay_ms) / 1000


class _StreamPump:
    """Queue stream chunks with one jitter sample per quiet-to-active burst."""

    def __init__(self, source: socket.socket, destination: socket.socket, config: LatencyConfig):
        self.source = source
        self.destination = destination
        self.config = config
        self.condition = threading.Condition()
        self.queue: deque[tuple[float, bytes]] = deque()
        self.queued_bytes = 0
        self.input_closed = False
        self.last_due = 0.0
        self.last_arrival = 0.0
        self.burst_delay = 0.0
        self.generator = random.Random()
        self.reader = threading.Thread(target=self._read, name="latency-relay-reader", daemon=True)
        self.writer = threading.Thread(target=self._write, name="latency-relay-writer", daemon=True)

    def start(self) -> None:
        self.reader.start()
        self.writer.start()

    def _read(self) -> None:
        try:
            while True:
                data = self.source.recv(64 * 1024)
                if not data:
                    break
                arrived = time.monotonic()
                # TCP recv boundaries can split one WebSocket frame. Reuse its
                # jitter sample across chunks inside a 200 ms burst so those
                # arbitrary boundaries do not add a second network delay.
                if arrived - self.last_arrival >= BURST_IDLE_SECONDS:
                    self.burst_delay = self.config.one_way_delay(self.generator)
                self.last_arrival = arrived
                due = max(arrived + self.burst_delay, self.last_due)
                self.last_due = due
                with self.condition:
                    while self.queued_bytes >= MAX_QUEUED_BYTES:
                        self.condition.wait()
                    self.queue.append((due, data))
                    self.queued_bytes += len(data)
                    self.condition.notify_all()
        except OSError:
            pass
        finally:
            with self.condition:
                self.input_closed = True
                self.condition.notify_all()

    def _write(self) -> None:
        try:
            while True:
                with self.condition:
                    while not self.queue and not self.input_closed:
                        self.condition.wait()
                    if not self.queue:
                        break
                    due, data = self.queue[0]
                    delay = due - time.monotonic()
                    if delay > 0:
                        self.condition.wait(delay)
                        continue
                    self.queue.popleft()
                    self.queued_bytes -= len(data)
                    self.condition.notify_all()
                self.destination.sendall(data)
        except OSError:
            pass
        finally:
            try:
                self.destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass


class LatencyDuplex:
    """Bidirectional byte-stream relay used for TCP and socket-pair test links."""

    def __init__(self, left: socket.socket, right: socket.socket, config: LatencyConfig):
        self.left = left
        self.right = right
        self.pumps = (
            _StreamPump(left, right, config),
            _StreamPump(right, left, config),
        )

    def start(self) -> None:
        for pump in self.pumps:
            pump.start()

    def join(self) -> None:
        for pump in self.pumps:
            pump.reader.join()
            pump.writer.join()

    def close(self) -> None:
        for sock in (self.left, self.right):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


class TcpLatencyProxy:
    """Loopback-only raw TCP forwarder that keeps HTTP and WebSocket bytes intact."""

    def __init__(self, listen: tuple[str, int], upstream: tuple[str, int], config: LatencyConfig):
        self.listen = listen
        self.upstream = upstream
        self.config = config
        self.listener = socket.create_server(listen, backlog=128, reuse_port=False)
        self.listener.settimeout(0.25)
        self.stopped = threading.Event()
        self.clients: set[LatencyDuplex] = set()
        self.clients_lock = threading.Lock()
        self.thread = threading.Thread(target=self._accept, name="latency-proxy-accept", daemon=True)

    @property
    def address(self) -> tuple[str, int]:
        host, port = self.listener.getsockname()[:2]
        return str(host), int(port)

    def start(self) -> None:
        self.thread.start()

    def _accept(self) -> None:
        while not self.stopped.is_set():
            try:
                client, _ = self.listener.accept()
                worker = threading.Thread(target=self._serve_client, args=(client,), daemon=True)
                worker.start()
            except OSError:
                if self.stopped.is_set():
                    return

    def _serve_client(self, client: socket.socket) -> None:
        relay: LatencyDuplex | None = None
        try:
            upstream = socket.create_connection(self.upstream, timeout=10)
            # The profile supplies the link delay. Nagle on either relay leg
            # adds delayed-ACK stalls to tiny terminal frames before that delay.
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            client.settimeout(None)
            upstream.settimeout(None)
            relay = LatencyDuplex(client, upstream, self.config)
            with self.clients_lock:
                self.clients.add(relay)
            relay.start()
            relay.join()
        except OSError:
            pass
        finally:
            if relay:
                relay.close()
                with self.clients_lock:
                    self.clients.discard(relay)
            else:
                client.close()

    def close(self) -> None:
        self.stopped.set()
        self.listener.close()
        with self.clients_lock:
            clients = list(self.clients)
        for relay in clients:
            relay.close()
        if self.thread.is_alive():
            self.thread.join(timeout=1)


def self_test(config: LatencyConfig, samples: int, *, measure_rtt: bool = True) -> None:
    """Check byte forwarding, optionally measuring whether configured RTT arrives."""
    if samples < 3:
        raise ValueError("latency self-test needs at least 3 samples")
    echo = socket.create_server(("127.0.0.1", 0))
    echo.settimeout(0.25)
    echo_address = echo.getsockname()
    stopped = threading.Event()

    def serve_echo() -> None:
        while not stopped.is_set():
            try:
                peer, _ = echo.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=echo_connection, args=(peer,), daemon=True).start()

    def echo_connection(peer: socket.socket) -> None:
        with peer:
            try:
                while True:
                    data = peer.recv(4096)
                    if not data:
                        return
                    peer.sendall(data)
            except OSError:
                return

    echo_thread = threading.Thread(target=serve_echo, name="latency-self-test-echo", daemon=True)
    echo_thread.start()
    proxy = TcpLatencyProxy(("127.0.0.1", 0), ("127.0.0.1", int(echo_address[1])), config)
    proxy.start()
    timings_ms: list[float] = []
    try:
        for index in range(samples):
            with socket.create_connection(proxy.address, timeout=10) as client:
                client.settimeout(10)
                token = bytes([index % 251])
                started = time.perf_counter() if measure_rtt else 0.0
                client.sendall(token)
                if client.recv(1) != token:
                    raise AssertionError("latency self-test echo changed bytes")
                if measure_rtt:
                    timings_ms.append((time.perf_counter() - started) * 1000)
    finally:
        proxy.close()
        stopped.set()
        echo.close()
        echo_thread.join(timeout=1)

    if not measure_rtt:
        print(f"PASS proxy_forwarding samples={samples} timed=false", flush=True)
        return

    timings_ms.sort()
    p50 = percentile(timings_ms, 0.50)
    p99 = percentile(timings_ms, 0.99)
    low = max(0.0, config.rtt_ms - config.jitter_ms - 5.0)
    high = config.rtt_ms + config.jitter_ms + 30.0
    median_high = config.rtt_ms + config.jitter_ms + 15.0
    if p50 < low or p50 > median_high or p99 > high:
        raise AssertionError(
            f"configured {config.rtt_ms} ms RTT did not arrive: p50={p50:.2f} ms p99={p99:.2f} ms"
        )
    print(
        "METRIC name=network_rtt_selftest "
        f"configured_rtt_ms={config.rtt_ms} jitter_ms={config.jitter_ms} "
        f"loss=unsupported transport=tcp-stream n={samples} "
        f"p50_ms={p50:.2f} p99_ms={p99:.2f} result=PASS",
        flush=True,
    )


def percentile(sorted_samples: list[float], value: float) -> float:
    rank = max(0, min(len(sorted_samples) - 1, int((len(sorted_samples) * value) + 0.999999) - 1))
    return sorted_samples[rank]


def serve_tracer(config: LatencyConfig) -> None:
    """Run tracer's test double behind the same TCP proxy used by browser tests."""
    front_port = port_from_env("TRACER_TEST_PORT", 4621)
    backend_port = port_from_env("TRACER_BACKEND_PORT", front_port + 1)
    if front_port == backend_port:
        raise ValueError("TRACER_BACKEND_PORT must differ from TRACER_TEST_PORT")
    app_root = Path(__file__).resolve().parents[1] / "apps" / "tracer"
    bun = shutil.which("bun")
    if not bun:
        raise FileNotFoundError("bun is required to start the tracer test double")
    proxy = TcpLatencyProxy(("localhost", front_port), ("localhost", backend_port), config)
    environment = dict(os.environ, TRACER_TEST_PORT=str(front_port), TRACER_BACKEND_PORT=str(backend_port))
    child = subprocess.Popen([bun, "run", "test/mock-server.ts"], cwd=app_root, env=environment)
    shutting_down = threading.Event()

    def stop(_signal: int, _frame: object) -> None:
        shutting_down.set()
        proxy.close()
        if child.poll() is None:
            child.terminate()

    old_term = signal.signal(signal.SIGTERM, stop)
    old_int = signal.signal(signal.SIGINT, stop)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError(f"tracer test double exited with status {child.returncode}")
            try:
                with socket.create_connection(("localhost", backend_port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise TimeoutError("tracer test double did not start")
        proxy.start()
        print(f"latency proxy listening on http://localhost:{front_port}; upstream port={backend_port}", flush=True)
        while not shutting_down.wait(0.1):
            if child.poll() is not None:
                raise RuntimeError(f"tracer test double exited with status {child.returncode}")
    finally:
        proxy.close()
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        signal.signal(signal.SIGTERM, old_term)
        signal.signal(signal.SIGINT, old_int)


def port_from_env(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        port = int(raw, 10)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer TCP port") from error
    if not 1 <= port <= 65535:
        raise ValueError(f"{name} must be an integer TCP port")
    return port


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    smoke = commands.add_parser("self-test", help="check byte forwarding and optionally measure configured TCP RTT")
    smoke.add_argument("--samples", type=int, default=31)
    smoke.add_argument(
        "--forwarding-only",
        action="store_true",
        help="check byte forwarding without timing bounds",
    )
    commands.add_parser("serve-tracer", help="serve the tracer test double behind a loopback latency proxy")
    args = parser.parse_args()
    try:
        if args.command == "self-test":
            config = LatencyConfig(rtt_ms=0, jitter_ms=0) if args.forwarding_only else LatencyConfig.from_environment()
            self_test(config, args.samples, measure_rtt=not args.forwarding_only)
        else:
            serve_tracer(LatencyConfig.from_environment())
    except (AssertionError, FileNotFoundError, OSError, RuntimeError, TimeoutError, ValueError) as error:
        print(f"latency proxy: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
