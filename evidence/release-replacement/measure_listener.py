#!/usr/bin/env python3
"""Measure live server listener gaps through the real local replacement control socket (#157)."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import statistics
import struct
import sqlite3
import uuid
import subprocess
import threading
import time


def connect(address):
    try:
        with socket.create_connection(address, timeout=0.2):
            return True
    except OSError:
        return False


def healthy(address):
    try:
        with socket.create_connection(address, timeout=0.3) as peer:
            peer.sendall(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            return b"200" in peer.recv(256).split(b"\r\n", 1)[0]
    except OSError:
        return False


def run(binary, state, samples):
    state.mkdir(parents=True, mode=0o700)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        address = reservation.getsockname()
    child = subprocess.Popen([str(binary), "server", "--listen", f"127.0.0.1:{address[1]}", "--data", str(state), "--public-origin", "https://localhost", "--behind-proxy", "--trusted-proxy", "127.0.0.1"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    endpoint = state / "restart/control.sock"
    gaps, totals, refusals = [], [], []
    deadline = time.monotonic() + 30
    try:
        while not (endpoint.exists() and healthy(address)):
            assert child.poll() is None, "server stopped before health"
            assert time.monotonic() < deadline, "server startup deadline"
            time.sleep(0.01)
        with sqlite3.connect(state / "infraternal.sqlite") as database:
            database.executemany("INSERT INTO users(id,name,username,display_name,owner,recovery_hash) VALUES(?, 'Fixture', ?, 'Fixture', ?, 'unused')", [(f"fixture-{i}", f"fixture-{i}", int(i == 0)) for i in range(50)])
            database.executemany("INSERT INTO remote_hosts(id,owner_id,mode,execution_uid,created_at) VALUES(?, 'fixture-0', 'rootless', ?, unixepoch())", [(uuid.uuid4().bytes, os.geteuid()) for _ in range(10000)])
        for _ in range(samples):
            active, ready = threading.Event(), threading.Event()
            active.set()
            observed = []
            def probe():
                last = time.monotonic()
                first, recovered, count = None, None, 0
                ready.set()
                while active.is_set():
                    now = time.monotonic()
                    if connect(address):
                        if first is not None and recovered is None:
                            recovered = time.monotonic()
                        last = now
                    else:
                        if first is None:
                            first = last
                        count += 1
                    time.sleep(0.001)
                observed.append(((recovered or time.monotonic()) - first if first else 0, count))
            thread = threading.Thread(target=probe)
            thread.start()
            ready.wait()
            old = endpoint.stat()
            started = time.monotonic()
            with socket.socket(socket.AF_UNIX) as peer:
                peer.settimeout(10)
                peer.connect(str(endpoint))
                peer.sendall(struct.pack("!H", 1) + b".")
                reply = peer.recv(64)
                assert reply.startswith(b"RESTARTING"), "replacement refused"
            deadline = time.monotonic() + 30
            while True:
                try:
                    new = endpoint.stat()
                    changed = (old.st_ino, old.st_ctime_ns) != (new.st_ino, new.st_ctime_ns)
                except FileNotFoundError:
                    changed = False
                if changed and healthy(address):
                    break
                assert child.poll() is None, "server stopped during replacement"
                assert time.monotonic() < deadline, "replacement health deadline"
                time.sleep(0.001)
            totals.append((time.monotonic() - started) * 1000)
            active.clear()
            thread.join()
            gaps.append(observed[0][0] * 1000)
            refusals.append(observed[0][1])
        return {"binary": str(binary), "samples": samples, "gap_p50_ms": statistics.median(gaps), "gap_max_ms": max(gaps), "total_p50_ms": statistics.median(totals), "total_max_ms": max(totals), "refusal_samples": sum(refusals), "sampling_interval_ms": 1, "same_pid": child.poll() is None, "users": 50, "retained_hosts": 10000, "live_ptys": 0, "load_end": os.getloadavg()}
    finally:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        shutil.rmtree(state)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("state", type=Path)
    parser.add_argument("--samples", type=int, default=25)
    args = parser.parse_args()
    print(json.dumps({"machine": os.uname().nodename, "cores": os.cpu_count(), "load_start": os.getloadavg()}), flush=True)
    print(json.dumps(run(args.binary, args.state, args.samples)), flush=True)
