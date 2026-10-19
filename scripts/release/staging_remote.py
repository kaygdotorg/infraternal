#!/usr/bin/env python3
"""Exercise the real deploy transaction and listener gap within an exclusive throwaway VM run (#188)."""
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import threading
import time

import deploy_remote as deploy


def staging_root_is_allowed(root):
    """Permit normalized legacy or per-job roots within the VM scratch tree."""
    bench = Path("/root/infraternal-bench").resolve(strict=True)
    try:
        parts = root.resolve(strict=True).relative_to(bench).parts
    except (OSError, ValueError):
        return False
    if any(part in ("", ".", "..") for part in parts):
        return False
    if len(parts) >= 2 and parts[0] == "deploy":
        return True
    return len(parts) >= 3 and parts[0] != "deploy" and parts[1] == "signed"


def run(config):
    operation = config.pop("operation")
    before = deploy.endpoint(Path(config["data"]))
    installed = Path(config["binary"]).resolve(strict=True)
    if operation == "refuse":
        try:
            deploy.restart(Path(config["data"]), Path(config["root"]) / "releases" / config["sha"] / "infraternal")
        except ValueError:
            pass
        else:
            raise ValueError("broken image unexpectedly admitted")
        if deploy.endpoint(Path(config["data"])) != before or not deploy.same_image(config["pid"], installed) or not deploy.healthy(config):
            raise ValueError("pre-shutdown refusal lost service")
        return {"refused_before_shutdown": True, "ca_unlocked": True}
    if operation == "bad-deploy":
        try:
            deploy.apply(config)
        except ValueError as error:
            if str(error) != "deployment refused; previous release healthy and CA unlocked":
                raise ValueError("warm rollback was not confirmed") from None
        else:
            raise ValueError("broken deployment unexpectedly succeeded")
        if not deploy.same_image(config["pid"], installed) or not deploy.healthy(config):
            raise ValueError("rollback did not retain the previous image")
        saved = sorted((Path(config["root"]) / "backups").glob("*-" + config["sha"]))[-1]
        deploy.verify_signed(saved / "previous", Path(config["root"]) / "allowed_signers", saved / "previous/infraternal")
        with sqlite3.connect(saved / "infraternal.sqlite") as database:
            if database.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise ValueError("backup integrity failed")
            nodes = database.execute("SELECT count(*) FROM remote_hosts").fetchone()[0]
            users = database.execute("SELECT count(*) FROM users").fetchone()[0]
        return {"automatic_rollback": True, "ca_unlocked": True, "backup_integrity": True,
                "backup_nodes": nodes, "backup_users": users, "backup": str(saved)}
    if operation != "handoff":
        raise ValueError("unknown staging operation")
    address = ("127.0.0.1", config.pop("port"))
    samples = []
    ready = threading.Event()
    stop = threading.Event()
    def probe():
        while not stop.is_set():
            started = time.monotonic_ns()
            try:
                with socket.create_connection(address, timeout=0.1):
                    ok = True
            except OSError:
                ok = False
            samples.append((started, time.monotonic_ns(), ok))
            if ok:
                ready.set()
            stop.wait(0.001)
    worker = threading.Thread(target=probe)
    worker.start()
    try:
        if not ready.wait(5):
            raise ValueError("listener probe not ready")
        started = time.monotonic_ns()
        receipt = deploy.apply(config)
        receipt["handoff_transaction_ms"] = (time.monotonic_ns() - started) / 1e6
    finally:
        stop.set()
        worker.join()
    failures = [index for index, sample in enumerate(samples) if not sample[2]]
    if failures:
        first, last = failures[0], failures[-1]
        if first == 0 or last + 1 >= len(samples):
            raise ValueError("listener gap lacks success bounds")
        # Conservative bracket: last successful connect's start through first
        # subsequent successful connect's end. Sample resolution is reported.
        receipt["listener_gap_bracket_ms"] = (samples[last + 1][1] - samples[first - 1][0]) / 1e6
    else:
        receipt["listener_gap_bracket_ms"] = 0.0
    receipt["refused_samples"] = len(failures)
    receipt["probe_max_interval_ms"] = max((b[0] - a[0]) / 1e6 for a, b in zip(samples, samples[1:]))
    return receipt


if __name__ == "__main__":
    os.umask(0o077)
    try:
        config = json.loads(sys.stdin.buffer.read(16385))
        root = Path(config["root"])
        if os.geteuid() != 0 or not staging_root_is_allowed(root):
            raise ValueError("exclusive staging root required")
        print(json.dumps(run(config)))
    except Exception:
        # Caller sessions and transport errors remain in memory; no diagnostics
        # may echo request bodies, cookies, signing material or provider output.
        print('{"state":"staging-proof-failed"}')
        raise SystemExit(1) from None
