#!/usr/bin/env python3
"""Measure D81 server scheduling with remote access and zero or one idle Linux host."""
import argparse
import base64
from contextlib import closing, ExitStack
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
from agent_fixture import cleanup, fixture_state
from idle_canary import measure_scheduled_slices, wait_until_idle
from latency_targets import row_line

WINDOW_SECONDS = 60
SAMPLES = 5

def port():
    """Choose a free local TCP port inside the fixture namespace."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def certificates(state, host):
    """Create an ephemeral CA and the server and host mTLS leaves."""
    def openssl(*args):
        """Run OpenSSL against the private fixture files."""
        return subprocess.check_output(["openssl", *args], cwd=state, stderr=subprocess.DEVNULL)

    openssl("req", "-new", "-x509", "-newkey", "ed25519", "-nodes", "-keyout", "issuer.key",
            "-out", "issuer.pem", "-days", "8", "-subj", "/CN=Idle measurement CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for name, purpose, san in (
        ("server", "serverAuth", "DNS:localhost"),
        ("host", "clientAuth", f"URI:urn:infraternal:host:{host}"),
    ):
        openssl("req", "-new", "-newkey", "ed25519", "-nodes", "-keyout", f"{name}.key",
                "-out", f"{name}.csr", "-subj", f"/CN={name if name == 'server' else host}")
        (state / f"{name}.ext").write_text(
            f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            f"extendedKeyUsage={purpose}\nsubjectAltName={san}\n")
        openssl("x509", "-req", "-in", f"{name}.csr", "-CA", "issuer.pem", "-CAkey", "issuer.key",
                "-CAcreateserial", "-days", "7", "-extfile", f"{name}.ext", "-out", f"{name}.pem")
    return openssl


def seed(state, openssl, host, app_port, remote_port):
    """Register one fixture host and write its normal infraternal agent identity."""
    def der(name):
        """Read a fixture certificate in DER form."""
        return openssl("x509", "-in", f"{name}.pem", "-outform", "DER")

    def b64(value):
        """Encode identity bytes in the CLI identity format."""
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    host_cert, issuer = der("host"), der("issuer")
    dates = openssl("x509", "-in", "host.pem", "-noout", "-dates").decode().splitlines()
    start, end = [int(datetime.strptime(date.split("=", 1)[1], "%b %d %H:%M:%S %Y %Z")
                      .replace(tzinfo=timezone.utc).timestamp())
                  for date in dates]
    raw = openssl("pkey", "-in", "host.key", "-pubout", "-outform", "DER")[-32:]
    db_path = state / "data/infraternal.sqlite"
    assert db_path.is_file()
    with closing(sqlite3.connect(db_path)) as db, db:
        db.execute("INSERT INTO users(id, name, owner, recovery_hash, username, display_name) "
                   "VALUES (?, 'Idle fixture', 1, 'fixture', 'owner', 'Idle fixture')",
                   (str(uuid.uuid4()),))
        db.execute("INSERT INTO remote_hosts(id, owner_id, mode, execution_uid, created_at) "
                   "SELECT ?, id, ?, ?, ? FROM users WHERE owner=1",
                   (host.bytes, "rootful" if os.getuid() == 0 else "rootless", os.getuid(), start))
        db.execute("INSERT INTO remote_certificates(fingerprint, host_id, issuer_fingerprint, "
                   "public_key, not_before, not_after, execution_uid, role) VALUES (?, ?, ?, ?, ?, ?, ?, 'active')",
                   (sha256(host_cert).digest(), host.bytes, sha256(issuer).digest(), raw, start, end, os.getuid()))
    agent = state / "host"
    agent.mkdir(mode=0o700)
    key = openssl("pkcs8", "-topk8", "-nocrypt", "-in", "host.key", "-outform", "DER")
    (agent / "identity.json").write_text(json.dumps({
        "host_id": str(host), "execution_uid": os.getuid(),
        "endpoint": f"127.0.0.1:{remote_port}", "server_name": "localhost",
        "public_origin": f"https://localhost:{app_port}", "ca_der": b64(issuer),
        "certificate_der": b64(host_cert), "key_der": b64(key),
    }))
    return agent


def stop(child):
    """Stop and reap the private process group, including fixture subprocesses."""
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=12)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)


def ready(child, predicate):
    """Wait for a readiness marker without making a server request."""
    deadline = time.monotonic() + 45
    while not predicate():
        assert child.poll() is None, f"fixture exited with {child.returncode}"
        assert time.monotonic() < deadline, "fixture did not become ready"
        # sleep: check the private fixture marker without probing the listener.
        time.sleep(.05)


def admitted(db_path, host):
    """Read the server's recorded OS, which is written after the authenticated Hello."""
    with closing(sqlite3.connect(f"{db_path.as_uri()}?mode=ro", uri=True)) as db:
        return db.execute("SELECT reported_os FROM remote_hosts WHERE id=?", (host.bytes,)).fetchone()[0]


def sample(server, label, seconds):
    """Observe schedule-ins once the one-time startup work has settled."""
    # sleep: Tokio's transient blocking threads retire after 10 seconds.
    time.sleep(15)
    wait_until_idle(server.pid, label)
    measurement = measure_scheduled_slices(server.pid, seconds)
    if server.poll() is not None:
        raise RuntimeError("server exited during observation")
    print(f"{label}: {measurement.total_slices} scheduler activations / "
          f"{measurement.elapsed_seconds:.3f}s ({measurement.scheduled_per_minute:.3f}/min); "
          f"machine={os.uname().machine}; cores={os.cpu_count()}; load={os.getloadavg()}", flush=True)
    return measurement.scheduled_per_minute


def launch(stack, command, env, stderr=None):
    """Start a fixture process in its own group and register its cleanup."""
    child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=stderr, start_new_session=True)
    stack.callback(stop, child)
    return child


def observe(binary, seconds):
    """Sample both host counts on one new server without sending measurement traffic."""
    state = fixture_state("ri")
    state.mkdir(mode=0o700)
    with ExitStack() as stack:
        stack.callback(cleanup, state)
        runtime = state / "runtime"
        runtime.mkdir(mode=0o700)
        env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime), XDG_DATA_HOME=str(state / "xdg"))
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={runtime}/no-bus"
        app_port, remote_port = port(), port()
        while app_port == remote_port:
            remote_port = port()
        host = uuid.uuid4()
        openssl = certificates(state, host)
        server = launch(stack, [str(binary), "server", "--listen", f"127.0.0.1:{app_port}",
                                "--data", str(state / "data"), "--public-origin",
                                f"https://localhost:{app_port}", "--tls-cert", str(state / "server.pem"),
                                "--tls-key", str(state / "server.key"), "--remote-listen",
                                f"127.0.0.1:{remote_port}", "--remote-ca-dir", str(state)], env)
        ready(server, lambda: (state / "data/setup-token.sock").exists())
        zero = sample(server, "remote enabled, zero hosts", seconds)
        agent_dir = seed(state, openssl, host, app_port, remote_port)
        agent_runtime = state / "host-runtime"
        agent_runtime.mkdir(mode=0o700)
        agent_log_path = state / "host.log"
        agent_log = stack.enter_context(agent_log_path.open("wb"))
        agent = launch(stack, [str(binary), "agent", "--data", str(agent_dir), "run"],
                       dict(env, XDG_RUNTIME_DIR=str(agent_runtime), INFRATERNAL_REMOTE_LINK_TRACE="1"),
                       stderr=agent_log)
        db_path = state / "data/infraternal.sqlite"
        ready(agent, lambda: admitted(db_path, host) == "Linux")
        one = sample(server, "remote enabled, one connected Linux host", seconds)
        # Check the transport and connection status outside the measurement.
        connections = subprocess.check_output(
            ["ss", "-Htn", "state", "established", f"( sport = :{app_port} or sport = :{remote_port} )"],
        )
        if connections:
            raise RuntimeError("fixture used TCP instead of the native QUIC link")
        if agent.poll() is not None or b"reconnecting" in agent_log_path.read_bytes():
            raise RuntimeError("infraternal agent did not stay connected")
        return zero, one


def terminate(signum, _frame):
    """Unwind the fixture if the report runner is terminated."""
    raise SystemExit(128 + signum)


def main():
    """Print the nearest-rank p95 across fresh pairs of 60-second windows."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    args = parser.parse_args()
    # The wrapper creates a loopback-only namespace and masks /run before startup.
    interfaces = {name for _, name in socket.if_nameindex()}
    if interfaces != {"lo"} or os.getuid() == 0:
        parser.error("run through scripts/verify-remote-server-idle inside its rootless fixture")
    signal.signal(signal.SIGTERM, terminate)
    os.umask(0o077)
    samples = [observe(args.binary.resolve(), WINDOW_SECONDS) for _ in range(SAMPLES)]
    for index, key in enumerate(("remote_server_idle_zero", "remote_server_idle_one")):
        rates = sorted(pair[index] for pair in samples)
        p95 = rates[math.ceil(.95 * len(rates)) - 1]
        print(row_line(key, source="release-server", n=len(rates), value=p95,
                       unit="activations/min", target=math.ceil(p95 * 1.10), report_only=True))


if __name__ == "__main__":
    main()
