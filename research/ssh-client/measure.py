#!/usr/bin/env python3
"""Measures OpenSSH and the research candidate against a rootless real sshd with only memory-held synthetic keys."""

import argparse
import base64
import getpass
import importlib.util
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ssh_latency_fixture", ROOT / "scripts/latency_proxy.py")
latency = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = latency
spec.loader.exec_module(latency)


def key():
    """Fixture private bytes stay in pipes/memfd; public identity may be stored."""
    private = subprocess.check_output(["openssl", "genpkey", "-algorithm", "ED25519"], stderr=subprocess.DEVNULL)
    public = subprocess.check_output(["openssl", "pkey", "-pubout", "-outform", "DER"], input=private, stderr=subprocess.DEVNULL)
    assert public[:12] == bytes.fromhex("302a300506032b6570032100") and len(public) == 44
    raw = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + public[12:]
    return private, "ssh-ed25519 " + base64.b64encode(raw).decode()


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(child):
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


def rss(pid):
    text = Path(f"/proc/{pid}/status").read_text()
    return int(next(line.split()[1] for line in text.splitlines() if line.startswith("VmRSS:")))


def memory(pid):
    values = {line.split()[0].rstrip(":"): int(line.split()[1]) for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines()[1:] if len(line.split()) == 3}
    return values["Pss"], values["Private_Clean"] + values["Private_Dirty"]


def authenticated_ssh(config, port, environment):
    start = time.monotonic_ns()
    child = subprocess.Popen(["ssh", "-F", str(config), "-vv", "-N", "-T", "-p", str(port), "127.0.0.1"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment, bufsize=0)
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if not select.select([child.stderr], [], [], 1)[0]:
                if child.poll() is not None:
                    break
                continue
            line = child.stderr.readline()
            if b"Authenticated to " in line:
                return child, (time.monotonic_ns() - start) // 1000
            if not line:
                break
        raise RuntimeError("synthetic OpenSSH fixture authentication failed (diagnostics withheld)")
    except BaseException:
        stop(child)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--negative-trust-oracle", action="store_true", help="isolate listener source penalties for repeated negative host-trust checks")
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--integration-binary", type=Path)
    parser.add_argument("--samples", type=int, default=25)
    parser.add_argument("--retained", type=int, default=200)
    args = parser.parse_args()
    scratch = Path.home() / ".cache/codex-scratch/ssh-bootstrap"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="sshd-", dir=scratch) as directory:
        fixture = Path(directory)
        fixture.chmod(0o700)
        private, public = key()
        host_private, host_public = key()
        host_fd = os.memfd_create("infraternal-test-sshd", os.MFD_CLOEXEC)
        os.fchmod(host_fd, 0o600)
        os.write(host_fd, host_private)
        port = available_port()
        authorized = fixture / "authorized_keys"
        authorized.write_text(public + "\n")
        authorized.chmod(0o600)
        config = fixture / "sshd_config"
        config.write_text(f"""# Disposable rootless SSH test configuration; no real server credentials.
Port {port}
ListenAddress 127.0.0.1
HostKey /proc/{os.getpid()}/fd/{host_fd}
AuthorizedKeysFile {authorized}
PidFile {fixture}/sshd.pid
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes yes
AllowUsers {getpass.getuser()}
MaxStartups 400
{"PerSourcePenalties no" if args.negative_trust_oracle else ""}
MaxSessions 256
LoginGraceTime 600
LogLevel ERROR
""")
        sshd = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        agent = subprocess.Popen(["ssh-agent", "-D", "-a", str(fixture / "agent.sock")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proxy = latency.TcpLatencyProxy(("127.0.0.1", 0), ("127.0.0.1", port), latency.LatencyConfig(300, 30))
        proxy.start()
        relay_port = proxy.address[1]
        environment = dict(os.environ, SSH_AUTH_SOCK=str(fixture / "agent.sock"), SSH_ASKPASS_REQUIRE="never")
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if sshd.poll() is not None:
                    raise RuntimeError("rootless sshd failed: " + sshd.stderr.read(2000).decode(errors="replace"))
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        pass
                    if (fixture / "agent.sock").exists():
                        break
                except OSError:
                    pass
                time.sleep(0.02)
            subprocess.run(["ssh-add", "-"], input=private, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            known = fixture / "known_hosts"
            known.write_text(f"[127.0.0.1]:{port} {host_public}\n[127.0.0.1]:{relay_port} {host_public}\n")
            client_config = fixture / "config"
            client_config.write_text(f"""# Synthetic test identity only; strict host trust is derived from our own fixture key.
Host *
  User {getpass.getuser()}
  UserKnownHostsFile {known}
  GlobalKnownHostsFile /dev/null
  StrictHostKeyChecking yes
  UpdateHostKeys no
  BatchMode yes
  IdentitiesOnly no
  IdentityFile none
  PreferredAuthentications publickey
  ControlMaster no
  ConnectTimeout 10
""")
            print(f"ENVIRONMENT machine={socket.gethostname()} cores={os.cpu_count()} load={' '.join(Path('/proc/loadavg').read_text().split()[:3])} fixture=rootless-real-sshd source_penalties={"isolated" if args.negative_trust_oracle else "default"}", flush=True)
            if args.integration_binary:
                wrapper = fixture / "ssh"
                wrapper.write_text(f"#!/bin/sh\nexec /usr/bin/ssh -F '{client_config}' \"$@\"\n")
                wrapper.chmod(0o700)
                test_environment = dict(environment, INFRATERNAL_SSH_FIXTURE=str(fixture), INFRATERNAL_SSH_FIXTURE_PORT=str(port), INFRATERNAL_SSH_FIXTURE_RELAY_PORT=str(relay_port))
                subprocess.run([str(args.integration_binary), "--ignored", "--nocapture"], input=private, env=test_environment, check=True)
                return
            for rtt, target_port in [(0, port), (300, relay_port)]:
                timings = []
                for _ in range(args.samples):
                    child, elapsed = authenticated_ssh(client_config, target_port, environment)
                    timings.append(elapsed)
                    stop(child)
                timings.sort()
                print(f"METRIC candidate=openssh rtt_ms={rtt} samples={args.samples} auth_p50_us={timings[len(timings)//2]} auth_p99_us={timings[min(len(timings)-1,len(timings)*99//100)]}", flush=True)
                if args.candidate:
                    subprocess.run([str(args.candidate), str(target_port), str(known), getpass.getuser(), str(args.samples), "0"], input=private, check=True)
            held = []
            try:
                for _ in range(args.retained):
                    child, _ = authenticated_ssh(client_config, port, environment)
                    held.append(child)
                total = sum(rss(child.pid) for child in held)
                proportional = sum(memory(child.pid)[0] for child in held)
                private_pages = sum(memory(child.pid)[1] for child in held)
                print(f"METRIC candidate=openssh connections={len(held)} client_rss_total_kib={total} client_pss_total_kib={proportional} client_private_total_kib={private_pages} scale_sessions=200", flush=True)
            finally:
                for child in held:
                    stop(child)
            if args.candidate:
                subprocess.run([str(args.candidate), str(port), str(known), getpass.getuser(), "0", str(args.retained)], input=private, check=True)
        finally:
            proxy.close()
            stop(agent)
            stop(sshd)
            os.close(host_fd)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Exceptions here contain only our fixed fixture configuration or status.
        print(str(error), file=sys.stderr)
        sys.exit(1)
