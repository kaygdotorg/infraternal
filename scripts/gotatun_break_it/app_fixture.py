"""Run real infraternal agents over their authenticated local control channel."""

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Mapping


def _encode_varint(value: int) -> bytes:
    """Encode one non-negative channel length using the agent's bounded varint format."""
    if value < 0:
        raise ValueError("channel lengths must be non-negative")
    encoded = bytearray()
    while value >= 128:
        encoded.append((value & 127) | 128)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _read_exact(stream: socket.socket, size: int) -> bytes:
    """Read one complete channel field or fail when its owner has stopped."""
    data = bytearray()
    while len(data) < size:
        part = stream.recv(size - len(data))
        if not part:
            raise EOFError("infraternal agent closed its control channel")
        data.extend(part)
    return bytes(data)


def _read_varint(stream: socket.socket) -> int:
    """Read one channel length and reject an integer wider than the wire format."""
    value = 0
    for shift in range(0, 35, 7):
        byte = _read_exact(stream, 1)[0]
        value |= (byte & 127) << shift
        if byte & 128 == 0:
            return value
    raise ValueError("infraternal agent sent an oversized channel length")


def _read_frame(stream: socket.socket) -> tuple[int, int, bytes]:
    """Read one framed message from the agent's local control channel."""
    stream_id = _read_varint(stream)
    body = _read_exact(stream, _read_varint(stream))
    if not body:
        raise ValueError("infraternal agent sent an empty channel frame")
    return stream_id, body[0], body[1:]


def _send_frame(stream: socket.socket, kind: int, body: bytes) -> None:
    """Send one framed message on the authenticated local control channel."""
    stream.sendall(_encode_varint(0) + _encode_varint(1 + len(body)) + bytes([kind]) + body)


def _refusal_summary(payload: bytes) -> str:
    """Describe a rejected action without copying arbitrary agent output into evidence."""
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return f"invalid refusal reply ({len(payload)} bytes)"
    if isinstance(decoded, dict) and decoded.get("error") == "Plugin action refused.":
        return "Plugin action refused."
    return "agent returned an opaque refusal"


def new_private_agent_runtime_root() -> Path:
    """Create short private agent state under the home directory for Unix socket paths."""
    return Path(tempfile.mkdtemp(prefix="j526-", dir=Path.home()))


class MeshNode:
    """Keep one real agent process, its durable state and its local Mesh actions."""

    def __init__(
        self,
        binary: Path,
        state_root: Path,
        *,
        label: str,
        namespace_pid: int | None = None,
        environment: Mapping[str, str] | None = None,
        log_root: Path | None = None,
    ) -> None:
        """Start one agent with short private state and optional retained stderr evidence."""
        if not label or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for character in label):
            raise ValueError("agent labels may use lowercase letters, digits, dash and underscore")
        if namespace_pid is not None and namespace_pid < 1:
            raise ValueError("network namespace PID must be positive")
        self.binary = binary
        self.label = label
        self.namespace_pid = namespace_pid
        self.state_root = state_root
        self.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.log_root = state_root if log_root is None else log_root
        self.log_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state = Path(tempfile.mkdtemp(prefix=f"{label}-", dir=self.state_root))
        self.log_path = self.log_root / f"{label}.stderr.log"
        self.environment = os.environ.copy()
        if environment is not None:
            self.environment.update(environment)
        self.process: subprocess.Popen[bytes] | None = None
        self.channel: socket.socket | None = None
        self.log: Any = None
        self._call_id = 0
        self.identity: dict[str, Any] = {}
        self._start_process()

    @property
    def pid(self) -> int:
        """Return the live agent PID used by resource samplers and namespace probes."""
        if self.process is None:
            raise RuntimeError("the infraternal agent is not running")
        return self.process.pid

    def call(self, action: str, value: Mapping[str, Any]) -> Any:
        """Call one authenticated Mesh action and return its JSON result."""
        if self.channel is None:
            raise RuntimeError("the infraternal agent control channel is closed")
        if not action or len(action.encode("utf-8")) > 128:
            raise ValueError("Mesh action name is empty or too long")
        call_id = getattr(self, "_call_id", 0) + 1
        self._call_id = call_id
        encoded_action = action.encode("utf-8")
        body = (
            struct.pack("<I", call_id)
            + _encode_varint(len(encoded_action))
            + encoded_action
            + json.dumps(value, separators=(",", ":")).encode("utf-8")
        )
        _send_frame(self.channel, 0x30, body)
        while True:
            stream_id, kind, response = _read_frame(self.channel)
            if stream_id != 0 or kind != 0x31:
                continue
            if len(response) < 5 or struct.unpack("<I", response[:4])[0] != call_id:
                raise RuntimeError("infraternal agent returned a mismatched Mesh action reply")
            if response[4] != 1:
                detail = _refusal_summary(response[5:])
                raise RuntimeError(f"infraternal agent refused Mesh action {action}: {detail}")
            return json.loads(response[5:])

    def configure(self, chunk: Mapping[str, Any]) -> dict[str, Any]:
        """Apply one coordinator-produced configuration chunk and return its apply time."""
        started_ns = time.monotonic_ns()
        result = self.call("mesh.configure", chunk)
        return {**result, "apply_us": (time.monotonic_ns() - started_ns) // 1_000}

    def peers(self) -> list[dict[str, Any]]:
        """Read every bounded page of the current peer list from this agent."""
        rows: list[dict[str, Any]] = []
        cursor: dict[str, int] | None = None
        while True:
            request = {} if cursor is None else {"cursor": cursor}
            page = self.call("mesh.peers", request)
            peers = page.get("peers")
            if not isinstance(peers, list):
                raise RuntimeError("Mesh peer page did not contain a peer list")
            rows.extend(row for row in peers if isinstance(row, dict))
            next_cursor = page.get("next_cursor")
            if next_cursor is None:
                return rows
            if not isinstance(next_cursor, dict) or not isinstance(next_cursor.get("version"), int) or not isinstance(next_cursor.get("node"), int):
                raise RuntimeError("Mesh peer page returned an invalid cursor")
            cursor = {"version": next_cursor["version"], "node": next_cursor["node"]}

    def restart(self) -> None:
        """Restart the agent over the same durable state directory and network namespace."""
        self._stop_process()
        self._start_process()

    def close(self) -> None:
        """Turn off a live mesh before stopping the agent and removing private state."""
        try:
            if (
                self.process is not None
                and self.process.poll() is None
                and self.channel is not None
            ):
                self.call("mesh.down", {})
                status = self.call("mesh.status", {})
                if not isinstance(status, dict) or status.get("state") != "Off":
                    raise RuntimeError("infraternal agent left the mesh on during fixture cleanup")
        finally:
            self._stop_process()
            shutil.rmtree(self.state, ignore_errors=True)

    def _start_process(self) -> None:
        """Spawn the agent and complete its authenticated local channel handshake."""
        parent, child = socket.socketpair()
        parent.settimeout(60)
        prefix: list[str] = []
        if self.namespace_pid is not None:
            nsenter = shutil.which("nsenter")
            if nsenter is None:
                parent.close()
                child.close()
                raise RuntimeError("nsenter is required for the second product node")
            prefix = [nsenter, "-t", str(self.namespace_pid), "-n", "--"]
        shell = shutil.which("bash")
        if shell is None:
            parent.close()
            child.close()
            raise RuntimeError("bash is required to preserve the agent control descriptor")
        command = prefix + [
            shell,
            "-c",
            'leg_b_fd=$1; if [ "$leg_b_fd" != 3 ]; then exec 3<&"$leg_b_fd"; exec {leg_b_fd}<&-; fi; shift; exec "$@"',
            "j526-mesh-node",
            str(child.fileno()),
            str(self.binary),
            "agent",
            "--fd",
            "3",
            "--state",
            str(self.state),
        ]
        self.log = self.log_path.open("ab")
        try:
            self.process = subprocess.Popen(
                command,
                pass_fds=(child.fileno(),),
                env=self.environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=self.log,
            )
        except Exception:
            parent.close()
            child.close()
            self.log.close()
            self.log = None
            raise
        child.close()
        self.channel = parent
        self._channel_handshake()
        self.call("mesh.up", {})
        identity = self.call("mesh.identity", {"dns_names": True, "key_rotation": True})
        if not isinstance(identity, dict):
            raise RuntimeError("Mesh identity action returned no identity")
        self.identity = identity

    def _channel_handshake(self) -> None:
        """Negotiate the agent control protocol used by the product integration fixtures."""
        if self.channel is None:
            raise RuntimeError("the agent control channel is closed")
        stream_id, kind, _ = _read_frame(self.channel)
        if (stream_id, kind) != (0, 0):
            raise RuntimeError("infraternal agent did not begin with the channel hello")
        _send_frame(self.channel, 0, struct.pack("<HQ", 1, 0) + _encode_varint(10) + b"mesh-proof")
        _send_frame(self.channel, 0x08, struct.pack("<QQ", 0, 0))
        while True:
            stream_id, kind, _ = _read_frame(self.channel)
            if (stream_id, kind) == (0, 0x09):
                return

    def _stop_process(self) -> None:
        """Stop only this fixture's recorded process and close its current channel."""
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
            self.process = None
        if self.channel is not None:
            self.channel.close()
            self.channel = None
        if self.log is not None:
            self.log.close()
            self.log = None


class CoordinatorFixture:
    """Keep one production-schema mesh coordinator compiler alive for a test pair."""

    def __init__(
        self,
        executable: Path,
        *,
        extra_members: int = 0,
        stderr_path: Path | None = None,
        state_path: Path | None = None,
    ) -> None:
        """Start the isolated production-schema compiler with optional simulated peer records."""
        if not 0 <= extra_members <= 200:
            raise ValueError("simulated peer count must be between zero and 200")
        self.executable = executable
        self.extra_members = extra_members
        self.stderr_path = stderr_path
        self.state_path = state_path
        self.current_version: int | None = None
        self.current_authority_epoch: str | None = None
        self._start_process()

    def _start_process(self) -> None:
        """Start the fixture and retain its SQLite state path across process restarts."""
        self.stderr = None if self.stderr_path is None else self.stderr_path.open("ab")
        command = [str(self.executable), str(self.extra_members)]
        if self.state_path is not None:
            self.state_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            command.append(str(self.state_path))
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            text=True,
            bufsize=1,
        )

    def restart(self) -> None:
        """Restart the coordinator process while preserving its private SQLite database."""
        self._stop_process()
        self._start_process()

    def request(
        self,
        mode: str,
        *,
        identities: list[dict[str, Any]] | None = None,
        operation_id: str | None = None,
        candidate_public_key: list[int] | None = None,
        count: int | None = None,
    ) -> dict[str, Any]:
        """Send one coordinator operation, omitting identities after the initial enrollment."""
        if not mode or len(mode) > 64:
            raise ValueError("coordinator request mode must be nonempty and bounded")
        if self.process.poll() is not None or self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("coordinator fixture stopped before compiling a snapshot")
        request: dict[str, Any] = {"mode": mode}
        if identities is not None:
            if len(identities) != 2:
                raise ValueError("coordinator enrollment needs exactly two node identities")
            request["identities"] = identities
        if operation_id is not None:
            request["operation_id"] = operation_id
        if candidate_public_key is not None:
            if len(candidate_public_key) != 32 or any(
                type(byte) is not int or not 0 <= byte <= 255 for byte in candidate_public_key
            ):
                raise ValueError("candidate public key must contain exactly 32 bytes")
            request["candidate_public_key"] = candidate_public_key
        if count is not None:
            if type(count) is not int or not 1 <= count <= 200:
                raise ValueError("peer change count must be between 1 and 200")
            request["count"] = count
        self.process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        ready, _, _ = select.select([self.process.stdout], [], [], 60)
        if not ready:
            raise TimeoutError("coordinator fixture did not compile a snapshot within 60 seconds")
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("coordinator fixture stopped while compiling a snapshot")
        result = json.loads(line)
        if not isinstance(result, dict):
            raise RuntimeError("coordinator fixture returned a non-object snapshot")
        chunks = result.get("chunks")
        if isinstance(chunks, list) and self.current_version is not None:
            from .linux_faults import build_next_config_chunks

            if len(chunks) != 2 or any(not isinstance(node_chunks, list) for node_chunks in chunks):
                raise RuntimeError("coordinator fixture returned an invalid two-node snapshot")
            if any(not node_chunks or not isinstance(node_chunks[0], dict) for node_chunks in chunks):
                raise RuntimeError("coordinator fixture returned an empty or invalid config chunk list")
            next_epoch = chunks[0][0].get("authority_epoch")
            if chunks[1][0].get("authority_epoch") != next_epoch:
                raise RuntimeError("coordinator fixture returned mixed authority epochs")
            if next_epoch == self.current_authority_epoch:
                result["chunks"] = [
                    build_next_config_chunks(node_chunks, current_version=self.current_version)
                    for node_chunks in chunks
                ]
        if isinstance(chunks, list) and chunks and isinstance(chunks[0], list) and chunks[0]:
            retained_chunks = result.get("chunks", chunks)
            version = retained_chunks[0][0].get("version")
            if type(version) is int:
                self.current_version = version
                authority_epoch = retained_chunks[0][0].get("authority_epoch")
                self.current_authority_epoch = authority_epoch
        return result

    def configuration(self, mode: str, identities: list[dict[str, Any]]) -> dict[str, Any]:
        """Compile one coordinator policy snapshot for the supplied real node identities."""
        if mode not in {"allow", "deny", "port"}:
            raise ValueError("coordinator mode must be allow, deny, or port")
        return self.request(mode, identities=identities)

    def close(self) -> None:
        """Stop the fixture process and close its protocol streams."""
        self._stop_process()

    def _stop_process(self) -> None:
        """Stop only this coordinator process and close its protocol streams."""
        if self.process.stdin is not None:
            self.process.stdin.close()
        if self.process.poll() is None:
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.stderr is not None:
            self.stderr.close()
            self.stderr = None


class ServerProcessFixture:
    """Run the product server in the suite namespace and keep its private state across restart."""

    # Each matrix run owns a fresh network namespace. A fixed port avoids releasing a probed
    # listener for the server process to bind later.
    LISTEN_PORT = 52_602

    def __init__(self, executable: Path, state_root: Path) -> None:
        """Start an isolated infraternal server and wait for its health route."""
        self.executable = executable
        self.state_root = state_root
        self.state_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.process: subprocess.Popen[bytes] | None = None
        self.health_status: int | None = None
        try:
            self._start_process()
        except BaseException:
            self.close()
            raise

    @property
    def pid(self) -> int:
        """Return the live server process ID used to prove a process replacement."""
        if self.process is None:
            raise RuntimeError("the infraternal server is not running")
        return self.process.pid

    def restart(self) -> dict[str, int | bool]:
        """Restart the server over the same private data directory and confirm health."""
        previous_pid = self.pid
        previous_directory_inode = self.state_root.stat().st_ino
        self._stop_process()
        self._start_process()
        current_directory_inode = self.state_root.stat().st_ino
        return {
            "server_pid_before": previous_pid,
            "server_pid_after": self.pid,
            "server_health_status": self.health_status or 0,
            "server_data_directory_preserved": current_directory_inode
            == previous_directory_inode,
        }

    def close(self) -> None:
        """Stop only this fixture's server process group."""
        self._stop_process()
        shutil.rmtree(self.state_root, ignore_errors=True)

    def _start_process(self) -> None:
        """Launch the product server without retaining its one-time setup token in logs."""
        command = [
            str(self.executable),
            "server",
            "--data",
            str(self.state_root),
            "--listen",
            f"127.0.0.1:{self.LISTEN_PORT}",
            "--public-origin",
            "https://auth.example.test",
            "--behind-proxy",
            "--trusted-proxy",
            "127.0.0.1/32",
        ]
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.health_status = self._wait_for_health()

    def _wait_for_health(self) -> int:
        """Return the first successful health response or fail on exit or timeout."""
        if self.process is None:
            raise RuntimeError("the infraternal server process was not started")
        url = f"http://127.0.0.1:{self.LISTEN_PORT}/healthz"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"infraternal server exited before health check: {self.process.returncode}"
                )
            try:
                with urllib.request.urlopen(url, timeout=0.5) as response:
                    if response.status == 200:
                        return response.status
            except (OSError, urllib.error.URLError):
                pass
            # sleep: readiness polling gives the server a short interval to bind its listener.
            time.sleep(0.05)
        raise TimeoutError("infraternal server did not become healthy within 30 seconds")

    def _stop_process(self) -> None:
        """Ask this private process group to exit and enforce a bounded cleanup."""
        process = self.process
        if process is None:
            return
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
        self.process = None


__all__ = ["CoordinatorFixture", "MeshNode", "ServerProcessFixture"]
