"""Run the Linux GotaTun failure matrix against two isolated product nodes."""

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from typing import Any, Callable

# A direct script launch sets no package and points Python at this folder;
# add the scripts parent so the package-relative imports below can resolve.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    __package__ = "gotatun_break_it"

from .app_fixture import (
    CoordinatorFixture,
    MeshNode,
    ServerProcessFixture,
    new_private_agent_runtime_root,
)
from .dns_probe import query_a
from .linux_faults import (
    FaultCase,
    build_bidirectional_netem_commands,
    select_fault_cases,
)
from .mesh_ix_soak import process_counters
from .packet_trace import trigger_handshake_storm
from .report import Probe, failed_case_report, report_case
from .tcp_progress import transfer_integrity_ok
from .trace import load_probe_samples

_TRAFFIC_WARMUP_BYTES = 1_048_576
# GotaTun's peer byte counter records a WireGuard handshake initiation as 148 sent bytes.
_HANDSHAKE_INITIATION_BYTES = 148


def _tool(name: str) -> str:
    """Return one required VM tool or name the missing dependency."""
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"required Linux tool is not on PATH: {name}")
    return path


def _run(command: list[str], *, timeout: float = 15.0) -> str:
    """Run a bounded setup command and retain useful failure text."""
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{command[0]} exited {result.returncode}: {detail}")
    return result.stdout


def _in_namespace(pid: int, *command: str) -> list[str]:
    """Build a command that acts only inside one fixture-owned network namespace."""
    return [_tool("nsenter"), "-t", str(pid), "-n", "--", *command]


def _stop_process(process: subprocess.Popen[Any] | None, *, process_group: bool = False) -> None:
    """Stop one recorded fixture process without searching by its command name."""
    if process is None or process.poll() is not None:
        return
    if process_group:
        os.killpg(process.pid, signal.SIGTERM)
    else:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if process_group:
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=5)


def _read_ready(process: subprocess.Popen[str], label: str) -> dict[str, Any]:
    """Read one JSON readiness line without hiding early fixture failure."""
    if process.stdout is None:
        raise RuntimeError(f"{label} has no readiness stream")
    readable, _, _ = select.select([process.stdout], [], [], 15)
    if not readable:
        raise TimeoutError(f"{label} did not become ready within 15 seconds")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError(f"{label} exited before becoming ready: {process.poll()}")
    value = json.loads(line)
    if not isinstance(value, dict) or value.get("ready") is not True:
        raise RuntimeError(f"{label} returned invalid readiness data: {value!r}")
    return value


def _wait_for_duration(duration_seconds: float) -> None:
    """Keep traffic running for a specified injected-fault window."""
    deadline_ns = time.monotonic_ns() + round(duration_seconds * 1_000_000_000)
    while time.monotonic_ns() < deadline_ns:
        # sleep: keep the injected fault active while probes and the TCP stream continue.
        time.sleep(min(0.01, max(0.0, (deadline_ns - time.monotonic_ns()) / 1_000_000_000)))


def _wait_until(predicate: Callable[[], bool], label: str, timeout_seconds: float = 12.0) -> None:
    """Wait for a traffic or route event, with a generous failure deadline."""
    deadline_ns = time.monotonic_ns() + round(timeout_seconds * 1_000_000_000)
    while not predicate():
        if time.monotonic_ns() >= deadline_ns:
            raise TimeoutError(f"timed out waiting for {label}")
        # sleep: poll the fixture progress event while its product processes run independently.
        time.sleep(0.01)


def _read_json(path: Path) -> dict[str, Any]:
    """Read one atomically published traffic-progress object."""
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return value


def _progress_bytes(path: Path) -> int:
    """Return the current monotonically published byte count or zero before readiness."""
    try:
        return int(_read_json(path).get("bytes", 0))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return 0


def _traffic_warmed_up(sender_bytes: int, receiver_bytes: int) -> bool:
    """Require one MiB to reach both endpoints before a case injects a fault."""
    return sender_bytes >= _TRAFFIC_WARMUP_BYTES and receiver_bytes >= _TRAFFIC_WARMUP_BYTES


def _node_dns_name(snapshot: dict[str, Any], node_index: int) -> str:
    """Read a node's assigned DNS label from its first coordinator configuration chunk."""
    chunks = snapshot.get("chunks")
    if not isinstance(chunks, list) or not 0 <= node_index < len(chunks):
        raise RuntimeError("coordinator snapshot did not include the requested node chunks")
    node_chunks = chunks[node_index]
    if not isinstance(node_chunks, list) or not node_chunks or not isinstance(node_chunks[0], dict):
        raise RuntimeError("coordinator snapshot did not include a node configuration chunk")
    name = node_chunks[0].get("name")
    if not isinstance(name, str) or not name:
        raise RuntimeError("coordinator snapshot did not assign a mesh DNS name")
    return name


def _verify_peer_dns(local_ipv4: str, peer_ipv4: str, peer_name: str) -> dict[str, Any]:
    """Resolve a peer through this node's own policy-filtered mesh DNS listener."""
    query = f"{peer_name}.internal"
    answers = query_a(local_ipv4, query)
    if peer_ipv4 not in answers:
        raise RuntimeError(
            f"local mesh DNS returned {answers!r} for {query}, expected {peer_ipv4}"
        )
    return {
        "resolver": local_ipv4,
        "query": query,
        "answers": list(answers),
        "expected_answer": peer_ipv4,
    }


def _interface_counters(interface: str, namespace_pid: int | None = None) -> dict[str, int]:
    """Read byte and packet totals for a disposable underlay interface."""
    command = ["cat", "/proc/net/dev"]
    if namespace_pid is not None:
        command = _in_namespace(namespace_pid, *command)
    output = _run(command)
    for line in output.splitlines():
        name, separator, counters = line.partition(":")
        if separator and name.strip() == interface:
            values = [int(value) for value in counters.split()]
            if len(values) < 16:
                break
            return {
                "rx_bytes": values[0],
                "rx_packets": values[1],
                "tx_bytes": values[8],
                "tx_packets": values[9],
            }
    raise RuntimeError(f"could not read counters for {interface}")


def _peer_transfer_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize public peer routes and counters without retaining key material."""
    ipv4_addresses: set[str] = set()
    endpoint_ports: set[int] = set()
    with_endpoint = 0
    with_handshake = 0
    with_unconfirmed_handshake = 0
    with_sent_bytes = 0
    samples: list[dict[str, Any]] = []
    for row in rows:
        peer = row.get("peer")
        if not isinstance(peer, dict):
            continue
        addresses = peer.get("addresses")
        counters = row.get("counters")
        endpoint = peer.get("endpoint")
        if isinstance(addresses, dict) and isinstance(addresses.get("ipv4"), str):
            ipv4 = addresses["ipv4"]
            ipv4_addresses.add(ipv4)
        else:
            ipv4 = None
        endpoint_port: int | None = None
        if isinstance(endpoint, str) and ":" in endpoint:
            try:
                endpoint_port = int(endpoint.rsplit(":", 1)[1])
            except ValueError:
                endpoint_port = None
        if endpoint_port is not None:
            with_endpoint += 1
            endpoint_ports.add(endpoint_port)
        if not isinstance(counters, dict):
            counters = {}
        sent_bytes = counters.get("sent_bytes", 0)
        handshake_secs = counters.get("handshake_secs", 0)
        if isinstance(sent_bytes, int) and sent_bytes > 0:
            with_sent_bytes += 1
        if isinstance(handshake_secs, int) and handshake_secs > 0:
            with_handshake += 1
        elif (
            isinstance(handshake_secs, int)
            and handshake_secs == 0
            and isinstance(sent_bytes, int)
            and sent_bytes >= _HANDSHAKE_INITIATION_BYTES
        ):
            # Initial config sends these before the later packet-capture window begins.
            with_unconfirmed_handshake += 1
        if len(samples) < 5:
            samples.append(
                {
                    "node": row.get("node"),
                    "ipv4": ipv4,
                    "endpoint_port": endpoint_port,
                    "sent_bytes": sent_bytes if isinstance(sent_bytes, int) else None,
                    "handshake_secs": handshake_secs
                    if isinstance(handshake_secs, int)
                    else None,
                }
            )
    return {
        "peer_count": len(rows),
        "unique_ipv4_count": len(ipv4_addresses),
        "peer_count_with_endpoint": with_endpoint,
        "peer_count_with_sent_bytes": with_sent_bytes,
        "peer_count_with_handshake": with_handshake,
        "peer_count_with_unconfirmed_handshake": with_unconfirmed_handshake,
        "endpoint_ports": sorted(endpoint_ports),
        "sample": samples,
    }


def _peer_scale_handshake_summary(
    rows: list[dict[str, Any]], *, expected_peer_count: int
) -> dict[str, Any]:
    """Count peers whose initial config sent a WireGuard initiation without a completed handshake."""
    if type(expected_peer_count) is not int or expected_peer_count < 1:
        raise ValueError("expected peer count must be a positive integer")

    attempted_peers = 0
    for row in rows:
        counters = row.get("counters")
        if not isinstance(counters, dict):
            continue
        sent_bytes = counters.get("sent_bytes")
        handshake_secs = counters.get("handshake_secs")
        if (
            type(sent_bytes) is int
            and sent_bytes >= _HANDSHAKE_INITIATION_BYTES
            and type(handshake_secs) is int
            and handshake_secs == 0
        ):
            attempted_peers += 1

    return {
        "handshake_attempt_peer_count_after_config": attempted_peers,
        "handshake_storm_source": "initial_config_commit",
        "handshake_storm_complete": attempted_peers >= expected_peer_count,
    }


def _mesh_status_summary(node: MeshNode) -> dict[str, Any]:
    """Keep public node health fields beside a failed coordinator config chunk."""
    try:
        status = node.call("mesh.status", {})
    except Exception as error:
        return {"available": False, "error_type": type(error).__name__}
    if not isinstance(status, dict):
        return {"available": False, "error_type": "invalid_status"}
    summary = {
        field: status[field]
        for field in ("state", "version", "peer_count")
        if field in status
    }
    engine = status.get("engine")
    if isinstance(engine, dict):
        summary["engine"] = {
            field: engine[field]
            for field in ("stopped", "restarts", "refused_frames", "bad_frames", "tx_queue_len")
            if field in engine
        }
    return summary


def _local_key_matches_identity(node: MeshNode, chunk: dict[str, Any]) -> bool | None:
    """Compare a rejected chunk binding with the node identity without retaining either key."""
    incoming = chunk.get("local_key")
    if not isinstance(incoming, list):
        return None
    try:
        identity = node.call("mesh.identity", {"dns_names": True, "key_rotation": True})
    except Exception:
        return None
    if not isinstance(identity, dict) or not isinstance(identity.get("public_key"), list):
        return None
    return incoming == identity["public_key"]


class NamespacePair:
    """Own two product agents, their private veth, and a production-schema coordinator."""

    def __init__(
        self,
        binary: Path,
        coordinator_binary: Path,
        scratch: Path,
        *,
        extra_members: int = 0,
        with_server: bool = False,
    ) -> None:
        """Create a fresh peer namespace and apply one allow-all coordinator snapshot."""
        self.binary = binary
        self.coordinator_binary = coordinator_binary
        self.scratch = scratch
        self.extra_members = extra_members
        self.peer_namespace: subprocess.Popen[bytes] | None = None
        self.coordinator: CoordinatorFixture | None = None
        self.server: ServerProcessFixture | None = None
        self.left: MeshNode | None = None
        self.right: MeshNode | None = None
        self.runtime_root: Path | None = None
        self.closed = False
        self.scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            self._create_underlay()
            self.runtime_root = new_private_agent_runtime_root()
            if with_server:
                self.server = ServerProcessFixture(
                    binary,
                    self.runtime_root / "server-data",
                    stderr_path=scratch / "server.stderr.log",
                )
            # Name the engine explicitly so the matrix keeps testing GotaTun even if the Linux
            # default ever changes (D346).
            environment = {"INFRATERNAL_MESH_ENGINE": "gotatun"}
            log_root = scratch / "agent-state"
            self.left = MeshNode(
                binary,
                self.runtime_root,
                label="a",
                environment=environment,
                log_root=log_root,
            )
            self.right = MeshNode(
                binary,
                self.runtime_root,
                label="b",
                namespace_pid=self.peer_namespace.pid,
                environment=environment,
                log_root=log_root,
            )
            self.resource_before = {
                "a": process_counters(self.left.pid),
                "b": process_counters(self.right.pid),
            }
            self.coordinator = CoordinatorFixture(
                coordinator_binary,
                extra_members=extra_members,
                stderr_path=scratch / "coordinator.stderr.log",
                state_path=scratch / "coordinator.sqlite",
            )
            self.identities = [self.left.identity, self.right.identity]
            initial = self.coordinator.configuration("allow", self.identities)
            self.configuration_us = self._apply_snapshot(initial)
            self.addresses = initial["addresses"]
            self.left_ipv4 = str(self.addresses[0]["ipv4"])
            self.right_ipv4 = str(self.addresses[1]["ipv4"])
            self.resource_after_config = {
                "a": process_counters(self.left.pid),
                "b": process_counters(self.right.pid),
            }
            route = _run([_tool("ip"), "route", "get", self.right_ipv4])
            if "dev infraternal0" not in route:
                raise RuntimeError(f"mesh route did not use infraternal0: {route.strip()}")
            self.route_check = route.strip()
            self.dns_check = _verify_peer_dns(
                self.left_ipv4,
                self.right_ipv4,
                _node_dns_name(initial, 1),
            )
        except BaseException:
            self.close()
            raise

    @property
    def peer_pid(self) -> int:
        """Return the recorded process that owns the second network namespace."""
        if self.peer_namespace is None:
            raise RuntimeError("the peer namespace is not running")
        return self.peer_namespace.pid

    def _create_underlay(self) -> None:
        """Create only the two named veth devices inside the caller's disposable namespace."""
        uid_map = Path("/proc/self/uid_map").read_text(encoding="ascii").split()
        if uid_map[2:] != ["1"]:
            raise RuntimeError("run inside a disposable user/network namespace: unshare -Urn")
        self.peer_namespace = subprocess.Popen(
            [_tool("unshare"), "-n", _tool("sleep"), "900"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        _run([_tool("ip"), "link", "set", "lo", "up"])
        _run(_in_namespace(self.peer_pid, _tool("ip"), "link", "set", "lo", "up"))
        _run(
            [
                _tool("ip"),
                "link",
                "add",
                "underlay0",
                "type",
                "veth",
                "peer",
                "name",
                "underlay1",
            ]
        )
        _run([_tool("ip"), "link", "set", "underlay1", "netns", str(self.peer_pid)])
        _run([_tool("ip"), "link", "set", "underlay0", "mtu", "1500"])
        _run(_in_namespace(self.peer_pid, _tool("ip"), "link", "set", "underlay1", "mtu", "1500"))
        _run([_tool("ip"), "addr", "add", "10.220.0.1/24", "dev", "underlay0"])
        _run([_tool("ip"), "link", "set", "underlay0", "up"])
        _run(_in_namespace(self.peer_pid, _tool("ip"), "addr", "add", "10.220.0.2/24", "dev", "underlay1"))
        _run(_in_namespace(self.peer_pid, _tool("ip"), "link", "set", "underlay1", "up"))

    def _apply_snapshot(
        self, snapshot: dict[str, Any], *, stage: str = "coordinator config"
    ) -> list[int]:
        """Apply ordered config chunks and retain safe context for a refused update."""
        if self.left is None or self.right is None:
            raise RuntimeError("both product nodes must be running before configuration")
        chunks = snapshot.get("chunks")
        if not isinstance(chunks, list) or len(chunks) != 2:
            raise RuntimeError("coordinator snapshot did not include two node chunk lists")
        applied: list[int] = []
        for node_name, node, node_chunks in zip(
            ("left", "right"), (self.left, self.right), chunks, strict=True
        ):
            if not isinstance(node_chunks, list) or not node_chunks:
                raise RuntimeError("coordinator snapshot contains an empty node chunk list")
            for chunk_index, chunk in enumerate(node_chunks):
                is_last = chunk.get("last")
                if type(is_last) is not bool:
                    raise RuntimeError("coordinator config chunk has no final-chunk marker")
                try:
                    result = node.configure(chunk)
                except RuntimeError as error:
                    chunk_version = chunk.get("version")
                    binding_matches_identity = _local_key_matches_identity(node, chunk)
                    raise RuntimeError(
                        f"stage={stage} config refused node={node_name} chunk={chunk_index} "
                        f"from_version={chunk.get('from_version')} version={chunk_version} "
                        f"last={is_last} local_key_matches_identity={binding_matches_identity}: "
                        f"{error}; agent_stderr_log={node.log_path}; "
                        f"mesh_status={_mesh_status_summary(node)}"
                    ) from error
                if result.get("applied") is not is_last:
                    raise RuntimeError(
                        f"product node config chunk {chunk.get('index')} returned an unexpected "
                        f"applied state: {result}"
                    )
                if is_last and result.get("version") != chunk.get("version"):
                    raise RuntimeError(
                        f"product node config version {result.get('version')} does not match "
                        f"coordinator version {chunk.get('version')}"
                    )
                applied.append(int(result["apply_us"]))
        return applied

    def configure(self, mode: str) -> list[int]:
        """Publish a new policy snapshot for the identities already enrolled in this fixture."""
        if self.coordinator is None:
            raise RuntimeError("the coordinator is not running")
        snapshot = self.coordinator.configuration(mode, self.identities)
        return self._apply_snapshot(snapshot)

    def close(self) -> None:
        """Stop only this pair's fixture processes and remove its veth from the caller namespace."""
        if self.closed:
            return
        self.closed = True
        if self.server is not None:
            self.server.close()
        for node in (self.left, self.right):
            if node is not None:
                node.close()
        if self.coordinator is not None:
            self.coordinator.close()
        if self.peer_namespace is not None:
            try:
                _run([_tool("ip"), "link", "del", "dev", "underlay0"])
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                pass
            _stop_process(self.peer_namespace, process_group=True)
        if self.runtime_root is not None:
            shutil.rmtree(self.runtime_root, ignore_errors=True)
            self.runtime_root = None


class Traffic:
    """Keep one TCP payload flow and monotonic UDP probes active through a fault."""

    def __init__(self, pair: NamespacePair, output: Path, *, duration_seconds: int) -> None:
        """Start endpoint services, one TCP sender and a fixed-cadence tunnel probe client."""
        self.pair = pair
        self.output = output
        self.duration_seconds = duration_seconds
        self.tcp_helper = Path(__file__).with_name("tcp_progress.py")
        self.probe_helper = Path(__file__).with_name("udp_probe.py")
        self.sender_progress = output / "sender-progress.json"
        self.receiver_progress = output / "receiver-progress.json"
        self.sender_result = output / "sender-result.json"
        self.receiver_result = output / "receiver-result.json"
        self.probe_path = output / "probes.jsonl"
        self.processes: list[subprocess.Popen[Any]] = []
        self.files: list[Any] = []
        self.tcp_server: subprocess.Popen[str] | None = None
        self.probe_server: subprocess.Popen[str] | None = None
        self.probe_client: subprocess.Popen[Any] | None = None
        self.sender: subprocess.Popen[Any] | None = None
        try:
            self._start_servers()
            self._start_clients()
        except BaseException:
            self.close()
            raise

    def _start_servers(self) -> None:
        """Bind the TCP receiver and UDP echo endpoint inside the second network namespace."""
        tcp_log = (self.output / "tcp-server.stderr.log").open("ab")
        udp_log = (self.output / "probe-server.stderr.log").open("ab")
        self.files.extend((tcp_log, udp_log))
        tcp_server = subprocess.Popen(
            _in_namespace(
                self.pair.peer_pid,
                sys.executable,
                str(self.tcp_helper),
                "serve",
                "--bind",
                "0.0.0.0",
                "--port",
                "5201",
                "--progress",
                str(self.receiver_progress),
                "--result",
                str(self.receiver_result),
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=tcp_log,
            text=True,
        )
        self.tcp_server = tcp_server
        self.processes.append(tcp_server)
        _read_ready(tcp_server, "TCP receiver")
        probe_server = subprocess.Popen(
            _in_namespace(
                self.pair.peer_pid,
                sys.executable,
                str(self.probe_helper),
                "serve",
                "--bind",
                "0.0.0.0",
                "--port",
                "5202",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=udp_log,
            text=True,
        )
        self.probe_server = probe_server
        self.processes.append(probe_server)
        _read_ready(probe_server, "UDP probe echo")

    def _start_clients(self) -> None:
        """Start the timed probe and deterministic single-flow payload sender."""
        probe_log = (self.output / "probe-client.stderr.log").open("ab")
        sender_log = (self.output / "tcp-sender.stderr.log").open("ab")
        self.files.extend((probe_log, sender_log))
        probe = subprocess.Popen(
            [
                sys.executable,
                str(self.probe_helper),
                "probe",
                "--target",
                self.pair.right_ipv4,
                "--port",
                "5202",
                "--seconds",
                str(self.duration_seconds + 10),
                "--interval-ms",
                "50",
                "--timeout-ms",
                "1000",
                "--output",
                str(self.probe_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=probe_log,
            start_new_session=True,
        )
        self.probe_client = probe
        self.processes.append(probe)
        sender = subprocess.Popen(
            [
                sys.executable,
                str(self.tcp_helper),
                "send",
                "--target",
                self.pair.right_ipv4,
                "--port",
                "5201",
                "--seconds",
                str(self.duration_seconds),
                "--rate-mbit",
                "80",
                "--progress",
                str(self.sender_progress),
                "--result",
                str(self.sender_result),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=sender_log,
            start_new_session=True,
        )
        self.sender = sender
        self.processes.append(sender)
        _wait_until(
            lambda: _traffic_warmed_up(
                _progress_bytes(self.sender_progress),
                _progress_bytes(self.receiver_progress),
            ),
            "sustained verified TCP traffic through the mesh",
        )

    def wait(self) -> tuple[dict[str, Any], dict[str, Any], list[Probe]]:
        """Join each recorded sender and return the final hashes and probe samples."""
        if self.sender is None or self.tcp_server is None or self.probe_client is None:
            raise RuntimeError("traffic clients were not started")
        self.sender.wait(timeout=self.duration_seconds + 20)
        self.tcp_server.wait(timeout=self.duration_seconds + 20)
        self.probe_client.wait(timeout=self.duration_seconds + 20)
        sent = _read_json(self.sender_result)
        received = _read_json(self.receiver_result)
        return sent, received, load_probe_samples(self.probe_path)

    def close(self) -> None:
        """Stop only traffic processes created by this case and close their log files."""
        if self.probe_server is not None:
            _stop_process(self.probe_server)
        for process in reversed(self.processes):
            _stop_process(process)
            if process.stdout is not None:
                process.stdout.close()
        for output in self.files:
            output.close()


def _partial_traffic_progress(
    output: Path, traffic: Traffic | None
) -> tuple[int, int, list[Probe]]:
    """Read partial byte and probe evidence even when Traffic startup raises."""
    sender_path = output / "sender-progress.json" if traffic is None else traffic.sender_progress
    receiver_path = (
        output / "receiver-progress.json" if traffic is None else traffic.receiver_progress
    )
    probe_path = output / "probes.jsonl" if traffic is None else traffic.probe_path
    samples: list[Probe] = []
    if probe_path.is_file():
        try:
            samples = load_probe_samples(probe_path)
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    return _progress_bytes(sender_path), _progress_bytes(receiver_path), samples


def _apply_rotation(pair: NamespacePair, *, timer_expired: bool) -> dict[str, Any]:
    """Rotate one real node key through coordinator phases while its peer carries traffic."""
    if pair.coordinator is None or pair.right is None:
        raise RuntimeError("rotation needs a live coordinator and second product node")
    operation_id = str(uuid.uuid4())
    begin_mode = "rotation-timer-begin" if timer_expired else "rotation-begin"
    prepared = pair.coordinator.request(begin_mode, operation_id=operation_id)
    operation = prepared.get("rotation")
    if not isinstance(operation, dict) or not isinstance(operation.get("sequence"), int):
        raise RuntimeError(f"coordinator did not prepare a rotation: {prepared}")
    input_value = {"operation_id": operation_id, "sequence": operation["sequence"]}
    candidate = pair.right.call("mesh.rotation.prepare", input_value).get("public_key")
    if not isinstance(candidate, list):
        raise RuntimeError("product node did not return its prepared public key")
    overlap = pair.coordinator.request(
        "rotation-overlap",
        operation_id=operation_id,
        candidate_public_key=candidate,
    )
    pair._apply_snapshot(overlap, stage="rekey overlap")
    # sleep: D166 requires a full 120-second dual-key overlap before the local key commits.
    _wait_for_duration(120)
    pair.right.call("mesh.rotation.commit", input_value)
    retiring = pair.coordinator.request("rotation-retiring", operation_id=operation_id)
    pair._apply_snapshot(retiring, stage="rekey retiring")
    cleanup = pair.coordinator.request("rotation-cleanup", operation_id=operation_id)
    pair._apply_snapshot(cleanup, stage="rekey cleanup")
    pair.right.call("mesh.rotation.finish", input_value)
    finished = pair.coordinator.request("rotation-finish", operation_id=operation_id)
    pair._apply_snapshot(finished, stage="rekey finished")
    return {
        "operation_id": operation_id,
        "sequence": operation["sequence"],
        "timer_due_in_fixture": bool(operation.get("timer_due")),
        "overlap_seconds": 120,
    }


def _rebind_nat_port(namespace: int, old_port: int, new_port: int) -> None:
    """Make B's namespace behave like a NAT that has moved B's mapping to a new public port.

    The table is never removed during the case: the namespace teardown discards it. Deleting a
    namespace's only nat chain unregisters the kernel NAT hooks, so the live flow silently loses
    its translation and leaves the old port again, while the stale reverse mapping still owns
    `A -> B:old`. Every datagram A then sends to the old port clashes with it in conntrack and
    is dropped, and B's own traffic keeps that entry alive: a permanent one-way black hole that
    no real router produces and no endpoint can recover from (#517, J634).

    Inbound packets that would open a new flow to the old port are dropped, as a real NAT drops
    traffic for a mapping it no longer has. Without that, A's next datagram can win the race
    against B's and create an untranslated inbound entry, and the row passes without any rebind.
    """
    nft = _tool("nft")
    conntrack = _tool("conntrack")
    rules = [
        ("add", "table", "ip", "j526"),
        (
            "add",
            "chain",
            "ip",
            "j526",
            "postrouting",
            "{ type nat hook postrouting priority srcnat; policy accept; }",
        ),
        (
            "add",
            "rule",
            "ip",
            "j526",
            "postrouting",
            "ip",
            "daddr",
            "10.220.0.1",
            "udp",
            "sport",
            str(old_port),
            "snat",
            "to",
            f"10.220.0.2:{new_port}",
        ),
        # Filter priority runs after conntrack, so `ct state new` means no mapping matched.
        (
            "add",
            "chain",
            "ip",
            "j526",
            "prerouting",
            "{ type filter hook prerouting priority filter; policy accept; }",
        ),
        (
            "add",
            "rule",
            "ip",
            "j526",
            "prerouting",
            "ip",
            "saddr",
            "10.220.0.1",
            "udp",
            "dport",
            str(old_port),
            "ct",
            "state",
            "new",
            "counter",
            "drop",
        ),
    ]
    for rule in rules:
        _run(_in_namespace(namespace, nft, *rule))
    # Drop only the underlay UDP mapping so the next datagram gets the new source port.
    # A full `conntrack -F` also wiped the namespace's state for the inner TCP flow, and
    # the product firewall rightly drops mid-stream TCP that looks new without a SYN (#260,
    # J561). The mapping's original direction depends on which side sent first at setup, so
    # both are tried; `conntrack -D` exits 1 when nothing matched.
    deleted = 0
    for selector in (
        ("--orig-src", "10.220.0.2", "--orig-dst", "10.220.0.1", "--orig-port-src"),
        ("--orig-src", "10.220.0.1", "--orig-dst", "10.220.0.2", "--orig-port-dst"),
    ):
        result = subprocess.run(
            _in_namespace(namespace, conntrack, "-D", "-p", "udp", *selector, str(old_port)),
            capture_output=True,
            text=True,
            check=False,
            timeout=15.0,
        )
        if result.returncode not in (0, 1):
            raise RuntimeError(f"conntrack exited {result.returncode}: {result.stderr.strip()}")
        deleted += result.returncode == 0
    if deleted == 0:
        raise RuntimeError("no underlay UDP mapping existed to rebind")


def _peer_endpoint(node: MeshNode) -> str | None:
    """Return where a two-node fixture's agent currently sends its only peer's packets."""
    rows = node.peers()
    if len(rows) != 1:
        raise RuntimeError(f"expected one mesh peer, found {len(rows)}")
    endpoint = rows[0].get("counters", {}).get("endpoint")
    return endpoint if isinstance(endpoint, str) else None


def _apply_fault(case: FaultCase, pair: NamespacePair) -> dict[str, Any]:
    """Inject and clear one repeatable fault while the TCP and UDP workloads stay live."""
    if pair.coordinator is None or pair.left is None or pair.right is None:
        raise RuntimeError("fault injection needs the configured product pair")
    tc = _tool("tc")
    ip = _tool("ip")
    details: dict[str, Any] = {}
    started_ns = time.monotonic_ns()
    if case.kind == "endpoint-ip":
        _run(_in_namespace(pair.peer_pid, ip, "addr", "del", "10.220.0.2/24", "dev", "underlay1"))
        _run(_in_namespace(pair.peer_pid, ip, "addr", "add", "10.220.0.3/24", "dev", "underlay1"))
        details["new_underlay_endpoint"] = "10.220.0.3"
        details["recovery_started_ns"] = time.monotonic_ns()
    elif case.kind == "nat-port":
        old_port = int(pair.right.identity["port"])
        new_port = old_port + 7000 if old_port <= 58_535 else old_port - 10_000
        if new_port <= 1024 or new_port == old_port:
            raise RuntimeError("could not choose a distinct NAT source port")
        _rebind_nat_port(pair.peer_pid, old_port, new_port)
        details["recovery_started_ns"] = time.monotonic_ns()
        _wait_for_duration(3)
        # The new mapping stays for the rest of the case, as a router's would. Prove that the
        # row really exercised a rebind: the peer must now address B at the translated port.
        endpoint = _peer_endpoint(pair.left)
        details.update(
            {
                "old_source_port": old_port,
                "new_source_port": new_port,
                "peer_endpoint_after_rebind": endpoint,
            }
        )
        if endpoint != f"10.220.0.2:{new_port}":
            raise RuntimeError(
                f"NAT rebind did not take effect: A still addresses B at {endpoint}"
            )
    elif case.kind in {"loss", "reorder", "duplicate"}:
        if case.kind == "loss":
            commands = build_bidirectional_netem_commands(Path(tc), loss_pct=int(case.value))
        elif case.kind == "reorder":
            commands = build_bidirectional_netem_commands(
                Path(tc),
                reorder_pct=int(case.value),
                reorder_correlation_pct=case.correlation_pct,
            )
        else:
            commands = build_bidirectional_netem_commands(
                Path(tc),
                duplicate_pct=int(case.value),
            )
        for command in commands:
            if command[4] == "underlay1":
                _run(_in_namespace(pair.peer_pid, *command))
            else:
                _run(command)
        _wait_for_duration(3)
        for command in commands:
            clear = [tc, "qdisc", "del", "dev", command[4], "root"]
            if command[4] == "underlay1":
                _run(_in_namespace(pair.peer_pid, *clear))
            else:
                _run(clear)
        fault_cleared_ns = time.monotonic_ns()
        details["netem_profile"] = commands[0][7:]
        details["netem_interfaces"] = [command[4] for command in commands]
        return {"fault_started_ns": started_ns, "fault_cleared_ns": fault_cleared_ns, **details}
    elif case.kind == "link-down-up":
        _run([ip, "link", "set", "underlay0", "down"])
        _wait_for_duration(1)
        _run([ip, "link", "set", "underlay0", "up"])
        details["recovery_started_ns"] = time.monotonic_ns()
    elif case.kind == "mtu-change":
        _run([ip, "link", "set", "underlay0", "mtu", "1300"])
        _run(_in_namespace(pair.peer_pid, ip, "link", "set", "underlay1", "mtu", "1300"))
        _wait_for_duration(3)
        _run([ip, "link", "set", "underlay0", "mtu", "1500"])
        _run(_in_namespace(pair.peer_pid, ip, "link", "set", "underlay1", "mtu", "1500"))
        details["underlay_mtu_bytes"] = [1500, 1300, 1500]
    elif case.kind == "agent-restart":
        pair.right.restart()
        details["restarted_pid"] = pair.right.pid
    elif case.kind == "coordinator-restart":
        pair.coordinator.restart()
        snapshot = pair.coordinator.configuration("allow", pair.identities)
        pair._apply_snapshot(snapshot, stage="coordinator restart restore")
        details["persistent_coordinator_database"] = str(pair.scratch / "coordinator.sqlite")
    elif case.kind == "server-restart":
        if pair.server is None:
            raise RuntimeError("server restart needs the live product server fixture")
        restart = pair.server.restart()
        if restart["server_pid_before"] == restart["server_pid_after"]:
            raise RuntimeError("infraternal server process ID did not change after restart")
        if restart["server_health_status"] != 200:
            raise RuntimeError("infraternal server health check did not return 200 after restart")
        if not restart["server_data_directory_preserved"]:
            raise RuntimeError("infraternal server data directory changed during restart")
        details.update(restart)
        details["server_data_directory"] = str(pair.server.state_root)
    elif case.kind == "peer-churn":
        added = pair.coordinator.request("peer-add", count=20)
        pair._apply_snapshot(added, stage="peer add")
        details["peers_added"] = 20
        _wait_for_duration(1)
        removed = pair.coordinator.request("peer-remove", count=20)
        pair._apply_snapshot(removed, stage="peer remove")
        details["peers_removed"] = 20
    elif case.kind == "rekey-load":
        details.update(_apply_rotation(pair, timer_expired=False))
    elif case.kind == "rekey-timer-load":
        details.update(_apply_rotation(pair, timer_expired=True))
    elif case.kind == "peer-scale":
        if pair.left is None:
            raise RuntimeError("the left product node is not running")
        peer_rows = pair.left.peers()
        peers = [
            row["peer"]["addresses"]["ipv4"]
            for row in peer_rows
            if isinstance(row.get("peer"), dict)
            and isinstance(row["peer"].get("addresses"), dict)
            and isinstance(row["peer"]["addresses"].get("ipv4"), str)
        ]
        if len(peers) < int(case.value):
            raise RuntimeError(f"only {len(peers)} routed peers appeared for a {case.value}-peer case")
        route_misses = [
            address
            for address in peers
            if "dev infraternal0" not in _run([ip, "route", "get", address])
        ]
        peer_summary_before_storm = _peer_transfer_summary(peer_rows)
        handshake_summary = _peer_scale_handshake_summary(
            peer_rows,
            expected_peer_count=int(case.value),
        )
        underlay_before = _interface_counters("underlay0")
        endpoint_port = int(pair.right.identity["port"])
        storm = trigger_handshake_storm(
            "underlay0",
            peers,
            endpoint_port=endpoint_port,
        )
        peer_summary_after_storm = _peer_transfer_summary(pair.left.peers())
        underlay_after = _interface_counters("underlay0")
        resources_at_end = {
            "a": process_counters(pair.left.pid),
            "b": process_counters(pair.right.pid),
        }
        peer_count = len(peers)
        rss_before = pair.resource_before["a"]["rss_bytes"] + pair.resource_before["b"]["rss_bytes"]
        rss_after = (
            pair.resource_after_config["a"]["rss_bytes"]
            + pair.resource_after_config["b"]["rss_bytes"]
        )
        details.update(
            {
                "routed_peer_rows": len(peer_rows),
                "peer_route_check_count": len(peers),
                "peer_route_miss_count": len(route_misses),
                "peer_route_misses": route_misses,
                "expected_endpoint_port": endpoint_port,
                "peer_counters_before_storm": peer_summary_before_storm,
                "peer_counters_after_storm": peer_summary_after_storm,
                "handshake_trigger_datagrams": len(peers),
                "expected_endpoint_port": endpoint_port,
                **storm,
                **handshake_summary,
                "added_peer_count": int(case.value),
                "process_rss_delta_bytes": rss_after - rss_before,
                "rss_delta_bytes_per_added_peer": (rss_after - rss_before) // int(case.value),
                "resource_before_config": pair.resource_before,
                "resource_after_config": pair.resource_after_config,
                "resource_at_storm_end": resources_at_end,
                "underlay_counters_before_storm": underlay_before,
                "underlay_counters_after_storm": underlay_after,
                "underlay_tx_bytes_delta": underlay_after["tx_bytes"] - underlay_before["tx_bytes"],
                "peer_count_for_memory_ratio": peer_count,
            }
        )
    else:
        raise ValueError(f"no Linux fault injector for {case.kind}")
    return {"fault_started_ns": started_ns, "fault_cleared_ns": time.monotonic_ns(), **details}


def _run_case(
    case: FaultCase,
    *,
    binary: Path,
    coordinator_binary: Path,
    output: Path,
) -> dict[str, Any]:
    """Run one fault with fresh namespaces and return its recovery and integrity record."""
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    scale = int(case.value) if case.kind == "peer-scale" else 0
    duration = 155 if case.kind in {"rekey-load", "rekey-timer-load"} else 30
    pair: NamespacePair | None = None
    traffic: Traffic | None = None
    event: dict[str, Any] | None = None
    fault_started_ns: int | None = None
    try:
        pair = NamespacePair(
            binary,
            coordinator_binary,
            output / "fixture",
            extra_members=scale,
            with_server=case.kind == "server-restart",
        )
        traffic = Traffic(pair, output, duration_seconds=duration)
        fault_started_ns = time.monotonic_ns()
        event = _apply_fault(case, pair)
        sent_at_clear = _progress_bytes(traffic.sender_progress)
        verified_at_clear = _progress_bytes(traffic.receiver_progress)
        stalled = max(0, sent_at_clear - verified_at_clear)
        sent, received, probes = traffic.wait()
        integrity = transfer_integrity_ok(sent, received)
        result = report_case(
            case=case.name,
            platform="linux",
            fault_started_ns=int(event["fault_started_ns"]),
            fault_cleared_ns=int(event["fault_cleared_ns"]),
            recovery_started_ns=int(
                event.get("recovery_started_ns", event["fault_cleared_ns"])
            ),
            recovery_budget_ms=case.recovery_budget_ms,
            probes=probes,
            bytes_sent=int(sent["bytes"]),
            bytes_verified=int(received["bytes"]),
            bytes_stalled=stalled,
            integrity_ok=integrity,
        )
        result["details"] = {
            **{key: value for key, value in event.items() if not key.endswith("_ns")},
            "sender_sha256": sent.get("sha256"),
            "receiver_sha256": received.get("sha256"),
            "route_check": pair.route_check,
            "dns_check": pair.dns_check,
            "configure_apply_us": pair.configuration_us,
            "resource_after_traffic": {
                "a": process_counters(pair.left.pid),
                "b": process_counters(pair.right.pid),
            },
        }
        handshake_storm_ok = bool(event.get("handshake_storm_complete", True))
        result["handshake_storm_ok"] = handshake_storm_ok
        result["outcome"] = (
            "PASS" if result["outcome"] == "PASS" and integrity and handshake_storm_ok else "FAIL"
        )
    except BaseException as error:
        now_ns = time.monotonic_ns()
        bytes_sent, bytes_verified, probe_samples = _partial_traffic_progress(output, traffic)
        result = failed_case_report(
            case=case.name,
            platform="linux",
            fault_started_ns=(
                int(event["fault_started_ns"])
                if event is not None
                else fault_started_ns if fault_started_ns is not None else now_ns
            ),
            fault_cleared_ns=(
                int(event["fault_cleared_ns"]) if event is not None else None
            ),
            recovery_started_ns=(
                int(event["recovery_started_ns"])
                if event is not None and isinstance(event.get("recovery_started_ns"), int)
                else None
            ),
            recovery_budget_ms=case.recovery_budget_ms,
            observed_through_ns=now_ns,
            probes=probe_samples,
            bytes_sent=bytes_sent,
            bytes_verified=bytes_verified,
            bytes_stalled=(
                max(0, bytes_sent - bytes_verified)
                if fault_started_ns is not None
                else None
            ),
            error=f"{type(error).__name__}: {error}",
        )
    finally:
        if traffic is not None:
            traffic.close()
        if pair is not None:
            pair.close()
    (output / "case.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    """Run all requested Linux cases and preserve one JSON report per case."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--coordinator", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--case", action="append", dest="cases")
    arguments = parser.parse_args()
    for path in (arguments.binary, arguments.coordinator):
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error(f"required executable is missing or not executable: {path}")
    cases = select_fault_cases(arguments.cases)
    arguments.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    (arguments.output / "host.json").write_text(
        json.dumps(
            {
                "platform": "linux",
                "kernel": _run([_tool("uname"), "-a"]).strip(),
                "case_names": [case.name for case in cases],
                "flow_count": 1,
                "tcp_rate_mbit": 80,
                "tcp_warmup_bytes": _TRAFFIC_WARMUP_BYTES,
                "probe_interval_ms": 50,
                "underlay_mtu_bytes": 1500,
                "manual_fix_policy": "any product recovery needing an operator action is a failure",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    reports: list[dict[str, Any]] = []
    for case in cases:
        print(f"START case={case.name}", flush=True)
        report = _run_case(
            case,
            binary=arguments.binary,
            coordinator_binary=arguments.coordinator,
            output=arguments.output / case.name,
        )
        reports.append(report)
        print(json.dumps(report, separators=(",", ":"), sort_keys=True), flush=True)
    (arguments.output / "summary.json").write_text(
        json.dumps(reports, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    failures = [report["case"] for report in reports if report["outcome"] != "PASS"]
    if failures:
        print(f"FAILURES cases={','.join(failures)}", flush=True)
        raise SystemExit(1)
    print(f"ALL_CASES_PASS count={len(reports)}", flush=True)


if __name__ == "__main__":
    main()
