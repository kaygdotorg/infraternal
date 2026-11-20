#!/usr/bin/env python3
"""Prove three-client candidate walks, restart recovery and live endpoint roaming (#483)."""

# SPDX-License-Identifier: AGPL-3.0-only

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mesh_nat_censorship_proof as proof
from gotatun_break_it.app_fixture import ServerProcessFixture
from mesh_agent_fixture import BinaryNode, CoordinatorFixture

MEMBERS = ("S", "A", "B", "C")
CLIENTS = ("A", "B", "C")
RECOVERY_BOUND_SECONDS = 30.0
ANNOUNCEMENT_BOUND_SECONDS = 5.0
IDLE_WINDOW_SECONDS = 7.0


class ThreeNodeTopology(proof.Topology):
    """Build three non-server peers behind one non-hairpin NAT and a public server node."""

    def __init__(self) -> None:
        """Set the shared-router profile and track every private namespace for cleanup."""
        scenario = proof.Scenario(
            "three-node-candidate-walk",
            "three clients share a non-hairpin NAT behind a public server node",
            side_a=(proof.HOME,),
            side_b=(),
            same_nat=True,
            delay_ms=0,
            jitter_ms=0,
        )
        super().__init__(scenario)
        self.nodes = {"A": "node-a", "B": "node-b", "C": "node-c"}
        self.routers = {side: [] for side in CLIENTS}
        self.created_names: list[str] = []

    def namespace(self, name: str) -> None:
        """Create one private namespace and remember its handle for explicit removal."""
        super().namespace(name)
        self.created_names.append(name)

    def build_shared(self) -> None:
        """Attach all three clients to one LAN behind a router that cannot hairpin."""
        nat = self.scenario.side_a[0]
        self.router_namespace("rs", nat.udp_timeout)
        proof.ns("rs", "ip", "link", "add", "lan", "type", "bridge")
        proof.ns("rs", "ip", "addr", "add", "10.9.0.1/24", "dev", "lan")
        proof.ns("rs", "ip", "link", "set", "lan", "up")
        public = f"{proof.CORE_PREFIX}.21"
        router = proof.Router("rs", nat, "lan", "wan", "10.9.0.0/24", public, True)
        for number, side in ((2, "A"), (3, "B"), (4, "C")):
            node = self.nodes[side]
            self.namespace(node)
            self.pair("rs", f"p{side.lower()}", node, "eth0")
            proof.ns("rs", "ip", "link", "set", f"p{side.lower()}", "master", "lan")
            address = f"10.9.0.{number}"
            proof.ns(node, "ip", "addr", "add", f"{address}/24", "dev", "eth0")
            proof.ns(node, "ip", "route", "replace", "default", "via", "10.9.0.1")
            self.node_address[side] = address
            self.public_address[side] = public
            self.routers[side] = [router]
        self.core_link("rs", public)

    def propagate(self) -> None:
        """Update the router's endpoint-independent mappings after a client address change."""
        for side in CLIENTS:
            address, port = self.node_address[side], self.ports[side]
            for router in self.routers[side]:
                router.inside[address] = port
                address = router.public_address

    def cleanup(self) -> None:
        """Stop namespace holders, then delete every namespace created for this row."""
        super().cleanup()
        for name in reversed(self.created_names):
            proof.run("ip", "netns", "delete", name, check=False)


def peer_rows(node: BinaryNode) -> dict[str, dict[str, Any]]:
    """Return the live peer rows indexed by the peer's mesh IPv4 address."""
    response = node.call("mesh.peers", {})
    rows = response.get("peers")
    if not isinstance(rows, list):
        raise RuntimeError("mesh.peers returned no peer list")
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        peer = row.get("peer", {})
        addresses = peer.get("addresses", {})
        address = addresses.get("ipv4")
        if not isinstance(address, str) or address in indexed:
            raise RuntimeError(f"mesh.peers returned a missing or duplicate peer address: {row!r}")
        indexed[address] = row
    return indexed


def start_node(
    binary: str,
    scratch: str,
    namespace_pid: int,
    state_path: str | None = None,
) -> BinaryNode:
    """Start one real node in its private namespace and keep its process-owned state."""
    return BinaryNode(binary, scratch, namespace_pid, state_path=state_path)


def public_endpoint(target: str, topology: ThreeNodeTopology, ports: dict[str, int]) -> str:
    """Return the public endpoint this topology's NAT maps to the target node."""
    if target in CLIENTS:
        router = topology.routers[target][0]
        port = router.outside_port(topology.node_address[target])
        return f"{router.public_address}:{port}"
    return f"{topology.public_address[target]}:{ports[target]}"


def expected_endpoint(source: str, target: str, topology: ThreeNodeTopology, ports: dict[str, int]) -> str:
    """Return the path address that the production engine should currently use."""
    if source in CLIENTS and target in CLIENTS:
        return f"{topology.node_address[target]}:{ports[target]}"
    return public_endpoint(target, topology, ports)


def assert_peer_inventory(
    nodes: dict[str, BinaryNode],
    addresses: dict[str, str],
    topology: ThreeNodeTopology,
    ports: dict[str, int],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Require exactly the configured peers, direct routes and current endpoint for every node."""
    snapshots: dict[str, dict[str, dict[str, Any]]] = {}
    for source in MEMBERS:
        rows = peer_rows(nodes[source])
        expected = {addresses[target] for target in MEMBERS if target != source}
        if set(rows) != expected:
            raise AssertionError(
                f"{source} peer inventory differs: expected {sorted(expected)}, got {sorted(rows)}"
            )
        snapshots[source] = rows
        for target in MEMBERS:
            if target == source:
                continue
            row = rows[addresses[target]]
            endpoint = row.get("counters", {}).get("endpoint")
            wanted = expected_endpoint(source, target, topology, ports)
            if endpoint != wanted:
                raise AssertionError(f"{source}->{target} endpoint is {endpoint}, expected {wanted}")
            route = proof.ns(
                topology.nodes[source], "ip", "-4", "route", "get", addresses[target]
            )
            if "dev infraternal0" not in route:
                raise AssertionError(f"{source}->{target} route escaped the mesh interface: {route.strip()}")
    return snapshots


def start_pingers(
    topology: ThreeNodeTopology,
    addresses: dict[str, str],
    pairs: list[tuple[str, str]],
) -> list[tuple[proof.Pinger, float, str, str]]:
    """Start a bounded set of directional mesh pings and remember their start times."""
    pingers: list[tuple[proof.Pinger, float, str, str]] = []
    for source, target in pairs:
        started = time.monotonic()
        pingers.append((proof.Pinger(topology.nodes[source], addresses[target]), started, source, target))
    return pingers


def stop_pingers(pingers: list[tuple[proof.Pinger, float, str, str]]) -> None:
    """Stop exactly the ping processes created for one proof phase."""
    for pinger, _, _, _ in pingers:
        pinger.stop()


def start_packet_capture(
    namespace: str,
    interface: str,
    path: Path,
) -> tuple[subprocess.Popen[bytes], Path]:
    """Capture one namespace's UDP traffic for the optional underlay-change diagnosis."""
    log_path = path.with_suffix(path.suffix + ".log")
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [
                "ip", "netns", "exec", namespace, "tcpdump", "-U", "-nn", "-tt",
                "-i", interface, "-w", str(path), "udp",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=log,
            start_new_session=True,
        )
    time.sleep(0.05)
    if process.poll() is not None:
        raise RuntimeError(f"UDP capture did not start in {namespace}: {log_path.read_text()}")
    return process, path


def stop_packet_captures(
    captures: list[tuple[str, subprocess.Popen[bytes], Path]],
) -> dict[str, dict[str, Any]]:
    """Stop only the capture process groups and summarize their packet receipts."""
    receipts: dict[str, dict[str, Any]] = {}
    for name, process, path in captures:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        decoded = subprocess.run(
            ["tcpdump", "-nn", "-tt", "-r", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        log_path = path.with_suffix(path.suffix + ".log")
        receipts[name] = {
            "pcap": str(path),
            "tcpdump_log": str(log_path),
            "decode_exit": decoded.returncode,
            "packets": decoded.stdout.splitlines(),
            "decode_stderr": decoded.stderr.strip(),
            "capture_log": log_path.read_text().strip(),
        }
    return receipts


def require_first_replies(
    pingers: list[tuple[proof.Pinger, float, str, str]],
    timeout: float,
) -> dict[str, float]:
    """Require one reply for every directed flow and report its elapsed recovery time."""
    results: dict[str, float] = {}
    for pinger, started, source, target in pingers:
        elapsed = pinger.first_after(started, timeout)
        if elapsed is None:
            raise TimeoutError(f"{source}->{target} did not carry traffic within {timeout:.1f}s")
        results[f"{source}->{target}"] = round(elapsed * 1000, 1)
    return results


def wait_for_direct(
    nodes: dict[str, BinaryNode],
    addresses: dict[str, str],
    topology: ThreeNodeTopology,
    ports: dict[str, int],
    timeout: float,
) -> dict[str, float]:
    """Wait for every row to show its expected direct endpoint and return transition times."""
    started = time.monotonic()
    deadline = started + timeout
    first_seen: dict[str, float] = {}
    while time.monotonic() < deadline:
        for source in MEMBERS:
            rows = peer_rows(nodes[source])
            for target in MEMBERS:
                if target == source:
                    continue
                name = f"{source}->{target}"
                row = rows.get(addresses[target])
                endpoint = None if row is None else row.get("counters", {}).get("endpoint")
                if endpoint == expected_endpoint(source, target, topology, ports):
                    first_seen.setdefault(name, round((time.monotonic() - started) * 1000, 1))
        if len(first_seen) == len(MEMBERS) * (len(MEMBERS) - 1):
            return first_seen
        # sleep: peer tables are independent snapshots; keep the poll below the five-second bound.
        time.sleep(0.1)
    missing = sorted(set(
        f"{source}->{target}" for source in MEMBERS for target in MEMBERS if source != target
    ) - set(first_seen))
    endpoint_state: dict[str, dict[str, str | None]] = {}
    for source in MEMBERS:
        rows = peer_rows(nodes[source])
        for target in MEMBERS:
            if target == source:
                continue
            name = f"{source}->{target}"
            if name not in missing:
                continue
            row = rows.get(addresses[target])
            actual = None if row is None else row.get("counters", {}).get("endpoint")
            endpoint_state[name] = {
                "actual": actual if isinstance(actual, str) else None,
                "expected": expected_endpoint(source, target, topology, ports),
            }
    raise TimeoutError(
        f"direct endpoints did not settle within {timeout:.1f}s: {missing}; "
        f"current endpoints: {endpoint_state}"
    )


def assert_no_idle_handshakes(nodes: dict[str, BinaryNode]) -> None:
    """Require a quiet peer table to emit neither a new handshake nor an initiation packet."""
    before = {
        source: {
            address: (
                row.get("counters", {}).get("handshake_secs"),
                row.get("counters", {}).get("sent_bytes", 0),
            )
            for address, row in peer_rows(nodes[source]).items()
        }
        for source in MEMBERS
    }
    time.sleep(IDLE_WINDOW_SECONDS)
    after = {source: peer_rows(nodes[source]) for source in MEMBERS}
    for source in MEMBERS:
        for address, row in after[source].items():
            counters = row.get("counters", {})
            handshake, sent = before[source][address]
            if counters.get("handshake_secs") != handshake:
                raise AssertionError(f"idle {source} handshook peer {address}")
            if int(counters.get("sent_bytes", 0)) - int(sent) >= 148:
                raise AssertionError(f"idle {source} sent a handshake initiation to peer {address}")


def restart_node(
    member: str,
    nodes: dict[str, BinaryNode],
    identities: dict[str, dict[str, Any]],
    topology: ThreeNodeTopology,
    binary: str,
    scratch: str,
    observer: proof.Observer,
    addresses: dict[str, str],
    ports: dict[str, int],
) -> dict[str, float]:
    """Kill and restart one mesh process, replay the snapshot, and time every reconnect."""
    old = nodes[member]
    old_identity = identities[member]
    old_state = str(old.state)
    before_pid = old.pid
    restart_started = time.monotonic()
    old.crash()
    restarted = start_node(
        binary,
        scratch,
        topology.node_pid[member],
        state_path=old_state,
    )
    nodes[member] = restarted
    observer.nodes = [nodes[name] for name in MEMBERS]
    identity = json.loads(restarted.stdout.readline())
    if identity["public_key"] != old_identity["public_key"] or identity["port"] != old_identity["port"]:
        raise AssertionError(f"{member} identity changed during process restart")
    identities[member] = identity
    observer.request({"mode": "allow", "full_snapshot": True})
    snapshot_applied = time.monotonic()
    pingers = start_pingers(
        topology,
        addresses,
        [(member, other) for other in MEMBERS if other != member]
        + [(other, member) for other in MEMBERS if other != member],
    )
    try:
        direct = wait_for_direct(nodes, addresses, topology, ports, RECOVERY_BOUND_SECONDS)
        direct_elapsed_ms = round((time.monotonic() - restart_started) * 1000, 1)
        traffic = require_first_replies(pingers, RECOVERY_BOUND_SECONDS)
        assert_peer_inventory(nodes, addresses, topology, ports)
        traffic_elapsed_ms = max(
            round((started - restart_started) * 1000 + traffic[f"{source}->{target}"], 1)
            for _, started, source, target in pingers
        )
        if direct_elapsed_ms > RECOVERY_BOUND_SECONDS * 1000:
            raise TimeoutError(f"{member} direct endpoints recovered after {direct_elapsed_ms}ms")
        if traffic_elapsed_ms > RECOVERY_BOUND_SECONDS * 1000:
            raise TimeoutError(f"{member} traffic recovered after {traffic_elapsed_ms}ms")
        return {
            "pid_before": float(before_pid),
            "pid_after": float(restarted.pid),
            "direct_endpoints_ms": direct_elapsed_ms,
            "traffic_recovery_ms": traffic_elapsed_ms,
            "snapshot_applied_ms": round((snapshot_applied - restart_started) * 1000, 1),
            "direct_observed_from_snapshot_ms": max(direct.values()),
            "first_packets_from_ping_start_ms": max(traffic.values()),
        }
    finally:
        stop_pingers(pingers)


def run_proof(
    binary: str,
    coordinator_path: str,
    scratch: str,
    restart_only: bool = False,
) -> dict[str, Any]:
    """Run four real mesh processes, restart checks and optional address roaming."""
    topology = ThreeNodeTopology()
    nodes: dict[str, BinaryNode] = {}
    identities: dict[str, dict[str, Any]] = {}
    pingers: list[tuple[proof.Pinger, float, str, str]] = []
    coordinator: CoordinatorFixture | None = None
    server: ServerProcessFixture | None = None
    captures: list[tuple[str, subprocess.Popen[bytes], Path]] = []
    row: dict[str, Any] = {
        "scenario": "three-node-candidate-walk-restarts",
        "recovery_bound_seconds": RECOVERY_BOUND_SECONDS,
        "announcement_bound_seconds": ANNOUNCEMENT_BOUND_SECONDS,
        "fixture_boundary": "server mesh node is a real agent; coordinator uses the production-schema fixture",
    }
    try:
        topology.create()
        topology.add_server()
        for member in MEMBERS:
            nodes[member] = start_node(
                binary,
                scratch,
                topology.node_pid[member],
            )
            identities[member] = json.loads(nodes[member].stdout.readline())
        ports = {member: int(identities[member]["port"]) for member in MEMBERS}
        topology.configure({member: ports[member] for member in CLIENTS})
        probes = [nodes[member].call("mesh.identity", {"candidates": True}) for member in MEMBERS]
        for member, probe in zip(MEMBERS, probes):
            if member in CLIENTS and f"{topology.node_address[member]}:{ports[member]}" not in probe.get("lan", []):
                raise AssertionError(f"{member} did not publish its current LAN candidate: {probe}")
        row["candidate_probes"] = probes
        endpoints = [public_endpoint(member, topology, ports) for member in MEMBERS]
        coordinator = CoordinatorFixture(coordinator_path)
        observer = proof.Observer(coordinator, [nodes[member] for member in MEMBERS], list(MEMBERS))
        initial = observer.request({
            "mode": "allow",
            "identities": [identities[member] for member in MEMBERS],
            "endpoints": endpoints,
            "probes": probes,
        })
        addresses = {
            member: initial["addresses"][index]["ipv4"]
            for index, member in enumerate(MEMBERS)
        }
        row["mesh_addresses"] = addresses
        row["underlay_addresses_initial"] = dict(topology.node_address)
        row["listen_ports"] = ports
        pairs = [(source, target) for source in MEMBERS for target in MEMBERS if source != target]
        pingers = start_pingers(topology, addresses, pairs)
        direct_times = wait_for_direct(nodes, addresses, topology, ports, RECOVERY_BOUND_SECONDS)
        traffic_times = require_first_replies(pingers, RECOVERY_BOUND_SECONDS)
        assert_peer_inventory(nodes, addresses, topology, ports)
        row["initial_direct_endpoint_ms"] = direct_times
        row["initial_first_packet_ms"] = traffic_times
        stop_pingers(pingers)
        pingers = []
        assert_no_idle_handshakes(nodes)
        row["idle_handshake_check_seconds"] = IDLE_WINDOW_SECONDS

        row["node_restart"] = restart_node(
            "B", nodes, identities, topology, binary, scratch, observer, addresses, ports
        )
        assert_no_idle_handshakes(nodes)
        row["node_restart"]["idle_handshake_check_seconds"] = IDLE_WINDOW_SECONDS
        assert_peer_inventory(nodes, addresses, topology, ports)
        row["server_mesh_node_restart"] = restart_node(
            "S", nodes, identities, topology, binary, scratch, observer, addresses, ports
        )
        assert_no_idle_handshakes(nodes)
        row["server_mesh_node_restart"]["idle_handshake_check_seconds"] = IDLE_WINDOW_SECONDS
        assert_peer_inventory(nodes, addresses, topology, ports)

        server = ServerProcessFixture(
            Path(binary),
            Path(scratch) / "server-state",
            stderr_path=Path(scratch) / "server.stderr.log",
        )
        server_restart_started = time.monotonic()
        server_restart: dict[str, Any] = server.restart()
        server_restart["recovery_ms"] = round(
            (time.monotonic() - server_restart_started) * 1000, 1
        )
        row["server_process_restart"] = server_restart
        assert_no_idle_handshakes(nodes)
        row["server_process_restart"]["idle_handshake_check_seconds"] = IDLE_WINDOW_SECONDS
        assert_peer_inventory(nodes, addresses, topology, ports)

        if restart_only:
            row["underlay_check_skipped"] = True
            row["outcome"] = "PASS"
            return row

        stop_pingers(pingers)
        pingers = []
        row["endpoints_before_underlay_change"] = {
            source: peer_rows(nodes[source])
            .get(addresses["C"], {})
            .get("counters", {})
            .get("endpoint")
            for source in ("S", "A", "B")
        }
        row["peer_state_before_underlay_change"] = {
            source: peer_rows(nodes[source]).get(addresses["C"])
            for source in ("S", "A", "B")
        }
        old_address = topology.node_address["C"]
        new_address = "10.9.0.44"
        if os.environ.get("J967_CAPTURE_UNDERLAY") == "1":
            capture_root = Path(scratch)
            for name, namespace, interface in (
                ("C", "node-c", "eth0"),
                ("S", "node-s", "wan"),
                ("router", "rs", "wan"),
            ):
                process, path = start_packet_capture(
                    namespace, interface, capture_root / f"underlay-{name}.pcap"
                )
                captures.append((name, process, path))
        # Include the address and NAT-rule updates; an announcement may arrive while they run.
        announcement_started = time.monotonic()
        proof.ns("node-c", "ip", "addr", "add", f"{new_address}/24", "dev", "eth0")
        for router in topology.routers["C"]:
            router.inside.pop(old_address, None)
        topology.node_address["C"] = new_address
        topology.propagate()
        topology.install()
        proof.ns("node-c", "ip", "addr", "del", f"{old_address}/24", "dev", "eth0")
        # Replacing nft rules does not change the destination stored in an established conntrack
        # entry. Retire C's old flow only, so the public mapping can now deliver to its new address.
        row["old_address_conntrack_delete"] = proof.ns(
            "rs", "conntrack", "-D", "-p", "udp", "-s", old_address, check=False
        ).strip()
        conntrack_after_move = proof.ns(
            "rs", "conntrack", "-L", "-p", "udp", check=False
        ).splitlines()
        if any(f"src={old_address} dst={proof.SERVER_ADDRESS}" in line for line in conntrack_after_move):
            raise AssertionError(
                f"router retained C's stale UDP mapping from {old_address} to {proof.SERVER_ADDRESS}"
            )
        row["router_conntrack_after_old_flow_removal"] = conntrack_after_move
        row["underlay_address_change"] = {"from": old_address, "to": new_address}
        new_endpoint = f"{new_address}:{ports['C']}"
        deadline = announcement_started + ANNOUNCEMENT_BOUND_SECONDS
        announced: dict[str, bool] = {"A": False, "B": False}
        while time.monotonic() < deadline and not all(announced.values()):
            for receiver in ("A", "B"):
                candidates = peer_rows(nodes[receiver]).get(addresses["C"], {})
                announced[receiver] = candidates.get("counters", {}).get("endpoint") == new_endpoint
            if not all(announced.values()):
                # sleep: no user traffic runs here, so this endpoint change can only come from the live-session announcement.
                time.sleep(0.05)
        if not all(announced.values()):
            raise TimeoutError(f"A and B did not learn C's announced endpoint within {ANNOUNCEMENT_BOUND_SECONDS}s: {announced}")
        row["announcement_ms"] = round((time.monotonic() - announcement_started) * 1000, 1)
        row["endpoints_after_announcement"] = {
            source: peer_rows(nodes[source])
            .get(addresses["C"], {})
            .get("counters", {})
            .get("endpoint")
            for source in ("S", "A", "B")
        }
        row["peer_state_after_announcement"] = {
            source: peer_rows(nodes[source]).get(addresses["C"])
            for source in ("S", "A", "B")
        }
        row["client_route_to_server_after_underlay_change"] = proof.ns(
            "node-c", "ip", "route", "get", proof.SERVER_ADDRESS
        ).strip()
        row["router_conntrack_after_underlay_change"] = proof.ns(
            "rs", "conntrack", "-L", "-p", "udp", check=False
        ).splitlines()
        stale_probe = dict(probes[MEMBERS.index("C")])
        stale_probe["lan"] = [f"10.9.0.45:{ports['C']}"]
        stale_probes = list(probes)
        stale_probes[MEMBERS.index("C")] = stale_probe
        observer.request({"mode": "keep", "probes": stale_probes})
        for receiver in ("A", "B"):
            endpoint = peer_rows(nodes[receiver])[addresses["C"]].get("counters", {}).get("endpoint")
            if endpoint != new_endpoint:
                raise AssertionError(
                    f"{receiver} left C's authenticated roaming endpoint after a stale snapshot: {endpoint}"
                )
        row["endpoints_after_stale_snapshot"] = {
            source: peer_rows(nodes[source])
            .get(addresses["C"], {})
            .get("counters", {})
            .get("endpoint")
            for source in ("S", "A", "B")
        }
        row["peer_state_after_stale_snapshot"] = {
            source: peer_rows(nodes[source]).get(addresses["C"])
            for source in ("S", "A", "B")
        }
        post_snapshot = start_pingers(
            topology,
            addresses,
            [(source, target) for source in MEMBERS for target in MEMBERS if source != target],
        )
        try:
            direct_after_snapshot = wait_for_direct(nodes, addresses, topology, ports, RECOVERY_BOUND_SECONDS)
            traffic_after_snapshot = require_first_replies(post_snapshot, RECOVERY_BOUND_SECONDS)
            assert_peer_inventory(nodes, addresses, topology, ports)
            conntrack_after_recovery = proof.ns(
                "rs", "conntrack", "-L", "-p", "udp", check=False
            ).splitlines()
            if any(
                f"src={old_address} dst={proof.SERVER_ADDRESS}" in line
                for line in conntrack_after_recovery
            ):
                raise AssertionError(
                    f"router recreated C's stale UDP mapping from {old_address}"
                )
            if not any(
                f"src={new_address} dst={proof.SERVER_ADDRESS}" in line
                and f"sport={ports['C']} dport={ports['S']}" in line
                for line in conntrack_after_recovery
            ):
                raise AssertionError(
                    f"router did not record C's new UDP mapping from {new_address} to the server"
                )
            row["stale_snapshot_direct_endpoint_ms"] = direct_after_snapshot
            row["stale_snapshot_first_packet_ms"] = traffic_after_snapshot
            row["router_conntrack_after_recovery"] = conntrack_after_recovery
        finally:
            stop_pingers(post_snapshot)
        assert_no_idle_handshakes(nodes)
        row["underlay_idle_handshake_check_seconds"] = IDLE_WINDOW_SECONDS
        if captures:
            row["underlay_packet_capture"] = stop_packet_captures(captures)
            captures.clear()

        current_probes = [nodes[member].call("mesh.identity", {"candidates": True}) for member in MEMBERS]
        observer.request({"mode": "keep", "probes": current_probes})
        assert_peer_inventory(nodes, addresses, topology, ports)
        row["outcome"] = "PASS"
        return row
    except Exception as error:
        row["outcome"] = "FAIL"
        row["error"] = f"{type(error).__name__}: {error}"
        return row
    finally:
        if captures:
            row["underlay_packet_capture"] = stop_packet_captures(captures)
        stop_pingers(pingers)
        if server is not None:
            try:
                server.close()
            except Exception as error:
                row.setdefault("cleanup_errors", []).append(f"server: {error}")
        if coordinator is not None:
            try:
                coordinator.close()
            except Exception as error:
                row.setdefault("cleanup_errors", []).append(str(error))
        for member, node in list(nodes.items()):
            try:
                node.close()
            except Exception as error:
                row.setdefault("cleanup_errors", []).append(f"{member}: {error}")
        try:
            topology.cleanup()
        except Exception as error:
            row.setdefault("cleanup_errors", []).append(f"namespaces: {error}")
        if row.get("cleanup_errors"):
            row["outcome"] = "FAIL"


def inner(args: argparse.Namespace) -> int:
    """Run the proof inside the private mount namespace and emit one machine-readable row."""
    proof.run("mount", "-t", "tmpfs", "-o", "mode=0700", "tmpfs", "/run")
    Path("/run/netns").mkdir(parents=True, exist_ok=True)
    try:
        row = run_proof(args.binary, args.coordinator, args.scratch, args.restart_only)
    except Exception as error:
        row = {"scenario": "three-node-candidate-walk-restarts", "outcome": "FAIL",
               "error": f"{type(error).__name__}: {error}"}
        print("ROW " + json.dumps(row, sort_keys=True), flush=True)
        return 1
    remaining = proof.run("ip", "netns", "list").strip()
    if remaining:
        row["outcome"] = "FAIL"
        row["cleanup_error"] = f"net namespaces remain after the row: {remaining}"
    print("ROW " + json.dumps(row, sort_keys=True), flush=True)
    return 0 if row.get("outcome") == "PASS" else 1


def outer(args: argparse.Namespace) -> int:
    """Start one root-owned private mount namespace, enforce the row cap, and save its receipt."""
    scratch = Path(args.scratch)
    scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    if scratch.stat().st_mode & 0o077:
        raise PermissionError(f"scratch directory must be private (0700): {scratch}")
    if os.geteuid() != 0:
        raise PermissionError("the three-node netns proof must run as root on a build VM")
    run_scratch = Path(tempfile.mkdtemp(prefix="run-", dir=scratch))
    command = ["unshare", "-m", "--propagation", "private", sys.executable,
               str(Path(__file__).resolve()), "--inner", "--binary", args.binary,
               "--coordinator", args.coordinator, "--scratch", str(run_scratch)]
    if args.restart_only:
        command.append("--restart-only")
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, start_new_session=True,
                               env={**os.environ, "TMPDIR": str(run_scratch)})
    try:
        stdout, stderr = process.communicate(timeout=300)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        row = {"outcome": "FAIL", "error": "the 300 second row cap expired"}
    else:
        lines = [line[4:] for line in stdout.splitlines() if line.startswith("ROW ")]
        row = json.loads(lines[-1]) if lines else {
            "outcome": "FAIL", "error": f"proof emitted no row: {stderr[-4000:]}"
        }
    if args.report:
        Path(args.report).write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
    print(json.dumps(row, sort_keys=True), flush=True)
    return 0 if process.returncode == 0 and row.get("outcome") == "PASS" else 1


def main() -> None:
    """Parse absolute inputs and run the root-only four-participant integration proof."""
    parser = argparse.ArgumentParser(description="Three-client candidate walk and restart proof (#483).")
    parser.add_argument("--binary", required=True, help="absolute infraternal executable path")
    parser.add_argument("--coordinator", required=True, help="absolute coordinator_fixture path")
    parser.add_argument("--scratch", required=True, help="absolute private scratch directory")
    parser.add_argument("--report", help="optional absolute JSON receipt path")
    parser.add_argument(
        "--restart-only",
        action="store_true",
        help="stop after the two mesh restarts and separate server-process restart",
    )
    parser.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    for name in ("binary", "coordinator", "scratch"):
        value = Path(getattr(args, name))
        if not value.is_absolute():
            parser.error(f"--{name} must be absolute")
    if args.report and not Path(args.report).is_absolute():
        parser.error("--report must be absolute")
    raise SystemExit(inner(args) if args.inner else outer(args))


if __name__ == "__main__":
    main()
