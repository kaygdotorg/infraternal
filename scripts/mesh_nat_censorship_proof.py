#!/usr/bin/env python3
"""Run two real mesh nodes through emulated NATs and censoring networks, without root.

What this is for
----------------
The mesh promises direct paths between hosts. Real hosts sit behind home
routers, carrier-grade NAT (CGNAT), double NAT, and networks that block or
inspect UDP. This harness builds each of those networks out of Linux network
namespaces, veth links and nftables NAT rules, starts two real `infraternal
agent` processes inside it, hands them the snapshot the production coordinator
would compute, and measures what happens:

* whether a direct path forms, and the time from snapshot to first packet;
* round-trip p50 at rest and p99 under a saturating TCP transfer;
* TCP throughput through the tunnel;
* how long the path takes to recover after the NAT rebinds mid-flow;
* what `infraternal mesh peers` tells the person when there is no path.

How to run it
-------------
It needs no root and no sudo. The outer process starts one rootless user,
network and mount namespace per profile (`unshare -Urnm`). Inside, it is root
over that private network stack only, so the NAT and conntrack it drives are
the real kernel ones, yet nothing on the host changes. Each profile has a
hard five-minute cap.

    scripts/mesh_nat_censorship_proof.py --binary /abs/infraternal \
        --coordinator /abs/coordinator_fixture --scratch /abs/private-dir \
        --report /abs/report.json [--scenario NAME ...]

`--list` prints the profile catalogue as JSON.

The production coordinator model
--------------------------------
In production a node's published endpoint is the source IP the server sees on
the node's control connection plus the node's *local* UDP listen port. There is
no reflexive (STUN-like) port discovery and no LAN candidate. The harness
publishes exactly that pair: the public address of the node's outermost NAT and
the node's own listen port. Anything that works here works because the product
and the NAT allow it, not because the harness peeked at a mapping.

The product model (#515)
------------------------
`--model product` runs the shipped candidate code instead of publishing anything itself. A
third real node, the server's own node, sits on the public core. Every node answers the real
candidate identity probe (its LAN address comes from its own routing table), and every five
seconds the harness reads the server node's real peer table and hands it to the coordinator
fixture, which runs the server's observation and republication code. The harness applies
whatever snapshot results, as the coordinator's workers would. It first lets the server observe
both nodes while Access still denies the pair (the steady state of a long-lived mesh), then
opens the pair and measures, so its numbers are comparable with the candidates model. A rebind
gets no help: the new mapping reaches the peer only through the server's next observation.

The relay model (D402)
----------------------
`--model relay` is the candidates model plus the relay manager's first slice. A third real node
sits on the public core and serves the relay role, exactly as the server's own node does: it
gets `mesh.relays` with a relay leaf from a disposable CA and answers with its bound UDP port.
Both measured nodes get `mesh.relays` naming that relay, and a host leaf from the same CA
through the test-only `INFRATERNAL_TEST_RELAY_HOST_LEAF` hook (so the binary under test must be
built with `infraternal-plugin-mesh/test-support`). Their relay manager relays a pair that has
no handshake 5.5 s after its configuration was installed. Each row records whether the pair
went direct or through the relay, why, and what the relay counted. `--relay-fixture` names the
`relay_fixture` example that issues the certificates.

NAT model
---------
Every router is described by a `Nat`: how it maps (endpoint-independent with an
optional port offset, or symmetric with a fresh random port per destination),
how it filters inbound packets (endpoint-independent, address-dependent or
address-and-port-dependent, after RFC 4787), whether it hairpins, and its UDP
mapping timeout. Endpoint-independent mappings are a fixed nft map from the
inside (address, port) to the outside port, so a "port-preserving" NAT and a
"port-translating" CGNAT differ only by that offset.
"""

import argparse
import hashlib
import json
import math
import os
import platform
import queue
import re
import select
import shutil
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

os.environ["PATH"] = os.environ.get("PATH", "") + ":/usr/sbin:/sbin:/usr/bin:/bin"

# Every profile must finish inside this many seconds, set by the owner's brief (#483).
PROFILE_CAP_SECONDS = 300
# The production handshake retries every 5 s; 75 s leaves room for a 30 s conntrack clash to clear.
FIRST_PACKET_TIMEOUT_SECONDS = 75.0
# How long a rebind may take before the harness records "did not recover".
REBIND_TIMEOUT_SECONDS = 90.0
# How long the loaded TCP stream runs.
LOAD_SECONDS = 8.0
# The documentation prefix that plays the public internet.
CORE_PREFIX = "198.51.100"
# Where the server's own node sits on the public core in the product model.
SERVER_ADDRESS = f"{CORE_PREFIX}.10"
# The server's presence poll interval (crates/plugins/mesh/src/presence.rs `POLL`).
PRESENCE_POLL_SECONDS = 5.0
# How long the server watches both nodes before the pair is opened: one 25 s keepalive plus two polls.
WARMUP_SECONDS = 35.0


@dataclass(frozen=True)
class Nat:
    """One router's NAT behaviour.

    `mapping` is "eim" (endpoint-independent: one outside port per inside
    socket, whatever the destination) or "apdm" (address-and-port-dependent,
    "symmetric": a new random outside port for every destination).
    `port_offset` shifts every EIM outside port; 0 keeps the inside port, which
    is what most home routers do when the port is free, and a non-zero offset
    models a CGNAT that hands out ports from its own block.
    `filtering` is "eif" (anyone may send to a mapping: "full cone"), "adf"
    (only addresses the inside host has sent to) or "apdf" (only the exact
    address and port it has sent to). Symmetric NATs always filter as "apdf".
    """

    mapping: str = "eim"
    filtering: str = "apdf"
    port_offset: int = 0
    hairpin: bool = False
    udp_timeout: int = 60


@dataclass(frozen=True)
class Scenario:
    """One network profile: the NAT tiers on each side plus any censorship.

    `side_a` and `side_b` list routers from the node outwards; an empty list
    puts the node straight on the public network. With `same_nat` both nodes
    share the single router in `side_a`.
    """

    name: str
    summary: str
    side_a: tuple[Nat, ...] = (Nat(),)
    side_b: tuple[Nat, ...] = (Nat(),)
    cgnat_tiers: tuple[int, ...] = ()
    same_nat: bool = False
    udp_blocked: bool = False
    tcp_ports: tuple[int, ...] = ()
    dpi_handshakes: bool = False
    wan_mtu: int | None = None
    block_icmp: bool = False
    idle_expiry_seconds: int = 0
    delay_ms: int = 15
    jitter_ms: int = 2
    loss_percent: float = 0.0


HOME = Nat()
FULL_CONE = Nat(filtering="eif")
ADDRESS_RESTRICTED = Nat(filtering="adf")
SYMMETRIC = Nat(mapping="apdm")
# RFC 6888 asks CGNATs for endpoint-independent mapping; most hand out ports from their own block.
CGNAT = Nat(port_offset=20_000, udp_timeout=30)
CGNAT_PRESERVING = Nat(udp_timeout=30)

# The owner's list (#483), plus the variants that separate one cause from another.
SCENARIOS = (
    Scenario("full-cone-both", "both sides endpoint-independent mapping and filtering", (FULL_CONE,), (FULL_CONE,)),
    Scenario("address-restricted-both", "EIM, address-dependent filtering", (ADDRESS_RESTRICTED,), (ADDRESS_RESTRICTED,)),
    Scenario("port-restricted-both", "EIM, address-and-port-dependent filtering (typical Linux home router)", loss_percent=0.2),
    Scenario("symmetric-one-side-vs-port-restricted", "A symmetric, B port-restricted", (SYMMETRIC,), (HOME,)),
    Scenario("symmetric-one-side-vs-full-cone", "A symmetric, B full cone", (SYMMETRIC,), (FULL_CONE,)),
    Scenario("symmetric-both", "both symmetric", (SYMMETRIC,), (SYMMETRIC,)),
    Scenario(
        "cgnat-both",
        "nodes on 100.64/10 behind port-translating CGNAT, 30 s UDP timeout, no hairpin",
        (CGNAT,), (CGNAT,), cgnat_tiers=(0,), delay_ms=30, jitter_ms=5,
    ),
    Scenario(
        "cgnat-both-port-preserving",
        "as cgnat-both, but the CGNAT keeps the inside port",
        (CGNAT_PRESERVING,), (CGNAT_PRESERVING,), cgnat_tiers=(0,), delay_ms=30, jitter_ms=5,
    ),
    Scenario(
        "cgnat-idle-35s",
        "port-preserving CGNAT, 30 s UDP timeout, path idle 35 s before traffic",
        (CGNAT_PRESERVING,), (CGNAT_PRESERVING,), cgnat_tiers=(0,), idle_expiry_seconds=35,
    ),
    Scenario("double-nat-one-side", "A home NAT behind CGNAT; B home NAT", (HOME, CGNAT), (HOME,), cgnat_tiers=(1,)),
    Scenario("double-nat-both", "home NAT behind CGNAT on both sides", (HOME, CGNAT), (HOME, CGNAT), cgnat_tiers=(1,), delay_ms=30),
    Scenario("same-nat-hairpin-on", "both nodes behind one router that hairpins", (Nat(hairpin=True),), (), same_nat=True),
    Scenario("same-nat-hairpin-off", "both nodes behind one router without hairpin", (HOME,), (), same_nat=True),
    Scenario("udp-blocked", "all UDP dropped at both edges", udp_blocked=True),
    Scenario("tcp-80-443-only", "only TCP 80 and 443 leave either network", udp_blocked=True, tcp_ports=(80, 443)),
    Scenario("dpi-wireguard-handshake", "edges drop UDP payloads shaped like handshake types 1 and 2 (148 and 92 bytes)", dpi_handshakes=True),
    Scenario("mtu-576-icmp-blocked", "WAN MTU 576 and all ICMP dropped (PMTU black hole)", wan_mtu=576, block_icmp=True),
    Scenario(
        "mapping-expiry-10s",
        "port-restricted, 10 s UDP timeout (below the 25 s keepalive), idle 40 s",
        (Nat(udp_timeout=10),), (Nat(udp_timeout=10),), idle_expiry_seconds=40,
    ),
)


def scenario_named(name: str) -> Scenario:
    """Return a profile by name, or explain which name is unknown."""
    for scenario in SCENARIOS:
        if scenario.name == name:
            return scenario
    raise ValueError(f"unknown scenario {name!r}")


def run(*arguments: str, input_data: str | None = None, check: bool = True, timeout: float = 30) -> str:
    """Run one command, returning stdout and raising with stderr when it fails."""
    result = subprocess.run(arguments, input=input_data, capture_output=True, check=False, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(arguments)} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def ns(namespace: str, *arguments: str, input_data: str | None = None, check: bool = True) -> str:
    """Run one command inside a named namespace of this private network world."""
    return run("ip", "netns", "exec", namespace, *arguments, input_data=input_data, check=check)


def apply_nft(namespace: str, program: str) -> None:
    """Parse-check one nft program, then install it."""
    ns(namespace, "nft", "--check", "-f", "-", input_data=program)
    ns(namespace, "nft", "-f", "-", input_data=program)


# ---------------------------------------------------------------------------
# nft rendering. Pure functions, unit-tested in scripts/test_mesh_nat_censorship_proof.py.
# ---------------------------------------------------------------------------


@dataclass
class Router:
    """One NAT box: its namespace, interfaces, addresses and the hosts it serves.

    `inside` maps each served host's inside address to its UDP mesh port as
    seen on the router's LAN side (after any inner NAT). `outside_ports` is the
    EIM mapping this router applies; the harness fills it when it renders.
    """

    namespace: str
    nat: Nat
    lan: str
    wan: str
    lan_subnet: str
    public_address: str
    edge: bool
    inside: dict[str, int] = field(default_factory=dict)
    rebinds: int = 0

    def outside_port(self, inside_address: str) -> int:
        """Return the EIM outside port for one served host, including rebinds and collisions."""
        port = self.inside[inside_address]
        mapped = (port + self.nat.port_offset + 1000 * self.rebinds - 1) % 64_511 + 1025
        mapped = mapped if self.nat.port_offset or self.rebinds else port
        taken = [self.outside_port(other) for other in sorted(self.inside) if other < inside_address]
        while mapped in taken:
            mapped += 1
        return mapped


def render_router(router: Router, scenario: Scenario) -> str:
    """Render one router's complete nft table: NAT, inbound filtering, hairpin and censorship."""
    nat = router.nat
    pre: list[str] = []
    post: list[str] = []
    forward: list[str] = []
    sets: list[str] = []
    if nat.mapping == "eim":
        pairs = ", ".join(
            f"{address} . {port} : {router.public_address} . {router.outside_port(address)}"
            for address, port in sorted(router.inside.items())
        )
        if pairs:
            post.append(f'  oifname "{router.wan}" meta l4proto udp snat ip to ip saddr . udp sport map {{ {pairs} }}')
        # Inbound: EIF forwards any sender to the mapping; ADF only a sender address the host has used.
        if nat.filtering in ("eif", "adf"):
            if nat.filtering == "adf":
                sets.append(f" set contacted {{ type ipv4_addr; flags dynamic,timeout; timeout {nat.udp_timeout}s; }}")
                forward.append(
                    f'  iifname "{router.lan}" oifname "{router.wan}" meta l4proto udp update @contacted {{ ip daddr }}'
                )
            for address, port in sorted(router.inside.items()):
                guard = "ip saddr @contacted " if nat.filtering == "adf" else ""
                pre.append(
                    f'  iifname "{router.wan}" ip daddr {router.public_address} {guard}'
                    f"udp dport {router.outside_port(address)} dnat ip to {address}:{port}"
                )
        if nat.hairpin:
            for address, port in sorted(router.inside.items()):
                pre.append(
                    f'  iifname "{router.lan}" ip daddr {router.public_address} '
                    f"udp dport {router.outside_port(address)} dnat ip to {address}:{port}"
                )
            if pairs:
                post.append(
                    f'  iifname "{router.lan}" oifname "{router.lan}" ct status dnat meta l4proto udp '
                    f"snat ip to ip saddr . udp sport map {{ {pairs} }}"
                )
    elif nat.mapping == "apdm":
        post.append(f'  oifname "{router.wan}" meta l4proto udp masquerade fully-random')
    else:
        raise ValueError(f"unknown mapping {nat.mapping!r}")
    # Everything else (ICMP, TCP) leaves through an ordinary masquerade.
    post.append(f'  oifname "{router.wan}" ip saddr {router.lan_subnet} masquerade')
    if router.edge:
        forward.extend(censorship_rules(scenario, router))
    policy = "drop" if router.edge and scenario.tcp_ports else "accept"
    lines = ["table ip j536 {", *sets]
    if pre:
        lines += [" chain pre { type nat hook prerouting priority dstnat; policy accept;", *pre, " }"]
    lines += [" chain post { type nat hook postrouting priority srcnat; policy accept;", *post, " }"]
    lines += [f" chain forward {{ type filter hook forward priority filter; policy {policy};", *forward, " }"]
    # A router never answers unsolicited UDP itself; real routers stay silent instead of sending port-unreachable.
    lines += [
        " chain input { type filter hook input priority filter; policy accept;",
        f'  iifname "{router.wan}" meta l4proto udp drop',
        " }",
    ]
    if router.edge and scenario.block_icmp:
        lines += [" chain output { type filter hook output priority filter; policy accept;", "  ip protocol icmp drop", " }"]
    lines.append("}")
    return "\n".join(lines) + "\n"


def censorship_rules(scenario: Scenario, router: Router) -> list[str]:
    """Return the forward-chain rules that make this edge router a censor."""
    rules: list[str] = []
    if scenario.block_icmp:
        rules.append("  ip protocol icmp drop")
    if scenario.dpi_handshakes:
        rules.extend(f"  {rule}" for rule in dpi_drop_rules())
    if scenario.tcp_ports:
        ports = ", ".join(str(port) for port in scenario.tcp_ports)
        rules += [
            "  ct state established,related accept",
            f"  iifname \"{router.lan}\" tcp dport {{ {ports} }} accept",
            "  ip protocol icmp accept",
        ]
    if scenario.udp_blocked:
        rules.append("  meta l4proto udp drop")
    return rules


def dpi_drop_rules() -> list[str]:
    """Match WireGuard handshake initiation and response by type and size, on any port.

    A censor does not know which port a mesh uses, so it keys on shape only.
    UDP length counts the 8-byte header: 148- and 92-byte messages show as 156
    and 100. The first payload word is the little-endian message type.
    """
    return [
        "udp length 156 @th,64,32 0x01000000 drop",
        "udp length 100 @th,64,32 0x02000000 drop",
    ]


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------


class Topology:
    """Build the namespaces, links and routers one scenario describes, inside the private world."""

    def __init__(self, scenario: Scenario):
        """Remember the scenario; nothing exists until `create`."""
        self.scenario = scenario
        self.nodes = {"A": "node-a", "B": "node-b"}
        self.node_address: dict[str, str] = {}
        self.public_address: dict[str, str] = {}
        self.routers: dict[str, list[Router]] = {"A": [], "B": []}
        self.holders: list[subprocess.Popen] = []
        self.node_pid: dict[str, int] = {}
        self.links = 0
        self.ports: dict[str, int] = {}

    def namespace(self, name: str) -> None:
        """Create one named namespace with loopback up."""
        run("ip", "netns", "add", name)
        ns(name, "ip", "link", "set", "lo", "up")

    def pair(self, left: str, left_name: str, right: str, right_name: str, mtu: int = 1500) -> None:
        """Connect two namespaces with one veth pair."""
        a, b = f"v{self.links}a", f"v{self.links}b"
        self.links += 1
        run("ip", "link", "add", a, "type", "veth", "peer", "name", b)
        for namespace, temporary, name in ((left, a, left_name), (right, b, right_name)):
            run("ip", "link", "set", temporary, "netns", namespace)
            ns(namespace, "ip", "link", "set", temporary, "name", name)
            ns(namespace, "ip", "link", "set", name, "mtu", str(mtu), "up")

    def router_namespace(self, name: str, udp_timeout: int) -> None:
        """Create a forwarding namespace with its own conntrack timeouts."""
        self.namespace(name)
        ns(name, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        # Hairpinned packets leave the interface they arrived on; a redirect would teach the LAN a shortcut.
        ns(name, "sysctl", "-qw", "net.ipv4.conf.all.send_redirects=0")
        ns(name, "sysctl", "-qw", "net.ipv4.conf.default.send_redirects=0")
        ns(name, "sysctl", "-qw", f"net.netfilter.nf_conntrack_udp_timeout={udp_timeout}")
        ns(name, "sysctl", "-qw", f"net.netfilter.nf_conntrack_udp_timeout_stream={max(udp_timeout, 30)}")

    def core_link(self, namespace: str, address: str) -> None:
        """Attach a namespace to the public bridge, with the scenario's WAN MTU."""
        port = f"c{self.links}"
        self.pair("core", port, namespace, "wan", mtu=self.scenario.wan_mtu or 1500)
        ns("core", "ip", "link", "set", port, "master", "br0")
        ns(namespace, "ip", "addr", "add", f"{address}/24", "dev", "wan")
        ns(namespace, "ip", "route", "replace", "default", "via", f"{CORE_PREFIX}.1")

    def create(self) -> "Topology":
        """Build the public core, both sides and the processes that hold the node namespaces."""
        self.namespace("core")
        ns("core", "ip", "link", "add", "br0", "type", "bridge")
        ns("core", "ip", "addr", "add", f"{CORE_PREFIX}.1/24", "dev", "br0")
        ns("core", "ip", "link", "set", "br0", "up")
        if self.scenario.same_nat:
            self.build_shared()
        else:
            for index, side in enumerate(("A", "B")):
                tiers = self.scenario.side_a if side == "A" else self.scenario.side_b
                self.build_side(side, index + 1, tiers)
        for side, node in self.nodes.items():
            holder = subprocess.Popen(["ip", "netns", "exec", node, "sleep", "900"])
            self.holders.append(holder)
            self.node_pid[side] = holder.pid
        return self

    def build_side(self, side: str, index: int, tiers: tuple[Nat, ...]) -> None:
        """Build one side: the node, then each router outwards, then the public link."""
        node = self.nodes[side]
        self.namespace(node)
        public = f"{CORE_PREFIX}.{20 + index}"
        self.public_address[side] = public
        if not tiers:
            self.core_link(node, public)
            self.node_address[side] = public
            return
        def subnet(depth: int) -> str:
            """The /24 behind tier `depth`: carrier space for CGNAT tiers, private space otherwise."""
            return f"100.64.{index}{depth}" if depth in self.scenario.cgnat_tiers else f"10.{index}.{depth}"

        inner_namespace, inner_interface = node, "eth0"
        for depth, nat in enumerate(tiers):
            name = f"r{side.lower()}{depth}"
            self.router_namespace(name, nat.udp_timeout)
            lan = subnet(depth)
            self.pair(name, "lan", inner_namespace, inner_interface)
            ns(name, "ip", "addr", "add", f"{lan}.1/24", "dev", "lan")
            ns(inner_namespace, "ip", "addr", "add", f"{lan}.2/24", "dev", inner_interface)
            ns(inner_namespace, "ip", "route", "replace", "default", "via", f"{lan}.1")
            if depth == 0:
                self.node_address[side] = f"{lan}.2"
            edge = depth == len(tiers) - 1
            outside = public if edge else f"{subnet(depth + 1)}.2"
            router = Router(name, nat, "lan", "wan", f"{lan}.0/24", outside, edge)
            self.routers[side].append(router)
            if edge:
                self.core_link(name, public)
            inner_namespace, inner_interface = name, "wan"

    def build_shared(self) -> None:
        """Put both nodes on one LAN bridge behind a single router."""
        nat = self.scenario.side_a[0]
        self.router_namespace("rs", nat.udp_timeout)
        ns("rs", "ip", "link", "add", "lan", "type", "bridge")
        ns("rs", "ip", "addr", "add", "10.9.0.1/24", "dev", "lan")
        ns("rs", "ip", "link", "set", "lan", "up")
        public = f"{CORE_PREFIX}.21"
        router = Router("rs", nat, "lan", "wan", "10.9.0.0/24", public, True)
        for number, side in ((2, "A"), (3, "B")):
            node = self.nodes[side]
            self.namespace(node)
            self.pair("rs", f"p{side.lower()}", node, "eth0")
            ns("rs", "ip", "link", "set", f"p{side.lower()}", "master", "lan")
            ns(node, "ip", "addr", "add", f"10.9.0.{number}/24", "dev", "eth0")
            ns(node, "ip", "route", "replace", "default", "via", "10.9.0.1")
            self.node_address[side] = f"10.9.0.{number}"
            self.public_address[side] = public
            self.routers[side] = [router]
        self.core_link("rs", public)

    def unique_routers(self) -> list[Router]:
        """Every router once, even when both sides share it."""
        seen: dict[str, Router] = {}
        for routers in self.routers.values():
            for router in routers:
                seen[router.namespace] = router
        return list(seen.values())

    def propagate(self) -> None:
        """Carry each node's port outwards: every tier's inside port is the tier below's outside port.

        Run again after a rebind, or an outer tier would still map the inner tier's old port.
        """
        for side in ("A", "B"):
            address, port = self.node_address[side], self.ports[side]
            for router in self.routers[side]:
                router.inside[address] = port
                if router.nat.mapping == "eim":
                    address, port = router.public_address, router.outside_port(address)
                else:
                    address = router.public_address

    def configure(self, ports: dict[str, int]) -> None:
        """Install every router's NAT and censorship rules, now that the nodes' ports are known."""
        self.ports = dict(ports)
        self.propagate()
        self.install()
        for router in self.unique_routers():
            if router.edge:
                command = ["tc", "qdisc", "replace", "dev", router.wan, "root", "netem",
                           "delay", f"{self.scenario.delay_ms}ms", f"{self.scenario.jitter_ms}ms"]
                if self.scenario.loss_percent:
                    command += ["loss", f"{self.scenario.loss_percent}%"]
                ns(router.namespace, *command)

    def install(self) -> None:
        """(Re)write every router's table."""
        for router in self.unique_routers():
            ns(router.namespace, "nft", "delete", "table", "ip", "j536", check=False)
            apply_nft(router.namespace, render_router(router, self.scenario))

    def reflexive_endpoints(self, ports: dict[str, int]) -> list[str]:
        """What a server-side observer would publish: the mapping its traffic actually got.

        This is the "candidates" model measured as an option for #483, not product behaviour.
        For endpoint-independent NATs the server sees the same outside port the peer would.
        A symmetric NAT gives the server a port of its own, which the peer cannot use, so the
        local port stands in for that useless observation. Two nodes behind one public
        address get each other's LAN address, as a host candidate would provide.
        """
        endpoints = []
        for side in ("A", "B"):
            peer = "B" if side == "A" else "A"
            if self.public_address[side] == self.public_address[peer] and self.routers[side]:
                endpoints.append(f"{self.node_address[side]}:{ports[side]}")
                continue
            port = ports[side]
            usable = True
            for router in self.routers[side]:
                if router.nat.mapping == "eim" and usable:
                    port = router.outside_port(self._inside(side, router))
                else:
                    usable = False
            endpoints.append(f"{self.public_address[side]}:{port}")
        return endpoints

    def _inside(self, side: str, router: Router) -> str:
        """The address one side's traffic carries on this router's LAN."""
        index = self.routers[side].index(router)
        return self.node_address[side] if index == 0 else self.routers[side][index - 1].public_address

    def rebind(self, side: str) -> None:
        """Make one side's NAT forget its mappings and hand out new outside ports mid-flow."""
        for router in self.routers[side]:
            router.rebinds += 1
        self.propagate()
        self.install()
        for router in self.routers[side]:
            ns(router.namespace, "conntrack", "-F", check=False)

    def conntrack(self) -> dict[str, list[str]]:
        """Dump every router's UDP conntrack table as evidence of the mappings it made."""
        return {
            router.namespace: ns(router.namespace, "conntrack", "-L", "-p", "udp", check=False).splitlines()
            for router in self.unique_routers()
        }

    def add_server(self) -> None:
        """Put the server's own node straight on the public core (product model)."""
        self.nodes["S"] = "node-s"
        self.namespace("node-s")
        self.core_link("node-s", SERVER_ADDRESS)
        self.node_address["S"] = SERVER_ADDRESS
        self.public_address["S"] = SERVER_ADDRESS
        holder = subprocess.Popen(["ip", "netns", "exec", "node-s", "sleep", "900"])
        self.holders.append(holder)
        self.node_pid["S"] = holder.pid

    def cleanup(self) -> None:
        """Stop the namespace holders; the private world disappears with the process."""
        for holder in self.holders:
            if holder.poll() is None:
                holder.kill()
                holder.wait(timeout=5)


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


class Pinger:
    """A continuous ping through the mesh that timestamps every reply as it arrives."""

    def __init__(self, namespace: str, address: str, interval: float = 0.05, size: int = 56):
        """Start pinging `address` from `namespace` every `interval` seconds until stopped."""
        self.process = subprocess.Popen(
            ["ip", "netns", "exec", namespace, "ping", "-n", "-i", str(interval), "-s", str(size), "-W", "1", address],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        self.replies: queue.Queue[tuple[float, float]] = queue.Queue()
        self.thread = threading.Thread(target=self.drain, daemon=True)
        self.thread.start()

    def drain(self) -> None:
        """Read ping output promptly so ping never blocks on a full pipe."""
        assert self.process.stdout is not None
        for line in self.process.stdout:
            match = re.search(r"time[=<]([0-9.]+) ms", line)
            if "bytes from" in line and match:
                self.replies.put((time.monotonic(), float(match.group(1))))

    def first_after(self, start: float, timeout: float) -> float | None:
        """Return seconds from `start` to the first reply received after it, or None."""
        deadline = start + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            try:
                at, _ = self.replies.get(timeout=left)
            except queue.Empty:
                return None
            if at >= start:
                return at - start

    def take(self) -> list[float]:
        """Drain and return every round-trip time collected so far, in milliseconds."""
        values = []
        while True:
            try:
                values.append(self.replies.get_nowait()[1])
            except queue.Empty:
                return values

    def stop(self) -> None:
        """Stop ping and its reader."""
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=5)
        self.thread.join(timeout=5)


def percentile(values: list[float], fraction: float) -> float | None:
    """Nearest-rank percentile, or None for no samples."""
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(fraction * len(ordered)) - 1)], 3)


RECEIVER = r"""import hashlib,json,socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],5201));s.listen(1);print('ready',flush=True);s.settimeout(30)
c,_=s.accept();c.settimeout(30);h=hashlib.sha256();n=0
try:
 while True:
  b=c.recv(262144)
  if not b:break
  h.update(b);n+=len(b)
except OSError:pass
print(json.dumps({'bytes':n,'sha256':h.hexdigest()}),flush=True)
"""

SENDER = r"""import hashlib,json,socket,sys,time
c=socket.create_connection((sys.argv[1],5201),timeout=15);c.settimeout(15)
block=bytes(range(256))*512;h=hashlib.sha256();n=0;start=time.monotonic();end=start+float(sys.argv[2]);error=None
try:
 while time.monotonic()<end:
  c.sendall(block);h.update(block);n+=len(block)
 c.shutdown(socket.SHUT_WR)
except OSError as e:error=str(e)
print(json.dumps({'bytes':n,'sha256':h.hexdigest(),'seconds':time.monotonic()-start,'error':error}),flush=True)
"""


def tcp_load(sender: str, receiver: str, address: str, seconds: float) -> dict[str, object]:
    """Push TCP through the tunnel for `seconds`; return Mbit/s and whether both checksums agree."""
    server = subprocess.Popen(["ip", "netns", "exec", receiver, "python3", "-c", RECEIVER, address],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert server.stdout is not None
        ready, _, _ = select.select([server.stdout], [], [], 10)
        if not ready or server.stdout.readline().strip() != "ready":
            return {"error": "receiver did not start"}
        sent = json.loads(run("ip", "netns", "exec", sender, "python3", "-c", SENDER, address, str(seconds),
                              check=False, timeout=seconds + 40) or '{"error":"sender produced no output"}')
        try:
            received = json.loads(server.communicate(timeout=40)[0].strip().splitlines()[-1])
        except (subprocess.TimeoutExpired, IndexError, json.JSONDecodeError):
            received = {"bytes": None}
        result = {
            "sent_bytes": sent.get("bytes"),
            "received_bytes": received.get("bytes"),
            "checksum_equal": received.get("bytes") == sent.get("bytes") and received.get("sha256") == sent.get("sha256"),
            "error": sent.get("error"),
        }
        if sent.get("seconds") and received.get("bytes"):
            result["mbit_per_s"] = round(received["bytes"] * 8 / sent["seconds"] / 1e6, 1)
        return result
    finally:
        if server.poll() is None:
            server.kill()
            server.wait(timeout=5)


def peer_view(node: object) -> dict[str, object]:
    """Read node A's `mesh.peers` and reproduce the sentence `infraternal mesh peers` prints."""
    try:
        reply = node.call("mesh.peers", {})
    except Exception as error:  # the CLI would show the refusal; record it
        return {"error": f"{type(error).__name__}: {error}"}
    peers = reply.get("peers", [])
    rows = [
        {
            "path": row.get("path"),
            "endpoint": row.get("peer", {}).get("endpoint"),
            "handshake_secs": row.get("counters", {}).get("handshake_secs"),
            "sent_bytes": row.get("counters", {}).get("sent_bytes"),
            "received_bytes": row.get("counters", {}).get("received_bytes"),
        }
        for row in peers
    ]
    waiting = [row for row in rows if row["path"] != "Direct"]
    count = len(rows)
    noun = "peer on the mesh" if count == 1 else "peers on the mesh"
    message = f"{count} {noun}, all direct." if not waiting else f"{count} {noun}, {len(waiting)} without a direct path yet."
    if waiting:
        message += " Next: Send traffic to <peer> to set up its direct path, for example: ping <peer address>"
    return {"message": message, "rows": rows}


# ---------------------------------------------------------------------------
# One profile
# ---------------------------------------------------------------------------


class Observer:
    """Stands in for the server's presence poll and the coordinator's workers (product model).

    Every `PRESENCE_POLL_SECONDS` it reads the server node's real `mesh.peers` presence pages,
    hands them to the coordinator fixture (which runs the product's observation and
    republication), and applies any resulting snapshot chunks to every node. It records each
    published candidate list with its time, as evidence of what the product decided.
    """

    def __init__(self, coordinator: object, nodes: list[object], members: list[str]):
        """`nodes` and `members` are in identity order, the server's own node first."""
        self.coordinator = coordinator
        self.nodes = nodes
        self.members = members
        self.next_poll = time.monotonic()
        self.started = time.monotonic()
        self.publications: list[dict[str, object]] = []
        self.readings: list[dict[str, object]] = []

    def pages(self) -> list[object]:
        """Every presence page of the server node's current peer table."""
        pages, cursor = [], None
        for _ in range(64):
            page = self.nodes[0].call("mesh.peers", {"cursor": cursor, "presence": True})
            pages.append(page)
            cursor = page.get("next_cursor")
            if cursor is None:
                return pages
        return pages

    def apply(self, snapshot: dict[str, object]) -> None:
        """Send each node its chunks and note every peer whose candidate list changed."""
        at = round(time.monotonic() - self.started, 3)
        for index, node in enumerate(self.nodes):
            for chunk in snapshot["chunks"][index]:
                node.request(chunk)
                for peer_id, policy in (chunk.get("upserted") or {}).items():
                    peer = policy["peer"]
                    self.publications.append({
                        "t": at, "viewer": self.members[index], "peer": int(peer_id),
                        "try": [peer.get("endpoint")] + list(peer.get("candidates") or []),
                    })

    def request(self, value: dict[str, object]) -> dict[str, object]:
        """Run one coordinator request and apply its result."""
        snapshot = self.coordinator.request(value)
        self.apply(snapshot)
        return snapshot

    def poll(self) -> None:
        """One presence poll, exactly as often as the server's. Its rows are kept as evidence."""
        pages = self.pages()
        self.readings.append({
            "t": round(time.monotonic() - self.started, 3),
            "rows": [row for page in pages for row in page.get("peers", [])],
        })
        self.request({"mode": "keep", "observe": pages})
        self.next_poll = time.monotonic() + PRESENCE_POLL_SECONDS

    def idle(self, seconds: float) -> None:
        """Let `seconds` pass while the polls keep running."""
        end = time.monotonic() + seconds
        while (now := time.monotonic()) < end:
            if now >= self.next_poll:
                self.poll()
                continue
            # sleep: wait for the next presence poll or the end of the idle period, whichever is first.
            time.sleep(max(0.0, min(end, self.next_poll) - now))

    def first_after(self, pinger: "Pinger", start: float, timeout: float) -> float | None:
        """`Pinger.first_after`, with the polls running meanwhile."""
        deadline = start + timeout
        while True:
            now = time.monotonic()
            if now >= deadline:
                return None
            if now >= self.next_poll:
                self.poll()
                continue
            try:
                at, _ = pinger.replies.get(timeout=max(0.0, min(deadline, self.next_poll) - now))
            except queue.Empty:
                continue
            if at >= start:
                return at - start


def run_product_profile(scenario: Scenario, binary: str, coordinator_path: str, scratch: str) -> dict[str, object]:
    """The product model: the shipped candidate code decides every address (module docs)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from mesh_agent_fixture import BinaryNode, CoordinatorFixture

    topology = Topology(scenario)
    nodes: list[BinaryNode] = []
    pingers: list[Pinger] = []
    coordinator = None
    observer = None
    row: dict[str, object] = {"scenario": scenario.name, "summary": scenario.summary, "coordinator_model": "product"}
    try:
        topology.create()
        topology.add_server()
        members = ["S", "A", "B"]
        for side in members:
            nodes.append(BinaryNode(binary, scratch, topology.node_pid[side]))
        identities = [json.loads(node.stdout.readline()) for node in nodes]
        ports = {side: identity["port"] for side, identity in zip(members, identities)}
        row["engine"] = (nodes[1].call("mesh.status", {}).get("engine_selection") or {}).get("engine")
        row["listen_ports"] = ports
        topology.configure({"A": ports["A"], "B": ports["B"]})
        probes = [node.call("mesh.identity", {"candidates": True}) for node in nodes]
        row["candidate_probes"] = probes
        # What the coordinator sees on each control connection: the outermost public address.
        guesses = [f"{topology.public_address[side]}:{ports[side]}" for side in members]
        coordinator = CoordinatorFixture(coordinator_path)
        observer = Observer(coordinator, nodes, members)
        warm = observer.request({"mode": "deny", "identities": identities, "endpoints": guesses, "probes": probes})
        observer.poll()
        observer.idle(WARMUP_SECONDS)
        observer.request({"mode": "allow"})
        applied = time.monotonic()
        target = warm["addresses"][2]["ipv4"]
        row["published_at_open"] = [entry for entry in observer.publications if entry["viewer"] in ("A", "B")][-4:]
        pinger = Pinger(topology.nodes["A"], target)
        pingers.append(pinger)
        first = observer.first_after(pinger, applied, FIRST_PACKET_TIMEOUT_SECONDS)
        row["direct"] = first is not None
        row["first_packet_ms"] = round(first * 1000) if first is not None else None
        row["what_the_user_sees"] = peer_view(nodes[1])
        if first is None:
            row["conntrack"] = topology.conntrack()
            # Which way A's packets for B would go, for the failure's evidence.
            row["node_a_routes"] = ns(topology.nodes["A"], "ip", "route", "show", "table", "all", check=False).splitlines()
            row["node_a_status"] = nodes[1].call("mesh.status", {})
            return row
        pinger.take()
        observer.idle(1.0)
        rest = pinger.take()
        row["rtt_p50_ms_rest"] = percentile(rest, 0.5)
        pinger.stop()
        loaded = Pinger(topology.nodes["A"], target, interval=0.02)
        pingers.append(loaded)
        load = tcp_load(topology.nodes["A"], topology.nodes["B"], target, LOAD_SECONDS)
        samples = loaded.take()
        loaded.stop()
        row["throughput"] = load
        row["loaded_p99_ms"] = percentile(samples, 0.99)
        row["loaded_ping_replies"] = len(samples)
        if scenario.idle_expiry_seconds:
            observer.idle(scenario.idle_expiry_seconds)
            after_idle = Pinger(topology.nodes["A"], target)
            pingers.append(after_idle)
            recovered = observer.first_after(after_idle, time.monotonic(), REBIND_TIMEOUT_SECONDS)
            row["after_idle_first_packet_ms"] = round(recovered * 1000) if recovered is not None else None
            after_idle.stop()
        # Mid-flow rebind: A's NAT forgets every mapping. Nothing republishes but the product itself.
        flow = Pinger(topology.nodes["A"], target)
        pingers.append(flow)
        if observer.first_after(flow, time.monotonic(), 10) is None:
            row["rebind_recovery_ms"] = "path lost before rebind"
        else:
            started = time.monotonic()
            topology.rebind("A")
            settled = time.monotonic() + 0.1
            recovered = observer.first_after(flow, settled, REBIND_TIMEOUT_SECONDS)
            row["rebind_recovery_ms"] = round((settled - started + recovered) * 1000) if recovered is not None else None
        flow.stop()
        row["after_rebind_user_sees"] = peer_view(nodes[1])
        return row
    finally:
        for pinger in pingers:
            pinger.stop()
        if observer is not None:
            row["publications"] = observer.publications
            row["server_readings"] = observer.readings
        if coordinator is not None:
            coordinator.child.kill()
            coordinator.child.wait(timeout=5)
        for node in nodes:
            try:
                node.close()
            except Exception as error:
                row.setdefault("cleanup_errors", []).append(str(error))
        topology.cleanup()


RELAY_NAME = "relay.mesh.test"
RELAY_PORT = 3478
HOST_UUIDS = {"A": "0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a", "B": "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b"}


def private_file(path: Path, text: str) -> Path:
    """Write `text` to a new 0600 file (keys never sit in a readable file)."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(text)
    return path


def relay_certificates(relay_fixture: str) -> dict[str, object]:
    """A disposable CA with a host leaf per side and one relay leaf, from `relay_fixture certs`."""
    request = json.dumps({"hosts": list(HOST_UUIDS.values()), "relays": [RELAY_NAME]})
    return json.loads(run(relay_fixture, "certs", input_data=request + "\n"))


def relay_status(node: object) -> dict[str, object]:
    """The relay part of a node's `mesh.status`, or the refusal text."""
    try:
        return node.call("mesh.status", {}).get("relay") or {}
    except Exception as error:
        return {"error": str(error)}


def run_relay_profile(
    scenario: Scenario, binary: str, coordinator_path: str, scratch: str, relay_fixture: str
) -> dict[str, object]:
    """The relay model: candidates plus a relay node on the public core (module docs)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from mesh_agent_fixture import BinaryNode, CoordinatorFixture

    topology = Topology(scenario)
    nodes: list[BinaryNode] = []
    pingers: list[Pinger] = []
    coordinator = None
    row: dict[str, object] = {"scenario": scenario.name, "summary": scenario.summary, "coordinator_model": "relay"}
    try:
        certificates = relay_certificates(relay_fixture)
        ca = private_file(Path(scratch) / "ca.pem", certificates["ca"])
        topology.create()
        topology.add_server()
        relay = BinaryNode(binary, scratch, topology.node_pid["S"])
        nodes.append(relay)
        leaf = certificates["relays"][RELAY_NAME]
        served = relay.call("mesh.relays", {"serve": {
            "name": RELAY_NAME, "port": RELAY_PORT, "leaf": leaf["cert"] + leaf["key"],
            "roots": [certificates["ca"]]}})
        row["relay_served"] = served
        assert served.get("serving"), served
        for side in ("A", "B"):
            host = certificates["hosts"][HOST_UUIDS[side]]
            path = private_file(Path(scratch) / f"host-{side}.pem", host["cert"] + host["key"])
            os.environ["INFRATERNAL_TEST_RELAY_HOST_LEAF"] = str(path)
            os.environ["INFRATERNAL_TEST_RELAY_CA"] = str(ca)
            try:
                nodes.append(BinaryNode(binary, scratch, topology.node_pid[side]))
            finally:
                os.environ.pop("INFRATERNAL_TEST_RELAY_HOST_LEAF", None)
                os.environ.pop("INFRATERNAL_TEST_RELAY_CA", None)
        members = nodes[1:]
        identities = [json.loads(node.stdout.readline()) for node in members]
        ports = {"A": identities[0]["port"], "B": identities[1]["port"]}
        row["engine"] = (members[0].call("mesh.status", {}).get("engine_selection") or {}).get("engine")
        row["listen_ports"] = ports
        topology.configure(ports)
        listed = {"relays": [{"name": RELAY_NAME, "port": served["serving"], "addresses": [SERVER_ADDRESS]}]}
        for node in members:
            node.call("mesh.relays", listed)
        endpoints = topology.reflexive_endpoints(ports)
        row["published_endpoints"] = endpoints
        coordinator = CoordinatorFixture(coordinator_path)
        snapshot = coordinator.configuration("allow", identities, endpoints)
        target = snapshot["addresses"][1]["ipv4"]
        pinger = Pinger(topology.nodes["A"], target)
        pingers.append(pinger)
        applied = time.monotonic()
        for index, node in enumerate(members):
            for chunk in snapshot["chunks"][index]:
                node.request(chunk)
        first = pinger.first_after(applied, FIRST_PACKET_TIMEOUT_SECONDS)
        row["connected"] = first is not None
        row["first_packet_ms"] = round(first * 1000) if first is not None else None
        status = relay_status(members[0])
        row["relayed"] = bool(status.get("relayed"))
        row["direct"] = first is not None and not row["relayed"]
        row["relay_a"] = status
        row["relay_b"] = relay_status(members[1])
        row["relay_node"] = relay_status(relay)
        row["what_the_user_sees"] = peer_view(members[0])
        if first is None:
            row["conntrack"] = topology.conntrack()
            return row
        pinger.take()
        # sleep: one second of unloaded pings gives the at-rest round-trip baseline.
        time.sleep(1.0)
        rest = pinger.take()
        row["rtt_p50_ms_rest"] = percentile(rest, 0.5)
        pinger.stop()
        loaded = Pinger(topology.nodes["A"], target, interval=0.02)
        pingers.append(loaded)
        load = tcp_load(topology.nodes["A"], topology.nodes["B"], target, LOAD_SECONDS)
        samples = loaded.take()
        loaded.stop()
        row["throughput"] = load
        row["loaded_p99_ms"] = percentile(samples, 0.99)
        row["relay_node_after_load"] = relay_status(relay)
        row["relay_a_after_load"] = relay_status(members[0])
        # The route budget a relayed pair runs on (the relay's DATAGRAM size sets it).
        row["node_a_routes"] = ns(topology.nodes["A"], "ip", "route", "show", "table", "all",
                                  check=False).splitlines()
        return row
    finally:
        for pinger in pingers:
            pinger.stop()
        if coordinator is not None:
            coordinator.child.kill()
            coordinator.child.wait(timeout=5)
        for node in nodes:
            try:
                node.close()
            except Exception as error:
                row.setdefault("cleanup_errors", []).append(str(error))
        topology.cleanup()


def run_profile(
    scenario: Scenario, binary: str, coordinator_path: str, scratch: str, model: str = "production",
    relay_fixture: str | None = None,
) -> dict[str, object]:
    """Build the network, start both nodes, connect them as production would, and measure."""
    if model == "product":
        return run_product_profile(scenario, binary, coordinator_path, scratch)
    if model == "relay":
        return run_relay_profile(scenario, binary, coordinator_path, scratch, relay_fixture)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from mesh_agent_fixture import BinaryNode, CoordinatorFixture

    topology = Topology(scenario)
    nodes: list[BinaryNode] = []
    pingers: list[Pinger] = []
    coordinator = None
    row: dict[str, object] = {"scenario": scenario.name, "summary": scenario.summary}
    try:
        topology.create()
        for side in ("A", "B"):
            nodes.append(BinaryNode(binary, scratch, topology.node_pid[side]))
        identities = [json.loads(node.stdout.readline()) for node in nodes]
        ports = {"A": identities[0]["port"], "B": identities[1]["port"]}
        status = nodes[0].call("mesh.status", {})
        row["engine"] = (status.get("engine_selection") or {}).get("engine")
        row["listen_ports"] = ports
        topology.configure(ports)
        # Production: control-connection source address plus the node's own listen port.
        endpoints = [f"{topology.public_address[side]}:{ports[side]}" for side in ("A", "B")]
        if model == "candidates":
            endpoints = topology.reflexive_endpoints(ports)
        row["coordinator_model"] = model
        row["published_endpoints"] = endpoints
        coordinator = CoordinatorFixture(coordinator_path)
        snapshot = coordinator.configuration("allow", identities, endpoints)
        target = snapshot["addresses"][1]["ipv4"]
        pinger = Pinger(topology.nodes["A"], target)
        pingers.append(pinger)
        applied = time.monotonic()
        for index, node in enumerate(nodes):
            for chunk in snapshot["chunks"][index]:
                node.request(chunk)
        first = pinger.first_after(applied, FIRST_PACKET_TIMEOUT_SECONDS)
        row["direct"] = first is not None
        row["first_packet_ms"] = round(first * 1000) if first is not None else None
        row["what_the_user_sees"] = peer_view(nodes[0])
        if first is None:
            row["conntrack"] = topology.conntrack()
            return row
        pinger.take()
        # sleep: one second of unloaded pings gives the at-rest round-trip baseline.
        time.sleep(1.0)
        rest = pinger.take()
        row["rtt_p50_ms_rest"] = percentile(rest, 0.5)
        pinger.stop()
        loaded = Pinger(topology.nodes["A"], target, interval=0.02)
        pingers.append(loaded)
        load = tcp_load(topology.nodes["A"], topology.nodes["B"], target, LOAD_SECONDS)
        samples = loaded.take()
        loaded.stop()
        row["throughput"] = load
        row["loaded_p99_ms"] = percentile(samples, 0.99)
        row["loaded_ping_replies"] = len(samples)
        if scenario.idle_expiry_seconds:
            # sleep: let the NAT mappings age past their UDP timeout with only keepalives flowing.
            time.sleep(scenario.idle_expiry_seconds)
            after_idle = Pinger(topology.nodes["A"], target)
            pingers.append(after_idle)
            recovered = after_idle.first_after(time.monotonic(), REBIND_TIMEOUT_SECONDS)
            row["after_idle_first_packet_ms"] = round(recovered * 1000) if recovered is not None else None
            after_idle.stop()
        # Mid-flow rebind: A's NAT forgets every mapping and hands out new outside ports.
        flow = Pinger(topology.nodes["A"], target)
        pingers.append(flow)
        if flow.first_after(time.monotonic(), 10) is None:
            row["rebind_recovery_ms"] = "path lost before rebind"
        else:
            started = time.monotonic()
            topology.rebind("A")
            if model == "candidates":
                # The observer sees the new mapping and republishes. In production that also waits
                # for the node's next packet to the observer (at most the 25 s keepalive).
                update = coordinator.update_endpoints(topology.reflexive_endpoints(ports))
                for index, node in enumerate(nodes):
                    for chunk in update["chunks"][index]:
                        node.request(chunk)
            applied = time.monotonic()
            # Replies already in flight when the NAT rebinds prove nothing; count only later ones.
            settled = applied + 0.1
            recovered = flow.first_after(settled, REBIND_TIMEOUT_SECONDS)
            row["rebind_apply_ms"] = round((applied - started) * 1000)
            row["rebind_recovery_ms"] = round((settled - started + recovered) * 1000) if recovered is not None else None
        flow.stop()
        row["after_rebind_user_sees"] = peer_view(nodes[0])
        return row
    finally:
        for pinger in pingers:
            pinger.stop()
        if coordinator is not None:
            coordinator.child.kill()
            coordinator.child.wait(timeout=5)
        for node in nodes:
            try:
                node.close()
            except Exception as error:
                row.setdefault("cleanup_errors", []).append(str(error))
        topology.cleanup()


def inner(args: argparse.Namespace) -> int:
    """Inside the private namespaces: run one profile and print its row as one JSON line."""
    run("mount", "-t", "tmpfs", "-o", "mode=0700", "tmpfs", "/run")
    Path("/run/netns").mkdir(parents=True, exist_ok=True)
    scenario = scenario_named(args.scenario[0])
    try:
        row = run_profile(scenario, args.binary, args.coordinator, args.scratch, args.model, args.relay_fixture)
    except Exception as error:
        row = {"scenario": scenario.name, "harness_error": f"{type(error).__name__}: {error}"}
    print("ROW " + json.dumps(row, sort_keys=True), flush=True)
    return 0


def outer(args: argparse.Namespace) -> int:
    """Run each selected profile in its own rootless namespace, capped, and write the report."""
    scratch = Path(args.scratch)
    scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
    selected = [scenario_named(name) for name in args.scenario] if args.scenario else list(SCENARIOS)
    rows = []
    for scenario in selected:
        # Short per-profile directory: node sockets live under it and Unix paths stop at 108 bytes.
        state = scratch / f"{SCENARIOS.index(scenario):02d}"
        shutil.rmtree(state, ignore_errors=True)
        state.mkdir(mode=0o700)
        command = ["unshare", "-Urnm", "--propagation", "private", sys.executable, os.path.abspath(__file__),
                   "--inner", "--binary", args.binary, "--coordinator", args.coordinator,
                   "--scratch", str(state), "--scenario", scenario.name, "--model", args.model]
        if args.relay_fixture:
            command += ["--relay-fixture", args.relay_fixture]
        started = time.monotonic()
        environment = {**os.environ, "TMPDIR": str(state)}
        if args.model == "relay":
            # The relay model needs a test-support build anyway; give its nodes a private host
            # firewall root, so a machine with a real install in /var/lib/infraternal still works.
            (state / "firewall-root").mkdir(mode=0o700)
            environment["INFRATERNAL_TEST_HOST_FIREWALL_ROOT"] = str(state / "firewall-root")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True, env=environment)
        try:
            stdout, stderr = process.communicate(timeout=PROFILE_CAP_SECONDS)
            lines = [line[4:] for line in stdout.splitlines() if line.startswith("ROW ")]
            row = json.loads(lines[-1]) if lines else {"scenario": scenario.name, "harness_error": stderr[-2000:]}
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            row = {"scenario": scenario.name, "harness_error": f"hit the {PROFILE_CAP_SECONDS} s cap"}
        row["wall_seconds"] = round(time.monotonic() - started, 1)
        logs = sorted(state.glob("*.stderr"))
        row["node_logs"] = [str(path) for path in logs]
        rows.append(row)
        print(json.dumps({key: row.get(key) for key in (
            "scenario", "direct", "relayed", "first_packet_ms", "rtt_p50_ms_rest", "loaded_p99_ms",
            "rebind_recovery_ms", "after_idle_first_packet_ms", "harness_error", "wall_seconds")}), flush=True)
        if args.report:
            write_report(args, rows)
    return 0


def write_report(args: argparse.Namespace, rows: list[dict[str, object]]) -> None:
    """Write the JSON receipt with enough context to reproduce the run."""
    binary = Path(args.binary).read_bytes()
    report = {
        "binary": args.binary,
        "binary_sha256": hashlib.sha256(binary).hexdigest(),
        "machine": os.uname().nodename,
        "architecture": platform.machine(),
        "kernel": os.uname().release,
        "rootless": os.geteuid() != 0,
        "coordinator_model": args.model,
        "scenarios": [asdict(scenario) for scenario in SCENARIOS],
        "rows": rows,
    }
    Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def main() -> None:
    """Parse arguments and run either the outer driver or one inner profile."""
    parser = argparse.ArgumentParser(description="Rootless mesh NAT and censorship matrix (#483).")
    parser.add_argument("--list", action="store_true", help="print the profile catalogue as JSON")
    parser.add_argument("--binary", help="absolute path of the infraternal executable under test")
    parser.add_argument("--coordinator", help="absolute path of the coordinator_fixture example")
    parser.add_argument("--scratch", help="private directory for node state and logs")
    parser.add_argument("--report", help="absolute path for the JSON report")
    parser.add_argument("--scenario", action="append", default=[], help="run only this profile; repeatable")
    parser.add_argument("--model", choices=("production", "candidates", "product", "relay"), default="production",
                        help="what the coordinator publishes: production's local port, the measured candidates "
                             "model, the shipped candidate code with the server's own node (#515), or "
                             "candidates with a relay node (D402)")
    parser.add_argument("--relay-fixture", help="absolute path of the relay_fixture example (--model relay)")
    parser.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.list:
        print(json.dumps([asdict(scenario) for scenario in SCENARIOS], indent=2))
        return
    for name in ("binary", "coordinator", "scratch"):
        value = getattr(args, name)
        if not value or not Path(value).is_absolute():
            parser.error(f"--{name} must be an absolute path")
    if args.model == "relay" and not (args.relay_fixture and Path(args.relay_fixture).is_absolute()):
        parser.error("--model relay needs --relay-fixture as an absolute path")
    raise SystemExit(inner(args) if args.inner else outer(args))


if __name__ == "__main__":
    main()
