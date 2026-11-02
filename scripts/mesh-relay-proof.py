#!/usr/bin/env python3
"""Seam C relay proof in network namespaces behind simulated NATs [313], #220.

Run without arguments and pass the absolute path of the `relay_fixture`
example. The script snapshots the host's links, namespaces, modules and
net.* sysctls, then re-runs itself inside `unshare -Urnm` (a private user,
mount and network namespace), so every namespace, link, NAT rule and sysctl
it creates belongs to that throwaway user namespace. It snapshots the host
again afterwards and fails on any difference.

Topology (all addresses are documentation or private ranges):

    relay1 198.51.100.11   relay2 198.51.100.12   nodeC 198.51.100.31 (public)
         \\                    |                    /
          `-------------- inet (bridge) ----------'
               |                 |                 |
    natA 198.51.100.21   natB 198.51.100.22   natA2 198.51.100.23
    EIM/EIF (full cone)  EDM (random ports)   EIM/APDF (rebind target)
           |                 |                 |
         nodeA 10.1.0.2    nodeB 10.2.0.2    nodeA's second uplink 10.3.0.2

A and B cannot reach each other directly (their configured endpoints are
the other's private address), so they relay. A and C go direct. Private
keys and certificates travel only through pipes.
"""
import argparse
import hashlib
import json
import os
import platform
import queue
import random
import re
import signal
import subprocess
import sys
import threading
import time

HOSTS = {
    "A": "0a000000-0000-4000-8000-00000000000a",
    "B": "0b000000-0000-4000-8000-00000000000b",
    "C": "0c000000-0000-4000-8000-00000000000c",
}
RELAYS = ["relay-1.mesh.test", "relay-2.mesh.test"]
RELAY_ADDRESSES = ["198.51.100.11:3478", "198.51.100.12:3478"]
MESH = {"A": ("10.254.0.1", "fd00:220::1"), "B": ("10.254.0.2", "fd00:220::2"),
        "C": ("10.254.0.3", "fd00:220::3")}
LABEL = f"build host, {platform.machine()}, not perf evidence"
# ip, nft, sysctl and rmmod live in the system directories even when a
# toolchain environment trimmed PATH.
os.environ["PATH"] = os.environ.get("PATH", "") + ":/usr/sbin:/sbin:/usr/bin:/bin"


def run(*args, check=True, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def ns(name, *args, **kwargs):
    return run("ip", "netns", "exec", name, *args, **kwargs)


def snapshot():
    """Host configuration that the proof must leave unchanged."""
    def sysctls():
        out = run("sysctl", "-a", check=False)
        keep = []
        for line in out.splitlines():
            key = line.split("=", 1)[0].strip()
            # Live counters are state, not configuration.
            if key.startswith("net.") and not (key.startswith("net.netfilter.") and key.endswith("_count")):
                keep.append(line)
        return sorted(keep)
    return {
        "links": run("ip", "-o", "link", "show").splitlines(),
        "netns": sorted(run("ip", "netns", "list").splitlines()),
        "modules": sorted(line.split()[0] for line in open("/proc/modules")),
        "sysctl": sysctls(),
    }


class Fixture:
    """One fixture process; lines from its stdout arrive on a queue."""

    def __init__(self, namespace, binary, mode, config=None):
        self.name = f"{mode}@{namespace}"
        self.process = subprocess.Popen(
            ["ip", "netns", "exec", namespace, binary, mode],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.lines = queue.Queue()
        self.events = []
        # Received but not yet matched; a wait matches in any order.
        self.pending = []
        self.errors = []
        threading.Thread(target=self._read, daemon=True).start()
        # Drain stderr continuously so a chatty fixture can never block on a full pipe.
        threading.Thread(target=lambda: self.errors.extend(self.process.stderr), daemon=True).start()
        if config is not None:
            self.send(config)

    def _read(self):
        for line in self.process.stdout:
            try:
                value = json.loads(line)
            except ValueError:
                continue
            # Arrival on this script's monotonic clock, comparable across fixtures.
            value["rx"] = time.monotonic()
            self.events.append(value)
            self.lines.put(value)

    def send(self, value):
        self.process.stdin.write((value if isinstance(value, str) else json.dumps(value)) + "\n")
        self.process.stdin.flush()

    def wait(self, predicate, timeout=20.0):
        for index, value in enumerate(self.pending):
            if predicate(value):
                return self.pending.pop(index)
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"{self.name}: no matching event; seen {self.events[-8:]}; "
                                   f"stderr: {self.stderr_tail()}")
            try:
                value = self.lines.get(timeout=left)
            except queue.Empty:
                continue
            if predicate(value):
                return value
            self.pending.append(value)

    def drain(self):
        """Forget unmatched events, so the next wait sees only what happens after this."""
        while not self.lines.empty():
            self.lines.get_nowait()
        self.pending.clear()

    def event(self, name, timeout=20.0, **fields):
        return self.wait(lambda v: v.get("event") == name and all(v.get(k) == f for k, f in fields.items()),
                         timeout)

    def ask(self, command, name, timeout=20.0, **fields):
        self.send(command)
        return self.event(name, timeout, **fields)

    def stderr_tail(self):
        return "".join(self.errors)[-2000:]

    def stop(self):
        if self.process.poll() is None:
            try:
                self.send("quit")
                self.process.stdin.close()
                self.process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired, BrokenPipeError):
                self.process.kill()
                self.process.wait()

    def kill(self):
        self.process.send_signal(signal.SIGKILL)
        self.process.wait()


def cpu_seconds(pid):
    fields = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


RECEIVER = r"""
import hashlib, json, socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(1)
print("ready", flush=True)
c, _ = s.accept(); c.settimeout(60)
h = hashlib.sha256(); total = 0; gap = 0.0; last = time.monotonic(); start = last
while True:
    b = c.recv(262144)
    now = time.monotonic(); gap = max(gap, now - last); last = now
    if not b: break
    h.update(b); total += len(b)
print(json.dumps({"bytes": total, "sha256": h.hexdigest(), "max_gap_ms": gap * 1000, "seconds": last - start}), flush=True)
"""

SENDER = r"""
import hashlib, json, random, socket, sys, time
total = int(sys.argv[3]); rng = random.Random(220)
c = socket.create_connection((sys.argv[1], int(sys.argv[2])), 10); c.settimeout(60)
h = hashlib.sha256(); sent = 0; start = time.monotonic(); pause_for_rotation = len(sys.argv) > 4
while sent < total:
    block = rng.randbytes(min(65536, total - sent))
    c.sendall(block); h.update(block); sent += len(block)
    if pause_for_rotation:
        print("ready", flush=True)
        if sys.stdin.read(1) != "g": sys.exit(2)
        pause_for_rotation = False
c.shutdown(socket.SHUT_WR); c.recv(1)
print(json.dumps({"bytes": sent, "sha256": h.hexdigest(), "seconds": time.monotonic() - start}), flush=True)
"""


def stream(sender_ns, receiver_ns, address, port, size, during=None):
    """Send `size` deterministic random bytes over TCP; returns both ends' reports."""
    receiver = subprocess.Popen(["ip", "netns", "exec", receiver_ns, sys.executable, "-c", RECEIVER, address, str(port)],
                                stdout=subprocess.PIPE, text=True)
    if receiver.stdout.readline().strip() != "ready":
        raise RuntimeError("receiver failed")
    sender = subprocess.Popen(
        ["ip", "netns", "exec", sender_ns, sys.executable, "-c", SENDER, address, str(port), str(size),
         *(["rotate"] if during else [])],
        stdin=subprocess.PIPE if during else None,
        stdout=subprocess.PIPE,
        text=True,
    )
    if during:
        if sender.stdout.readline().strip() != "ready":
            raise RuntimeError("sender did not pause after starting the stream")
        during()
        sender.stdin.write("g")
        sender.stdin.flush()
    out, _ = sender.communicate(timeout=180)
    got, _ = receiver.communicate(timeout=30)
    return json.loads(out), json.loads(got)


def ping(namespace, address, count=20):
    out = ns(namespace, "ping", "-n", "-q", "-c", str(count), "-i", "0.05", "-W", "2", address, check=False)
    match = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    loss = re.search(r"([\d.]+)% packet loss", out)
    return {"loss_pct": float(loss.group(1)) if loss else 100.0,
            "rtt_min_avg_max_ms": [float(x) for x in match.groups()[:3]] if match else None}


def topology():
    run("mount", "-t", "tmpfs", "none", "/run")
    os.makedirs("/run/netns", exist_ok=True)
    names = ["inet", "relay1", "relay2", "natA", "natB", "natA2", "nodeA", "nodeB", "nodeC"]
    for name in names:
        run("ip", "netns", "add", name)
        ns(name, "ip", "link", "set", "lo", "up")
    ns("inet", "ip", "link", "add", "br0", "type", "bridge")
    ns("inet", "ip", "link", "set", "br0", "up")

    def public(name, address):
        run("ip", "-n", "inet", "link", "add", f"p-{name}", "type", "veth", "peer", "name", "pub", "netns", name)
        ns("inet", "ip", "link", "set", f"p-{name}", "master", "br0", "up")
        ns(name, "ip", "addr", "add", f"{address}/24", "dev", "pub")
        ns(name, "ip", "link", "set", "pub", "up")

    def private(nat, node, subnet, device):
        run("ip", "-n", nat, "link", "add", "lan", "type", "veth", "peer", "name", device, "netns", node)
        ns(nat, "ip", "addr", "add", f"{subnet}.1/24", "dev", "lan")
        ns(nat, "ip", "link", "set", "lan", "up")
        ns(node, "ip", "addr", "add", f"{subnet}.2/24", "dev", device)
        ns(node, "ip", "link", "set", device, "up")
        ns(nat, "sysctl", "-qw", "net.ipv4.ip_forward=1")

    for name, address in [("relay1", "198.51.100.11"), ("relay2", "198.51.100.12"), ("natA", "198.51.100.21"),
                          ("natB", "198.51.100.22"), ("natA2", "198.51.100.23"), ("nodeC", "198.51.100.31")]:
        public(name, address)
    private("natA", "nodeA", "10.1.0", "up0")
    private("natB", "nodeB", "10.2.0", "up0")
    private("natA2", "nodeA", "10.3.0", "up1")
    ns("nodeA", "ip", "route", "add", "default", "via", "10.1.0.1")
    ns("nodeB", "ip", "route", "add", "default", "via", "10.2.0.1")
    ns("nodeC", "ip", "route", "add", "default", "dev", "pub")
    # EDM: a random source port for every new mapping; conntrack filters by address and port.
    ns("natB", "nft", "add table ip nat; add chain ip nat post { type nat hook postrouting priority srcnat; }; "
       "add rule ip nat post oifname pub snat to 198.51.100.22 random")
    ns("natA2", "nft", "add table ip nat; add chain ip nat post { type nat hook postrouting priority srcnat; }; "
       "add rule ip nat post oifname pub snat to 198.51.100.23")


def full_cone(port):
    """natA: port-preserving mapping, and inbound to the mapped port from anyone (EIM/EIF)."""
    ns("natA", "nft", "add table ip nat; "
       "add chain ip nat post { type nat hook postrouting priority srcnat; }; "
       "add rule ip nat post oifname pub snat to 198.51.100.21; "
       "add chain ip nat pre { type nat hook prerouting priority dstnat; }; "
       f"add rule ip nat pre iifname pub udp dport {port} dnat to 10.1.0.2")


def inner(binary):
    results = {"label": LABEL, "kernel": os.uname().release, "cores": os.cpu_count()}
    fixtures = []
    try:
        topology()
        certs = subprocess.run([binary, "certs"], input=json.dumps({"hosts": list(HOSTS.values()), "relays": RELAYS}),
                               capture_output=True, text=True, check=True)
        material = json.loads(certs.stdout)
        relays = []
        for index, name in enumerate(RELAYS):
            fixture = Fixture(f"relay{index + 1}", binary, "relay", {
                "listen": RELAY_ADDRESSES[index], "cert": material["relays"][name]["cert"],
                "key": material["relays"][name]["key"], "ca": material["ca"]})
            fixture.event("ready")
            fixtures.append(fixture)
            relays.append(fixture)
        relay_list = [{"address": address, "name": name} for address, name in zip(RELAY_ADDRESSES, RELAYS)]
        nodes, identity, started = {}, {}, {}
        for node in "ABC":
            started[node] = time.monotonic()
            fixture = Fixture(f"node{node}", binary, "node", {
                "host": HOSTS[node],
                "cert": material["hosts"][HOSTS[node]]["cert"], "key": material["hosts"][HOSTS[node]]["key"],
                "ca": material["ca"], "port": 0,
                "addresses": {"ipv4": MESH[node][0], "ipv6": MESH[node][1]},
                "relays": relay_list if node in "AB" else []})
            fixtures.append(fixture)
            identity[node] = fixture.event("identity")
            nodes[node] = fixture
        # natA maps only once A's WireGuard port is known; A connects to the relays after it.
        full_cone(identity["A"]["port"])
        for node in "AB":
            for i in (0, 1):
                nodes[node].event("relay_up", relay=i)
            results.setdefault("node_start_to_both_relays_ms", {})[node] = round(
                (time.monotonic() - started[node]) * 1000, 1)
        a, b, c = nodes["A"], nodes["B"], nodes["C"]

        # 1. Observation from the WireGuard port through each NAT.
        observed = {}
        for node, fixture in (("A", a), ("B", b)):
            observed[node] = [fixture.ask({"observe": {"relay": i, "observer": 100 + i}}, "observed", relay=i)
                              for i in (0, 1)]
            observed[node].append(fixture.ask("\"evidence\"", "evidence"))
        assert all(o["reflexive"] == f"198.51.100.21:{identity['A']['port']}" for o in observed["A"][:2]), observed["A"]
        assert observed["A"][2]["ipv4"] == "Stable", observed["A"][2]
        assert all(o["reflexive"].startswith("198.51.100.22:") for o in observed["B"][:2]), observed["B"]
        assert observed["B"][0]["reflexive"] != observed["B"][1]["reflexive"], "EDM must map per destination"
        assert observed["B"][2]["ipv4"] == "DestinationDependent", observed["B"][2]
        results["observation"] = {node: {"reflexive": [o["reflexive"] for o in observed[node][:2]],
                                         "evidence": observed[node][2]["ipv4"],
                                         "probe_rtt_us": [o["rtt_us"] for o in observed[node][:2]]}
                                  for node in observed}

        # 2. Probes reached each WireGuard port without touching kernel state.
        for fixture in (a, b):
            stats = fixture.ask("\"stats\"", "stats")
            assert stats["tap_delivered"] == 2, stats
        results["tap_delivered_after_probes"] = {"A": 2, "B": 2}

        # 3. Peers. A and B only know each other's private address: no direct path.
        def peer(node, endpoint, *, current_key=None, previous_key=None, previous_active=False):
            value = {"host": HOSTS[node], "key": current_key or identity[node]["public_key"],
                     "addresses": {"ipv4": MESH[node][0], "ipv6": MESH[node][1]}, "endpoint": endpoint,
                     "previous_active": previous_active}
            if previous_key is not None:
                value["previous_key"] = previous_key
            return value
        a.ask({"peers": [peer("B", f"10.2.0.2:{identity['B']['port']}"),
                         peer("C", f"198.51.100.31:{identity['C']['port']}")]}, "peers")
        b.ask({"peers": [peer("A", f"10.1.0.2:{identity['A']['port']}")]}, "peers")
        c.ask({"peers": [peer("A", f"198.51.100.21:{identity['A']['port']}")]}, "peers")
        decided = time.monotonic()
        a.send({"direct_or_relay": {"host": HOSTS["B"], "grace_ms": 2000}})
        b.send({"direct_or_relay": {"host": HOSTS["A"], "grace_ms": 2000}})
        a_relayed = a.event("relayed", peer=HOSTS["B"])
        b_relayed = b.event("relayed", peer=HOSTS["A"])
        a_linked = a.event("active", peer=HOSTS["B"], relay=0)
        b_linked = b.event("active", peer=HOSTS["A"], relay=0)
        # The first relayed handshake starts on its own once both ends are linked.
        handshake = None
        while time.monotonic() - decided < 20:
            stats = a.ask("\"stats\"", "stats")
            row = next(p for p in stats["peers"] if p["peer"] == HOSTS["B"])
            if row["handshake_secs"]:
                handshake = stats["rx"]
                break
            time.sleep(0.005)
        assert handshake, "no relayed handshake"
        second = max(a_relayed["rx"], b_relayed["rx"])
        results["relayed_setup_ms"] = {
            "decision_grace_ms": 2000,
            "second_end_relayed_to_linked": round((max(a_linked["rx"], b_linked["rx"]) - second) * 1000, 1),
            "second_end_relayed_to_first_handshake": round((handshake - second) * 1000, 1),
            "including_grace": round((handshake - decided) * 1000, 1),
            "poll_resolution_ms": "about 5",
        }
        # A and C are on reachable addresses: the same rule keeps them direct.
        a.send({"direct_or_relay": {"host": HOSTS["C"], "grace_ms": 2000}})
        assert a.event("direct", peer=HOSTS["C"])
        rows = {p["peer"]: p for p in a.ask("\"stats\"", "stats")["peers"]}
        assert rows[HOSTS["B"]]["endpoint"].startswith("127.0.0.1:"), rows
        assert rows[HOSTS["C"]]["endpoint"] == f"198.51.100.31:{identity['C']['port']}", rows

        # 4. Latency and a clean stream over each path.
        results["ping_relayed"] = ping("nodeA", MESH["B"][0])
        results["ping_direct"] = ping("nodeA", MESH["C"][0])
        before = a.ask("\"stats\"", "stats")
        cpu_a, cpu_b = cpu_seconds(a.process.pid), cpu_seconds(b.process.pid)
        sent, got = stream("nodeA", "nodeB", MESH["B"][0], 5201, 32 << 20)
        cpu_a, cpu_b = cpu_seconds(a.process.pid) - cpu_a, cpu_seconds(b.process.pid) - cpu_b
        after_relayed = a.ask("\"stats\"", "stats")
        assert sent["sha256"] == got["sha256"] and got["bytes"] == 32 << 20, (sent, got)
        packets_a = (after_relayed["sent"] + after_relayed["received"]) - (before["sent"] + before["received"])
        b_stats = b.ask("\"stats\"", "stats")
        results["stream_relayed"] = {
            "bytes": got["bytes"], "sha256_equal": True, "mbit_s": round(got["bytes"] * 8 / got["seconds"] / 1e6, 1),
            "max_gap_ms": round(got["max_gap_ms"], 1),
            "shim_packets_A": packets_a, "shim_cpu_s_A": round(cpu_a, 3), "shim_cpu_s_B": round(cpu_b, 3),
            "shim_cpu_us_per_packet_A": round(cpu_a * 1e6 / max(packets_a, 1), 2),
            "too_large_A": after_relayed["too_large"], "unlinked_A": after_relayed["unlinked"],
            "too_large_B": b_stats["too_large"],
        }

        # 4b. Keep a relayed TCP stream byte-exact while one endpoint rotates its local key.
        old_key = identity["A"]["public_key"]
        candidate_key = a.ask("\"prepare_rotation\"", "rotation_prepared")["public_key"]
        b.ask({"peers": [peer("A", None, current_key=old_key,
                              previous_key=candidate_key, previous_active=False)]}, "peers")

        def rotate_key_during_stream():
            committed = a.ask("\"commit_rotation\"", "rotation_committed")
            assert committed["public_key"] == candidate_key, committed
            b.ask({"peers": [peer("A", None, current_key=candidate_key,
                                  previous_key=old_key, previous_active=False)]}, "peers")

        sent, got = stream("nodeA", "nodeB", MESH["B"][0], 5205, 128 << 20,
                           during=rotate_key_during_stream)
        assert sent["sha256"] == got["sha256"] and got["bytes"] == 128 << 20, (sent, got)
        identity["A"]["public_key"] = candidate_key
        c.ask({"peers": [peer("A", f"198.51.100.21:{identity['A']['port']}")]}, "peers")
        b_stats = b.ask("\"stats\"", "stats")
        rotated_peer = next(row for row in b_stats["peers"] if row["peer"] == HOSTS["A"])
        assert rotated_peer["active_relay"] == 0 and rotated_peer["handshake_secs"] > 0, b_stats
        results["rotation_relayed"] = {
            "bytes": got["bytes"], "sha256_equal": True,
            "active_relay": rotated_peer["active_relay"],
            "candidate_handshake_secs": rotated_peer["handshake_secs"],
        }
        after_relayed = a.ask("\"stats\"", "stats")
        sent, got = stream("nodeA", "nodeC", MESH["C"][0], 5202, 32 << 20)
        after_direct = a.ask("\"stats\"", "stats")
        assert sent["sha256"] == got["sha256"] and got["bytes"] == 32 << 20
        # The direct pair never touched the shim, and no WireGuard packet reached the tap.
        assert after_direct["sent"] == after_relayed["sent"], (after_direct, after_relayed)
        assert after_direct["tap_delivered"] == 2, after_direct
        assert b_stats["tap_delivered"] == 2, b_stats
        results["stream_direct"] = {"bytes": got["bytes"], "sha256_equal": True,
                                    "mbit_s": round(got["bytes"] * 8 / got["seconds"] / 1e6, 1)}
        results["tap_delivered_after_streams"] = {"A": after_direct["tap_delivered"], "B": b_stats["tap_delivered"]}

        # 5. Relay 1 killed mid-stream: the pair moves to relay 2, the stream stays intact.
        killed = {}

        a.drain()
        b.drain()

        def kill_relay():
            time.sleep(1.0)
            killed["at"] = time.monotonic()
            relays[0].kill()
        sent, got = stream("nodeA", "nodeB", MESH["B"][0], 5203, 384 << 20, during=kill_relay)
        ended = time.monotonic()
        assert sent["sha256"] == got["sha256"] and got["bytes"] == 384 << 20, (sent, got)
        assert killed["at"] < ended - 1.0, "the relay must die while the stream runs"
        a_down = a.event("relay_down", relay=0)
        b_down = b.event("relay_down", relay=0)
        a_moved = a.event("active", peer=HOSTS["B"], relay=1)
        b_moved = b.event("active", peer=HOSTS["A"], relay=1)
        results["relay_killed_mid_stream"] = {
            "bytes": got["bytes"], "sha256_equal": True, "max_gap_ms": round(got["max_gap_ms"], 1),
            "kill_to_relay_down_ms": {"A": round((a_down["rx"] - killed["at"]) * 1000, 1),
                                      "B": round((b_down["rx"] - killed["at"]) * 1000, 1)},
            "kill_to_both_on_relay_2_ms": round((max(a_moved["rx"], b_moved["rx"]) - killed["at"]) * 1000, 1),
            "stream_seconds": round(got["seconds"], 2),
            "killed_after_stream_start_s": round(killed["at"] - (ended - got["seconds"]), 2),
        }

        # 6. No relay left: the pair says so plainly; a restarted relay brings it back.
        a.drain()
        b.drain()
        relays[1].kill()
        a.event("active", peer=HOSTS["B"], relay=None)
        b.event("active", peer=HOSTS["A"], relay=None)
        results["no_relay"] = {"ping": ping("nodeA", MESH["B"][0], count=5)}
        assert results["no_relay"]["ping"]["loss_pct"] == 100.0
        restarted = time.monotonic()
        results["no_relay"]["relay1_down_before_restart_ms"] = round(
            (restarted - killed["at"]) * 1000, 1)
        relays[0] = Fixture("relay1", binary, "relay", {
            "listen": RELAY_ADDRESSES[0], "cert": material["relays"][RELAYS[0]]["cert"],
            "key": material["relays"][RELAYS[0]]["key"], "ca": material["ca"]})
        fixtures.append(relays[0])
        ready = relays[0].event("ready")
        results["no_relay"]["restart_to_ready_ms"] = round(
            (ready["rx"] - restarted) * 1000, 1)
        active_a = a.event("active", peer=HOSTS["B"], relay=0, timeout=30)
        active_b = b.event("active", peer=HOSTS["A"], relay=0, timeout=30)
        results["no_relay"]["ready_to_links_ms"] = round(
            (max(active_a["rx"], active_b["rx"]) - ready["rx"]) * 1000, 1)
        recovered = ping("nodeA", MESH["B"][0], count=10)
        assert recovered["loss_pct"] < 50, recovered
        results["no_relay"]["recovered_after_restart_ms"] = round(
            (time.monotonic() - restarted) * 1000, 1)
        assert (
            results["no_relay"]["recovered_after_restart_ms"] < 1500.0
        ), results["no_relay"]
        results["no_relay"]["ping_after"] = recovered

        # 7. Rebind: A moves to another uplink (another NAT, another public address).
        old = [o["reflexive"] for o in observed["A"][:2]]
        moved_at = time.monotonic()
        rebind = {}

        def move():
            time.sleep(0.5)
            ns("nodeA", "ip", "route", "replace", "default", "via", "10.3.0.1")
            rebind["at"] = time.monotonic()
        sent, got = stream("nodeA", "nodeB", MESH["B"][0], 5204, 16 << 20, during=move)
        assert sent["sha256"] == got["sha256"] and got["bytes"] == 16 << 20, (sent, got)
        assert a.ask({"generation": 2}, "generation")["ok"]
        fresh = a.ask({"observe": {"relay": 0, "observer": 100}}, "observed", relay=0, timeout=30)
        evidence = a.ask("\"evidence\"", "evidence")
        assert fresh["reflexive"].startswith("198.51.100.23:"), fresh
        assert [o["reflexive"] for o in evidence["observations"]] == [fresh["reflexive"]], evidence
        assert not any(o in old for o in [x["reflexive"] for x in evidence["observations"]])
        results["rebind"] = {"old_mappings": old, "new_mapping": fresh["reflexive"],
                             "old_retired": True, "bytes": got["bytes"], "sha256_equal": True,
                             "max_gap_ms": round(got["max_gap_ms"], 1)}
        relay_stats = relays[0].ask("stats", "stats")
        results["relay1_after_restart"] = relay_stats
    finally:
        for fixture in reversed(fixtures):
            fixture.stop()
        if os.environ.get("RELAY_PROOF_STDERR"):
            with open(os.environ["RELAY_PROOF_STDERR"], "w") as out:
                for fixture in fixtures:
                    out.write(f"== {fixture.name}\n{''.join(fixture.errors)}\n")
    print(json.dumps(results, indent=2), flush=True)


# Modules the topology can make the kernel load. Only these are ever unloaded,
# and only when absent before the run and unused: the host is shared, and a
# module another job loaded meanwhile must stay.
OURS = {"bridge", "stp", "llc", "veth"}
NAMESPACES = {"inet", "relay1", "relay2", "natA", "natB", "natA2", "nodeA", "nodeB", "nodeC"}


def unload(added):
    """Unload modules the namespaces caused the kernel to load; see OURS."""
    deadline = time.monotonic() + 10
    added = set(added) & OURS
    while added and time.monotonic() < deadline:
        for name in sorted(added):
            if subprocess.run(["sudo", "-n", "rmmod", name], capture_output=True).returncode == 0:
                added.discard(name)
        if added:
            time.sleep(0.2)
    return sorted(added)


def outer(binary):
    before = snapshot()
    status = subprocess.run(["unshare", "-Urnm", "--propagation", "private", sys.executable,
                             os.path.abspath(__file__), "--inner", binary]).returncode
    added = [m for m in snapshot()["modules"] if m not in before["modules"]]
    print(json.dumps({"modules_loaded_by_run": added, "still_loaded": unload(added)}), flush=True)
    after = snapshot()
    changed = {key: [line for line in after[key] if line not in before[key]] +
               [line for line in before[key] if line not in after[key]] for key in before}
    # Every namespace of this proof lives in its private mount namespace and
    # can never appear in the host's list; other jobs on the shared host can.
    foreign = {"netns": [name for name in changed["netns"] if name.split()[0] not in NAMESPACES],
               "modules": [name for name in changed["modules"] if name not in OURS]}
    ours = {key: [line for line in lines if line not in foreign.get(key, [])] for key, lines in changed.items()}
    print(json.dumps({"host_state_diff": ours, "unchanged": not any(ours.values()),
                      "other_jobs_changed": foreign}), flush=True)
    if status or any(ours.values()):
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("fixture", help="absolute path of the relay_fixture example")
    args = parser.parse_args()
    if not os.path.isabs(args.fixture):
        parser.error("fixture path must be absolute")
    (inner if args.inner else outer)(args.fixture)
