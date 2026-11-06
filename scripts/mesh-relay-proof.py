#!/usr/bin/env python3
"""GotaTun relay proof in network namespaces behind simulated NATs [220].

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
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
from mesh_rotation_latency import (
    cpu_mask_for_namespace,
    cpu_scope_unit_name,
    parse_ping_reply,
    summarize_latency,
)

HOSTS = {
    "A": "0a000000-0000-4000-8000-00000000000a",
    "B": "0b000000-0000-4000-8000-00000000000b",
    "C": "0c000000-0000-4000-8000-00000000000c",
}
RELAYS = ["relay-1.mesh.test", "relay-2.mesh.test"]
RELAY_ADDRESSES = ["198.51.100.11:3478", "198.51.100.12:3478"]
MESH = {"A": ("10.254.0.1", "fd00:220::1"), "B": ("10.254.0.2", "fd00:220::2"),
        "C": ("10.254.0.3", "fd00:220::3")}
LABEL = os.environ.get("RELAY_PROOF_LABEL", f"build host, {platform.machine()}, not perf evidence")
CPU_SCOPE_RECEIPTS = []
# ip, nft, sysctl and rmmod live in the system directories even when a
# toolchain environment trimmed PATH.
os.environ["PATH"] = os.environ.get("PATH", "") + ":/usr/sbin:/sbin:/usr/bin:/bin"
os.environ["INFRATERNAL_MESH_ENGINE"] = "gotatun"


def run(*args, check=True, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def namespace_scope(namespace):
    """Return this namespace's D348 mask and transient scope name when pinning is enabled."""
    if os.environ.get("H2H_CPUSET_PIN") != "1":
        return None
    mask = cpu_mask_for_namespace(
        namespace,
        os.environ.get("H2H_CPUSET_A", "1-2"),
        os.environ.get("H2H_CPUSET_B", "3-4"),
        os.environ.get("H2H_CPUSET_HOUSEKEEPING", "0,5"),
    )
    unit = cpu_scope_unit_name(namespace, os.getpid(), random.randrange(1 << 24))
    return {"mask": mask, "unit": unit, "namespace": namespace}


def namespace_command(namespace, *args):
    """Build a namespace command in its D348 cpuset, or leave ordinary proofs unscoped."""
    command = ["ip", "netns", "exec", namespace, *args]
    scope = namespace_scope(namespace)
    if scope is None:
        return command
    return [
        "systemd-run", "--scope", "--quiet", "--collect", "--slice=perf.slice",
        f"--unit={scope['unit']}", f"--property=AllowedCPUs={scope['mask']}",
        "--", "taskset", "-c", scope["mask"], *command,
    ]


def spawn_namespace_process(namespace, *args, **kwargs):
    """Start a fixture, load or probe process and verify its live D348 scope when pinned."""
    scope = namespace_scope(namespace)
    command = ["ip", "netns", "exec", namespace, *args]
    if scope is None:
        process = subprocess.Popen(command, **kwargs)
        return process, process.pid

    descriptor, pid_path = tempfile.mkstemp(prefix="j279-scope-pid-")
    os.close(descriptor)
    wrapper = [
        "/bin/bash", "-c",
        'pidfile=$1; shift; printf "%s\\n" "$$" > "$pidfile"; exec "$@"',
        "j279-scope", pid_path, "taskset", "-c", scope["mask"], *command,
    ]
    launcher = [
        "systemd-run", "--scope", "--quiet", "--collect", "--slice=perf.slice",
        f"--unit={scope['unit']}", f"--property=AllowedCPUs={scope['mask']}", "--", *wrapper,
    ]
    process = subprocess.Popen(launcher, **kwargs)
    try:
        deadline = time.monotonic() + 10
        process_pid = None
        while time.monotonic() < deadline:
            try:
                with open(pid_path, encoding="utf-8") as pid_file:
                    contents = pid_file.read().strip()
                if contents:
                    process_pid = int(contents)
                    break
            except FileNotFoundError:
                pass
            if process.poll() is not None:
                raise RuntimeError(f"D348 scope {scope['unit']} exited before publishing its command PID")
            # sleep: give the transient scope time to publish the process ID.
            time.sleep(0.01)
        if process_pid is None:
            raise RuntimeError(f"D348 scope {scope['unit']} did not publish its command PID")

        status = open(f"/proc/{process_pid}/status", encoding="utf-8").read()
        allowed = next(
            line.split(":", 1)[1].strip()
            for line in status.splitlines()
            if line.startswith("Cpus_allowed_list:")
        )
        cgroup = next(
            line.split("::", 1)[1].strip()
            for line in open(f"/proc/{process_pid}/cgroup", encoding="utf-8").read().splitlines()
            if line.startswith("0::")
        )
        effective_path = f"/sys/fs/cgroup{cgroup}/cpuset.cpus.effective"
        with open(effective_path, encoding="utf-8") as effective_file:
            effective = effective_file.read().strip()
        if allowed != scope["mask"] or effective != scope["mask"]:
            raise RuntimeError(
                f"D348 scope {scope['unit']} placement mismatch: "
                f"allowed={allowed}, cpuset={effective}, expected={scope['mask']}"
            )
        CPU_SCOPE_RECEIPTS.append({
            "namespace": namespace,
            "pid": process_pid,
            "unit": scope["unit"],
            "cpus_allowed_list": allowed,
            "cpuset_cpus_effective": effective,
        })
        return process, process_pid
    except BaseException:
        subprocess.run(["systemctl", "stop", scope["unit"]], capture_output=True)
        if process.poll() is None:
            process.wait(timeout=5)
        raise
    finally:
        try:
            os.unlink(pid_path)
        except FileNotFoundError:
            pass


def ns(name, *args, **kwargs):
    return run(*namespace_command(name, *args), **kwargs)


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
        self.process, self.cpu_pid = spawn_namespace_process(
            namespace, binary, mode,
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
import hashlib, json, os, socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(1)
print("ready", flush=True)
c, _ = s.accept(); c.settimeout(60)
gate_after = int(sys.argv[3]) if len(sys.argv) > 3 else 0
gate_notify = int(sys.argv[4]) if gate_after else None
gate_resume = int(sys.argv[5]) if gate_after else None
h = hashlib.sha256(); total = 0; gap = 0.0; last = time.monotonic(); start = last
while True:
    b = c.recv(262144)
    now = time.monotonic(); gap = max(gap, now - last); last = now
    if not b: break
    while b:
        if gate_after and total < gate_after:
            count = min(len(b), gate_after - total)
            h.update(b[:count]); total += count; b = b[count:]
            if total == gate_after:
                os.write(gate_notify, b"G")
                if os.read(gate_resume, 1) != b"R": raise RuntimeError("stream gate was not released")
                gate_after = 0
        else:
            h.update(b); total += len(b); break
print(json.dumps({"bytes": total, "sha256": h.hexdigest(), "max_gap_ms": gap * 1000, "seconds": last - start}), flush=True)
"""

SENDER = r"""
import hashlib, json, random, socket, sys, time
total = int(sys.argv[3]); rng = random.Random(220)
pace = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
c = socket.create_connection((sys.argv[1], int(sys.argv[2])), 10); c.settimeout(60)
h = hashlib.sha256(); sent = 0; start = time.monotonic()
while sent < total:
    block = rng.randbytes(min(65536, total - sent))
    c.sendall(block); h.update(block); sent += len(block)
    if pace: time.sleep(pace)
c.shutdown(socket.SHUT_WR); c.recv(1)
print(json.dumps({"bytes": sent, "sha256": h.hexdigest(), "seconds": time.monotonic() - start}), flush=True)
"""


def stream(sender_ns, receiver_ns, address, port, size, during=None, pace_seconds=0.0, gate_after=0):
    """Send `size` deterministic random bytes over TCP; returns both ends' reports."""
    receiver_args = [sys.executable, "-c", RECEIVER, address, str(port)]
    gate_read = gate_write = resume_read = resume_write = None
    if gate_after:
        if not during:
            raise ValueError("a held receiver gate requires a during callback")
        gate_read, gate_write = os.pipe()
        resume_read, resume_write = os.pipe()
        receiver_args.extend([str(gate_after), str(gate_write), str(resume_read)])
    receiver, _ = spawn_namespace_process(
        receiver_ns, *receiver_args, stdout=subprocess.PIPE, text=True,
        pass_fds=tuple(fd for fd in (gate_write, resume_read) if fd is not None))
    if gate_after:
        os.close(gate_write); os.close(resume_read)
    if receiver.stdout.readline().strip() != "ready":
        raise RuntimeError("receiver failed")
    sender_args = [sys.executable, "-c", SENDER, address, str(port), str(size)]
    if pace_seconds:
        sender_args.append(str(pace_seconds))
    sender, _ = spawn_namespace_process(sender_ns, *sender_args,
                                        stdout=subprocess.PIPE, text=True)
    try:
        if during:
            if gate_after:
                during(sender, gate_read, resume_write)
            elif pace_seconds:
                during(sender)
            else:
                during()
        out, _ = sender.communicate(timeout=180)
        got, _ = receiver.communicate(timeout=30)
        return json.loads(out), json.loads(got)
    except BaseException:
        if resume_write is not None:
            try:
                os.write(resume_write, b"R")
            except OSError:
                pass
        for process in (sender, receiver):
            if process.poll() is None:
                process.kill()
                process.wait()
        raise
    finally:
        for fd in (gate_read, gate_write, resume_read, resume_write):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def ping(namespace, address, count=20):
    out = ns(namespace, "ping", "-n", "-q", "-c", str(count), "-i", "0.05", "-W", "2", address, check=False)
    match = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    loss = re.search(r"([\d.]+)% packet loss", out)
    return {"loss_pct": float(loss.group(1)) if loss else 100.0,
            "rtt_min_avg_max_ms": [float(x) for x in match.groups()[:3]] if match else None}


def start_latency_probe(namespace, address, count=3600, interval_seconds=0.01):
    """Start one fixed-rate D348 probe window and drain replies without stalling ping."""
    args = ["ping", "-n", "-D", "-i", str(interval_seconds), "-c", str(count), "-W", "1", address]
    process, cpu_pid = spawn_namespace_process(
        namespace, *args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    lines = []

    def drain():
        for line in process.stdout:
            lines.append(line)

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    return {"count": count, "interval_seconds": interval_seconds, "lines": lines,
            "cpu_pid": cpu_pid, "process": process, "reader": reader}


def finish_latency_probe(probe):
    """Return loss-aware p50/p99 for a completed probe window without hiding packet loss."""
    process = probe["process"]
    process.wait(timeout=probe["count"] * probe["interval_seconds"] + 15)
    probe["reader"].join(timeout=5)
    if probe["reader"].is_alive():
        raise RuntimeError("the latency probe output reader did not finish")
    output = "".join(probe["lines"])
    summary = re.search(
        r"(?m)^(\d+) packets transmitted, (\d+) received, ([0-9.]+)% packet loss",
        output,
    )
    if process.returncode not in (0, 1) or summary is None:
        raise RuntimeError(f"ping probe failed: exit={process.returncode}; output={output[-2000:]}")
    sent, received = int(summary.group(1)), int(summary.group(2))
    replies = [sample for line in probe["lines"] if (sample := parse_ping_reply(line)) is not None]
    if sent != probe["count"] or received != len(replies):
        raise RuntimeError(
            f"ping probe summary mismatch: sent={sent}/{probe['count']}, "
            f"received={received}/{len(replies)}"
        )
    report = summarize_latency(range(1, sent + 1), [(sequence, rtt) for _, sequence, rtt in replies])
    return {"interval_seconds": probe["interval_seconds"], **report}


def topology():
    if os.environ.get("H2H_CPUSET_PIN") == "1":
        run("mount", "-t", "tmpfs", "-o", "mode=0700", "tmpfs", "/run/netns")
    else:
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


def inner(binary, report_path=None):
    results = {"label": LABEL, "kernel": os.uname().release, "cores": os.cpu_count()}
    if os.environ.get("H2H_CPUSET_PIN") == "1":
        CPU_SCOPE_RECEIPTS.clear()
        results["cpu_placement"] = {
            "side_a": os.environ.get("H2H_CPUSET_A", "1-2"),
            "side_b": os.environ.get("H2H_CPUSET_B", "3-4"),
            "housekeeping": os.environ.get("H2H_CPUSET_HOUSEKEEPING", "0,5"),
            "scope": "systemd AllowedCPUs plus matching task affinity",
        }
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
                "ca": material["ca"],
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
        def peer(node, endpoint, key=None, previous_key=None, previous_active=False):
            """Build one fixture peer, optionally retaining a rotation overlap identity."""
            return {"host": HOSTS[node], "key": key or identity[node]["public_key"],
                    "previous_key": previous_key, "previous_active": previous_active,
                    "addresses": {"ipv4": MESH[node][0], "ipv6": MESH[node][1]}, "endpoint": endpoint}
        a.ask({"peers": [peer("B", f"10.2.0.2:{identity['B']['port']}"),
                         peer("C", f"198.51.100.31:{identity['C']['port']}")]}, "peers")
        b.ask({"peers": [peer("A", f"10.1.0.2:{identity['A']['port']}")]}, "peers")
        c.ask({"peers": [peer("A", f"198.51.100.21:{identity['A']['port']}")]}, "peers")
        direct_before_relay = ping("nodeA", MESH["C"][0])
        assert direct_before_relay["loss_pct"] < 100.0, direct_before_relay
        peer_keys = {"A": HOSTS["B"], "B": HOSTS["A"]}
        before_handshake = {
            node: next(p for p in fixture.ask("\"stats\"", "stats")["peers"]
                       if p["peer"] == peer_keys[node])
            for node, fixture in (("A", a), ("B", b))
        }
        decided = time.monotonic()
        a.send({"direct_or_relay": {"host": HOSTS["B"], "grace_ms": 2000}})
        b.send({"direct_or_relay": {"host": HOSTS["A"], "grace_ms": 2000}})
        a_relayed = a.event("relayed", peer=HOSTS["B"])
        b_relayed = b.event("relayed", peer=HOSTS["A"])
        a_linked = a.event("active", peer=HOSTS["B"], relay=0)
        b_linked = b.event("active", peer=HOSTS["A"], relay=0)
        # Relay activation starts a handshake without waiting for application traffic.
        handshake_deadline = max(a_linked["rx"], b_linked["rx"]) + 5.0
        handshake = None
        a_stats = b_stats = None
        while time.monotonic() < handshake_deadline:
            a_stats = a.ask("\"stats\"", "stats")
            b_stats = b.ask("\"stats\"", "stats")
            rows = {
                "A": next(p for p in a_stats["peers"] if p["peer"] == peer_keys["A"]),
                "B": next(p for p in b_stats["peers"] if p["peer"] == peer_keys["B"]),
            }
            if all(
                (row["handshake_secs"], row["handshake_nanos"])
                > (before_handshake[node]["handshake_secs"], before_handshake[node]["handshake_nanos"])
                for node, row in rows.items()
            ):
                handshake = a_stats["rx"]
                break
            time.sleep(0.005)
        if not handshake:
            a_stats = a_stats or a.ask("\"stats\"", "stats")
            b_stats = b_stats or b.ask("\"stats\"", "stats")
            relay_stats = [relay.ask("stats", "stats") for relay in relays]
            raise AssertionError(
                f"no fresh relayed handshake on both peers within 5s of activation; "
                f"before={before_handshake}; A={a_stats}; B={b_stats}; relays={relay_stats}; "
                f"events_A={[event for event in a.events if event.get('event') in ('relay_up', 'relay_down', 'relayed', 'active')][-12:]}; "
                f"events_B={[event for event in b.events if event.get('event') in ('relay_up', 'relay_down', 'relayed', 'active')][-12:]}"
            )
        second = max(a_relayed["rx"], b_relayed["rx"])
        results["relayed_setup_ms"] = {
            "decision_grace_ms": 2000,
            "second_end_relayed_to_linked": round((max(a_linked["rx"], b_linked["rx"]) - second) * 1000, 1),
            "second_end_relayed_to_first_handshake": round((handshake - second) * 1000, 1),
            "including_grace": round((handshake - decided) * 1000, 1),
            "poll_resolution_ms": "about 5",
        }
        direct_after_B_redirect = ping("nodeA", MESH["C"][0])
        if direct_after_B_redirect["loss_pct"] == 100.0:
            direct_peer_stats = a.ask("\"stats\"", "stats")
            raise AssertionError(
                "direct peer C stopped after redirecting peer B to its relay shim; "
                f"before={direct_before_relay}; after={direct_after_B_redirect}; "
                f"A={direct_peer_stats}"
            )
        results["direct_peer_control"] = {
            "before_B_redirect": direct_before_relay,
            "after_B_redirect": direct_after_B_redirect,
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
        cpu_a, cpu_b = cpu_seconds(a.cpu_pid), cpu_seconds(b.cpu_pid)
        sent, got = stream("nodeA", "nodeB", MESH["B"][0], 5201, 32 << 20)
        cpu_a, cpu_b = cpu_seconds(a.cpu_pid) - cpu_a, cpu_seconds(b.cpu_pid) - cpu_b
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

        # 5. The same relayed TCP stream survives a live GotaTun key rotation.
        rotation = {"operation_id": "00000000-0000-4000-8000-000000003679", "sequence": 1}
        rotation_state = {}
        rotation_latency = {
            "before_probe": start_latency_probe("nodeA", MESH["B"][0]),
            "before": None,
            "after_probe": None,
            "after": None,
        }

        def rotate_during_stream(sender, gate_read, resume_write):
            """Rotate B while the receiver holds the same relayed TCP stream open."""
            ready, _, _ = select.select([gate_read], [], [], 60)
            assert ready and os.read(gate_read, 1) == b"G", "receiver did not reach the rotation gate"
            assert sender.poll() is None, "the rotation stream finished before the key switch"
            rotation_latency["before"] = finish_latency_probe(rotation_latency["before_probe"])
            started_rotation = time.monotonic()
            prepared = b.ask({"rotation_prepare": rotation}, "rotation_prepared")
            candidate = prepared["public_key"]
            assert candidate != identity["B"]["public_key"], prepared
            a.ask({"peers": [
                peer("B", f"10.2.0.2:{identity['B']['port']}", key=candidate,
                     previous_key=identity["B"]["public_key"], previous_active=True),
                peer("C", f"198.51.100.31:{identity['C']['port']}")]}, "peers")
            overlap = a.ask("\"stats\"", "stats")
            assert identity["B"]["public_key"] in overlap["peer_keys"] and candidate in overlap["peer_keys"], overlap

            committed = b.ask({"rotation_commit": rotation}, "rotation_committed")
            assert committed["public_key"] == candidate, committed
            a.ask({"peers": [
                peer("B", f"10.2.0.2:{identity['B']['port']}", key=candidate,
                     previous_key=identity["B"]["public_key"], previous_active=False),
                peer("C", f"198.51.100.31:{identity['C']['port']}")]}, "peers")
            a.ask({"peers": [
                peer("B", f"10.2.0.2:{identity['B']['port']}", key=candidate),
                peer("C", f"198.51.100.31:{identity['C']['port']}")]}, "peers")
            b.ask({"rotation_finish": rotation}, "rotation_finished")
            rotation_state.update({
                "old_key": identity["B"]["public_key"],
                "candidate_key": candidate,
                "overlap_had_both_keys": True,
                "stream_gate_rotation_ms": round((time.monotonic() - started_rotation) * 1000, 1),
            })
            rotation_latency["after_probe"] = start_latency_probe("nodeA", MESH["B"][0])
            os.write(resume_write, b"R")

        a.drain()
        b.drain()
        sent, got = stream("nodeA", "nodeB", MESH["B"][0], 5205, 128 << 20,
                           during=rotate_during_stream, pace_seconds=0.036, gate_after=64 << 20)
        rotation_latency["after"] = finish_latency_probe(rotation_latency["after_probe"])
        assert sent["sha256"] == got["sha256"] and got["bytes"] == 128 << 20, (sent, got)
        results["rotation_during_relayed_stream"] = {
            **rotation_state,
            "bytes": got["bytes"], "sha256_equal": True,
            "mbit_s": round(got["bytes"] * 8 / got["seconds"] / 1e6, 1),
            "max_gap_ms": round(got["max_gap_ms"], 1),
            "stream_seconds": round(got["seconds"], 2),
        }
        results["rotation_packet_latency"] = {
            "probe_count_per_window": 3600,
            "probe_interval_seconds": 0.01,
            "flow_count": 1,
            "traffic": "one paced 128 MiB relayed TCP stream",
            "before_rotation_under_load": rotation_latency["before"],
            "after_rotation_under_load": rotation_latency["after"],
            "loss_rule": (
                "each lost probe contributes infinite RTT before nearest-rank p99; "
                "37 or more losses of 3600 makes p99 infinite"
            ),
        }

        # 6. Relay 1 killed mid-stream: capture link state and counters on relay 2.
        killed = {}
        switched = {}

        a.drain()
        b.drain()

        def kill_relay(sender, gate_read, resume_write):
            ready, _, _ = select.select([gate_read], [], [], 30)
            assert ready and os.read(gate_read, 1) == b"G", "receiver did not acknowledge the first MiB"
            assert sender.poll() is None, "the failover stream finished before relay 1 was killed"
            killed["at"] = time.monotonic()
            relays[0].kill()
            switched["a_down"] = a.event("relay_down", relay=0)
            switched["b_down"] = b.event("relay_down", relay=0)
            switched["a_moved"] = a.event("active", peer=HOSTS["B"], relay=1)
            switched["b_moved"] = b.event("active", peer=HOSTS["A"], relay=1)
            assert sender.poll() is None, "the same TCP stream must remain open through relay 2 selection"
            switched["a_stats"] = a.ask("\"stats\"", "stats")
            switched["b_stats"] = b.ask("\"stats\"", "stats")
            switched["relay2_stats"] = relays[1].ask("stats", "stats")
            os.write(resume_write, b"R")
        sent, got = stream("nodeA", "nodeB", MESH["B"][0], 5203, 64 << 20,
                           during=kill_relay, pace_seconds=0.01, gate_after=1 << 20)
        ended = time.monotonic()
        assert sent["sha256"] == got["sha256"] and got["bytes"] == 64 << 20, (sent, got)
        assert killed["at"] < ended, "relay 1 must be killed while the same stream remains active"
        a_down = switched["a_down"]
        b_down = switched["b_down"]
        a_moved = switched["a_moved"]
        b_moved = switched["b_moved"]
        results["relay_killed_mid_stream"] = {
            "bytes": got["bytes"], "sha256_equal": True, "max_gap_ms": round(got["max_gap_ms"], 1),
            "kill_to_relay_down_ms": {"A": round((a_down["rx"] - killed["at"]) * 1000, 1),
                                      "B": round((b_down["rx"] - killed["at"]) * 1000, 1)},
            "kill_to_both_on_relay_2_ms": round((max(a_moved["rx"], b_moved["rx"]) - killed["at"]) * 1000, 1),
            "stream_seconds": round(got["seconds"], 2),
            "killed_after_stream_start_s": round(killed["at"] - (ended - got["seconds"]), 2),
        }

        # 7. No relay left: the pair says so plainly; a restarted relay brings it back.
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
        # Recovery timing is reported only: relay reconnect backoff grows to five seconds after
        # a long outage, and throughput/latency thresholds belong to the R4b harness.
        results["no_relay"]["recovered_after_restart_ms"] = round(
            (time.monotonic() - restarted) * 1000, 1)
        results["no_relay"]["ping_after"] = recovered

        # 8. Rebind: A moves to another uplink (another NAT, another public address).
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
    if os.environ.get("H2H_CPUSET_PIN") == "1":
        results["cpu_scope_receipts"] = CPU_SCOPE_RECEIPTS
    report = json.dumps(results, indent=2)
    if report_path:
        with open(report_path, "w", encoding="utf-8") as output:
            output.write(report + "\n")
    print(report, flush=True)


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


def outer(binary, report_path=None):
    before = snapshot()
    pinned = os.environ.get("H2H_CPUSET_PIN") == "1"
    if pinned and os.geteuid() != 0:
        raise RuntimeError("D348 cpuset scopes require the root perf-run wrapper")
    namespaces = ["-mn"] if pinned else ["-Urnm"]
    command = ["unshare", *namespaces, "--propagation", "private", sys.executable,
               os.path.abspath(__file__), "--inner"]
    if report_path:
        command.extend(["--report", report_path])
    command.append(binary)
    status = subprocess.run(command).returncode
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
    parser.add_argument("--report", help="write the inner run's JSON report to this path")
    parser.add_argument("fixture", help="absolute path of the relay_fixture example")
    args = parser.parse_args()
    if not os.path.isabs(args.fixture):
        parser.error("fixture path must be absolute")
    if args.report and not os.path.isabs(args.report):
        parser.error("report path must be absolute")
    (inner if args.inner else outer)(args.fixture, args.report)
