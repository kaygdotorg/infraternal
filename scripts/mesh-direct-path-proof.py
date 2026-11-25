#!/usr/bin/env python3
"""Direct-path RTT probes and the direct/relay choice, in network namespaces with netem [220, J1194].

Run without arguments and pass the absolute path of the `relay_fixture` example (built with
`--features relay,test-support`). Like `mesh-relay-proof.py` it snapshots the host, re-runs itself
inside `unshare -Urnm` (a private user, mount and network namespace, so nothing it creates can
outlive it or touch the host), and fails on any host difference afterwards.

Topology: one bridge `inet` with four members on a private 198.51.100.0/24 inside the namespace
(no route to any uplink): relay1 .11, relay2 .12, nodeA .21 and nodeC .31. A and C know each
other's address, so their direct path always works; both also have the two relays.

`tc netem` on each node's egress delays by destination: packets to the peer by D ms, packets to
a relay by R ms. The direct round trip is therefore 2*D and the relayed one 4*R (node, relay,
node, and back). Phases alternate between "direct is faster" and "the relay is faster":

    direct fast:  D = 10 ms (RTT 20), R = 20 ms (RTT 80)
    relay fast:   D = 40 ms (RTT 80), R =  5 ms (RTT 20)

A ping from A to C every 0.2 s through the mesh keeps both ends' traffic flowing (probes ride on
traffic). For every phase the script samples both ends once a second and reports the decision
latency (phase start to the first sample on the better path), the switches made, and the share
of one-second samples after that on the worse path (the wrong-choice rate). A last idle window
counts the direct probes sent and the voluntary context switches of the node processes, and
compares them with the same window before the pair was watched.
"""
import argparse
import importlib.util
import json
import os
import statistics
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
_spec = importlib.util.spec_from_file_location("relay_proof", os.path.join(HERE, "mesh-relay-proof.py"))
relay_proof = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(relay_proof)
run, ns, Fixture, snapshot, unload = (
    relay_proof.run, relay_proof.ns, relay_proof.Fixture, relay_proof.snapshot, relay_proof.unload)
HOSTS, RELAYS, RELAY_ADDRESSES, MESH = (
    relay_proof.HOSTS, relay_proof.RELAYS, relay_proof.RELAY_ADDRESSES, relay_proof.MESH)

NAMES = ["inet", "relay1", "relay2", "nodeA", "nodeC"]
ADDRESS = {"relay1": "198.51.100.11", "relay2": "198.51.100.12", "nodeA": "198.51.100.21", "nodeC": "198.51.100.31"}
# (name, direct one-way ms, relay one-way ms, which path is faster)
PHASES = [("direct fast", 10, 20, "direct"), ("relay fast", 40, 5, "relay")]
PHASE_SECONDS = int(os.environ.get("DIRECT_PROOF_PHASE_SECONDS", "40"))
CYCLES = int(os.environ.get("DIRECT_PROOF_CYCLES", "3"))
IDLE_SECONDS = int(os.environ.get("DIRECT_PROOF_IDLE_SECONDS", "30"))


def topology():
    """Four public members on one bridge, all inside this process's private namespaces."""
    run("mount", "-t", "tmpfs", "none", "/run")
    os.makedirs("/run/netns", exist_ok=True)
    for name in NAMES:
        run("ip", "netns", "add", name)
        ns(name, "ip", "link", "set", "lo", "up")
    ns("inet", "ip", "link", "add", "br0", "type", "bridge")
    ns("inet", "ip", "link", "set", "br0", "up")
    for name, address in ADDRESS.items():
        run("ip", "-n", "inet", "link", "add", f"p-{name}", "type", "veth", "peer", "name", "pub", "netns", name)
        ns("inet", "ip", "link", "set", f"p-{name}", "master", "br0", "up")
        ns(name, "ip", "addr", "add", f"{address}/24", "dev", "pub")
        ns(name, "ip", "link", "set", "pub", "up")


def shape(node, peer, direct_ms, relay_ms):
    """Delay `node`'s egress by destination: to `peer` by `direct_ms`, to the relays by `relay_ms`.

    Replaces the previous shaping in place, so a phase change is one `tc` run per node.
    """
    ns(node, "tc", "qdisc", "replace", "dev", "pub", "root", "handle", "1:", "prio", "bands", "3",
       "priomap", *(["2"] * 16))
    ns(node, "tc", "qdisc", "replace", "dev", "pub", "parent", "1:1", "handle", "10:", "netem",
       "delay", f"{direct_ms}ms")
    ns(node, "tc", "qdisc", "replace", "dev", "pub", "parent", "1:2", "handle", "20:", "netem",
       "delay", f"{relay_ms}ms")
    ns(node, "tc", "filter", "del", "dev", "pub", "parent", "1:", check=False)
    for address, flow in ((ADDRESS[peer], "1:1"), (ADDRESS["relay1"], "1:2"), (ADDRESS["relay2"], "1:2")):
        ns(node, "tc", "filter", "add", "dev", "pub", "protocol", "ip", "parent", "1:", "prio", "1",
           "u32", "match", "ip", "dst", f"{address}/32", "flowid", flow)


def switches(pid):
    """Voluntary context switches by thread id for one process.

    Threads come and go (the blocking pool retires idle ones), so callers diff only the thread
    ids present in both snapshots.
    """
    counts = {}
    for task in os.listdir(f"/proc/{pid}/task"):
        try:
            with open(f"/proc/{pid}/task/{task}/status", encoding="utf-8") as status:
                for line in status:
                    if line.startswith("voluntary_ctxt_switches:"):
                        counts[task] = int(line.split()[1])
        except FileNotFoundError:
            continue
    return counts


def switch_rate(before, after, seconds):
    """Voluntary context switches per second over threads that lived through the whole window."""
    return round(sum(after[t] - before[t] for t in before if t in after) / seconds, 2)


def state(fixture, peer):
    """One `direct_state` sample from a node."""
    return fixture.ask({"direct_state": {"host": HOSTS[peer]}}, "direct_state", timeout=10)


def where(sample):
    """Which path the sampled pair is on: "direct" or "relay"."""
    return "direct" if sample.get("active_relay") is None else "relay"


def idle_window(fixtures, seconds):
    """Voluntary context switches per second of each node process over an idle window, and the
    direct probes they sent in it."""
    start = {name: switches(f.cpu_pid) for name, f in fixtures.items()}
    sent0 = {name: state(f, "C" if name == "A" else "A").get("probes_sent") for name, f in fixtures.items()}
    time.sleep(seconds)
    out = {}
    for name, f in fixtures.items():
        other = "C" if name == "A" else "A"
        out[name] = {
            "voluntary_ctxt_switches_per_s": switch_rate(start[name], switches(f.cpu_pid), seconds),
            "direct_probes_sent": (state(f, other).get("probes_sent") or 0) - (sent0[name] or 0),
        }
    return out


def inner(binary, report_path=None):
    results = {"label": relay_proof.LABEL, "kernel": os.uname().release, "phase_seconds": PHASE_SECONDS}
    fixtures = []
    traffic = None
    try:
        topology()
        certs = subprocess.run([binary, "certs"], input=json.dumps({"hosts": [HOSTS["A"], HOSTS["C"]], "relays": RELAYS}),
                               capture_output=True, text=True, check=True)
        material = json.loads(certs.stdout)
        for index, name in enumerate(RELAYS):
            relay = Fixture(f"relay{index + 1}", binary, "relay", {
                "listen": RELAY_ADDRESSES[index], "cert": material["relays"][name]["cert"],
                "key": material["relays"][name]["key"], "ca": material["ca"]})
            relay.event("ready")
            fixtures.append(relay)
        relay_list = [{"address": a, "name": n} for a, n in zip(RELAY_ADDRESSES, RELAYS)]
        nodes, identity = {}, {}
        for node in "AC":
            fixture = Fixture(f"node{node}", binary, "node", {
                "host": HOSTS[node], "cert": material["hosts"][HOSTS[node]]["cert"],
                "key": material["hosts"][HOSTS[node]]["key"], "ca": material["ca"],
                "addresses": {"ipv4": MESH[node][0], "ipv6": MESH[node][1]}, "relays": relay_list})
            fixtures.append(fixture)
            identity[node] = fixture.event("identity")
            nodes[node] = fixture
        for fixture in nodes.values():
            for i in (0, 1):
                fixture.event("relay_up", relay=i)
        a, c = nodes["A"], nodes["C"]

        def peer(node, endpoint):
            return {"host": HOSTS[node], "key": identity[node]["public_key"], "previous_key": None,
                    "previous_active": False, "addresses": {"ipv4": MESH[node][0], "ipv6": MESH[node][1]},
                    "endpoint": endpoint}
        a.ask({"peers": [peer("C", f"{ADDRESS['nodeC']}:{identity['C']['port']}")]}, "peers")
        c.ask({"peers": [peer("A", f"{ADDRESS['nodeA']}:{identity['A']['port']}")]}, "peers")
        shape("nodeA", "nodeC", *PHASES[0][1:3])
        shape("nodeC", "nodeA", *PHASES[0][1:3])
        warm = relay_proof.ping("nodeA", MESH["C"][0], count=10)
        assert warm["loss_pct"] < 100.0, warm
        results["warm_ping"] = warm

        # Baseline idle window: nothing watched, nothing sent.
        fixtures_by_name = {"A": a, "C": c}
        before = {name: switches(f.cpu_pid) for name, f in fixtures_by_name.items()}
        time.sleep(IDLE_SECONDS)
        results["idle_before_watch"] = {
            name: {"voluntary_ctxt_switches_per_s": switch_rate(before[name], switches(f.cpu_pid), IDLE_SECONDS)}
            for name, f in fixtures_by_name.items()}

        a.ask({"watch": {"host": HOSTS["C"]}}, "watching", timeout=10)
        c.ask({"watch": {"host": HOSTS["A"]}}, "watching", timeout=10)
        # Traffic: one echo every 0.2 s, in the background, for the whole run.
        traffic = relay_proof.spawn_namespace_process(
            "nodeA", "ping", "-n", "-q", "-i", "0.2", MESH["C"][0],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)[0]

        phases = []
        for cycle in range(CYCLES):
            for name, direct_ms, relay_ms, faster in PHASES:
                shape("nodeA", "nodeC", direct_ms, relay_ms)
                shape("nodeC", "nodeA", direct_ms, relay_ms)
                begin = time.monotonic()
                samples = []
                while time.monotonic() - begin < PHASE_SECONDS:
                    row = {"t": round(time.monotonic() - begin, 1)}
                    for node, fixture in fixtures_by_name.items():
                        s = state(fixture, "C" if node == "A" else "A")
                        row[node] = where(s)
                        row[f"{node}_rtt_ms"] = None if s.get("rtt_us") is None else round(s["rtt_us"] / 1000, 1)
                        row[f"{node}_switches"] = s["switches"]
                    samples.append(row)
                    time.sleep(1.0)
                # Latency: first second at which BOTH ends are on the faster path for good.
                settled = None
                for index, row in enumerate(samples):
                    if all(r["A"] == faster and r["C"] == faster for r in samples[index:]):
                        settled = row["t"]
                        break
                # A phase that never settled counts every sample on the worse path as wrong.
                tail = samples[int(settled):] if settled is not None else samples
                wrong = sum(1 for r in tail for node in "AC" if r[node] != faster)
                phases.append({
                    "cycle": cycle, "phase": name, "faster": faster,
                    "decision_latency_s": settled,
                    "wrong_choice_samples_after_settling": wrong, "samples_after_settling": 2 * len(tail),
                    "switches_at_end": {n: samples[-1][f"{n}_switches"] for n in "AC"},
                    "rtt_ms_end": {n: samples[-1][f"{n}_rtt_ms"] for n in "AC"}})
        results["phases"] = phases
        latencies = [p["decision_latency_s"] for p in phases if p["decision_latency_s"] is not None]
        results["summary"] = {
            "phases": len(phases), "settled": len(latencies),
            "decision_latency_s": {"min": min(latencies, default=None), "median": statistics.median(latencies) if latencies else None,
                                    "max": max(latencies, default=None)},
            "wrong_choice_samples": sum(p["wrong_choice_samples_after_settling"] for p in phases),
            "samples_after_settling": sum(p["samples_after_settling"] for p in phases),
            "wrong_choice_rate_after_settling": round(
                sum(p["wrong_choice_samples_after_settling"] for p in phases)
                / max(1, sum(p["samples_after_settling"] for p in phases)), 4)}
        traffic.terminate()
        traffic.wait(timeout=5)
        traffic = None
        time.sleep(3)
        results["idle_after_probing"] = idle_window(fixtures_by_name, IDLE_SECONDS)
        ok = (results["summary"]["settled"] == len(phases)
              and results["summary"]["wrong_choice_samples"] == 0
              and all(w["direct_probes_sent"] == 0 for w in results["idle_after_probing"].values()))
        results["pass"] = ok
        return_code = 0 if ok else 1
    finally:
        if traffic is not None:
            traffic.kill()
        for fixture in reversed(fixtures):
            fixture.stop()
    print(json.dumps(results, indent=2), flush=True)
    if report_path:
        with open(report_path, "w", encoding="utf-8") as report:
            json.dump(results, report, indent=2)
    sys.exit(return_code)


def outer(binary, report_path=None):
    before = snapshot()
    command = ["unshare", "-Urnm", "--propagation", "private", sys.executable, os.path.abspath(__file__), "--inner"]
    if report_path:
        command.extend(["--report", report_path])
    command.append(binary)
    status = subprocess.run(command).returncode
    added = [m for m in snapshot()["modules"] if m not in before["modules"]]
    print(json.dumps({"modules_loaded_by_run": added, "still_loaded": unload(added)}), flush=True)
    after = snapshot()
    changed = {key: [x for x in after[key] if x not in before[key]] + [x for x in before[key] if x not in after[key]]
               for key in before}
    foreign = {"netns": [n for n in changed["netns"] if n.split()[0] not in relay_proof.NAMESPACES],
               "modules": [m for m in changed["modules"] if m not in relay_proof.OURS]}
    ours = {key: [x for x in lines if x not in foreign.get(key, [])] for key, lines in changed.items()}
    # Autoloaded kernel modules (bridge, llc, stp) stay loaded when this user cannot `sudo rmmod`;
    # they are reported but are not a configuration change, so only links, namespaces and sysctls
    # decide the exit status.
    configuration = {key: lines for key, lines in ours.items() if key != "modules"}
    print(json.dumps({"host_state_diff": ours, "configuration_unchanged": not any(configuration.values()),
                      "other_jobs_changed": foreign}), flush=True)
    if status or any(configuration.values()):
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inner", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--report", help="write the inner run's JSON report to this path")
    parser.add_argument("fixture", help="absolute path of the relay_fixture example")
    args = parser.parse_args()
    if not os.path.isabs(args.fixture):
        parser.error("fixture path must be absolute")
    (inner if args.inner else outer)(args.fixture, args.report)
