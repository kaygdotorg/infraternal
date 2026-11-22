#!/usr/bin/env python3
"""Relay choice by measured round trip: per-key echo, switches and idle cost (J1105, #201).

Run as root on the perf VM through `perf-run --root`:

    relay_rtt.py <bin-root> <out.jsonl> <case>...

`<bin-root>` holds one directory per build (for example `base/` and `head/`), each with
`relay_fixture` and `relay_echo` from `crates/plugins/mesh/examples`. A case is

    name:BUILDS:R1:R2:JITTER:KEYS:INTERVAL_MS:IDLE_S

- BUILDS: builds to run, `+`-separated, interleaved (`base+head`).
- R1, R2: the round trip in ms of every node<->relay leg of relay 1 and relay 2, so a
  pair's path through relay N costs about 2 x RN. Relay 1 is first in the shared list,
  the relay today's code always keeps.
- JITTER: normal jitter, in percent of each leg's one-way delay (0 for none).
- KEYS, INTERVAL_MS: keys node A sends, one at a time, this far apart; node B echoes.
- IDLE_S: after the keys, A stays silent this long and reports probe packets and its own
  context switches over that window.

Topology: four network namespaces this script creates (j1105a, j1105b, j1105r1, j1105r2)
and four veth pairs among them, one per node<->relay leg. netem is applied only to those
veths. The `finally` block (also run on SIGTERM) stops every helper process and deletes the
namespaces, which removes every veth and qdisc with them. Nothing outside the namespaces is
touched. Each run appends one summary line and the raw node lines to <out.jsonl>.
"""
import json
import os
import signal
import statistics
import subprocess
import sys
import time

NAMESPACES = ["j1105a", "j1105b", "j1105r1", "j1105r2"]
HOSTS = {"A": "0a000000-0000-4000-8000-0000000011a5", "B": "0b000000-0000-4000-8000-0000000011b5"}
RELAYS = ["relay-1.mesh.test", "relay-2.mesh.test"]
# (veth name, node namespace, node address, relay namespace, relay address, relay index)
LEGS = [
    ("a1", "j1105a", "10.105.1.1", "j1105r1", "10.105.1.2", 0),
    ("b1", "j1105b", "10.105.2.1", "j1105r1", "10.105.2.2", 0),
    ("a2", "j1105a", "10.105.3.1", "j1105r2", "10.105.3.2", 1),
    ("b2", "j1105b", "10.105.4.1", "j1105r2", "10.105.4.2", 1),
]
PROCESSES = []


def run(*args):
    subprocess.run(args, check=True)


def spawn(namespace, *args):
    """Start a helper in `namespace` with piped stdio and remember it for cleanup."""
    process = subprocess.Popen(["ip", "netns", "exec", namespace, *args], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    PROCESSES.append(process)
    return process


def line(process):
    text = process.stdout.readline()
    if not text:
        raise RuntimeError(f"helper ended: {process.args}: {process.stderr.read()[-2000:]}")
    return json.loads(text)


def topology():
    for namespace in NAMESPACES:
        if namespace in subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout:
            raise SystemExit(f"namespace {namespace} already exists; refusing")
    for namespace in NAMESPACES:
        run("ip", "netns", "add", namespace)
        run("ip", "-n", namespace, "link", "set", "lo", "up")
    for name, node_ns, node_ip, relay_ns, relay_ip, _ in LEGS:
        run("ip", "link", "add", f"{name}n", "netns", node_ns, "type", "veth", "peer", "name",
            f"{name}r", "netns", relay_ns)
        run("ip", "-n", node_ns, "addr", "add", f"{node_ip}/30", "dev", f"{name}n")
        run("ip", "-n", relay_ns, "addr", "add", f"{relay_ip}/30", "dev", f"{name}r")
        run("ip", "-n", node_ns, "link", "set", f"{name}n", "up")
        run("ip", "-n", relay_ns, "link", "set", f"{name}r", "up")


def shape(rtts, jitter):
    """Half of each leg's round trip on each end's egress, with optional normal jitter."""
    for name, node_ns, _, relay_ns, _, relay in LEGS:
        half = rtts[relay] / 2
        for namespace, device in ((node_ns, f"{name}n"), (relay_ns, f"{name}r")):
            command = ["ip", "netns", "exec", namespace, "tc", "qdisc", "replace", "dev", device,
                       "root", "netem", "delay", f"{half}ms"]
            if jitter:
                command += [f"{round(half * jitter / 100, 3)}ms", "distribution", "normal"]
            run(*command, "limit", "10000")


def certs(binary):
    process = subprocess.run([binary, "certs"], input=json.dumps(
        {"hosts": list(HOSTS.values()), "relays": RELAYS}), capture_output=True, text=True, check=True)
    return json.loads(process.stdout)


def percentile(values, share):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(share * len(ordered)))] if ordered else None


def one_run(root, build, case, run_number, out):
    fixture, echo = f"{root}/{build}/relay_fixture", f"{root}/{build}/relay_echo"
    material = certs(fixture)
    relays = []
    for index, namespace in enumerate(["j1105r1", "j1105r2"]):
        relay = spawn(namespace, fixture, "relay")
        relay.stdin.write(json.dumps({"listen": "0.0.0.0:3478", "cert": material["relays"][RELAYS[index]]["cert"],
                                      "key": material["relays"][RELAYS[index]]["key"], "ca": material["ca"]}) + "\n")
        relay.stdin.flush()
        assert line(relay)["event"] == "ready"
        relays.append(relay)

    def node(name, namespace, role):
        relay_list = [{"address": f"{relay_ip}:3478", "name": RELAYS[index]}
                      for _, node_ns, _, _, relay_ip, index in LEGS if node_ns == namespace]
        peer = HOSTS["B" if name == "A" else "A"]
        process = spawn(namespace, echo)
        process.stdin.write(json.dumps({
            "host": HOSTS[name], "peer": peer, "cert": material["hosts"][HOSTS[name]]["cert"],
            "key": material["hosts"][HOSTS[name]]["key"], "ca": material["ca"], "relays": relay_list,
            "role": role, "keys": case["keys"], "interval_ms": case["interval"], "idle_s": case["idle"]}) + "\n")
        process.stdin.flush()
        return process

    responder = node("B", "j1105b", "echo")
    # The echo end reports its relay connections first, then `ready`.
    while line(responder)["event"] != "ready":
        pass
    measurer = node("A", "j1105a", "measure")
    lines = []
    while True:
        text = measurer.stdout.readline()
        if not text:
            break
        lines.append(json.loads(text))
    measurer.wait()
    responder.stdin.close()
    responder_lines = [json.loads(text) for text in responder.stdout.read().splitlines()]
    responder.wait()
    for relay in relays:
        relay.stdin.close()
        relay.wait(timeout=10)
    keys = [entry for entry in lines if entry["event"] == "key"]
    rtts = [entry["rtt_us"] / 1000 for entry in keys]
    linked = next((entry["t_ms"] for entry in lines if entry["event"] == "linked"), 0)
    settled = [entry["rtt_us"] / 1000 for entry in keys if entry["t_ms"] - linked > 10_000]
    actives = [entry for entry in lines if entry["event"] == "active"]
    stats = next((entry for entry in lines if entry["event"] == "stats"), {})
    idle = next((entry for entry in lines if entry["event"] == "idle"), None)
    ranked_after_keys = (stats.get("counters") or {}).get("ranked") or {}
    ranked_after_idle = ((idle or {}).get("counters") or {}).get("ranked") or {}
    summary = {
        "kind": "summary", "case": case["name"], "build": build, "run": run_number,
        "r1_ms": case["rtts"][0], "r2_ms": case["rtts"][1], "jitter_pct": case["jitter"],
        "keys": len(keys), "lost": stats.get("lost"),
        "p50_ms": statistics.median(rtts) if rtts else None, "p99_ms": percentile(rtts, 0.99),
        "settled_p50_ms": statistics.median(settled) if settled else None,
        "settled_p99_ms": percentile(settled, 0.99),
        "first_relay": actives[0]["relay"] if actives else None,
        "final_relay": actives[-1]["relay"] if actives else None,
        "relay_changes": max(0, len(actives) - 1),
        "first_move_after_link_ms": round(actives[1]["t_ms"] - linked) if len(actives) > 1 else None,
        "switches": ranked_after_keys.get("switches"),
        "probes_sent_during_keys": ranked_after_keys.get("probes_sent"),
        "probes_sent_while_idle": (ranked_after_idle.get("probes_sent", 0) - ranked_after_keys.get("probes_sent", 0))
        if idle and ranked_after_idle else None,
        "idle_s": case["idle"], "idle_context_switches": idle and idle["context_switches"],
        "idle_data_sent": idle and idle["sent"],
        "rtt_ms_by_relay": ranked_after_keys.get("rtt_ms"),
    }
    print(json.dumps(summary), flush=True)
    with open(out, "a") as handle:
        handle.write(json.dumps(summary) + "\n")
        for entry in lines:
            handle.write(json.dumps({"kind": "measure", "case": case["name"], "build": build, "run": run_number, **entry}) + "\n")
        for entry in responder_lines:
            handle.write(json.dumps({"kind": "echo", "case": case["name"], "build": build, "run": run_number, **entry}) + "\n")


def parse(text):
    name, builds, r1, r2, jitter, keys, interval, idle = text.split(":")
    return {"name": name, "builds": builds.split("+"), "rtts": [float(r1), float(r2)], "jitter": float(jitter),
            "keys": int(keys), "interval": int(interval), "idle": int(idle)}


def cleanup(*_):
    for process in PROCESSES:
        if process.poll() is None:
            process.kill()
    for namespace in NAMESPACES:
        subprocess.run(["ip", "netns", "del", namespace], capture_output=True)


def main():
    root, out, *cases = sys.argv[1:]
    runs = int(os.environ.get("RUNS", "1"))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try:
        topology()
        for text in cases:
            case = parse(text)
            shape(case["rtts"], case["jitter"])
            for run_number in range(1, runs + 1):
                for build in case["builds"]:
                    one_run(root, build, case, run_number, out)
    finally:
        cleanup()
        left = subprocess.run(["ip", "netns", "list"], capture_output=True, text=True).stdout
        print(json.dumps({"kind": "cleanup", "namespaces_left": [n for n in NAMESPACES if n in left]}), flush=True)


if __name__ == "__main__":
    main()
