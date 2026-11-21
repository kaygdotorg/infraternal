#!/usr/bin/env python3
"""Relay choice on the real mesh: relays and pair ends on the build VMs over NetBird (J1105, #201).

Run from the control host; it only starts processes over `netbird ssh` and reads their output:

    real_mesh.py <out.jsonl> <case>...

A case is `name:BUILDS:A_HOST:B_HOST:RELAY_HOSTS:KEYS:INTERVAL_MS`, with BUILDS `+`-separated
(`base+head`), and RELAY_HOSTS `,`-separated in list order (the first is today's choice).
Host names are keys of HOSTS below. Each host has the static example binaries under
`~/j1105-bin/<build>/<arch>/`. Relays always run the head relay: the relay itself did not change.

A disposable CA and leaves come from `relay_fixture certs` and travel only through the ssh
pipes; nothing with a key is written to disk. Every remote process is a plain user process
on a high UDP port; nothing on any host changes, and closing stdin stops each one.
"""
import json
import statistics
import subprocess
import sys
import time

HOSTS = {
    "compute01": ("claude@infraternal-dev-01-compute01.vpn.kayg.org", "10.69.69.218", "x86_64"),
    "dev02": ("claude@infraternal-dev-02-std.vpn.kayg.org", "10.69.69.117", "aarch64"),
}
PORT = 34781
IDS = {"A": "0a000000-0000-4000-8000-0000000011a6", "B": "0b000000-0000-4000-8000-0000000011b6"}
PROCESSES = []


def remote(host, command):
    target, _, _ = HOSTS[host]
    process = subprocess.Popen(["netbird", "ssh", target, command], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    PROCESSES.append(process)
    return process


def binary(host, build, name):
    return f"~/j1105-bin/{build}/{HOSTS[host][2]}/{name}"


def ready(process, what):
    """The process's `ready` line; earlier lines (relay connections coming up) are skipped."""
    while True:
        text = process.stdout.readline()
        if not text:
            raise RuntimeError(f"{what} ended: {process.stderr.read()[-2000:]}")
        line = json.loads(text)
        if line.get("event") == "ready":
            return line


def percentile(values, share):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(share * len(ordered)))] if ordered else None


def main():
    out, *cases = sys.argv[1:]
    certs = subprocess.run(["netbird", "ssh", HOSTS["compute01"][0], binary("compute01", "head", "relay_fixture") + " certs"],
                           input=json.dumps({"hosts": list(IDS.values()), "relays": [f"relay-{h}.mesh.test" for h in HOSTS]}),
                           capture_output=True, text=True, check=True)
    material = json.loads(certs.stdout)
    try:
        for text in cases:
            name, builds, a_host, b_host, relay_hosts, keys, interval = text.split(":")
            relay_hosts = relay_hosts.split(",")
            relays = []
            for host in relay_hosts:
                relay = remote(host, binary(host, "head", "relay_fixture") + " relay")
                leaf = material["relays"][f"relay-{host}.mesh.test"]
                relay.stdin.write(json.dumps({"listen": f"0.0.0.0:{PORT}", "cert": leaf["cert"], "key": leaf["key"],
                                              "ca": material["ca"]}) + "\n")
                relay.stdin.flush()
                assert ready(relay, f"relay on {host}")["event"] == "ready"
                relays.append(relay)
            relay_list = [{"address": f"{HOSTS[h][1]}:{PORT}", "name": f"relay-{h}.mesh.test"} for h in relay_hosts]
            for run_number in (1, 2, 3):
                for build in builds.split("+"):
                    def node(role, host, me, peer):
                        process = remote(host, binary(host, build, "relay_echo"))
                        leaf = material["hosts"][IDS[me]]
                        process.stdin.write(json.dumps({
                            "host": IDS[me], "peer": IDS[peer], "cert": leaf["cert"], "key": leaf["key"],
                            "ca": material["ca"], "relays": relay_list, "role": role, "keys": int(keys),
                            "interval_ms": int(interval), "idle_s": 0}) + "\n")
                        process.stdin.flush()
                        return process
                    responder = node("echo", b_host, "B", "A")
                    assert ready(responder, "echo")["event"] == "ready"
                    measurer = node("measure", a_host, "A", "B")
                    lines = [json.loads(line) for line in measurer.stdout]
                    measurer.wait()
                    responder.stdin.close()
                    responder.wait(timeout=30)
                    keys_seen = [entry for entry in lines if entry["event"] == "key"]
                    rtts = [entry["rtt_us"] / 1000 for entry in keys_seen]
                    linked = next((entry["t_ms"] for entry in lines if entry["event"] == "linked"), 0)
                    settled = [entry["rtt_us"] / 1000 for entry in keys_seen if entry["t_ms"] - linked > 10_000]
                    actives = [entry for entry in lines if entry["event"] == "active"]
                    stats = next((entry for entry in lines if entry["event"] == "stats"), {})
                    ranked = (stats.get("counters") or {}).get("ranked") or {}
                    summary = {
                        "kind": "summary", "case": name, "build": build, "run": run_number, "a": a_host, "b": b_host,
                        "relays": relay_hosts, "keys": len(keys_seen), "lost": stats.get("lost"),
                        "p50_ms": statistics.median(rtts) if rtts else None, "p99_ms": percentile(rtts, 0.99),
                        "settled_p50_ms": statistics.median(settled) if settled else None,
                        "settled_p99_ms": percentile(settled, 0.99),
                        "first_relay": actives[0]["relay"] if actives else None,
                        "final_relay": actives[-1]["relay"] if actives else None,
                        "relay_changes": max(0, len(actives) - 1),
                        "first_move_after_link_ms": round(actives[1]["t_ms"] - linked) if len(actives) > 1 else None,
                        "switches": ranked.get("switches"), "probes_sent": ranked.get("probes_sent"),
                        "rtt_ms_by_relay": ranked.get("rtt_ms"),
                    }
                    print(json.dumps(summary), flush=True)
                    with open(out, "a") as handle:
                        handle.write(json.dumps(summary) + "\n")
                        for entry in lines:
                            handle.write(json.dumps({"kind": "measure", "case": name, "build": build,
                                                     "run": run_number, **entry}) + "\n")
            for relay in relays:
                relay.stdin.close()
                relay.wait(timeout=30)
    finally:
        for process in PROCESSES:
            if process.poll() is None:
                process.kill()


if __name__ == "__main__":
    main()
