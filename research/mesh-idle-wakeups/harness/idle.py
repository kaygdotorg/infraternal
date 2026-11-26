#!/usr/bin/env python3
"""Idle-wakeup timeline of one mesh hub (#260, J1253). Run as root.

Uses J1234's hub test binary and peer simulator (`../../many-peer-hub/harness`) in two network
namespaces joined by a veth (no default route, nothing in the host namespace), then walks one
scenario and prints one JSON line per window: voluntary context switches per second for every
hub thread, CPU, UDP datagrams in and out of the hub's namespace and, with `--trace`, how many
of each engine timer event fired. Everything it creates is removed on exit.

Scenarios (t = 0 is the end of the snapshot apply for `offline`, of the cold storm otherwise):

- `offline`: N configured peers with endpoints that never answer (their packets are dropped
  silently, like a host that is switched off);
- `connected`: N peers dial in, then stay silent but keep answering (J1234's passive peers);
- `keepalive`: as `connected`, and every peer sends an empty keepalive every 25 s;
- `afterload`: as `connected`, then every peer sends data to a sink on the hub for 6 s, and t = 0
  is the end of that traffic (J1234's `after_load` windows);
- `realistic`: N peers dial in and run their own WireGuard timers with a 25 s persistent
  keepalive, as real clients do.

usage: idle.py --hub TESTBIN --sim PEERSIM --out DIR --peers N --scenario S [--secs 300]
       [--window 10] [--candidates K] [--trace] [--perf PERF --perf-at 40,120]
       [--hub-cpus 1,2 --sim-cpu 3]
"""
import argparse, json, os, shlex, shutil, signal, subprocess, sys, tempfile, time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../many-peer-hub/harness"))
from run import Peer, cpu_s, snmp, thread_switches  # noqa: E402

NS_HUB, NS_SIM = "hub1253", "sim1253"
VETH_HUB, VETH_SIM = "j53hub", "j53sim"


def sh(*args, check=True, **kw):
    """Run one command."""
    return subprocess.run(args, check=check, **kw)


def window_stats(pid, before, after, seconds):
    """Per-thread-name voluntary switch rates between two `thread_switches` samples."""
    by_name = {}
    for tid, (name, count) in after.items():
        delta = count - before.get(tid, ("", 0))[1]
        by_name[name] = by_name.get(name, 0) + delta
    return {name: round(delta / seconds, 2) for name, delta in sorted(by_name.items()) if delta}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hub", required=True)
    ap.add_argument("--sim", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--peers", type=int, required=True)
    ap.add_argument("--scenario", required=True, choices=["offline", "connected", "keepalive", "realistic", "afterload"])
    ap.add_argument("--secs", type=int, default=300)
    ap.add_argument("--window", type=int, default=10)
    ap.add_argument("--candidates", type=int, default=0, help="further dead addresses per offline peer")
    ap.add_argument("--trace", action="store_true")
    ap.add_argument("--tag", default="r1")
    ap.add_argument("--perf", help="perf binary; records sched_waking stacks of the engine threads")
    ap.add_argument("--perf-at", default="", help="comma-separated window start times to record")
    ap.add_argument("--hub-cpus", default="1,2")
    ap.add_argument("--sim-cpu", default="3")
    args = ap.parse_args()
    n = args.peers
    os.makedirs(args.out, exist_ok=True)
    work = tempfile.mkdtemp(prefix="j1253.", dir="/tmp")
    os.chmod(work, 0o700)
    name = f"{args.scenario}-{n}-{args.tag}"
    out = open(os.path.join(args.out, f"windows-{name}.jsonl"), "w")
    children = []

    def emit(record):
        line = json.dumps(record)
        out.write(line + "\n")
        out.flush()
        print(line, flush=True)

    def cleanup(*_):
        for child in children:
            try:
                child.proc.kill()
                child.proc.wait(timeout=5)
            except Exception:
                pass
        for ns in (NS_HUB, NS_SIM):
            sh("ip", "netns", "del", ns, check=False, stderr=subprocess.DEVNULL)
        shutil.rmtree(work, ignore_errors=True)

    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, lambda *_: (cleanup(), sys.exit(143)))
    try:
        for ns in (NS_HUB, NS_SIM):
            sh("ip", "netns", "del", ns, check=False, stderr=subprocess.DEVNULL)
            sh("ip", "netns", "add", ns)
            sh("ip", "-n", ns, "link", "set", "lo", "up")
        sh("ip", "link", "add", VETH_HUB, "type", "veth", "peer", "name", VETH_SIM)
        sh("ip", "link", "set", VETH_HUB, "netns", NS_HUB)
        sh("ip", "link", "set", VETH_SIM, "netns", NS_SIM)
        for ns, dev, addr in ((NS_HUB, VETH_HUB, "10.220.0.1/24"), (NS_SIM, VETH_SIM, "10.220.0.2/24")):
            sh("ip", "-n", ns, "addr", "add", addr, "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")
        for ns in (NS_HUB, NS_SIM):
            routes = subprocess.run(["ip", "-n", ns, "route", "show", "default"], capture_output=True, text=True).stdout
            assert not routes.strip(), f"default route in {ns}"

        offline = args.scenario == "offline"
        mode = "known" if offline else "spread"
        keys, listing = f"{work}/keys.bin", f"{work}/peers-all.json"
        sh(*shlex.split(args.sim), "keys", str(n), keys, listing, mode)
        with open(listing) as f:
            entries = json.load(f)[:n]
        sh("ip", "-n", NS_HUB, "route", "add", "10.64.0.0/12", "via", "10.220.0.2")
        if offline:
            # No address on the simulator side: the hub's packets arrive there and are dropped.
            for entry in entries:
                host = entry["endpoint"].rsplit(":", 1)[0]
                entry["candidates"] = [f"{host}:{51821 + i}" for i in range(args.candidates)]
        else:
            batch = "\n".join(f"addr add {e['underlay']}/32 dev {VETH_SIM}" for e in entries)
            subprocess.run(["ip", "-n", NS_SIM, "-batch", "-"], input=batch, text=True, check=True)
        peers_json = f"{work}/peers.json"
        with open(peers_json, "w") as f:
            json.dump(entries, f)

        hubdir = f"{work}/hub"
        os.mkdir(hubdir, 0o700)
        hub_env = dict(os.environ, HUB_DIR=hubdir, HUB_OUT=f"{work}/hub.out", HUB_FIFO=f"{work}/hub.fifo",
                       TMPDIR=work, RUST_BACKTRACE="1")
        if args.trace:
            hub_env["HUB_TRACE"] = "1"
        hub = Peer(["ip", "netns", "exec", NS_HUB, "taskset", "-c", args.hub_cpus, *shlex.split(args.hub),
                    "--exact", "node::many_peer_hub_bench::many_peer_hub", "--ignored", "--nocapture"],
                   hub_env["HUB_FIFO"], hub_env["HUB_OUT"], env=hub_env, err=f"{work}/hub.err")
        children.append(hub)
        pid = hub.proc.pid
        hub.cmd("identity", 120)
        ident = json.load(open(f"{hubdir}/identity.json"))
        hubkey = bytes(ident["public_key"]).hex() if isinstance(ident["public_key"], list) else ident["public_key"]
        time.sleep(2)
        res = hub.cmd(f"apply {peers_json}", 900)
        emit({"step": "applied", "peers": n, "scenario": args.scenario, "apply_ms": res["apply_us"] / 1000})

        sim = None
        if not offline:
            sim = Peer(["ip", "netns", "exec", NS_SIM, "taskset", "-c", args.sim_cpu, "sh", "-c",
                        f"ulimit -n 65536; exec {args.sim} sim {keys} {work}/sim.fifo {work}/sim.out 10.220.0.1 {ident['port']} {mode}"],
                       f"{work}/sim.fifo", f"{work}/sim.out", err=f"{work}/sim.err")
            children.append(sim)
            sim.cmd(f"identity {hubkey}")
            if args.scenario == "realistic":
                sim.cmd("realistic 25")
            res = sim.cmd(f"connect {n} 0", 400)
            emit({"step": "connected", "established": res["established"], "wall_ms": res["wall_ms"]})
            if args.scenario == "keepalive":
                sim.cmd("keepalive 25")
            if args.scenario == "afterload":
                sink = subprocess.Popen(["ip", "netns", "exec", NS_HUB, "taskset", "-c", args.sim_cpu,
                                         *shlex.split(args.sim), "sink", "5601", "10.254.1.1"],
                                        stdout=subprocess.DEVNULL)
                children.append(type("Child", (), {"proc": sink})())
                time.sleep(10)
                res = sim.cmd(f"send {n} 6 1252 100", 120)
                emit({"step": "sent", "datagrams": res["sent"]})
        if args.trace:
            emit({"step": "trace_until_start", "events": hub.cmd("trace")["events"]})

        perf_at = {int(t) for t in args.perf_at.split(",") if t}
        start = time.monotonic()
        t = 0
        while t < args.secs:
            recorder = None
            if args.perf and t in perf_at:
                data = os.path.join(args.out, f"perf-{name}-t{t}.data")
                # Filter on the hub's own thread ids: a host may run a real agent whose threads
                # carry the same names.
                only = " || ".join(f"pid=={tid}" for tid in os.listdir(f"/proc/{pid}/task"))
                recorder = subprocess.Popen(
                    [args.perf, "record", "-q", "-a", "-e", "sched:sched_waking",
                     "--filter", only, "--call-graph", "fp", "-o", data,
                     "--", "sleep", str(args.window)], stderr=subprocess.DEVNULL)
            s0, c0, n0, t0 = thread_switches(pid), cpu_s(pid), snmp(pid), time.monotonic()
            if sim:
                sim.cmd(f"hold {args.window}", args.window + 60)
            else:
                time.sleep(args.window)
            s1, c1, n1, t1 = thread_switches(pid), cpu_s(pid), snmp(pid), time.monotonic()
            took = t1 - t0
            threads = window_stats(pid, s0, s1, took)
            record = {"step": "window", "t": t, "at_s": round(t0 - start, 1), "secs": round(took, 1),
                      "wakeups_per_s": round(sum(threads.values()), 2), "threads": threads,
                      "cpu_pct": round((c1 - c0) / took * 100, 3),
                      "udp_out": n1["Udp.OutDatagrams"] - n0["Udp.OutDatagrams"],
                      "udp_in": n1["Udp.InDatagrams"] - n0["Udp.InDatagrams"]}
            if args.trace:
                record["events"] = hub.cmd("trace")["events"]
            emit(record)
            if recorder:
                recorder.wait(timeout=120)
            t += args.window
        hub.cmd("exit", 120)
        hub.proc.wait(timeout=60)
        if sim:
            sim.cmd("exit", 60)
        shutil.copy(f"{work}/hub.err", os.path.join(args.out, f"hub-stderr-{name}.txt"))
    finally:
        cleanup()


if __name__ == "__main__":
    main()
