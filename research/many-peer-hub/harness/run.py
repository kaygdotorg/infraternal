#!/usr/bin/env python3
"""Many-peer hub measurement driver (#260, J1234). Run as root under `perf-run --root`.

Builds two network namespaces joined by a veth pair (10.220.0.0/24, no default route, nothing in
the host namespace), starts the hub (the production Node, as the ignored test
`node::many_peer_hub_bench::many_peer_hub`) in one and `peersim` in the other, walks one peer
count through the measurement steps below, and appends one CSV row per measurement.
Everything it creates is removed in a `finally`/signal handler.

usage: run.py --hub TESTBIN --sim PEERSIM --out DIR --peers N [--repeat-tag TAG]

CPU layout (the perf slice owns cpus 1-3): hub cpus 1,2; peer simulator and sink cpu 3.
"""
import argparse, csv, json, os, shlex, shutil, signal, subprocess, sys, tempfile, time

NS_HUB, NS_SIM = "hub1234", "sim1234"
HUB_CPUS, SIM_CPU = "1,2", "3"
TICK = os.sysconf("SC_CLK_TCK")


def sh(*args, check=True, **kw):
    return subprocess.run(args, check=check, **kw)


def cpu_s(pid):
    """utime+stime of a process, in seconds."""
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / TICK


def thread_cpu(pid):
    """{tid: (name, cpu seconds)} for every thread of `pid`."""
    out = {}
    for tid in os.listdir(f"/proc/{pid}/task"):
        try:
            with open(f"/proc/{pid}/task/{tid}/stat") as f:
                raw = f.read()
            name = raw[raw.index("(") + 1 : raw.rindex(")")]
            fields = raw.rsplit(")", 1)[1].split()
            out[tid] = (name, (int(fields[11]) + int(fields[12])) / TICK)
        except FileNotFoundError:
            pass
    return out


def switches(pid):
    """(voluntary, involuntary) context switches summed over every thread, and thread count."""
    vol = invol = threads = 0
    for tid in os.listdir(f"/proc/{pid}/task"):
        try:
            with open(f"/proc/{pid}/task/{tid}/status") as f:
                for line in f:
                    if line.startswith("voluntary_ctxt_switches"):
                        vol += int(line.split()[1])
                    elif line.startswith("nonvoluntary_ctxt_switches"):
                        invol += int(line.split()[1])
            threads += 1
        except FileNotFoundError:
            pass
    return vol, invol, threads


def thread_switches(pid):
    """{tid: (name, voluntary context switches)} for every thread of `pid`."""
    out = {}
    for tid in os.listdir(f"/proc/{pid}/task"):
        try:
            name = open(f"/proc/{pid}/task/{tid}/comm").read().strip()
            with open(f"/proc/{pid}/task/{tid}/status") as f:
                for line in f:
                    if line.startswith("voluntary_ctxt_switches"):
                        out[tid] = (name, int(line.split()[1]))
        except FileNotFoundError:
            pass
    return out


def mem(pid):
    """RSS, HWM and PSS in KiB, plus open fds."""
    out = {}
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith(("VmRSS", "VmHWM")):
                out[line.split(":")[0]] = int(line.split()[1])
    with open(f"/proc/{pid}/smaps_rollup") as f:
        for line in f:
            if line.startswith("Pss:"):
                out["Pss"] = int(line.split()[1])
    out["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
    return out


def snmp(pid):
    """Selected IP/UDP counters of the hub's own network namespace, read through /proc/<pid>/net."""
    want = {"Ip": ("InReceives", "InDelivers", "InDiscards", "InAddrErrors", "ForwDatagrams"),
            "Udp": ("InDatagrams", "NoPorts", "InErrors", "RcvbufErrors", "OutDatagrams")}
    out = {}
    with open(f"/proc/{pid}/net/snmp") as f:
        lines = [l.split() for l in f.read().splitlines()]
    for head, vals in zip(lines[::2], lines[1::2]):
        proto = head[0].rstrip(":")
        if proto in want:
            for k, v in zip(head[1:], vals[1:]):
                if k in want[proto]:
                    out[f"{proto}.{k}"] = int(v)
    return out


class Peer:
    """A child process with a command FIFO and a JSON-lines result file."""

    def __init__(self, argv, fifo, out, env=None, cwd=None, err=None):
        os.mkfifo(fifo)
        self.out = out
        open(out, "w").close()
        self.fifo_path = fifo
        self.err_path = err
        self.proc = subprocess.Popen(argv, env=env, cwd=cwd, stderr=open(err, "w") if err else None)
        self.fifo = os.open(fifo, os.O_WRONLY)  # blocks until the child opens it for reading
        self.seen = 0

    def cmd(self, text, timeout=300):
        os.write(self.fifo, (text + "\n").encode())
        end = time.time() + timeout
        while time.time() < end:
            with open(self.out) as f:
                content = f.read()
            # A result line counts only once it is complete; the child may still be writing it.
            lines = content.splitlines() if content.endswith("\n") else content.splitlines()[:-1]
            if len(lines) > self.seen:
                self.seen = len(lines)
                return json.loads(lines[-1])
            if self.proc.poll() is not None:
                tail = open(self.err_path).read()[-3000:] if self.err_path else ""
                raise RuntimeError(f"{self.proc.args[0]} exited with {self.proc.returncode}\n{tail}")
            time.sleep(0.05)
        raise TimeoutError(text)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hub", required=True)
    ap.add_argument("--sim", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--peers", type=int, required=True)
    ap.add_argument("--tag", default="r1")
    ap.add_argument("--idle", type=int, default=30, help="seconds per idle window")
    ap.add_argument("--load-secs", type=int, default=10)
    ap.add_argument("--mode", default="single", choices=["single", "spread", "known"],
                    help="peer source addresses: all behind one address, one /24 each, or one /24 each and told to the hub as endpoints")
    ap.add_argument("--hub-env", action="append", default=[], metavar="KEY=VALUE",
                    help="extra environment for the hub (for example GOTATUN_AQM=off); repeatable")
    ap.add_argument("--ks", default="1,10,100", help="concurrent sender counts")
    ap.add_argument("--perf", help="path to a perf binary; records call graphs of the hub per phase into --out")
    ap.add_argument("--mbit", type=int, default=400, help="fixed offered load for the CPU/Gbit rows")
    args = ap.parse_args()
    n = args.peers
    if args.mode != "single":
        args.tag = f"{args.tag}-{args.mode}"
    os.makedirs(args.out, exist_ok=True)
    work = tempfile.mkdtemp(prefix="j1234.", dir="/tmp")
    os.chmod(work, 0o700)
    csv_path = os.path.join(args.out, f"rows-{n}-{args.tag}.csv")
    rows = []
    children = []

    def row(step, metric, value, unit, note=""):
        rows.append([n, args.tag, step, metric, value, unit, note])
        print(f"[{n}/{args.tag}] {step:<14} {metric:<22} {value} {unit} {note}", flush=True)

    class Prof:
        """Context manager: `perf record` the hub process for the duration of one phase."""

        def __init__(self, name, pid):
            self.name, self.pid, self.proc = name, pid, None

        def __enter__(self):
            if args.perf:
                self.proc = subprocess.Popen([args.perf, "record", "-q", "-F", "999", "-g", "-p", str(self.pid), "-o",
                                              os.path.join(args.out, f"perf-{n}-{self.name}.data")],
                                             stderr=subprocess.DEVNULL)
                time.sleep(1)

        def __exit__(self, *exc):
            if self.proc:
                self.proc.send_signal(signal.SIGINT)
                self.proc.wait(timeout=120)

    def cleanup(*_):
        for c in children:
            try:
                c.proc.kill()
                c.proc.wait(timeout=5)
            except Exception:
                pass
        for ns in (NS_HUB, NS_SIM):
            sh("ip", "netns", "del", ns, check=False, stderr=subprocess.DEVNULL)
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["peers", "run", "step", "metric", "value", "unit", "note"])
            w.writerows(rows)
        shutil.rmtree(work, ignore_errors=True)

    signal.signal(signal.SIGTERM, lambda *_: (cleanup(), sys.exit(143)))
    try:
        for ns in (NS_HUB, NS_SIM):
            sh("ip", "netns", "del", ns, check=False, stderr=subprocess.DEVNULL)
            sh("ip", "netns", "add", ns)
            sh("ip", "-n", ns, "link", "set", "lo", "up")
        sh("ip", "link", "add", "j34hub", "type", "veth", "peer", "name", "j34sim")
        sh("ip", "link", "set", "j34hub", "netns", NS_HUB)
        sh("ip", "link", "set", "j34sim", "netns", NS_SIM)
        for ns, dev, addr in ((NS_HUB, "j34hub", "10.220.0.1/24"), (NS_SIM, "j34sim", "10.220.0.2/24")):
            sh("ip", "-n", ns, "addr", "add", addr, "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")
        # Peers sit in the simulator namespace only; verify no default route exists in either.
        for ns in (NS_HUB, NS_SIM):
            routes = subprocess.run(["ip", "-n", ns, "route", "show", "default"], capture_output=True, text=True).stdout
            assert not routes.strip(), f"default route in {ns}"

        # Key material: private keys stay in the sim namespace's working dir.
        keys, listing = f"{work}/keys.bin", f"{work}/peers-all.json"
        # n+1 keys: the last one is the "spare" peer that the add-one-peer step brings in.
        sh(*shlex.split(args.sim), "keys", str(n + 1), keys, listing, args.mode)
        with open(listing) as f:
            entries = json.load(f)
        if args.mode != "single":
            # One address per peer on the simulator side, and the hub reaches them through it.
            batch = "\n".join(f"addr add {e['underlay']}/32 dev j34sim" for e in entries)
            subprocess.run(["ip", "-n", NS_SIM, "-batch", "-"], input=batch, text=True, check=True)
            sh("ip", "-n", NS_HUB, "route", "add", "10.64.0.0/12", "via", "10.220.0.2")
        peers_json = f"{work}/peers-base.json"
        plus_json = f"{work}/peers-plus1.json"
        json.dump(entries[:n], open(peers_json, "w"))
        json.dump(entries, open(plus_json, "w"))

        hubdir = f"{work}/hub"
        os.mkdir(hubdir, 0o700)
        hub_env = dict(os.environ, HUB_DIR=hubdir, HUB_OUT=f"{work}/hub.out", HUB_FIFO=f"{work}/hub.fifo",
                       INFRATERNAL_CUTOFF_MEASURE="1", TMPDIR=work, RUST_BACKTRACE="1",
                       **dict(item.split("=", 1) for item in args.hub_env))
        hub = Peer(["ip", "netns", "exec", NS_HUB, "taskset", "-c", HUB_CPUS, *shlex.split(args.hub),
                    "--exact", "node::many_peer_hub_bench::many_peer_hub", "--ignored", "--nocapture"],
                   hub_env["HUB_FIFO"], hub_env["HUB_OUT"], env=hub_env, err=f"{work}/hub.err")
        children.append(hub)
        pid = hub.proc.pid
        hub.cmd("identity", 120)
        ident = json.load(open(f"{hubdir}/identity.json"))
        hubkey = bytes(ident["public_key"]).hex() if isinstance(ident["public_key"], list) else ident["public_key"]
        hub_port = ident["port"]
        time.sleep(2)

        sim_ref = []  # the simulator, once it exists; it keeps answering the hub during idle windows

        def idle_window(step, secs):
            """Wakeups per second (voluntary + involuntary) and CPU over a quiet window.

            Once peers are connected the simulator serves their sockets for the whole window
            (`hold`), as online peers would: a silent peer would make the hub retry its own
            handshakes and keepalives and the window would measure the retries, not idleness.
            """
            v0, i0, t0 = switches(pid)
            s0 = thread_switches(pid)
            c0 = cpu_s(pid)
            if sim_ref:
                sim_ref[0].cmd(f"hold {secs}", secs + 60)
            else:
                time.sleep(secs)
            v1, i1, t1 = switches(pid)
            s1 = thread_switches(pid)
            c1 = cpu_s(pid)
            per_thread = sorted(((s1[t][1] - s0.get(t, ("", 0))[1], s1[t][0]) for t in s1), reverse=True)[:3]
            row(step, "idle_busiest_threads", ";".join(f"{name}={d / secs:.1f}/s" for d, name in per_thread), "")
            row(step, "idle_voluntary_per_s", round((v1 - v0) / secs, 2), "1/s")
            row(step, "idle_involuntary_per_s", round((i1 - i0) / secs, 2), "1/s")
            row(step, "idle_cpu_pct", round((c1 - c0) / secs * 100, 3), "%")
            row(step, "threads", t1, "")

        def snapshot_mem(step):
            m = mem(pid)
            row(step, "rss", m["VmRSS"], "KiB")
            row(step, "hwm", m["VmHWM"], "KiB")
            row(step, "pss", m["Pss"], "KiB")
            row(step, "fds", m["fds"], "")
            return m

        base = snapshot_mem("baseline")
        idle_window("baseline", args.idle)

        # Snapshot apply: the complete list, from an empty peer set.
        with open(f"{work}/stderr-mark", "w"):
            pass
        with Prof("apply", pid):
            res = hub.cmd(f"apply {peers_json}", 900)
        row("apply_full", "apply_ms", round(res["apply_us"] / 1000, 2), "ms", f"{res['chunks']} chunks")
        row("apply_full", "apply_us_per_peer", round(res["apply_us"] / n, 1), "us")
        configured = snapshot_mem("configured")
        row("configured", "rss_per_peer", round((configured["VmRSS"] - base["VmRSS"]) * 1024 / n), "B")
        routes = subprocess.run(["ip", "-n", NS_HUB, "route", "show"], capture_output=True, text=True).stdout.count("\n")
        row("configured", "routes", routes, "")
        nft = subprocess.run(["ip", "netns", "exec", NS_HUB, "nft", "list", "ruleset"], capture_output=True, text=True)
        row("configured", "nft_lines", nft.stdout.count("\n"), "")
        with open(os.path.join(args.out, f"nft-{n}-{args.tag}.txt"), "w") as f:
            f.write(nft.stdout[:200000])
        link = subprocess.run(["ip", "-n", NS_HUB, "-o", "link", "show", "infraternal0"], capture_output=True, text=True).stdout
        mtu = int(link.split(" mtu ")[1].split()[0])
        payload = mtu - 28  # the largest inner UDP payload that fits one tunnel packet
        row("configured", "mesh_mtu", mtu, "B")
        idle_window("configured", args.idle)

        # The sink needs the hub's mesh address, which exists once the snapshot is applied.
        sink_out = open(f"{work}/sink.out", "w")
        sink = subprocess.Popen(["ip", "netns", "exec", NS_HUB, "taskset", "-c", SIM_CPU, *shlex.split(args.sim), "sink", "5601",
                                 "10.254.1.1"], stdout=sink_out)
        children.append(type("C", (), {"proc": sink})())
        sim_env = dict(os.environ)
        sim = Peer(["ip", "netns", "exec", NS_SIM, "taskset", "-c", SIM_CPU, "sh", "-c",
                    f"ulimit -n 65536; exec {args.sim} sim {keys} {work}/sim.fifo {work}/sim.out 10.220.0.1 {hub_port} {args.mode}"],
                   f"{work}/sim.fifo", f"{work}/sim.out", env=sim_env, err=f"{work}/sim.err")
        children.append(sim)
        sim.cmd(f"identity {hubkey}")
        sim_ref.append(sim)

        # Cold handshake storm: every peer initiates at once.
        c0 = cpu_s(pid)
        t0 = time.time()
        with Prof("coldstorm", pid):
            res = sim.cmd(f"connect {n} 0", 400)
        wall = time.time() - t0
        row("cold_storm", "established", res["established"], f"of {n}")
        row("cold_storm", "wall_ms", round(res["wall_ms"], 1), "ms")
        row("cold_storm", "hs_p50_ms", res["hs_p50_ms"], "ms")
        row("cold_storm", "hs_p99_ms", res["hs_p99_ms"], "ms")
        row("cold_storm", "hs_max_ms", res["hs_max_ms"], "ms")
        row("cold_storm", "peers_retried", res["peers_retried"], f"of {n}")
        row("cold_storm", "max_attempts", res["max_attempts"], "initiations")
        row("cold_storm", "hub_cpu_s", round(cpu_s(pid) - c0, 3), "s")
        row("cold_storm", "sim_cpu_s", round(res["sim_cpu_s"], 3), "s")
        time.sleep(10)  # let handshake confirmation and the packet pool settle before the idle window
        connected = snapshot_mem("connected")
        row("connected", "rss_per_peer", round((connected["VmRSS"] - base["VmRSS"]) * 1024 / n), "B")
        for window in ("connected", "connected_2"):
            idle_window(window, args.idle)

        # Idle with the keepalive every real peer sends (D81: 25 s), random phase.
        sim.cmd("keepalive 25")
        v0, i0, _ = switches(pid)
        c0 = cpu_s(pid)
        hold = 60
        sim.cmd(f"hold {hold}", 200)
        v1, i1, _ = switches(pid)
        row("keepalive25", "idle_voluntary_per_s", round((v1 - v0) / hold, 2), "1/s", f"{n} peers send 1 keepalive/25 s each = {n / 25:.1f} pkt/s")
        row("keepalive25", "idle_cpu_pct", round((cpu_s(pid) - c0) / hold * 100, 3), "%")
        sim.cmd("keepalive 0")

        # Concurrent senders. The sink reports bytes once a second; use first/last line of the window.
        def sink_last():
            time.sleep(1.2)
            with open(f"{work}/sink.out") as f:
                return json.loads(f.read().splitlines()[-1])

        for k in [k for k in map(int, args.ks.split(",")) if k <= n]:
            for label, rate in (("max", 0), ("1000mbit", 1000), (f"{args.mbit}mbit", args.mbit)):
                s0 = sink_last()
                c0, tc0 = cpu_s(pid), thread_cpu(pid)
                n0 = snmp(pid)
                with Prof(f"send{k}{label}", pid):
                    res = sim.cmd(f"send {k} {args.load_secs} {payload} {rate}", args.load_secs + 120)
                c1, tc1 = cpu_s(pid), thread_cpu(pid)
                s1 = sink_last()
                dt = s1["t"] - s0["t"]
                # Inner IP bytes delivered through the hub (payload + 28 bytes of IP/UDP headers).
                got_bytes = (s1["bytes"] - s0["bytes"]) + 28 * (s1["packets"] - s0["packets"])
                gbit = got_bytes * 8 / 1e9
                step = f"send_{k}_{label}"
                row(step, "offered_mbit", round(res["inner_mbit"], 1), "Mbit/s")
                row(step, "delivered_mbit", round(gbit * 1e3 / res["secs"], 1), "Mbit/s", f"window {dt:.1f}s")
                row(step, "loss_pct", round(100 * (1 - (s1["packets"] - s0["packets"]) / max(res["sent"], 1)), 2), "%")
                row(step, "hub_cpu_s", round(c1 - c0, 3), "s")
                row(step, "hub_cpu_s_per_gbit", round((c1 - c0) / gbit, 2) if gbit > 0 else "", "cpu-s/Gbit")
                hot = sorted(((tc1[t][1] - tc0.get(t, ("", 0))[1], tc1[t][0]) for t in tc1), reverse=True)[:4]
                row(step, "busiest_threads", ";".join(f"{name}={d:.2f}s" for d, name in hot), "")
                row(step, "sim_cpu_s", round(res["sim_cpu_s"], 2), "s")
                n1 = snmp(pid)
                row(step, "hub_ns_counters", ";".join(f"{k}={n1[k] - n0[k]}" for k in n1), "")
        # Every peer talks once, so each has its packet-filter flow cell (D394's per-peer memory).
        if n > 100:
            sim.cmd(f"send {n} 6 {payload} 100", 120)
            time.sleep(2)
            touched = snapshot_mem("all_touched")
            row("all_touched", "rss_per_peer", round((touched["VmRSS"] - base["VmRSS"]) * 1024 / n), "B")
        loaded = snapshot_mem("after_load")
        row("after_load", "rss_per_peer", round((loaded["VmRSS"] - base["VmRSS"]) * 1024 / n), "B")
        time.sleep(15)
        snapshot_mem("after_load_15s")
        for window in ("after_load", "after_load_2", "after_load_3"):
            idle_window(window, args.idle)

        # Handshake storm on live sessions: all peers send a fresh initiation at once.
        c0, tc0 = cpu_s(pid), thread_cpu(pid)
        with Prof("rekeystorm", pid):
            res = sim.cmd("storm 0", 400)
        row("rekey_storm", "established", res["established"], f"of {n}")
        row("rekey_storm", "wall_ms", round(res["wall_ms"], 1), "ms")
        row("rekey_storm", "hs_p50_ms", res["hs_p50_ms"], "ms")
        row("rekey_storm", "hs_p99_ms", res["hs_p99_ms"], "ms")
        row("rekey_storm", "hs_max_ms", res["hs_max_ms"], "ms")
        row("rekey_storm", "peers_retried", res["peers_retried"], f"of {n}")
        row("rekey_storm", "max_attempts", res["max_attempts"], "initiations")
        row("rekey_storm", "hub_cpu_s", round(cpu_s(pid) - c0, 3), "s")
        tc1 = thread_cpu(pid)
        hot = sorted(((tc1[t][1] - tc0.get(t, ("", 0))[1], tc1[t][0]) for t in tc1), reverse=True)[:4]
        row("rekey_storm", "busiest_threads", ";".join(f"{name}={d:.2f}s" for d, name in hot), "")

        # Snapshot apply, one-peer change, and a no-op re-apply.
        res = hub.cmd("change 1", 300)
        row("apply_one_change", "apply_ms", round(res["apply_us"] / 1000, 2), "ms")
        res = hub.cmd(f"apply {peers_json}", 900)
        row("apply_reapply", "apply_ms", round(res["apply_us"] / 1000, 2), "ms", "same list, one peer reverts")
        with Prof("applysame", pid):
            res = hub.cmd(f"apply {peers_json}", 900)
        row("apply_same", "apply_ms", round(res["apply_us"] / 1000, 2), "ms", "identical list")
        with Prof("addone", pid):
            res = hub.cmd(f"apply {plus_json}", 900)
        row("apply_add_one", "apply_ms", round(res["apply_us"] / 1000, 2), "ms", "one new peer joins")
        res = hub.cmd(f"apply {peers_json}", 900)
        row("apply_remove_one", "apply_ms", round(res["apply_us"] / 1000, 2), "ms", "that peer leaves")
        res = hub.cmd("counters", 120)
        row("counters", "counters_ms", round(res["counters_us"] / 1000, 2), "ms", f"{res['counted_peers']} peers")
        snapshot_mem("final")
        hub.cmd("exit", 120)
        hub.proc.wait(timeout=60)
        stages = [l for l in open(f"{work}/hub.err").read().splitlines() if l.startswith("CUTOFF_STAGE")]
        with open(os.path.join(args.out, f"stages-{n}-{args.tag}.log"), "w") as f:
            f.write("\n".join(stages) + "\n")
        sim.cmd("exit", 60)
        shutil.copy(f"{work}/hub.out", os.path.join(args.out, f"hub-{n}-{args.tag}.jsonl"))
        shutil.copy(f"{work}/sim.out", os.path.join(args.out, f"sim-{n}-{args.tag}.jsonl"))
        shutil.copy(f"{work}/hub.err", os.path.join(args.out, f"hub-stderr-{n}-{args.tag}.log"))
        shutil.copy(f"{work}/sink.out", os.path.join(args.out, f"sink-{n}-{args.tag}.jsonl"))
    finally:
        cleanup()


if __name__ == "__main__":
    main()
