#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Control-host driver of the mixed flood-plus-TCP measurement (#260, J1249). Speaks ssh only.

    drive.py --out DIR --bin BINDIR --plan FILE [--window 20] [--tag NAME]

Takes every perf and build lock on the three perf VMs (`research/fair-bench/kit/lock.sh`), stages
the agent and binaries, and runs the plan's cells in order, writing one `DIR/<n>-<cell>.json` per
cell with every raw counter. Locks and namespaces are released on every way out.

The plan is a text file with one cell per line, `LOAD:MODE:SCENARIO:REP` (LOAD is the flood's
payload rate in Gbit/s), ending with the line `END`. Lines may be appended while the hold runs, so a
calibration cell can decide the load of the cells after it; a hold without new lines for 20 minutes
ends by itself.

Modes (the engine's environment): `default` (the shipped AQM), `off`, `cap<N>` (the scratch
build's signal-count cap). Scenarios: `tcp` (10 bulk TCP peers and one idle peer, all probed),
`mix90`/`mix10` (the same plus an open-loop UDP flood from 90 or 10 other peers at --load) and
`flood90` (the flood with only the idle peer's probe).

Freeze a copy before running it: do not edit a driver while it runs.
"""
import argparse
import json
import os
import pathlib
import select
import signal
import subprocess
import sys
import tarfile
import threading
import time

HOSTS = {
    # role: (ssh target, namespace address). Locks are taken in this order (hub VM first).
    "hub": ("root@infraternal-perf-01-backup01.vpn.kayg.org", "10.70.3.231"),
    "tcp": ("root@calternal-perf-01-backup01.vpn.kayg.org", "10.70.3.232"),
    "flood": ("root@calternal-perf-02-backup01.vpn.kayg.org", "10.70.3.233"),
}
REMOTE = "/root/j1249"
SSH = ["ssh", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=15", "-o", "ConnectTimeout=20"]
#: The hub's CPUs: eth0's single queue interrupts CPU 1 there, so the engine has CPU 2 to itself
#: and the sinks live on 3-4 (TCP) and 5 (UDP).
ENGINE_CPUS, SINK_CPUS, UDP_CPUS = "2", "3,4", "5"
FLOOD_CPUS = ["1", "2"]
#: Flooding processes as [peers, id base]: 90 peers over two processes.
SIMS = [[45, 0], [45, 45]]
TCP_PEERS = 11  # 0-9 bulk and probed; 10 only probed (an idle, interactive peer)
PAYLOAD = 1320  # inner UDP payload bytes of a flood datagram (1,348 B inner IP packet)
PROBE_MS = 10


def log(*words):
    """A timestamped progress line."""
    print(f"[{time.strftime('%H:%M:%S', time.gmtime())}Z]", *words, flush=True)


def ssh(host, command, **kw):
    """Run one command on a VM."""
    return subprocess.run([*SSH, host, command], check=True, capture_output=True, **kw)


class Node:
    """One VM's agent (`node.py`) held open over ssh; one request at a time."""

    def __init__(self, role):
        """Start the agent for `role`."""
        self.role = role
        self.process = subprocess.Popen([*SSH, HOSTS[role][0], f"python3 -I {REMOTE}/node.py {role}"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        self.pending = b""

    def call(self, cmd, timeout=180, **arguments):
        """Send one request and return its result; raise on a remote failure or silence."""
        self.process.stdin.write((json.dumps({"cmd": cmd, **arguments}) + "\n").encode())
        deadline = time.time() + timeout
        while True:
            while b"\n" in self.pending:
                line, self.pending = self.pending.split(b"\n", 1)
                if line.startswith(b"J "):
                    reply = json.loads(line[2:])
                    if not reply["ok"]:
                        raise RuntimeError(f"{self.role} {cmd}: {reply['error']}")
                    return reply["result"]
            ready, _, _ = select.select([self.process.stdout], [], [], max(0, deadline - time.time()))
            if not ready:
                raise RuntimeError(f"{self.role} {cmd}: no answer in {timeout} s")
            chunk = os.read(self.process.stdout.fileno(), 1 << 20)
            if not chunk:
                raise RuntimeError(f"{self.role} {cmd}: agent connection closed")
            self.pending += chunk

    def close(self):
        """Close stdin, which makes the agent tear its namespace down, and wait for it."""
        try:
            self.process.stdin.close()
            self.process.wait(timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            self.process.kill()


def parallel(calls):
    """Run `{name: thunk}` at once; return their results or raise the first failure."""
    results, failures = {}, []

    def run(name, thunk):
        """Keep one thunk's result or failure."""
        try:
            results[name] = thunk()
        except Exception as error:  # reported after all have finished
            failures.append(error)

    threads = [threading.Thread(target=run, args=item) for item in calls.items()]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if failures:
        raise failures[0]
    return results


def stage(kit, bindir):
    """Copy the agent, the lock script and the binaries to each VM (mode 0700, as root)."""
    files = [(kit / "node.py", "node.py"), (kit / "tcpload.py", "tcpload.py"),
             (kit.parents[2] / "fair-bench/kit/lock.sh", "lock.sh")]
    files += [(bindir / "gotatun-j1249", "bin/gotatun"), (bindir / "peersim", "bin/peersim"),
              (bindir / "wg", "bin/wg")]
    for role, (host, _) in HOSTS.items():
        pipe = subprocess.Popen([*SSH, host, f"umask 077; mkdir -p {REMOTE}/bin && chmod 700 {REMOTE} {REMOTE}/bin "
                                 f"&& tar -C {REMOTE} -xf - --no-same-owner && chmod 700 {REMOTE}/lock.sh {REMOTE}/bin/*"],
                                stdin=subprocess.PIPE)
        with tarfile.open(fileobj=pipe.stdin, mode="w|") as archive:
            for source, name in files:
                archive.add(source, arcname=name)
        pipe.stdin.close()
        if pipe.wait():
            raise RuntimeError(f"staging to {role} failed")


def take_locks(tag):
    """Take every perf and build lock, VM by VM (may wait a long time for other jobs)."""
    for role, (host, _) in HOSTS.items():
        log(f"waiting for the locks on {role}")
        command = f"echo $$ > {REMOTE}/take.pid; FB_JOB=j1249 exec {REMOTE}/lock.sh take {tag}"
        while True:
            done = subprocess.run([*SSH, host, command], capture_output=True)
            if not done.returncode:
                break
            message = done.stderr.decode().strip()
            # The lock script gives up after an hour of another job's marker: queue again.
            if "other hold still present" not in message:
                raise RuntimeError(f"locks on {role}: {message}")
            log(role, message)
        log(role, done.stdout.decode().strip())


def planned(plan, nodes):
    """The plan's cells as they appear, keeping the agents alive while waiting for more."""
    taken, waiting_since = 0, time.time()
    while time.time() - waiting_since < 1200:
        lines = [line.strip() for line in plan.read_text().split("\n")[:-1] if line.strip()]
        if taken < len(lines):
            if lines[taken] == "END":
                return
            load, mode, scenario, rep = lines[taken].split(":")
            taken += 1
            yield float(load), mode, scenario, int(rep)
            waiting_since = time.time()
            continue
        for node in nodes.values():
            node.call("info")
        # sleep: wait for the next plan line.
        time.sleep(10)
    log("no new plan line for 20 minutes, ending the hold")


def release_locks():
    """Release (or stop waiting for) the locks on every VM."""
    for role, (host, _) in HOSTS.items():
        command = (f"if [ -s {REMOTE}/take.pid ]; then p=$(cat {REMOTE}/take.pid); "
                   f"grep -qa lock.sh /proc/$p/cmdline 2>/dev/null && kill $p; rm -f {REMOTE}/take.pid; fi; "
                   f"FB_JOB=j1249 {REMOTE}/lock.sh release")
        result = subprocess.run([*SSH, host, command], capture_output=True)
        log(role, result.stdout.decode().strip() or result.stderr.decode().strip())


def engine_env(mode):
    """The engine's environment for a mode name."""
    if mode == "default":
        return {}
    if mode == "off":
        return {"GOTATUN_AQM": "off"}
    if mode.startswith("cap"):
        return {"GOTATUN_AQM_COUNT_CAP": str(int(mode[3:]))}
    raise SystemExit(f"unknown mode {mode}")


def run_cell(nodes, keys, mode, scenario, load, window):
    """One measurement: fresh engine and sessions, the load, counters over the window."""
    hub, tcp, flood = nodes["hub"], nodes["tcp"], nodes["flood"]
    senders = {"tcp": None, "mix90": [45, 45], "mix10": [5, 5], "flood90": [45, 45]}[scenario]
    bulk = list(range(10)) if scenario != "flood90" else []
    probes = list(range(TCP_PEERS)) if scenario != "flood90" else [10]
    cell = {"mode": mode, "scenario": scenario, "load_gbit": load if senders else 0, "window_s": window,
            "payload": PAYLOAD, "probe_ms": PROBE_MS}
    cell["hub_start"] = hub.call("hub_start", env=engine_env(mode), peers=keys["tcp"] + keys["flood"],
                                 tcp_ip=HOSTS["tcp"][1], flood_ip=HOSTS["flood"][1], engine_cpus=ENGINE_CPUS,
                                 sink_cpus=SINK_CPUS, udp_cpus=UDP_CPUS)
    try:
        cell["tcp_up"] = tcp.call("tcp_up", hub_public=keys["hub"], hub_ip=HOSTS["hub"][1])
        if cell["tcp_up"]["unreachable"]:
            raise RuntimeError(f"TCP peers unreachable: {cell['tcp_up']}")
        if senders:
            cell["sim_start"] = flood.call("sim_start", hub_public=keys["hub"], hub_ip=HOSTS["hub"][1],
                                           cpus=FLOOD_CPUS)
            if any(answer["established"] != answer["peers"] for answer in cell["sim_start"]["connect"]):
                raise RuntimeError(f"flood sessions missing: {cell['sim_start']}")
        # TCP starts at once and has 4 s alone; the flood starts at t0; the window opens 3 s later.
        t0 = time.time() + 5
        start = t0 + 3
        stop_at = start + window
        until = stop_at + 1
        calls = {
            "hub": lambda: hub.call("hub_sample", start=start, stop_at=stop_at),
            "tcp": lambda: tcp.call("tcp_load", bulk_peers=bulk, probe_peers=probes, start=start,
                                    stop_at=stop_at, until=until, interval_ms=PROBE_MS),
        }
        if senders:
            each = load * 1000 / 2 * (PAYLOAD + 60) / PAYLOAD  # peersim paces WireGuard bytes
            calls["flood"] = lambda: flood.call("sim_send", start=t0, secs=until - t0, senders=senders,
                                                payload=PAYLOAD, mbit=[each, each])
        cell.update(times={"t0": t0, "start": start, "stop": stop_at}, results=parallel(calls))
    finally:
        flood.call("sim_stop")
        cell["hub_stop"] = hub.call("hub_stop")
    return cell


def main():
    """Lock, set up, run the cells, tear down."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--bin", required=True, type=pathlib.Path)
    ap.add_argument("--plan", required=True, type=pathlib.Path)
    ap.add_argument("--window", type=int, default=20)
    ap.add_argument("--tag", default="matrix")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    kit = pathlib.Path(__file__).resolve().parent
    nodes = {}

    def leave(signum, _frame):
        """Turn a signal into an exit so the `finally` below runs."""
        raise SystemExit(128 + signum)

    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, leave)
    failed = 0
    try:
        stage(kit, args.bin)
        take_locks(args.tag)
        log("locks held")
        nodes = {role: Node(role) for role in HOSTS}
        meta = {"info": {}, "setup": {}}
        for role, node in nodes.items():
            sent = time.time()
            info = node.call("info")
            info["clock_offset_s"] = round(info["time"] - (sent + time.time()) / 2, 4)
            meta["info"][role] = info
            meta["setup"][role] = node.call("setup", ip=HOSTS[role][1])
            log(role, f"offset {info['clock_offset_s']} s, load {info['load']}")
        keys = {"hub": nodes["hub"].call("hub_keys")["public"],
                "tcp": nodes["tcp"].call("tcp_keys", count=TCP_PEERS)["peers"],
                "flood": nodes["flood"].call("sim_keys", instances=SIMS)["peers"]}
        for number, (load, mode, scenario, rep) in enumerate(planned(args.plan, nodes)):
            name = f"{number:02d}-{scenario}-{mode}-l{load}-r{rep}"
            try:
                cell = run_cell(nodes, keys, mode, scenario, load, args.window)
            except (RuntimeError, SystemExit) as error:
                if isinstance(error, SystemExit) and not str(error).startswith("unknown"):
                    raise
                log(name, "FAILED", error)
                failed += 1
                if any(node.process.poll() is not None for node in nodes.values()):
                    raise
                continue
            cell["rep"] = rep
            cell["info_after"] = {role: node.call("info") for role, node in nodes.items()}
            (args.out / f"{name}.json").write_text(json.dumps(cell))
            log(name, "done")
        meta["guard"] = {role: node.call("guard")["guard"] for role, node in nodes.items()}
        (args.out / f"meta-{args.tag}.json").write_text(json.dumps(meta, indent=1))
    finally:
        for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        for node in nodes.values():
            node.close()
        release_locks()
    log(f"HOLD_DONE failed={failed}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
