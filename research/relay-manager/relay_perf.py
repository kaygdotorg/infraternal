#!/usr/bin/env python3
"""Relay manager slice 1 measurements (D401, J1254): relayed against direct, on one machine.

What it measures
----------------
Two real `infraternal agent` nodes and a third one serving the relay role, inside J536b's NAT
topology (`scripts/mesh_nat_censorship_proof.py`, relay model). `full-cone-both` gives the
direct baseline, `symmetric-both` the relayed path (the relay manager relays it after its 5.5 s
backstop). The direct baseline's nodes get no relay list. For each it records:

* round-trip p50/p99 at rest (ping every 20 ms for 10 s) and the latency the relay adds;
* TCP goodput with 1 and 8 flows for 10 s each, and the CPU seconds each agent process spent
  (utime + stime from /proc) per Gbit carried;
* idle wakeups: context switches per second of every agent thread over 30 s with no traffic;
* (relayed only) how long the pair is dark when the relay process is killed and a new one
  serves again at the same address, split into the relay's own restart and the paths' recovery.

How to run it
-------------
Rootless, like the matrix: it re-executes itself in a private user, network and mount namespace,
so nothing on the host changes. On the perf VM run it through `perf-run` (no `--root`):

    perf-run --out DIR -- python3 relay_perf.py --repo /abs/checkout --binary /abs/infraternal \
        --coordinator /abs/coordinator_fixture --relay-fixture /abs/relay_fixture \
        --scratch /abs/private-dir --report /abs/report.json

The binary must be built with `infraternal-plugin-mesh/test-support` (the matrix's relay model).
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

CLOCK = os.sysconf("SC_CLK_TCK")
SENDER = r"""import socket,sys,time
c=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=15)
b=bytes(262144);n=0;end=time.monotonic()+float(sys.argv[3])
while time.monotonic()<end:
  c.sendall(b);n+=len(b)
c.shutdown(socket.SHUT_WR);print(n,flush=True)
"""
RECEIVER = r"""import socket,sys,threading
flows=int(sys.argv[2]);ports=range(5301,5301+flows);total=[0]*flows
def serve(i,p):
  s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],p));s.listen(1)
  c,_=s.accept()
  while True:
    d=c.recv(1<<20)
    if not d:break
    total[i]+=len(d)
threads=[threading.Thread(target=serve,args=(i,p)) for i,p in enumerate(ports)]
[t.start() for t in threads];print('ready',flush=True);[t.join() for t in threads];print(sum(total),flush=True)
"""


def cpu_seconds(pid: int) -> float:
    """User plus system CPU seconds of one process, all its threads."""
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / CLOCK


def switches(pid: int) -> dict[int, int]:
    """Voluntary plus involuntary context switches of each thread of one process, by thread id."""
    counts = {}
    for task in Path(f"/proc/{pid}/task").iterdir():
        try:
            counts[int(task.name)] = sum(int(line.split()[1]) for line in (task / "status").read_text().splitlines()
                                         if "ctxt_switches:" in line)
        except (OSError, ValueError):
            pass
    return counts


def woken(before: dict[int, int], after: dict[int, int]) -> int:
    """Switches between two samples: growth of threads alive in both, plus all of new ones."""
    return sum(count - before.get(tid, 0) for tid, count in after.items() if count >= before.get(tid, 0))


def agent_pid(node) -> int:
    """The agent process behind a fixture node (the fixture execs bash into it)."""
    return node.child.pid


def blast(m, sender_ns: str, receiver_ns: str, address: str, flows: int, seconds: float) -> dict:
    """Push `flows` TCP flows for `seconds`; return goodput in Gbit/s."""
    receiver = subprocess.Popen(["ip", "netns", "exec", receiver_ns, "python3", "-c", RECEIVER, address, str(flows)],
                                stdout=subprocess.PIPE, text=True)
    assert receiver.stdout.readline().strip() == "ready"
    started = time.monotonic()
    senders = [subprocess.Popen(["ip", "netns", "exec", sender_ns, "python3", "-c", SENDER, address, str(5301 + i),
                                 str(seconds)], stdout=subprocess.PIPE, text=True) for i in range(flows)]
    for sender in senders:
        sender.communicate(timeout=seconds + 30)
    elapsed = time.monotonic() - started
    received = int(receiver.communicate(timeout=30)[0].strip().splitlines()[-1])
    return {"flows": flows, "seconds": round(elapsed, 2), "gbit_per_s": round(received * 8 / elapsed / 1e9, 3)}


def restart_relay(m, args, scratch, topology, target, relay, nodes, serve, served, pingers) -> dict:
    """Kill the relay process mid-flow, serve again from a new one at the same address, and
    time how long the relayed pair is dark: the relay's own restart, then the paths' recovery."""
    from mesh_agent_fixture import BinaryNode

    flow = m.Pinger(topology.nodes["A"], target, interval=0.02)
    pingers.append(flow)
    assert flow.first_after(time.monotonic(), 10) is not None
    killed = time.monotonic()
    relay.child.kill()
    relay.child.wait(timeout=10)
    nodes.remove(relay)
    # A killed agent leaves its TUN behind; a new node in that namespace would refuse to adopt it.
    m.ns(topology.nodes["S"], "ip", "link", "del", "infraternal0", check=False)
    replacement = BinaryNode(args.binary, str(scratch), topology.node_pid["S"])
    nodes.append(replacement)
    again = replacement.call("mesh.relays", serve)
    serving = time.monotonic()
    recovered = flow.first_after(serving, 30)
    flow.stop()
    return {
        "relay_back_ms": round((serving - killed) * 1000),
        "path_back_after_relay_ms": round(recovered * 1000) if recovered is not None else None,
        "same_port": again.get("serving") == served["serving"],
    }


def measure(m, scenario_name: str, args) -> dict:
    """Build one profile with a relay node, connect the pair and run every measurement."""
    from mesh_agent_fixture import BinaryNode, CoordinatorFixture

    scenario = m.scenario_named(scenario_name)
    scratch = Path(args.scratch) / scenario_name
    scratch.mkdir(mode=0o700)
    os.environ["INFRATERNAL_TEST_HOST_FIREWALL_ROOT"] = str(scratch / "fw")
    (scratch / "fw").mkdir(mode=0o700)
    topology = m.Topology(scenario)
    nodes, pingers, coordinator = [], [], None
    row = {"scenario": scenario_name}
    try:
        certificates = m.relay_certificates(args.relay_fixture)
        ca = m.private_file(scratch / "ca.pem", certificates["ca"])
        topology.create()
        topology.add_server()
        relay = BinaryNode(args.binary, str(scratch), topology.node_pid["S"])
        nodes.append(relay)
        leaf = certificates["relays"][m.RELAY_NAME]
        serve = {"serve": {"name": m.RELAY_NAME, "port": m.RELAY_PORT, "leaf": leaf["cert"] + leaf["key"],
                           "roots": [certificates["ca"]]}}
        served = relay.call("mesh.relays", serve)
        for side in ("A", "B"):
            host = certificates["hosts"][m.HOST_UUIDS[side]]
            path = m.private_file(scratch / f"host-{side}.pem", host["cert"] + host["key"])
            os.environ["INFRATERNAL_TEST_RELAY_HOST_LEAF"] = str(path)
            os.environ["INFRATERNAL_TEST_RELAY_CA"] = str(ca)
            nodes.append(BinaryNode(args.binary, str(scratch), topology.node_pid[side]))
        members = nodes[1:]
        identities = [json.loads(node.stdout.readline()) for node in members]
        ports = {"A": identities[0]["port"], "B": identities[1]["port"]}
        topology.configure(ports)
        # The direct baseline gets no relay list: it measures the plain direct path, with no
        # relay connection or deadline on the nodes at all.
        if scenario_name != "full-cone-both":
            listed = {"relays": [{"name": m.RELAY_NAME, "port": served["serving"],
                                  "addresses": [m.SERVER_ADDRESS]}]}
            for node in members:
                node.call("mesh.relays", listed)
        coordinator = CoordinatorFixture(args.coordinator)
        snapshot = coordinator.configuration("allow", identities, topology.reflexive_endpoints(ports))
        target = snapshot["addresses"][1]["ipv4"]
        pinger = m.Pinger(topology.nodes["A"], target, interval=0.02)
        pingers.append(pinger)
        applied = time.monotonic()
        for index, node in enumerate(members):
            for chunk in snapshot["chunks"][index]:
                node.request(chunk)
        first = pinger.first_after(applied, 60)
        row["first_packet_ms"] = round(first * 1000) if first is not None else None
        row["relayed"] = bool(m.relay_status(members[0]).get("relayed"))
        if first is None:
            return row
        # sleep: let the path settle (the relay manager's deadline and the first measured move).
        time.sleep(3)
        pinger.take()
        # sleep: ten seconds of 20 ms pings at rest.
        time.sleep(10)
        rest = sorted(pinger.take())
        pinger.stop()
        row["rtt_ms_rest"] = {"p50": m.percentile(rest, 0.5), "p99": m.percentile(rest, 0.99), "samples": len(rest)}
        pids = {"A": agent_pid(members[0]), "B": agent_pid(members[1]), "relay": agent_pid(relay)}
        for flows in (1, 8):
            before = {name: cpu_seconds(pid) for name, pid in pids.items()}
            result = blast(m, topology.nodes["A"], topology.nodes["B"], target, flows, 10.0)
            after = {name: cpu_seconds(pid) for name, pid in pids.items()}
            gbit = result["gbit_per_s"] * result["seconds"]
            result["cpu_seconds"] = {name: round(after[name] - before[name], 3) for name in pids}
            result["cpu_seconds_per_gbit"] = {name: round((after[name] - before[name]) / gbit, 3) if gbit else None
                                              for name in pids}
            row[f"tcp_{flows}_flow"] = result
        # sleep: quiet before the idle window, so the transfers' tail is not counted.
        time.sleep(5)
        before = {name: switches(pid) for name, pid in pids.items()}
        # sleep: the idle window itself (D81: count every wakeup of every agent thread).
        time.sleep(30)
        after = {name: switches(pid) for name, pid in pids.items()}
        row["idle_wakeups_per_s"] = {name: round(woken(before[name], after[name]) / 30, 2) for name in pids}
        row["relay_node"] = m.relay_status(relay)
        if row["relayed"]:
            try:
                row["relay_restart"] = restart_relay(m, args, scratch, topology, target, relay, nodes, serve,
                                                     served, pingers)
            except Exception as error:
                row["relay_restart"] = {"error": f"{type(error).__name__}: {error}"}
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
        for name in ("INFRATERNAL_TEST_RELAY_HOST_LEAF", "INFRATERNAL_TEST_RELAY_CA",
                     "INFRATERNAL_TEST_HOST_FIREWALL_ROOT"):
            os.environ.pop(name, None)


def main() -> None:
    """Measure each profile in its own private namespaces (fresh /run each), then report."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in ("repo", "binary", "coordinator", "relay-fixture", "scratch", "report"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--inner", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inner:
        subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0700", "tmpfs", "/run"], check=True)
        Path("/run/netns").mkdir(parents=True, exist_ok=True)
        sys.path.insert(0, str(Path(args.repo) / "scripts"))
        import mesh_nat_censorship_proof as m

        try:
            row = measure(m, args.inner, args)
        except Exception as error:
            row = {"scenario": args.inner, "error": f"{type(error).__name__}: {error}"}
        print("ROW " + json.dumps(row), flush=True)
        return
    Path(args.scratch).mkdir(mode=0o700, parents=True, exist_ok=True)
    environment = {**os.environ, "TMPDIR": args.scratch, "PATH": os.environ.get("PATH", "") + ":/usr/sbin:/sbin"}
    rows = []
    for scenario in ("full-cone-both", "symmetric-both"):
        output = subprocess.run(["unshare", "-Urnm", "--propagation", "private", sys.executable,
                                 os.path.abspath(__file__), "--inner", scenario, *sys.argv[1:]],
                                env=environment, capture_output=True, text=True, timeout=900).stdout
        lines = [line[4:] for line in output.splitlines() if line.startswith("ROW ")]
        rows.append(json.loads(lines[-1]) if lines else {"scenario": scenario, "error": output[-2000:]})
        print(json.dumps(rows[-1]), flush=True)
    direct, relayed = rows
    if "rtt_ms_rest" in direct and "rtt_ms_rest" in relayed:
        added = {key: round(relayed["rtt_ms_rest"][key] - direct["rtt_ms_rest"][key], 3) for key in ("p50", "p99")}
    else:
        added = None
    report = {"machine": os.uname().nodename, "kernel": os.uname().release, "rows": rows,
              "relay_added_rtt_ms": added}
    Path(args.report).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
