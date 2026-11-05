#!/usr/bin/env python3
"""Real GotaTun direct-path Mesh proof in two isolated network namespaces [167,169], #129.

Run with unshare -Urn and an absolute kernel_node fixture path, in the high
CPUWeight scope. Nothing touches the host's interfaces or firewall. Public
keys pass through memory only. Namespace processes and interfaces retire on exit.
"""
import argparse
import json
import os
import socket
import statistics
import subprocess
import sys
import time

os.environ["INFRATERNAL_MESH_ENGINE"] = "gotatun"


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def namespace(pid, *args):
    return run("nsenter", "-t", str(pid), "-n", *args)


def request(proc, value):
    if hasattr(proc, "request"):
        return proc.request(value)
    proc.stdin.write(value if isinstance(value, str) else json.dumps(value))
    proc.stdin.write("\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("namespace kernel fixture stopped")
    return json.loads(line)


def throughput(pid, address, port):
    server_code = """import socket
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',int(__import__('sys').argv[1])));s.listen(1)
print('ready',flush=True)
c,_=s.accept();count=0
while True:
 b=c.recv(262144)
 if not b:break
 count+=len(b)
c.sendall(str(count).encode());c.close();s.close()
"""
    server = subprocess.Popen(["nsenter", "-t", str(pid), "-n", "python3", "-c", server_code, str(port)], stdout=subprocess.PIPE, text=True)
    try:
        if server.stdout.readline().strip() != "ready":
            raise RuntimeError("TCP fixture failed")
        conn = socket.create_connection((address, port), 5)
        block = bytes(256 * 1024)
        count = 128 * 1024 * 1024
        started = time.monotonic_ns()
        for _ in range(count // len(block)):
            conn.sendall(block)
        conn.shutdown(socket.SHUT_WR)
        received = int(conn.recv(64))
        elapsed = (time.monotonic_ns() - started) / 1e9
        conn.close()
        server.wait(timeout=5)
        assert received == count
        return round(count * 8 / elapsed / 1e6, 2)
    finally:
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=5)


def echo_server(pid, port):
    code = """import socket,sys
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',int(sys.argv[1])));s.listen(2)
print('ready',flush=True)
while True:
 c,_=s.accept()
 while True:
  b=c.recv(4096)
  if not b:break
  c.sendall(b)
 c.close()
"""
    proc = subprocess.Popen(["nsenter", "-t", str(pid), "-n", "python3", "-c", code, str(port)], stdout=subprocess.PIPE, text=True)
    assert proc.stdout.readline().strip() == "ready"
    return proc


def new_tcp_denied(address, port):
    try:
        conn = socket.create_connection((address, port), 0.5)
        conn.close()
        return False
    except TimeoutError:
        return True


def ping(address):
    output = run("ping", "-n", "-c", "25", "-i", "0.02", "-W", "2", address)
    values = [float(line.split("time=")[1].split()[0]) for line in output.splitlines() if "time=" in line]
    assert len(values) == 25, output
    return {"p50_ms": statistics.median(values), "p99_ms": max(values), "received": len(values)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture")
    parser.add_argument("--binary")
    parser.add_argument("--coordinator")
    parser.add_argument("--scratch")
    parser.add_argument("--extra-members", type=int, default=0)
    parser.add_argument("--nf-tables", action="store_true")
    args = parser.parse_args()
    if bool(args.fixture) == bool(args.binary):
        parser.error("choose --fixture or --binary")
    if args.binary and (not args.coordinator or not args.scratch or args.nf_tables):
        parser.error("--binary requires --coordinator and --scratch; fallback is tested with --fixture")
    if args.extra_members < 0 or (args.extra_members and not args.binary):
        parser.error("--extra-members requires the production coordinator")
    from pathlib import Path
    if Path("/proc/self/uid_map").read_text().split()[2:] != ["1"]:
        parser.error("run inside a disposable user/network namespace: unshare -Urn")
    frontend = ["--nf-tables"] if args.nf_tables else []
    coordinator = None
    child = subprocess.Popen(["unshare", "-n", "sleep", "600"])
    left = right = held = None
    echoes = []
    try:
        time.sleep(0.1)
        run("ip", "link", "set", "lo", "up")
        namespace(child.pid, "ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "underlay0", "type", "veth", "peer", "name", "underlay1")
        run("ip", "link", "set", "underlay1", "netns", str(child.pid))
        run("ip", "addr", "add", "10.220.0.1/24", "dev", "underlay0")
        run("ip", "link", "set", "underlay0", "up")
        namespace(child.pid, "ip", "addr", "add", "10.220.0.2/24", "dev", "underlay1")
        namespace(child.pid, "ip", "link", "set", "underlay1", "up")
        underlay_ping = ping("10.220.0.2")
        underlay_mbps = throughput(child.pid, "10.220.0.2", 5201)
        started = time.monotonic_ns()
        if args.binary:
            from mesh_agent_fixture import BinaryNode, CoordinatorFixture
            left = BinaryNode(args.binary, args.scratch)
            right = BinaryNode(args.binary, args.scratch, child.pid)
            coordinator = CoordinatorFixture(args.coordinator, args.extra_members)
        else:
            left = subprocess.Popen([args.fixture, *frontend], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            right = subprocess.Popen(["nsenter", "-t", str(child.pid), "-n", args.fixture, *frontend], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        identities = [json.loads(proc.stdout.readline()) for proc in (left, right)]
        addresses = [{"ipv4": "10.254.0.1", "ipv6": "fd01:203:405::1"}, {"ipv4": "10.254.0.2", "ipv6": "fd01:203:405::2"}]
        compiled = coordinator.configuration("allow", identities) if coordinator else None
        if compiled:
            addresses = compiled["addresses"]
        chunks = []
        applies = []
        for index, proc in enumerate((left, right)):
            other = 1 - index
            chunk = {"node": index + 1, "from_version": None, "version": 1, "index": 0, "last": True, "addresses": addresses[index], "default_policy": "Allow", "upserted": {str(other + 1): {"peer": {"key": identities[other]["public_key"], "addresses": addresses[other], "endpoint": f"10.220.0.{other + 1}:{identities[other]['port']}"}, "inbound": "All", "outbound": "All"}}, "removed": []}
            chunks.append(chunk)
            if compiled:
                for part in compiled["chunks"][index]:
                    applies.append(request(proc, part))
            else:
                applies.append(request(proc, chunk))
        try:
            run("ping", "-n", "-c", "1", "-W", "5", "10.254.0.2")
        except subprocess.CalledProcessError as error:
            def capture(label, command):
                try:
                    return command()
                except Exception as diagnostic_error:
                    return f"{label}: {diagnostic_error}"

            diagnostic = {
                "ping_stdout": error.stdout,
                "ping_stderr": error.stderr,
                "left_route": capture("left route", lambda: run("ip", "route", "get", "10.254.0.2")),
                "right_route": capture("right route", lambda: namespace(child.pid, "ip", "route", "get", "10.254.0.1")),
                "left_tun": capture("left TUN", lambda: run("ip", "-s", "addr", "show", "dev", "infraternal0")),
                "right_tun": capture("right TUN", lambda: namespace(child.pid, "ip", "-s", "addr", "show", "dev", "infraternal0")),
            }
            for label, proc in (("left_stats", left), ("right_stats", right)):
                diagnostic[label] = capture(label, lambda proc=proc: request(proc, "stats"))
            print(json.dumps(diagnostic, sort_keys=True), file=sys.stderr, flush=True)
            raise
        join_us = (time.monotonic_ns() - started) // 1000
        mesh_ping = ping("10.254.0.2")
        mesh_ipv6_ping = ping(addresses[1]["ipv6"])
        mesh_mbps = throughput(child.pid, "10.254.0.2", 5202)
        echoes.append(echo_server(child.pid, 5203))
        echoes.append(echo_server(child.pid, 5211))
        held = socket.create_connection(("10.254.0.2", 5203), 2)
        held.settimeout(2)
        held.sendall(b"before")
        assert held.recv(6) == b"before"
        # D242 retires the open stream when its initiating service is no longer permitted.
        compiled = coordinator.configuration("deny") if coordinator else None
        for index, proc in enumerate((left, right)):
            chunk = chunks[index]
            chunk["from_version"] = 1
            chunk["version"] = 2
            chunk["default_policy"] = "Deny"
            for peer in chunk["upserted"].values():
                peer["inbound"] = "None"
                peer["outbound"] = "None"
            if compiled:
                for part in compiled["chunks"][index]:
                    request(proc, part)
            else:
                request(proc, chunk)
        denied = subprocess.run(["ping", "-n", "-c", "1", "-W", "1", "10.254.0.2"], capture_output=True).returncode != 0
        assert denied
        if coordinator:
            assert subprocess.run(["nsenter", "-t", str(child.pid), "-n", "ping", "-n", "-c", "1", "-W", "2", addresses[0]["ipv4"]], capture_output=True).returncode == 0
        try:
            held.sendall(b"after")
            retired_stream_refused = held.recv(5) != b"after"
        except (TimeoutError, ConnectionError, PermissionError):
            retired_stream_refused = True
        assert retired_stream_refused
        denied_tcp = new_tcp_denied("10.254.0.2", 5203)
        assert denied_tcp
        compiled = coordinator.configuration("port") if coordinator else None
        for index, proc in enumerate((left, right)):
            chunk = chunks[index]
            chunk["from_version"] = 2
            chunk["version"] = 3
            for peer in chunk["upserted"].values():
                peer["inbound"] = {"Ports": [{"protocol": "Tcp", "number": 5211}]}
                peer["outbound"] = {"Ports": [{"protocol": "Tcp", "number": 5211}]}
            if compiled:
                for part in compiled["chunks"][index]:
                    request(proc, part)
            else:
                request(proc, chunk)
        allowed = socket.create_connection(("10.254.0.2", 5211), 2)
        allowed.sendall(b"access")
        permitted_port = allowed.recv(6) == b"access"
        allowed.close()
        assert permitted_port and new_tcp_denied("10.254.0.2", 5203)
        # Count process CPU ticks and RSS without starting a workload generator.
        def ticks(proc):
            return sum(int(field) for field in open(f"/proc/{proc.pid}/stat").read().split()[13:15])
        before = [ticks(proc) for proc in (left, right)]
        idle_seconds = 10 if args.binary else 2
        time.sleep(idle_seconds)
        idle_ticks = [ticks(proc) - count for proc, count in zip((left, right), before)]
        rss = [int(open(f"/proc/{proc.pid}/statm").read().split()[1]) * os.sysconf("SC_PAGE_SIZE") for proc in (left, right)]
        assert all(identity.get("engine") == "gotatun" for identity in identities), identities
        report = {"machine": socket.gethostname(), "load": open("/proc/loadavg").read().strip(), "rootless_userns": True, "engine": "gotatun", "pairs": 1, "direct_pairs": 1, "needs_later_paths": 0, "underlay_ping": underlay_ping, "mesh_ping": mesh_ping, "mesh_ipv6_ping": mesh_ipv6_ping, "deny_new_tcp": denied_tcp, "retired_stream_refused": retired_stream_refused, "permitted_port_and_other_port_refusal": permitted_port, "underlay_mbps": underlay_mbps, "mesh_mbps": mesh_mbps, "join_to_first_packet_us": join_us, "apply": applies, "deny_new_ping": denied, "fixture_idle_ticks_2s": idle_ticks, "fixture_rss_bytes": rss, "fixture_rss_at_1000_nodes_bytes": sum(rss) * 500}
        if args.binary:
            report["peer_count_per_node"] = args.extra_members + 1
            report["additional_public_members"] = args.extra_members
            report["full_infraternal_agent"] = True
            report["production_coordinator"] = True
            report["agent_idle_ticks_10s"] = report.pop("fixture_idle_ticks_2s")
            report["agent_rss_bytes"] = report.pop("fixture_rss_bytes")
            report["agent_rss_at_1000_nodes_bytes"] = report.pop("fixture_rss_at_1000_nodes_bytes")
        print(json.dumps(report, sort_keys=True))
        for proc in (left, right):
            assert request(proc, "quit")["off"]
            proc.wait(timeout=5)
    finally:
        if coordinator:
            coordinator.close()
        if held:
            held.close()
        for proc in (left, right, child, *echoes):
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)


if __name__ == "__main__":
    main()
