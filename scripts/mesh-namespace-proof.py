#!/usr/bin/env python3
"""Real kernel direct-path Mesh proof in two isolated network namespaces [167,169], #129.

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
import time


def run(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout


def namespace(pid, *args):
    return run("nsenter", "-t", str(pid), "-n", *args)


def request(proc, value):
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
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--nf-tables", action="store_true")
    args = parser.parse_args()
    frontend = ["--nf-tables"] if args.nf_tables else []
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
        left = subprocess.Popen([args.fixture, *frontend], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        right = subprocess.Popen(["nsenter", "-t", str(child.pid), "-n", args.fixture, *frontend], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        identities = [json.loads(proc.stdout.readline()) for proc in (left, right)]
        addresses = [{"ipv4": "10.254.0.1", "ipv6": "fd01:203:405::1"}, {"ipv4": "10.254.0.2", "ipv6": "fd01:203:405::2"}]
        chunks = []
        applies = []
        for index, proc in enumerate((left, right)):
            other = 1 - index
            chunk = {"node": index + 1, "from_version": None, "version": 1, "index": 0, "last": True, "addresses": addresses[index], "default_policy": "Allow", "upserted": {str(other + 1): {"peer": {"key": identities[other]["public_key"], "addresses": addresses[other], "endpoint": f"10.220.0.{other + 1}:{identities[other]['port']}"}, "inbound": "All", "outbound": "All"}}, "removed": []}
            chunks.append(chunk)
            applies.append(request(proc, chunk))
        run("ping", "-n", "-c", "1", "-W", "5", "10.254.0.2")
        join_us = (time.monotonic_ns() - started) // 1000
        mesh_ping = ping("10.254.0.2")
        mesh_ipv6_ping = ping("fd01:203:405::2")
        mesh_mbps = throughput(child.pid, "10.254.0.2", 5202)
        echoes.append(echo_server(child.pid, 5203))
        echoes.append(echo_server(child.pid, 5211))
        held = socket.create_connection(("10.254.0.2", 5203), 2)
        held.settimeout(2)
        held.sendall(b"before")
        assert held.recv(6) == b"before"
        # The established flow must survive while new flows lose reach.
        for index, proc in enumerate((left, right)):
            chunk = chunks[index]
            chunk["from_version"] = 1
            chunk["version"] = 2
            chunk["default_policy"] = "Deny"
            for peer in chunk["upserted"].values():
                peer["inbound"] = "None"
                peer["outbound"] = "None"
            request(proc, chunk)
        denied = subprocess.run(["ping", "-n", "-c", "1", "-W", "1", "10.254.0.2"], capture_output=True).returncode != 0
        assert denied
        held.sendall(b"after")
        established_survives = held.recv(5) == b"after"
        assert established_survives
        denied_tcp = new_tcp_denied("10.254.0.2", 5203)
        assert denied_tcp
        for index, proc in enumerate((left, right)):
            chunk = chunks[index]
            chunk["from_version"] = 2
            chunk["version"] = 3
            for peer in chunk["upserted"].values():
                peer["inbound"] = {"Ports": [{"protocol": "Tcp", "number": 5211}]}
                peer["outbound"] = {"Ports": [{"protocol": "Tcp", "number": 5211}]}
            request(proc, chunk)
        allowed = socket.create_connection(("10.254.0.2", 5211), 2)
        allowed.sendall(b"grant")
        port_grant = allowed.recv(5) == b"grant"
        allowed.close()
        assert port_grant and new_tcp_denied("10.254.0.2", 5203)
        # Count process CPU ticks and RSS without starting a workload generator.
        def ticks(proc):
            return sum(int(field) for field in open(f"/proc/{proc.pid}/stat").read().split()[13:15])
        before = [ticks(proc) for proc in (left, right)]
        time.sleep(2)
        idle_ticks = [ticks(proc) - count for proc, count in zip((left, right), before)]
        rss = [int(open(f"/proc/{proc.pid}/statm").read().split()[1]) * os.sysconf("SC_PAGE_SIZE") for proc in (left, right)]
        print(json.dumps({"machine": "infraternal-dev", "load": open("/proc/loadavg").read().strip(), "rootless_userns": True, "real_kernel": True, "pairs": 1, "direct_pairs": 1, "needs_later_paths": 0, "underlay_ping": underlay_ping, "mesh_ping": mesh_ping, "mesh_ipv6_ping": mesh_ipv6_ping, "deny_new_tcp": denied_tcp, "established_survives_switch": established_survives, "port_grant_and_other_port_denial": port_grant, "underlay_mbps": underlay_mbps, "mesh_mbps": mesh_mbps, "join_to_first_packet_us": join_us, "apply": applies, "deny_new_ping": denied, "fixture_idle_ticks_2s": idle_ticks, "fixture_rss_bytes": rss, "fixture_rss_at_1000_nodes_bytes": sum(rss) * 500}, sort_keys=True))
        for proc in (left, right):
            assert request(proc, "quit")["off"]
            proc.wait(timeout=5)
    finally:
        if held:
            held.close()
        for proc in (left, right, child, *echoes):
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)


if __name__ == "__main__":
    main()
