#!/usr/bin/env python3
"""Verify packet policy with actual WireGuard and disposable namespaces [164,216,235], #173.

The sender's filter is deliberately removed for inbound tests: refusal must
come from the receiving node, not a cooperative peer. Raw inner packets use
synthetic public payloads; no key or packet capture is printed. Reuse the
existing namespace fixture and process helpers rather than another engine.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import statistics
import struct
import subprocess
import time


spec = importlib.util.spec_from_file_location(
    "mesh_proof", Path(__file__).with_name("mesh-namespace-proof.py")
)
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


def checksum(data):
    """Internet checksum for synthetic inner packets, including IPv6 UDP."""
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(source, destination, port, sequence, fragmented=False):
    """Build whole or two-fragment UDP; receiver reassembly must enforce ports."""
    ipv6 = ":" in destination
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    src = socket.inet_pton(family, source)
    dst = socket.inet_pton(family, destination)
    data = b"mesh-policy-public-fixture" * 2
    udp = struct.pack("!HHHH", 30000 + sequence, port, len(data) + 8, 0) + data
    pseudo = (src + dst + struct.pack("!I3xB", len(udp), 17)) if ipv6 else (
        src + dst + struct.pack("!BBH", 0, 17, len(udp))
    )
    udp = udp[:6] + struct.pack("!H", checksum(pseudo + udp) or 65535) + udp[8:]
    parts = [(0, False, udp)] if not fragmented else [
        (0, True, udp[:24]), (3, False, udp[24:])
    ]
    result = []
    for offset, more, body in parts:
        if ipv6:
            if fragmented:
                body = struct.pack("!BBHI", 17, 0, offset << 3 | int(more), sequence) + body
            header = struct.pack("!IHBB", 6 << 28, len(body), 44 if fragmented else 17, 64)
            result.append(header + src + dst + body)
        else:
            header = struct.pack("!BBHHHBBH", 0x45, 0, len(body) + 20, sequence,
                                 offset | (8192 if more else 0), 64, 17, 0) + src + dst
            header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
            result.append(header + body)
    return family, result


class Campaign:
    """One independent real pair; each check has a fresh socket and tuple."""
    def __init__(self, fixture, fallback, coordinator=None):
        self.fallback = fallback
        self.processes = []
        self.rows = []
        self.sequence = 0
        self.version = 0
        self.child = subprocess.Popen(["unshare", "-n", "sleep", "1800"])
        self.processes.append(self.child)
        # Wait for the child's namespace, not a scheduling-dependent fixed delay.
        for _ in range(200):
            if Path(f"/proc/{self.child.pid}/ns/net").readlink() != Path("/proc/self/ns/net").readlink():
                break
            time.sleep(0.01)
        else:
            raise RuntimeError("network namespace did not start")
        proof.run("ip", "link", "set", "lo", "up")
        self.remote("ip", "link", "set", "lo", "up")
        proof.run("ip", "link", "add", "underlay0", "type", "veth", "peer", "name", "underlay1")
        proof.run("ip", "link", "set", "underlay1", "netns", str(self.child.pid))
        proof.run("ip", "addr", "add", "10.220.0.1/24", "dev", "underlay0")
        proof.run("ip", "link", "set", "underlay0", "up")
        self.remote("ip", "addr", "add", "10.220.0.2/24", "dev", "underlay1")
        self.remote("ip", "link", "set", "underlay1", "up")
        proof.run("ip", "-6", "addr", "add", "fd03::1/64", "dev", "underlay0", "nodad")
        self.remote("ip", "-6", "addr", "add", "fd03::2/64", "dev", "underlay1", "nodad")
        extra = ["--nf-tables"] if fallback else []
        self.left = subprocess.Popen([fixture, *extra], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True)
        self.processes.append(self.left)
        self.right = self.spawn(fixture, *extra)
        identities = [json.loads(p.stdout.readline()) for p in (self.left, self.right)]
        self.addresses = [{"ipv4": "10.254.0.1", "ipv6": "fd01:203:405::1"},
                          {"ipv4": "10.254.0.2", "ipv6": "fd01:203:405::2"}]
        self.chunks = []
        for index in range(2):
            other = 1 - index
            self.chunks.append({"node": index + 1, "from_version": None, "version": 1,
                "index": 0, "last": True, "addresses": self.addresses[index],
                "default_policy": "Allow", "upserted": {str(other + 1): {"peer": {
                "key": identities[other]["public_key"], "addresses": self.addresses[other],
                "endpoint": f"10.220.0.{other + 1}:{identities[other]['port']}"},
                "inbound": "All", "outbound": "All"}}, "removed": []})
        if coordinator:
            result = subprocess.run([coordinator], input=json.dumps({
                "mode": "unbound-identity", "identities": identities}) + "\n",
                capture_output=True, text=True, check=True)
            self.enrollment = json.loads(result.stdout)
            self.addresses = self.enrollment["addresses"]
            for proc, chunks in zip((self.left, self.right), self.enrollment["denied"]):
                for chunk in chunks:
                    proof.request(proc, chunk)
        else:
            self.apply("All")
            proof.run("ping", "-n", "-c", "1", "-W", "5", self.addresses[1]["ipv4"])
        self.remove_sender_filter()

    def remote(self, *args):
        return proof.namespace(self.child.pid, *args)

    def spawn(self, *args, namespace_pid=None):
        p = subprocess.Popen(["nsenter", "-t", str(namespace_pid or self.child.pid), "-n", *args],
                             stdout=subprocess.PIPE, stdin=subprocess.PIPE, text=True)
        self.processes.append(p)
        return p

    def remove_sender_filter(self):
        # Only this job's disposable namespace is ever modified.
        if self.fallback:
            for tool in ["iptables-nft", "ip6tables-nft"]:
                proof.run(tool, "-F", "IFM_OUT")
        else:
            proof.run("nft", "flush", "chain", "inet", "infraternal_mesh", "outgoing")

    def apply(self, policy):
        self.version += 1
        self.last_apply_us = []
        for proc, template in zip((self.left, self.right), self.chunks):
            chunk = copy.deepcopy(template)
            chunk["version"] = self.version
            chunk["from_version"] = self.version - 1 if self.version > 1 else None
            for peer in chunk["upserted"].values():
                peer["inbound"] = policy
                peer["outbound"] = policy
            reply = proof.request(proc, chunk)
            assert reply["applied"]
            self.last_apply_us.append(reply["apply_us"])

    def record(self, name, expected, actual):
        row = {"test": name, "expected": expected, "actual": actual,
               "result": "PASS" if actual == expected else "FAIL"}
        self.rows.append(row)
        print(json.dumps(row), flush=True)

    def udp(self, name, source, destination, port, expected, fragmented=False, receiver=None, wire_destination=None):
        self.sequence += 1
        listener = self.spawn("python3", "-c", """import socket,sys
family=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
port=int(sys.argv[2])
s=socket.socket(family,socket.SOCK_DGRAM) if port else socket.socket(family,socket.SOCK_RAW,socket.IPPROTO_UDP)
s.bind((sys.argv[1],port))
s.settimeout(0.5);print('ready',flush=True)
try:
 b=s.recv(4096)
 if not port:
  offset=(b[0]&15)*4 if family==socket.AF_INET else 0
  assert int.from_bytes(b[offset+2:offset+4],'big')==0
 print('delivered' if b else 'empty',flush=True)
except TimeoutError: print('blocked',flush=True)
""", destination, str(port), namespace_pid=receiver)
        assert listener.stdout.readline().strip() == "ready"
        target = wire_destination or destination
        family, packets = packet(source, target, port, self.sequence, fragmented)
        with socket.socket(family, socket.SOCK_RAW, socket.IPPROTO_RAW) as sender:
            for data in packets:
                try:
                    sender.sendto(data, (target, 0))
                except PermissionError:
                    # An OUTPUT drop is reported synchronously by the kernel.
                    # Still require the real receiver to observe no datagram.
                    if expected:
                        raise
        assert select.select([listener.stdout], [], [], 5)[0], "listener did not complete"
        actual = listener.stdout.readline().strip() == "delivered"
        assert listener.wait(timeout=5) == 0, "UDP receiver failed"
        self.record(name, expected, actual)

    def tcp(self, name, address, port, expected):
        listener = self.spawn("python3", "-c", """import socket,sys
family=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind((sys.argv[1],int(sys.argv[2])));s.listen();s.settimeout(0.5);print('ready',flush=True)
try:
 c,_=s.accept();c.sendall(b'fixture');c.close()
except TimeoutError: pass
""", address, str(port))
        assert listener.stdout.readline().strip() == "ready"
        try:
            with socket.create_connection((address, port), 0.4) as conn:
                actual = conn.recv(7) == b"fixture"
        except (TimeoutError, ConnectionRefusedError, OSError):
            actual = False
        assert listener.wait(timeout=5) == 0, "TCP receiver failed"
        self.record(name, expected, actual)

    def enrollment_check(self):
        """Check compiled public enrollment policy on an actual encrypted path."""
        self.record("unbound_identity_refused", True, self.enrollment["refused"])
        for family in ["ipv4", "ipv6"]:
            self.udp(f"unbound_identity_not_permitted_{family}", self.addresses[0][family],
                     self.addresses[1][family], 5540, False)
        for proc, chunks in zip((self.left, self.right), self.enrollment["allowed"]):
            for chunk in chunks:
                proof.request(proc, chunk)
        self.remove_sender_filter()
        for family in ["ipv4", "ipv6"]:
            self.udp(f"explicit_grant_permitted_{family}", self.addresses[0][family],
                     self.addresses[1][family], 5540, True)
        return self.rows

    def check(self):
        for policy in ["All", "None", {"Ports": [
                {"protocol": "Tcp", "number": 65535},
                {"protocol": "Udp", "number": 65535},
                *({"protocol": "Udp", "number": p} for p in range(5400, 5403))]}]:
            self.apply(policy)
            self.remove_sender_filter()
            label = policy if isinstance(policy, str) else "Ports"
            for family in ["ipv4", "ipv6"]:
                src, dst = (a[family] for a in self.addresses)
                suffix = f"{label}_{family}"
                for port in [0, 5399, 5400, 5401, 5402, 5403, 65535]:
                    self.udp(f"udp_{port}_{suffix}", src, dst, port,
                             policy == "All" or label == "Ports" and port in [5400, 5401, 5402, 65535])
                for port in [5400, 65535]:
                    self.tcp(f"tcp_{port}_{suffix}", dst, port,
                             policy == "All" or label == "Ports" and port == 65535)
                self.udp(f"fragments_allowed_port_{suffix}", src, dst, 65535, policy != "None", True)
                self.udp(f"fragments_denied_port_{suffix}", src, dst, 5410, policy == "All", True)
                ping = subprocess.run(["ping", "-n", "-c", "1", "-W", "1", dst],
                                      capture_output=True).returncode == 0
                self.record(f"icmp_{suffix}", policy == "All", ping)
        self.apply("All")
        self.remove_sender_filter()
        self.ingress()
        # Configure the sender with unauthorized source addresses only; receiver
        # AllowedIPs remain the production /32 and /128 cryptokey selectors.
        for family, sources in [("ipv4", ["10.254.0.3", "192.0.2.9", "127.0.0.2", "169.254.1.2", "224.0.0.1", "255.255.255.255"]),
                                ("ipv6", ["fd01:203:405::3", "2001:db8::9", "::1", "fe80::9", "ff02::1", "::ffff:10.254.0.1"])]:
            dst = self.addresses[1][family]
            # Ensure a real authenticated baseline before refusing each spoof.
            self.udp(f"identity_positive_{family}", self.addresses[0][family], dst, 5500, True)
            for source in sources:
                self.udp(f"source_identity_{source}", source, dst, 5500, False)
        self.transit(self.output())
        # Removal must retire the cryptokey even if a sender retains the tunnel.
        chunk = copy.deepcopy(self.chunks[1])
        chunk.update(from_version=self.version, version=self.version + 1, upserted={}, removed=[1])
        assert proof.request(self.right, chunk)["applied"]
        for family in ["ipv4", "ipv6"]:
            self.udp(f"removed_peer_{family}", self.addresses[0][family], self.addresses[1][family], 5501, False)
        return self.rows

    def output(self):
        """Independent outbound checks keep the receiving node permissive."""
        version = self.version
        for policy in ["All", "None", {"Ports": [
                {"protocol": "Tcp", "number": 65535},
                {"protocol": "Udp", "number": 65535},
                *({"protocol": "Udp", "number": p} for p in range(5400, 5403))]}]:
            chunk = copy.deepcopy(self.chunks[0])
            chunk.update(from_version=version, version=version + 1)
            chunk["upserted"]["2"]["outbound"] = policy
            assert proof.request(self.left, chunk)["applied"]
            version += 1
            label = policy if isinstance(policy, str) else "Ports"
            for family in ["ipv4", "ipv6"]:
                src, dst = (a[family] for a in self.addresses)
                suffix = f"output_{label}_{family}"
                for port in [0, 5399, 5400, 5401, 5402, 5403, 65535]:
                    self.udp(f"udp_{port}_{suffix}", src, dst, port,
                             policy == "All" or label == "Ports" and port in [5400, 5401, 5402, 65535])
                for port in [5400, 65535]:
                    self.tcp(f"tcp_{port}_{suffix}", dst, port,
                             policy == "All" or label == "Ports" and port == 65535)
                self.udp(f"fragments_allowed_port_{suffix}", src, dst, 65535, policy != "None", True)
                self.udp(f"fragments_denied_port_{suffix}", src, dst, 5410, policy == "All", True)
                ping = subprocess.run(["ping", "-n", "-c", "1", "-W", "1", dst],
                                      capture_output=True).returncode == 0
                self.record(f"icmp_{suffix}", policy == "All", ping)
        # Transit checks need a live sender; restoring it is a new version.
        chunk.update(from_version=version, version=version + 1)
        chunk["upserted"]["2"]["outbound"] = "All"
        assert proof.request(self.left, chunk)["applied"]
        return version + 1

    def ingress(self):
        """Published underlay ports must not become authenticated mesh ingress."""
        for family, source, wire in [("ipv4", "10.220.0.1", "10.220.0.2"),
                                     ("ipv6", "fd03::1", "fd03::2")]:
            destination = self.addresses[1][family]
            self.udp(f"underlay_positive_{family}", source, wire, 5530, True)
            route_family, prefix = ([], "32") if family == "ipv4" else (["-6"], "128")
            proof.run("ip", *route_family, "route", "replace", f"{destination}/{prefix}", "via", wire, "dev", "underlay0")
            self.udp(f"plaintext_mesh_ingress_{family}", source, destination, 5531, False)
            proof.run("ip", *route_family, "route", "replace", f"{destination}/{prefix}", "dev", "infraternal0", "proto", "static", "scope", "link")
            nft_family = "ip" if family == "ipv4" else "ip6"
            # This job owns the NAT table in this disposable namespace only.
            script = (f"table {nft_family} mesh_policy_nat {{\n"
                      " chain published { type nat hook prerouting priority -100; policy accept;\n"
                      f" {nft_family} daddr {wire} udp dport 5532 dnat to {destination}\n"
                      " }\n}\n")
            tool = "iptables-nft" if family == "ipv4" else "ip6tables-nft"
            rule = ["PREROUTING", "-d", wire, "-p", "udp", "--dport", "5532", "-j", "DNAT", "--to-destination", destination]
            if self.fallback:
                self.remote(tool, "-t", "nat", "-A", *rule)
            else:
                p = self.spawn("nft", "-f", "-")
                p.stdin.write(script)
                p.stdin.close()
                assert p.wait(timeout=5) == 0
            self.udp(f"published_mesh_ingress_{family}", source, destination, 5532, False, wire_destination=wire)
            if self.fallback:
                self.remote(tool, "-t", "nat", "-D", *rule)
            else:
                self.remote("nft", "delete", "table", nft_family, "mesh_policy_nat")

    def transit(self, left_version):
        """An authenticated peer must not reach a third namespace via forwarding."""
        third = subprocess.Popen(["unshare", "-n", "sleep", "600"])
        self.processes.append(third)
        for _ in range(200):
            if Path(f"/proc/{third.pid}/ns/net").readlink() != Path("/proc/self/ns/net").readlink():
                break
            time.sleep(0.01)
        else:
            raise RuntimeError("third namespace did not start")
        self.remote("ip", "link", "add", "transit0", "type", "veth", "peer", "name", "transit1")
        self.remote("ip", "link", "set", "transit1", "netns", str(third.pid))
        for pid, interface, number in [(self.child.pid, "transit0", 1), (third.pid, "transit1", 2)]:
            proof.namespace(pid, "ip", "link", "set", "lo", "up")
            proof.namespace(pid, "ip", "addr", "add", f"10.230.0.{number}/24", "dev", interface)
            proof.namespace(pid, "ip", "-6", "addr", "add", f"fd02::{number}/64", "dev", interface, "nodad")
            proof.namespace(pid, "ip", "link", "set", interface, "up")
        self.remote("sysctl", "-qw", "net.ipv4.ip_forward=1")
        self.remote("sysctl", "-qw", "net.ipv6.conf.all.forwarding=1")
        proof.namespace(third.pid, "ip", "route", "add", "10.254.0.0/16", "via", "10.230.0.1")
        proof.namespace(third.pid, "ip", "-6", "route", "add", "fd01:203:405::/64", "via", "fd02::1")
        # A receiver-origin packet proves that both downstream routes/listeners
        # work, before checking tunnel transit. No forwarding refusal is inferred
        # from an absent listener or an unreachable destination.
        for destination in ["10.230.0.2", "fd02::2"]:
            listener = self.spawn("python3", "-c", """import socket,sys
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,socket.SOCK_DGRAM)
s.bind((sys.argv[1],5520));s.settimeout(2);print('ready',flush=True)
assert s.recv(64)==b'public-baseline';print('delivered',flush=True)
""", destination, namespace_pid=third.pid)
            assert listener.stdout.readline().strip() == "ready"
            self.remote("python3", "-c", """import socket,sys
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET,socket.SOCK_DGRAM)
s.sendto(b'public-baseline',(sys.argv[1],5520))
""", destination)
            assert listener.stdout.readline().strip() == "delivered"
            assert listener.wait(timeout=5) == 0
        chunk = copy.deepcopy(self.chunks[0])
        chunk.update(from_version=left_version, version=left_version + 1)
        chunk["upserted"]["2"]["peer"]["addresses"] = {"ipv4": "10.230.0.2", "ipv6": "fd02::2"}
        assert proof.request(self.left, chunk)["applied"]
        self.remove_sender_filter()
        for family, destination in [("ipv4", "10.230.0.2"), ("ipv6", "fd02::2")]:
            before = sum(row["received_bytes"] for row in proof.request(self.right, "stats"))
            self.udp(f"unrequested_subnet_transit_{family}", self.addresses[0][family], destination, 5521, False, receiver=third.pid)
            after = sum(row["received_bytes"] for row in proof.request(self.right, "stats"))
            self.record(f"transit_tunnel_observed_{family}", True, after > before)
        chunk = copy.deepcopy(self.chunks[0])
        chunk.update(from_version=left_version + 1, version=left_version + 2)
        assert proof.request(self.left, chunk)["applied"]
        self.remove_sender_filter()

    def measure(self):
        """At-scale diagnostic: one real pair and 999 additional public keys per node."""
        for chunk in self.chunks:
            for node in range(3, 1002):
                # These are synthetic PUBLIC peer identifiers, never private keys.
                key = list(hashlib.sha256(f"mesh-policy-public-peer-{node}".encode()).digest())
                chunk["upserted"][str(node)] = {"peer": {"key": key,
                    "addresses": {"ipv4": f"10.254.{node // 256}.{node % 256}",
                                  "ipv6": f"fd01:203:405::{node:x}"}, "endpoint": None},
                    "inbound": "All", "outbound": "All"}
        started = time.monotonic_ns()
        self.apply("All")
        apply_us = (time.monotonic_ns() - started) // 1000
        apply_node_us = self.last_apply_us
        saved = []
        for prefix in [[], ["nsenter", "-t", str(self.child.pid), "-n"]]:
            if self.fallback:
                for tool in ["iptables-nft", "ip6tables-nft"]:
                    rules = proof.run(*prefix, f"{tool}-save")
                    saved.append(([*prefix, f"{tool}-restore"], rules))
            else:
                rules = proof.run(*prefix, "nft", "-s", "list", "table", "inet", "infraternal_mesh")
                saved.append(([*prefix, "nft", "-f", "-"],
                              "delete table inet infraternal_mesh\n" + rules))
        if self.fallback:
            counts = {tool: sum(line.startswith("-A IFM_") for line in self.remote(tool, "-S").splitlines())
                      for tool in ["iptables-nft", "ip6tables-nft"]}
        else:
            table = json.loads(self.remote("nft", "-j", "list", "table", "inet", "infraternal_mesh"))
            counts = {"inet_rules": sum("rule" in row for row in table["nftables"]),
                      "inet_sets": sum("set" in row for row in table["nftables"])}
        samples = []
        # Alternate policy/no-policy in the same kernel/WireGuard pair. Removing
        # only the owned chains isolates filter work from crypto and routing.
        for iteration in range(3):
            for policy_on in [True, False]:
                if policy_on:
                    # Restore the saved namespace-owned rules directly: unchanged
                    # configuration replay intentionally skips a filter rebuild.
                    for command, rules in saved:
                        subprocess.run(command, input=rules, text=True, capture_output=True, check=True)
                elif self.fallback:
                    for tool in ["iptables-nft", "ip6tables-nft"]:
                        for chain in ["IFM_IN", "IFM_OUT", "IFM_DELIVERY", "IFM_GUARD"]:
                            self.remote(tool, "-t", "raw" if chain == "IFM_GUARD" else "filter", "-F", chain)
                            proof.run(tool, "-t", "raw" if chain == "IFM_GUARD" else "filter", "-F", chain)
                else:
                    for chain in ["incoming", "outgoing", "input", "output", "ingress"]:
                        self.remote("nft", "flush", "chain", "inet", "infraternal_mesh", chain)
                        proof.run("nft", "flush", "chain", "inet", "infraternal_mesh", chain)
                if policy_on:
                    if self.fallback:
                        observed = {tool: sum(line.startswith("-A IFM_") for line in self.remote(tool, "-S").splitlines())
                                    for tool in ["iptables-nft", "ip6tables-nft"]}
                    else:
                        installed = json.loads(self.remote("nft", "-j", "list", "table", "inet", "infraternal_mesh"))
                        observed = {"inet_rules": sum("rule" in row for row in installed["nftables"]),
                                    "inet_sets": sum("set" in row for row in installed["nftables"])}
                    assert observed == counts, "policy measurement has invalid state"
                values = {}
                for family in ["ipv4", "ipv6"]:
                    output = proof.run("ping", "-n", "-c", "101", "-i", "0.005", "-W", "2", self.addresses[1][family])
                    times = [float(line.split("time=")[1].split()[0]) for line in output.splitlines() if "time=" in line]
                    assert len(times) == 101
                    values[family] = {"n": len(times), "p50_ms": statistics.median(times),
                                      "p99_ms": sorted(times)[99]}
                samples.append({"iteration": iteration, "policy_on": policy_on, "rtt": values,
                                "load": Path("/proc/loadavg").read_text().strip()})
        print(json.dumps({"measurement": "policy_path", "machine": "infraternal-dev",
            "kernel": proof.run("uname", "-r").strip(), "cpus": proof.run("getconf", "_NPROCESSORS_ONLN").strip(),
            "profile": "debug fixture; kernel packet path", "peers_per_node": 1000,
            "live_pairs": 1, "apply_pair_us": apply_us, "apply_node_us": apply_node_us, "rules": counts,
            "samples": samples}), flush=True)

    def close(self):
        for p in reversed(self.processes):
            if p.poll() is None:
                p.terminate()
                p.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--nf-tables", action="store_true")
    parser.add_argument("--measure", action="store_true")
    parser.add_argument("--enrollment-fixture")
    args = parser.parse_args()
    if Path("/proc/self/uid_map").read_text().split()[2:] != ["1"]:
        parser.error("run inside unshare -Urn")
    os.environ["PATH"] = "/usr/sbin:" + os.environ.get("PATH", "")
    campaign = None
    try:
        # Assign before initialization so a failed setup also retires namespaces.
        campaign = Campaign.__new__(Campaign)
        campaign.__init__(args.fixture, args.nf_tables, args.enrollment_fixture)
        if args.measure:
            campaign.measure()
            return 0
        rows = campaign.enrollment_check() if args.enrollment_fixture else campaign.check()
        print(json.dumps({"backend": "nf_tables" if args.nf_tables else "nft",
                          "checks": len(rows), "failures": sum(r["result"] == "FAIL" for r in rows),
                          "machine": "infraternal-dev", "load": Path("/proc/loadavg").read_text().strip()}))
        return int(any(r["result"] == "FAIL" for r in rows))
    finally:
        if campaign:
            campaign.close()


if __name__ == "__main__":
    raise SystemExit(main())
