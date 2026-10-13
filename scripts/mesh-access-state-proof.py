#!/usr/bin/env python3
"""Prove immediate, exact retirement of open mesh connection state [242,252], #173.

Removing unconditional established acceptance must refuse existing TCP/UDP while
preserving allowed same-peer and unrelated underlay state IDs. Only disposable
namespaces are used; raw state and frontend output remain in evidence files.
"""
import argparse
import contextlib
import copy
import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
from evidence_path import evidence_directory

spec = importlib.util.spec_from_file_location("packet_proof", Path(__file__).with_name("mesh-policy-proof.py"))
packet_proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packet_proof)
proof = packet_proof.proof


def attributes(data):
    """Decode the independent kernel fixture's aligned attribute framing."""
    values = {}
    while data:
        size, kind = struct.unpack_from("HH", data)
        assert 4 <= size <= len(data)
        values[kind & 0x3fff] = data[4:size]
        data = data[(size + 3) & ~3:]
    return values


def state_dump():
    """Retain raw kernel messages and independently identify TCP/UDP tuples."""
    rows, raw = [], bytearray()
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12) as channel:
        channel.bind((0, 0))
        channel.settimeout(5)
        channel.send(struct.pack("IHHII", 20, 257, 0x301, 1, 0) + bytes(4))
        while True:
            data = channel.recv(65536)
            raw.extend(data)
            while data:
                size, kind, flags, sequence, pid = struct.unpack_from("IHHII", data)
                body = data[16:size]
                data = data[(size + 3) & ~3:]
                assert sequence == 1 and not flags & 0x10
                if kind == 3:
                    return rows, bytes(raw)
                if kind == 2:
                    assert struct.unpack_from("i", body)[0] == 0
                    continue
                top = attributes(body[4:])
                original = attributes(top[1])
                ip, proto = attributes(original[1]), attributes(original[2])
                family = body[0]
                protocol = proto[1][0]
                if protocol not in (6, 17):
                    continue
                rows.append({"src": socket.inet_ntop(family, ip[1 if family == 2 else 3]),
                             "dst": socket.inet_ntop(family, ip[2 if family == 2 else 4]),
                             "protocol": protocol, "sport": int.from_bytes(proto[2], "big"),
                             "dport": int.from_bytes(proto[3], "big"),
                             "id": top[12].hex(), "zone": top.get(18, bytes(2)).hex()})


SERVER = """import socket,sys,threading
family=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
s=socket.socket(family,socket.SOCK_DGRAM if sys.argv[3]=='udp' else socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((sys.argv[1],int(sys.argv[2])))
def echo(c):
 while True:
  b=c.recv(4096)
  if not b: break
  c.sendall(b)
if sys.argv[3]=='tcp': s.listen()
print('ready',flush=True)
while True:
 if sys.argv[3]=='udp':
  b,a=s.recvfrom(4096);s.sendto(b,a)
 else:
  c,a=s.accept();threading.Thread(target=echo,args=(c,),daemon=True).start()
"""


class HeldCampaign(packet_proof.Campaign):
    """Keep both node frontends active for persistent connection checks."""
    def remove_sender_filter(self):
        pass


class Flow:
    """A persistent socket whose source tuple never changes across updates."""
    def __init__(self, fixture, address, port, protocol):
        server = fixture.spawn("python3", "-c", SERVER, address, str(port), protocol)
        assert server.stdout.readline().strip() == "ready"
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        self.socket = socket.socket(family, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM)
        self.socket.settimeout(.7)
        self.socket.connect((address, port))
        self.protocol, self.address, self.port = protocol, address, port
        self.source = self.socket.getsockname()
        assert self.echo()

    def echo(self):
        try:
            self.socket.sendall(b"state-check")
            return self.socket.recv(64) == b"state-check"
        except OSError:
            return False

    def row(self, rows):
        matches = [r for r in rows if (r["src"], r["dst"], r["protocol"], r["sport"], r["dport"]) ==
                   (self.source[0], self.address, 17 if self.protocol == "udp" else 6, self.source[1], self.port)]
        assert len(matches) <= 1
        return matches[0] if matches else None


def campaign(args):
    fixture = HeldCampaign.__new__(HeldCampaign)
    results, flows = [], []
    def record(name, value):
        results.append({"test": name, "result": "PASS" if value else "FAIL"})
    try:
        with (args.evidence / "setup.log").open("w") as log, contextlib.redirect_stdout(log):
            fixture.__init__(args.fixture, args.nf_tables)
        # Leave both frontends active. The imported packet harness disables the
        # sender only to inspect independent receiving enforcement.
        for operation in ("rule_removal", "default_tightening", "peer_retirement"):
            fixture.version += 1
            for node, template in zip((fixture.left, fixture.right), fixture.chunks):
                chunk = copy.deepcopy(template)
                chunk.update(from_version=None, version=fixture.version)
                assert proof.request(node, chunk)["applied"]
            current = []
            for family in ("ipv4", "ipv6"):
                address = fixture.addresses[1][family]
                for protocol in ("tcp", "udp"):
                    for port in (5540, 5541):
                        current.append(Flow(fixture, address, port, protocol))
            # Positive underlay controls are unrelated to mesh ownership.
            unrelated = [Flow(fixture, "10.220.0.2", 5542, protocol) for protocol in ("tcp", "udp")]
            flows.extend(current + unrelated)
            before, raw = state_dump() if args.outgoing else (json.loads(fixture.remote("python3", str(Path(__file__).resolve()), "--dump")), b"remote-state")
            (args.evidence / f"{operation}-before.bin").write_bytes(raw)
            assert all(flow.row(before) for flow in current + unrelated)
            chunk = copy.deepcopy(fixture.chunks[0 if args.outgoing else 1])
            chunk.update(from_version=fixture.version, version=fixture.version + 1)
            if operation == "peer_retirement":
                chunk.update(upserted={}, removed=[2 if args.outgoing else 1])
            else:
                if operation == "default_tightening":
                    chunk["default_policy"] = "Deny"
                # Port 5541 remains permitted on the same peer.
                peer = chunk["upserted"]["2" if args.outgoing else "1"]
                peer["outbound" if args.outgoing else "inbound"] = {"Ports": [
                    {"protocol": protocol, "number": 5541} for protocol in ("Tcp", "Udp")]}
            assert proof.request(fixture.left if args.outgoing else fixture.right, chunk)["applied"]
            fixture.version += 1
            # Query state in the node which changed, without sending a packet
            # which could recreate a loosely tracked retired TCP tuple.
            if args.outgoing:
                after, raw = state_dump()
            else:
                output = fixture.remote("python3", str(Path(__file__).resolve()), "--dump")
                after = json.loads(output)
                raw = output.encode()
            (args.evidence / f"{operation}-after.bin").write_bytes(raw)
            for flow in current:
                allowed = operation != "peer_retirement" and flow.port == 5541
                record(f"{operation}_{flow.protocol}_{flow.address}_state", bool(flow.row(after)) == allowed)
                if allowed:
                    record(f"{operation}_{flow.protocol}_{flow.address}_same_id", flow.row(before)["id"] == flow.row(after)["id"])
                for attempt in range(2):
                    record(f"{operation}_{flow.protocol}_{flow.address}_echo_{attempt}", flow.echo() == allowed)
            for flow in unrelated:
                record(f"{operation}_underlay_{flow.protocol}", flow.echo() and flow.row(before)["id"] == flow.row(after)["id"])
            for flow in current + unrelated:
                flow.socket.close()
            # Echo fixtures own their sockets; stop each before the next case.
            for proc in fixture.processes[3:]:
                if proc.poll() is None:
                    proc.terminate();proc.wait(timeout=5)
            fixture.processes = fixture.processes[:3]
        (args.evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
        passed = sum(row["result"] == "PASS" for row in results)
        print(f"PASS={passed} FAIL={len(results)-passed}")
        return 0 if passed == len(results) else 1
    finally:
        for flow in flows:
            flow.socket.close()
        for proc in getattr(fixture, "processes", []):
            if proc.poll() is None:
                proc.terminate();proc.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture")
    parser.add_argument("--nf-tables", action="store_true")
    parser.add_argument("--outgoing", action="store_true")
    parser.add_argument("--evidence", type=Path, default=evidence_directory("mesh-access-state-proof"))
    parser.add_argument("--dump", action="store_true")
    args = parser.parse_args()
    if args.dump:
        print(json.dumps(state_dump()[0]));return 0
    assert Path("/proc/self/uid_map").read_text().split()[2:] == ["1"]
    args.evidence.mkdir(parents=True, exist_ok=True)
    return campaign(args)


if __name__ == "__main__":
    raise SystemExit(main())
