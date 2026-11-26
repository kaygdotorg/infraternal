#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""J1227 (#260, from J1137/J1160): a two-node infraternal mesh with one node per VM.

The kit's mesh_ix.py runs both shipping `infraternal agent` nodes on one machine and
talks to each over a local socket pair (leg B). Here node B lives on another VM, so
its leg-B channel is a TCP connection between the two J1137 fixture namespaces
(10.70.3.204 -> 10.70.3.205, inside the VM LAN only). The node, its data path and the
production coordinator compiler (`coordinator_fixture`) are unchanged.

    xix.py serve --listen IP:PORT --binary B --scratch DIR --pidfile F   (VM B)
    xix.py drive --remote IP:PORT --binary B --coordinator C --scratch DIR (VM A)

`drive` prints one JSON line when both nodes are configured, then waits for "quit"
on stdin, turns the mesh off on both nodes and exits. `serve` accepts one connection,
runs the agent with it as fd 3, and exits when the agent does.
"""
import argparse
import io
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + "/lib")
from mesh_agent_fixture import BinaryNode, CoordinatorFixture  # noqa: E402
from agent_fixture import varint  # noqa: E402


def _call(self, action, value):
    """BinaryNode.call, but a refusal carries the node's own reason (for diagnosis)."""
    self.call_id += 1
    encoded = action.encode()
    self.send(0x30, struct.pack("<I", self.call_id) + varint(len(encoded)) + encoded
              + json.dumps(value, separators=(",", ":")).encode())
    while True:
        stream, kind, body = self.read()
        if (stream, kind) == (0, 0x31):
            assert struct.unpack("<I", body[:4])[0] == self.call_id
            if body[4] != 1:
                raise RuntimeError(f"{action} refused: {body[5:][:2000]!r}")
            return json.loads(body[5:])


BinaryNode.call = _call


class RemoteNode(BinaryNode):
    """The same leg-B client as BinaryNode, over a TCP socket to `xix.py serve`."""

    def __init__(self, address):  # pylint: disable=super-init-not-called
        host, port = address.rsplit(":", 1)
        deadline = time.monotonic() + 30
        while True:
            try:
                self.sock = socket.create_connection((host, int(port)), timeout=5)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(60)
        self.call_id = 0
        self.pid = None
        self.child = None
        stream, kind, _ = self.read()
        assert (stream, kind) == (0, 0)
        self.send(0, struct.pack("<HQ", 1, 0) + varint(10) + b"mesh-proof")
        self.send(0x08, struct.pack("<QQ", 0, 0))
        while True:
            stream, kind, _ = self.read()
            if (stream, kind) == (0, 0x09):
                break
        self.call("mesh.up", {})
        identity = self.call("mesh.identity", {})
        assert identity is not None
        self.stdout = io.StringIO(json.dumps(identity) + "\n")

    def poll(self):
        return None

    def terminate(self):
        pass

    def wait(self, timeout):
        self.sock.close()
        return 0

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def serve(args):
    host, port = args.listen.rsplit(":", 1)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, int(port)))
    listener.listen(1)
    conn, _ = listener.accept()
    listener.close()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    state = Path(tempfile.mkdtemp(prefix="node-", dir=args.scratch))
    fd = conn.fileno()
    command = ["bash", "-c", 'leg_b_fd=$1; if [ "$leg_b_fd" != 3 ]; then exec 3<&"$leg_b_fd"; exec {leg_b_fd}<&-; fi; shift; exec "$@"',
               "leg-b", str(fd), args.binary, "agent", "--fd", "3", "--state", str(state)]
    with open(Path(args.scratch) / "agent-b.stderr", "wb") as log:
        child = subprocess.Popen(command, pass_fds=(fd,), stdout=subprocess.DEVNULL, stderr=log)
        conn.close()
        Path(args.pidfile).write_text(f"{child.pid}\n")
        return child.wait()


def drive(args):
    start_ns = time.monotonic_ns()
    coordinator = CoordinatorFixture(args.coordinator, 0)
    left = BinaryNode(args.binary, args.scratch)
    right = RemoteNode(args.remote)
    try:
        identities = [json.loads(node.stdout.readline()) for node in (left, right)]
        compiled = coordinator.configuration("allow", identities)
        # The coordinator fixture compiles the kit's single-host endpoints (10.220.0.x). Here each
        # node's peer is the other VM's fixture address, so point every upserted peer at it.
        endpoints = args.endpoints.split(",")
        for index, chunks in enumerate(compiled["chunks"]):
            for part in chunks:
                for peer in part.get("upserted", {}).values():
                    port = peer["peer"]["endpoint"].rsplit(":", 1)[1]
                    peer["peer"]["endpoint"] = f"{endpoints[1 - index]}:{port}"
        # Diagnosis only: public identities and the compiled chunks (no private keys exist here).
        Path(args.scratch, "compiled.json").write_text(json.dumps({"identities": identities, "compiled": compiled}))
        applied = []
        for index, node in enumerate((left, right)):
            for part in compiled["chunks"][index]:
                try:
                    applied.append(node.request(part)["apply_us"])
                except RuntimeError as error:
                    raise RuntimeError(f"node index {index}: {error}") from None
        print(json.dumps({
            "start_ns": start_ns,
            "peer_ipv4": compiled["addresses"][1]["ipv4"],
            "self_ipv4": compiled["addresses"][0]["ipv4"],
            "pids": [left.pid],
            "identities": identities,
            "configure_apply_us": applied,
        }), flush=True)
        for line in sys.stdin:
            if line.strip() == "quit":
                break
        for node in (left, right):
            node.request("quit")
        left.wait(timeout=10)
    finally:
        for node in (left, right):
            node.close()
        coordinator.close()


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--listen", required=True)
    s.add_argument("--binary", required=True)
    s.add_argument("--scratch", required=True)
    s.add_argument("--pidfile", required=True)
    d = sub.add_parser("drive")
    d.add_argument("--remote", required=True)
    d.add_argument("--binary", required=True)
    d.add_argument("--coordinator", required=True)
    d.add_argument("--scratch", required=True)
    d.add_argument("--endpoints", required=True, help="underlay IPv4 of node A,node B")
    args = parser.parse_args()
    sys.exit(serve(args) if args.mode == "serve" else drive(args))


if __name__ == "__main__":
    main()
