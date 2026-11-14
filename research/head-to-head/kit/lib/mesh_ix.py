#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bring up a two-node infraternal mesh for the head-to-head kit (#260).

Both nodes are the shipping `infraternal agent` binary (the dev build as it
ships), each in its own network namespace, enabled with `mesh.up` over its
leg-B channel. Their configuration comes from the production coordinator
library (crates/plugins/mesh, built as `coordinator_fixture`), which compiles
addresses, peers and the default-allow policy exactly as the server does.

What differs from a deployed mesh, and is documented with the numbers: the
coordinator talks to each node over a local socket pair instead of the
server's leg-B transport, so time to first packet excludes enrollment and the
server round trip; the data path (kernel WireGuard, the node's nftables
rules) is the shipping one.

Protocol: prints one JSON line when the pair passes traffic, then waits for
"quit" (or EOF) on stdin, turns the mesh off on both nodes and exits.
Reuses scripts/mesh_agent_fixture.py and scripts/agent_fixture.py unchanged.
"""
import argparse
import json
import os
import sys
import time

sys.dont_write_bytecode = True
# Run with -I (no environment or working directory on the path); the fixtures sit beside this file.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mesh_agent_fixture import BinaryNode, CoordinatorFixture  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--coordinator", required=True)
    parser.add_argument("--scratch", required=True)
    parser.add_argument("--pid-b", type=int, required=True, help="a process inside node B's namespace")
    args = parser.parse_args()
    start_ns = time.monotonic_ns()
    coordinator = CoordinatorFixture(args.coordinator, int(os.environ.get("H2H_IX_EXTRA_MEMBERS", "0")))
    left = BinaryNode(args.binary, args.scratch)
    right = BinaryNode(args.binary, args.scratch, args.pid_b)
    try:
        identities = [json.loads(node.stdout.readline()) for node in (left, right)]
        compiled = coordinator.configuration("allow", identities)
        applied = []
        for index, node in enumerate((left, right)):
            for part in compiled["chunks"][index]:
                applied.append(node.request(part)["apply_us"])
        print(json.dumps({
            "start_ns": start_ns,
            "peer_ipv4": compiled["addresses"][1]["ipv4"],
            "self_ipv4": compiled["addresses"][0]["ipv4"],
            "pids": [left.pid, right.pid],
            "configure_apply_us": applied,
        }), flush=True)
        for line in sys.stdin:
            if line.strip() == "quit":
                break
        for node in (left, right):
            node.request("quit")
            node.wait(timeout=10)
    finally:
        for node in (left, right):
            node.close()
        coordinator.close()


if __name__ == "__main__":
    main()
