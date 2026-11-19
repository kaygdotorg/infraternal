#!/usr/bin/env python3
"""Exercise endpoint updates through the real production-schema coordinator example."""

import json
import os
import subprocess
import unittest


class CoordinatorEndpointTests(unittest.TestCase):
    """Prove the coordinator fixture publishes both initial and rebound UDP endpoints."""

    def test_snapshot_and_rebind_publish_the_supplied_udp_endpoints(self):
        """A fresh attach and a same-identity reattach update the peer endpoints."""
        executable = os.environ.get("COORDINATOR_FIXTURE")
        if not executable:
            self.skipTest("set COORDINATOR_FIXTURE to the built production coordinator example")

        identities = [
            {"public_key": [1] * 32, "port": 10254, "compact_access": False},
            {"public_key": [2] * 32, "port": 10255, "compact_access": False},
        ]
        initial = ["198.51.100.21:41000", "198.51.100.22:41001"]
        rebound = ["198.51.100.21:42000", "198.51.100.22:42001"]
        requests = [
            {"mode": "allow", "identities": identities, "endpoints": initial},
            {"mode": "allow", "endpoints": rebound},
        ]
        result = subprocess.run(
            [executable],
            input="".join(json.dumps(request) + "\n" for request in requests),
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        snapshots = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(len(snapshots), 2)
        published = {
            peer["peer"]["endpoint"]
            for snapshot in snapshots
            for node_chunks in snapshot["chunks"]
            for chunk in node_chunks
            for peer in chunk.get("upserted", {}).values()
        }
        self.assertTrue(set(initial).issubset(published), published)
        self.assertTrue(set(rebound).issubset(published), published)


if __name__ == "__main__":
    unittest.main()
