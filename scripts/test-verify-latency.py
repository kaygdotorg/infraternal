#!/usr/bin/env python3
"""Keep the real-PTY latency fixture's visible marker state correct across repaints [#477]."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

sys.dont_write_bytecode = True

SCRIPT = Path(__file__).with_name("verify-latency.py")
SPEC = importlib.util.spec_from_file_location("verify_latency_fixture", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load the latency fixture")
verify_latency = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_latency)


class SnapshotFrame:
    """Supply one snapshot frame and record the credit the fixture returns."""

    def __init__(self, payload):
        """Keep the visible bytes and collect Credit frames sent by the fixture."""
        self.payload = payload
        self.credits = []

    def read(self):
        """Return one sequenced snapshot for the fixture's stream parser."""
        return 7, 0x15, struct.pack("<Q", 512) + self.payload

    def send(self, stream, kind, body):
        """Record the flow-control frame returned to this snapshot's stream."""
        self.credits.append((stream, kind, body))


class SnapshotMarkerTests(unittest.TestCase):
    """Ensure repaint state supplies the markers used by the latency fixture."""

    def test_snapshot_refreshes_recent_output_with_visible_marker(self):
        """A repaint must let flood-stop waits see a marker visible on screen."""
        marker = b"__FLOOD_STOPPED__"
        client = SnapshotFrame(b"screen contents " + marker)
        state = {
            "out": 0,
            "output_bytes": 0,
            "echoes": 0,
            "repaints": 0,
            "echo_by_token": False,
            "token": 0,
            "token_tail": b"stale raw tail",
            "recent_output": bytearray(b"stale raw tail"),
            "pending_echo": None,
        }

        verify_latency.frame(client, {7: state})

        self.assertEqual(state["recent_output"], bytearray(b"screen contents " + marker))
        self.assertIn(marker, state["recent_output"])
        self.assertEqual(client.credits, [(7, 0x14, struct.pack("<I", len(b"screen contents " + marker)))])


if __name__ == "__main__":
    unittest.main()
