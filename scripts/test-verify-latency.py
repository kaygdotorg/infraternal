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

    def test_snapshot_restores_visible_marker_and_token_from_encoded_repaint(self):
        """Strip per-cell terminal controls before searching the repainted screen."""
        marker = b"__FLOOD_STOPPED__"
        visible = b"screen contents " + marker + b" <K000042>"
        repaint = b"\x1bc\x1b(B\x0f" + b"".join(
            b"\x1b[24;" + str(column).encode() + b"H\x1b[0m" + bytes((character,))
            for column, character in enumerate(visible, 1)
        )
        client = SnapshotFrame(repaint)
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

        self.assertNotIn(marker, repaint, "screen text is interleaved with cursor controls")
        self.assertEqual(state["recent_output"], bytearray(visible))
        self.assertIn(marker, state["recent_output"])
        self.assertEqual(state["token"], 42)
        self.assertEqual(client.credits, [(7, 0x14, struct.pack("<I", len(repaint)))])


if __name__ == "__main__":
    unittest.main()
