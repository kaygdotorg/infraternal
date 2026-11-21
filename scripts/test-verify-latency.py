#!/usr/bin/env python3
"""Keep the real-PTY latency fixture's visible marker state correct across repaints [#477]."""
import importlib.util
from pathlib import Path
import struct
import sys
from unittest.mock import patch
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


class OutputFrame:
    """Supply one raw output frame and record credit returned after its paint."""

    def __init__(self, payload):
        """Keep the sequenced output bytes and collect Credit frames from the fixture."""
        self.payload = payload
        self.credits = []

    def read(self):
        """Return one raw output frame for the fixture's stream parser."""
        return 7, 0x11, struct.pack("<Q", 0) + self.payload

    def send(self, stream, kind, body):
        """Record the flow-control frame returned to this output's stream."""
        self.credits.append((stream, kind, body))


class OneOutputFrame(OutputFrame):
    """Return one output frame, then reject any read after a completed paint."""

    def __init__(self, payload):
        """Keep one frame and count fixture reads."""
        super().__init__(payload)
        self.reads = 0
        # paint_if_due needs a socket to reach the patched timeout boundary.
        self.sock = object()

    def read(self):
        """Return the output once and expose a blocking read after it."""
        self.reads += 1
        if self.reads > 1:
            raise AssertionError("fixture read again after the painted echo was settled")
        return super().read()


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

        streams = {7: state}
        verify_latency.frame(client, streams)
        verify_latency.paint_frame(client, streams)

        self.assertNotIn(marker, repaint, "screen text is interleaved with cursor controls")
        self.assertEqual(state["recent_output"], bytearray(visible))
        self.assertIn(marker, state["recent_output"])
        self.assertEqual(state["token"], 42)
        self.assertEqual(client.credits, [(7, 0x14, struct.pack("<I", len(repaint)))])


class PaintCreditTests(unittest.TestCase):
    """Ensure the fixture returns output credit only at its simulated paint boundary."""

    def test_output_credit_and_echo_settlement_wait_for_paint(self):
        """Parsing visible output does not send credit or finish a key before paint."""
        payload = b"<K000001>"
        client = OutputFrame(payload)
        state = {
            "out": 0,
            "output_bytes": 0,
            "echoes": 0,
            "token": 0,
            "token_tail": b"",
            "recent_output": bytearray(),
            "echo_by_token": True,
            "pending_echo": [1, 0.0, None],
            "paint_credit_pending": 0,
        }
        streams = {7: state}

        verify_latency.frame(client, streams)

        self.assertEqual(client.credits, [])
        self.assertIsNone(state["pending_echo"][2])

        verify_latency.paint_frame(client, streams)

        self.assertEqual(client.credits, [(7, 0x14, struct.pack("<I", len(payload)))])
        self.assertIsNotNone(state["pending_echo"][2])

    def test_paint_settles_echo_before_waiting_for_another_wire_frame(self):
        """A completed simulated paint returns control without reading a new frame."""
        payload = b"<K000001>"
        client = OneOutputFrame(payload)
        state = {
            "out": 0,
            "output_bytes": 0,
            "echoes": 0,
            "token": 0,
            "token_tail": b"",
            "recent_output": bytearray(),
            "echo_by_token": True,
            "pending_echo": [1, 0.0, None],
            "paint_credit_pending": 0,
        }
        streams = {7: state}

        with patch.object(verify_latency.time, "monotonic", return_value=10.0), patch.object(
            verify_latency.select, "select", return_value=([], [], [])
        ):
            verify_latency.frame(client, streams)
            verify_latency.frame(client, streams)

        self.assertEqual(client.reads, 1)
        self.assertEqual(client.credits, [(7, 0x14, struct.pack("<I", len(payload)))])
        self.assertIsNotNone(state["pending_echo"][2])


if __name__ == "__main__":
    unittest.main()
