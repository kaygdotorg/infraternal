#!/usr/bin/env python3
"""A resumed browser that reuses its stream id gets its replay from its own cursor (#477).

Real binary, real PTY. The client opens the browser's window (1 MiB plus the
64 KiB repaint reserve, in one Credit), floods bounded output, reads about 256 KiB without
returning credit, and types one key. That key's repaint goes out on the
writer's priority lane and marks raw output below the relay's cursor as
covered. The client then closes the stream, as the server does when a browser
socket drops, and attaches the same stream id again at the offset it had
actually received, as a resumed browser does.

Exact delivery requires the first replayed Output to start at that offset.
Before the fix the writer kept the old attachment's cover cursor, so the
replay began hundreds of KiB later, or never arrived at all: the server then
retired the stream ("reader fell behind") and the browser showed a blank or
frozen terminal.
"""
import argparse
from pathlib import Path
import select
import struct
import sys
import time

sys.dont_write_bytecode = True
from agent_fixture import Binary, HANG, cleanup, fixture_state, varint

# The browser's opening grant: the 1 MiB bulk window plus the 64 KiB it keeps
# for a key repaint (D381), sent as one Credit on every attach.
BROWSER_OPENING = 1024 * 1024 + 64 * 1024
# Read this much flood before typing, so the key lands mid-flood with output parked.
READ_BEFORE_KEY = 256 * 1024
# Replayed bytes that prove the resumed stream is contiguous from its cursor.
REPLAY_PROOF = 64 * 1024
# The flood: `seq 1 150000` is about 1.09 MB after onlcr, so the reattach at
# about 256 KiB is some 0.83 MB behind. That stays under the shim's
# snapshot-first threshold (1 MiB, #583): a shell exports exactly since #521,
# and a reattach further behind would rightly get the screen first instead of
# the raw replay this test is about.
FLOOD = b"seq 1 150000\n"
# Use the shared fixture bound: control replies can take longer than 20 seconds
# under gate load.


def next_frame(client, deadline, what, credit):
    """Process one frame, failing with `what` instead of blocking forever when none comes by `deadline`."""
    remaining = deadline - time.monotonic()
    assert remaining > 0 and select.select([client.sock], [], [], remaining)[0], what
    client.process(credit=credit)


def attach_like_a_browser(client):
    """Attach at the client's cursors and grant the browser's whole opening window in one Credit."""
    client.send(client.stream, 0x16, client.id.bytes + struct.pack('<QQ', client.out, client.acked))
    client.credit_pending = 0
    client.credit_available = BROWSER_OPENING
    client.send(client.stream, 0x14, struct.pack('<I', BROWSER_OPENING))
    client.process()


def run(binary):
    """Check that a key repaint does not move a resumed stream past its own cursor."""
    state = fixture_state('rr')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    try:
        client.open()
        attach_like_a_browser(client)
        client.wait_for_shell()
        client.input(FLOOD)
        while client.out < READ_BEFORE_KEY:
            client.process(credit=False)
        resume_at = client.out
        client.input(b'k')
        deadline = time.monotonic() + HANG
        while client.acked < client.entered or not client.snapshots:
            next_frame(client, deadline, ('the key got no Ack and repaint', client.acked, client.entered, client.snapshots), credit=False)
        repainted_through = client.snapshots[-1][0]
        # Leave the stream the way the server does for a dropped socket, then
        # resume the same stream id at the cursor this client really received.
        client.send(client.stream, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
        client.fence()
        client.out = resume_at
        client.data.clear()
        client.snapshots.clear()
        attach_like_a_browser(client)
        deadline = time.monotonic() + HANG
        while len(client.data) < REPLAY_PROOF and not client.snapshots:
            # `process` asserts every Output starts exactly at `client.out`.
            next_frame(client, deadline, f'no replay from {resume_at} after reattach (key repaint covered through {repainted_through}); got {len(client.data)} bytes', credit=True)
        assert not client.snapshots, f'the replay from {resume_at} was answered by a Snapshot {client.snapshots}; the ring must still hold it'
        print(f'Reattach after a key repaint: replay resumed at {resume_at} (repaint had covered through {repainted_through}), {len(client.data)} contiguous bytes: PASS')
    finally:
        client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    run(parser.parse_args().binary)
