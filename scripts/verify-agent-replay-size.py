#!/usr/bin/env python3
"""Replay fences preserve pre-Resize geometry across real PTY viewers (#257)."""
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, event_object, fixture_state


def run(binary):
    state = fixture_state('rs')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    try:
        client.open(cols=80, rows=24)
        cursors = {}

        def next_frame():
            stream, kind, body = client.read_without_inventory()
            if kind == 0x11:
                seq = struct.unpack('<Q', body[:8])[0]
                assert seq == cursors.get(stream, 0), (stream, seq, cursors)
                cursors[stream] = seq + len(body) - 8
            elif kind == 0x15:
                cursors[stream] = struct.unpack('<Q', body[:8])[0]
            elif kind == 0x33:
                event = event_object(body)
                if event['type'] == 'terminal.replay_complete':
                    assert int(event['out_seq']) == cursors.get(stream, 0), event
            return stream, kind, body

        def replay(stream, expected, resize=None):
            client.send(stream, 0x16, client.id.bytes + struct.pack('<QQ', 0, 0))
            # Ack proves Hello was captured; no output credit has been given.
            while True:
                s, kind, body = next_frame()
                if s != stream:
                    continue
                if kind == 0x13:
                    break
            if resize:
                client.send(stream, 0x12, struct.pack('<HHHH', *resize, 0, 0))
            client.send(stream, 0x14, struct.pack('<I', 1048576))
            while True:
                s, kind, body = next_frame()
                if s != stream:
                    continue
                if kind == 0x33:
                    event = event_object(body)
                    if event['type'] == 'terminal.replay_complete':
                        assert (event.get('cols'), event.get('rows')) == expected, event
                        return
                else:
                    assert kind in (0x11, 0x13, 0x15), kind

        def shim_fence(stream):
            # Terminal Pong crosses an ordered shim InputState fence, proving
            # the preceding Resize was handled before a new viewer attaches.
            expected = struct.pack('<QQ', stream, 0)
            client.send(stream, 0x08, expected)
            while True:
                s, kind, body = next_frame()
                if (s, kind) == (stream, 0x09):
                    assert body == expected
                    return

        replay(1, (80, 24), resize=(120, 40))
        client.send(1, 0x10, struct.pack('<Q', 0) + b' ')
        shim_fence(1)
        replay(3, (120, 40), resize=(60, 20))
        # A second writer's size becomes active when it accepts typing [74].
        client.send(3, 0x10, struct.pack('<Q', 0) + b' ')
        shim_fence(3)
        replay(5, (60, 20))
        print('real PTY replay geometry: PASS; fences 80x24 -> 120x40 -> 60x20; attaching Resize excluded')
    finally:
        client.kill()
        cleanup(state)


if __name__ == '__main__':
    run(Path(sys.argv[sys.argv.index('--binary') + 1]))
