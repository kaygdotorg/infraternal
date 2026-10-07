#!/usr/bin/env python3
"""Saturate multiplexed terminal command queues against the real daemon [13][41]."""
import argparse
import sys

# Keep fixture imports from creating untracked bytecode in the worktree.
sys.dont_write_bytecode = True
import os
from pathlib import Path
import struct
import signal
import socket

from agent_fixture import AckBarrier, Binary, cleanup, exact, fixture_state


def run(binary):
    state = fixture_state('tq')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    barriers = []
    try:
        sessions = []
        for index in range(12):
            session = client.open()
            client.attach()
            client.until(b'shim-test')
            client.input(b"stty raw -echo; printf 'QUEUE_%s' READY; cat\n")
            client.until(b'QUEUE_READY')
            client.wait_ack()
            # Preparation uses writer 1. The later stream ids 2..12 are
            # new writers and must start at zero, even on an existing PTY.
            sessions.append((session, client.out, client.acked if index == 0 else 0))
            client.send(1, 0x0f, struct.pack('<H', 0) + b'\x04done')
        # Hold InputState, before the terminal task can drain even one command.
        # More than eight requests now deterministically fills the bounded queue.
        for stream, (session, out, ack) in enumerate(sessions, 1):
            barrier = AckBarrier(state, session, kind=0x1a)
            barrier.threshold = 0
            barriers.append(barrier)
            client.send(stream, 0x16, session.bytes + struct.pack('<QQ', out, ack))
            assert barrier.held.wait(20), 'terminal never reached handshake barrier'
        payloads = {stream: (sessions[stream - 1][2], f'session-{stream:02d}|'.encode() * 20000)
                    for stream in range(1, 13)}
        # Queue nine Inputs behind each held handshake: full-policy retires only
        # this attachment. Replay after release uses surviving shim cursors.
        for stream, (offset, payload) in payloads.items():
            for index in range(9):
                begin = index * len(payload) // 9
                end = (index + 1) * len(payload) // 9
                client.send(stream, 0x10, struct.pack('<Q', offset + begin) + payload[begin:end])
        closed = set()
        while len(closed) < len(payloads):
            stream, kind, _ = client.read()
            assert kind == 0x0f and stream in payloads, (stream, kind)
            closed.add(stream)
        assert client.child.poll() is None
        for barrier in barriers:
            barrier.release.set()
        outputs = {stream: bytearray() for stream in payloads}
        cursors = {stream: sessions[stream - 1][1] for stream in payloads}
        acknowledgments = {stream: 0 for stream in payloads}
        for stream, (session, out, ack) in enumerate(sessions, 1):
            client.send(stream, 0x16, session.bytes + struct.pack('<QQ', out, ack))
        # Admit batches below capacity; wait on PTY Acks before the next batch.
        # The whole original range is replayed even if prior acceptance raced
        # retirement, proving that refusal never silently loses input.
        for index in range(65):
            ends = {}
            for stream, (offset, payload) in payloads.items():
                begin = index * len(payload) // 65
                end = (index + 1) * len(payload) // 65
                ends[stream] = offset + end
                client.send(stream, 0x10, struct.pack('<Q', offset + begin) + payload[begin:end])
            while any(acknowledgments[stream] < end for stream, end in ends.items()):
                stream, kind, body = client.read()
                assert stream in outputs, (stream, kind)
                if kind == 0x11:
                    seq = struct.unpack('<Q', body[:8])[0]
                    assert seq == cursors[stream]
                    cursors[stream] += len(body) - 8
                    outputs[stream].extend(body[8:])
                elif kind == 0x13:
                    acknowledgments[stream] = struct.unpack('<Q', body)[0]
                else:
                    raise AssertionError((stream, kind, body))
        while any(len(outputs[stream]) < len(payload) for stream, (_, payload) in payloads.items()):
            stream, kind, body = client.read()
            if kind == 0x13:
                continue
            assert kind == 0x11 and struct.unpack('<Q', body[:8])[0] == cursors[stream]
            cursors[stream] += len(body) - 8
            outputs[stream].extend(body[8:])
        for stream, (_, payload) in payloads.items():
            assert outputs[stream] == payload
        client.send(0, 0x08, struct.pack('<QQ', 123, 456))
        assert client.read() == (0, 0x09, struct.pack('<QQ', 123, 456))
        # A genuinely dead shim must close its own stream, preserving siblings.
        dead = barriers[0]
        with socket.socket(socket.AF_UNIX) as peer:
            peer.connect(str(dead.real))
            hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
            os.kill(struct.unpack('<I', hello[27:31])[0], signal.SIGKILL)
        while True:
            stream, kind, _ = client.read()
            if stream == 1 and kind == 0x0f:
                break
        client.send(0, 0x08, struct.pack('<QQ', 789, 101))
        assert client.read() == (0, 0x09, struct.pack('<QQ', 789, 101))
        print(f'queue overload: 12 streams retired then replayed x 65 Input frames; {sum(len(p) for _, p in payloads.values())} payload bytes exactly once; dead shim isolated; daemon Ping: PASS', flush=True)
    finally:
        for barrier in barriers:
            barrier.close()
        if client.child.poll() is None:
            client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    run(parser.parse_args().binary)
