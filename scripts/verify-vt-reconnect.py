#!/usr/bin/env python3
"""Real shim/infraternal-agent replay, ring-gap and legacy-limit regressions [13][41]."""
import argparse
import os
from pathlib import Path
import socket
import select
import struct
import sys
import time
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path('scripts').resolve()))
from agent_fixture import AckBarrier, Binary, cleanup, exact, fixture_state


def local(state, identity, caps, kind, payload=b''):
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(10)
        peer.connect(str(state / 'sessions' / (identity.hex + '.sock')))
        hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
        head, start = struct.unpack('<QQ', hello[43:59])
        peer.sendall(struct.pack('<I', 9) + bytes([2]) + struct.pack('<Q', caps))
        peer.sendall(struct.pack('<I', 1 + len(payload)) + bytes([kind]) + payload)
        frame = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
        return head, start, frame


def emit_and_detach(client, state, content):
    fixture = state / 'output.vt'; fixture.write_bytes(content)
    hold = state / 'hold'
    ready = state / 'ready'
    for path in [hold, ready]:
        if path.exists(): path.unlink()
    os.mkfifo(hold)
    emitter = state / 'emit.py'
    emitter.write_text('"""Emit fixture completely, signal readiness, then hold terminal state."""\n'
        + f'import sys\nfrom pathlib import Path\nsys.stdout.buffer.write(Path({str(fixture.resolve())!r}).read_bytes())\nsys.stdout.buffer.flush()\nPath({str(ready.resolve())!r}).touch()\nopen({str(hold.resolve())!r}).read()\n')
    client.input(f'python3 {emitter.resolve()}\n'.encode()); client.wait_ack()
    client.kill()
    # Detachment lets output beyond the initial credit finish into the ring.
    deadline = time.monotonic() + 20
    while not ready.exists():
        assert time.monotonic() < deadline, 'emitter did not finish detached output'
        time.sleep(.01)
    time.sleep(.05)
    return hold


def release(hold):
    # Opening a FIFO only after readiness is bounded by the known live reader.
    with hold.open('w') as writer: writer.write('continue\n')


def run_case(binary, name, fixture):
    state = fixture_state('vr')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    proxy = None
    try:
        client.open(); client.attach(); client.until(b'shim-test'); client.wait_ack()
        client.input(b'stty -echo -opost\n'); client.wait_ack()
        # less's small capture needs harmless pre-reset output to exercise the
        # one-shot 1 MiB credit deadline. The final captured state is unchanged.
        content = (b'\r\n' * 600000 if name == 'less' else b'') + fixture
        hold = emit_and_detach(client, state, content)
        head, start, frame = local(state, client.id, 0, 0x14)
        assert start == 0, 'first fixture must retain every raw byte'
        assert frame[0] == 0x7f, 'fixture must exercise faithful Snapshot rejection'
        assert struct.unpack('<H', frame[1:3])[0] == 2, 'restoration gap must be distinguished from capacity'
        assert b'overflow' not in frame[3:], 'Unsupported reason must not claim frame overflow'
        client.start(); client.out = 0; client.data.clear()
        client.send(1, 0x16, client.id.bytes + struct.pack('<QQ', 0, client.acked))
        client.send(1, 0x14, struct.pack('<I', 1024 * 1024))
        while client.out < 1024 * 1024:
            client.process(credit=False)
        time.sleep(.4)
        client.send(1, 0x14, struct.pack('<I', 1024 * 1024))
        while client.out < head:
            client.process()
        assert not client.snapshots, 'retained-ring recovery must replay raw output'
        assert content in client.data, 'retained replay must include the complete fixture'
        print(f'reconnect {name}: retained bytes={head}; starvation replay PASS', flush=True)
        client.kill()
        _, _, approximate = local(state, client.id, 4, 0x14)
        assert approximate[0] == 0x1c and approximate[9] == 1, 'fallback must announce approximation'
        assert len(approximate) <= 1024 * 1024, 'fallback frame must remain bounded'
        print(f'reconnect {name}: direct approximate bytes={len(approximate)-10} PASS', flush=True)
        release(hold)
        client.start(); client.out = head; client.attach()
        # Force a real ring gap. Padding is emitted before the final reset and
        # capture, so it changes neither the captured rejection nor continuation.
        hold = emit_and_detach(client, state, b'\r\n' * (5 * 1024 * 1024) + fixture)
        head, start, frame = local(state, client.id, 0, 0x14)
        assert start > 0 and frame[0] == 0x7f, 'second fixture must combine a gap and Snapshot limit'
        client.start(); client.out = 0; client.data.clear(); client.events.clear(); client.snapshots.clear()
        client.send(1, 0x16, client.id.bytes + struct.pack('<QQ', 0, client.acked))
        client.send(1, 0x14, struct.pack('<I', 1024 * 1024))
        while not client.snapshots:
            client.process()
        notices = [event for event in client.events if event.get('type') == 'terminal.snapshot']
        assert len(notices) == 1 and notices[0]['approximate'] is True, 'mux approximation notice missing'
        assert notices[0]['seq'] == head == client.snapshots[0][0], 'notice/repaint head must agree'
        assert client.child.poll() is None, 'Snapshot limit must not kill infraternal agent'
        print(f'reconnect {name}: ring_start={start}; approximate head={head}; notices=1 PASS', flush=True)
        client.kill()
        proxy = AckBarrier(state, client.id, caps_mask=3)
        client.start(); client.out = 0; client.events.clear(); client.snapshots.clear()
        client.send(1, 0x16, client.id.bytes + struct.pack('<QQ', 0, client.acked))
        client.send(1, 0x14, struct.pack('<I', 1024 * 1024))
        while not any(event.get('type') == 'terminal.snapshot_unavailable' for event in client.events):
            client.process()
        assert not client.snapshots, 'legacy peer must not receive approximation'
        client.send(0, 0x08, struct.pack('<QQ', 123, 456))
        stream, kind, _ = client.read()
        assert (stream, kind) == (0, 0x09), 'legacy Snapshot rejection must leave daemon live'
        print(f'reconnect {name}: legacy limitation parks live stream; Ping PASS', flush=True)
        release(hold)
        client.input(b"printf '\\033cLIVE_%s\\n' RESET\n")
        # Input can trigger a retry before the PTY has produced its reset.
        # The real shim has one peer, so probing it would replace the daemon.
        # Keep the live stream and issue bounded explicit credit retries while
        # draining availability events; never abandon a partially read frame.
        deadline = time.monotonic() + 10
        while not client.snapshots:
            assert time.monotonic() < deadline, 'legacy reset never recovered'
            if select.select([client.sock], [], [], .05)[0]:
                client.process()
            else:
                client.send(1, 0x14, struct.pack('<I', 1024 * 1024))
        assert not any(event.get('approximate') for event in client.events), 'legacy retry must remain faithful'
        client.input(b"printf 'LIVE_%s\\n' AFTER\n"); client.until(b'LIVE_AFTER\n'); client.wait_ack()
        print(f'reconnect {name}: legacy retry and subsequent live output PASS', flush=True)
    finally:
        if client.child.poll() is None: client.kill()
        if proxy: proxy.close()
        cleanup(state)


def run(binary):
    wrapped = b'\x1bc' + b'A' * (80 * 27000) + b'VTEND'
    less = b'\x1bc' + Path('crates/infraternal-shim/tests/fixtures/review-less.vt').read_bytes()
    for name, fixture in [('wrapped', wrapped), ('less', less)]:
        run_case(binary, name, fixture)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    run(parser.parse_args().binary)
