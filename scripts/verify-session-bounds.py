#!/usr/bin/env python3
"""Real local lifecycle, trusted background counts and memory admission regressions [D178,D214], #151."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import time

sys.dont_write_bytecode = True
from agent_fixture import HANG, Binary, cleanup, exact, fixture_state, varint


def run(binary):
    state = fixture_state('b')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    call_id = 150

    def call(action, input):
        nonlocal call_id
        call_id += 1
        encoded = action.encode()
        client.send(0, 0x30, struct.pack('<I', call_id) + varint(len(encoded)) + encoded + json.dumps(input).encode())
        while True:
            frame = client.read()
            if frame[:2] == (0, 0x31):
                body = frame[2]
                assert struct.unpack('<I', body[:4])[0] == call_id
                return body[4] == 1, json.loads(body[5:])
            client.process(frame=frame)

    def counts(total, background):
        deadline = time.monotonic() + 1
        while True:
            ok, facts = call('host.facts.read', {})
            assert ok
            # Missing counters fail immediately, instead of turning an absent contract into a timeout.
            actual = facts['sessionCount'], facts['backgroundSessionCount']
            if actual == (total, background):
                return
            assert time.monotonic() < deadline, (actual, total, background)
            time.sleep(.01)

    def kill_shell(id):
        path = state / 'sessions' / f'{id.hex}.sock'
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(2)
            peer.connect(str(path))
            hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
        assert hello[11:27] == id.bytes
        pid = struct.unpack('<I', hello[27:31])[0]
        children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
        assert len(children) == 1
        os.kill(int(children[0]), signal.SIGKILL)
        return path, pid, time.monotonic()

    def process_active(pid):
        try:
            return Path(f'/proc/{pid}/exe').exists()
        except PermissionError:
            # A live daemon can deny executable inspection while dumpability is disabled.
            return True

    def retired(path, pid, started):
        """Wait for the dead shell's shim to retire: its socket and process gone.

        The wait ends on that event; HANG only detects a shim that never
        retires. The elapsed time is reported, not asserted: a one-second bound
        measured the host and failed under gate load (#355).
        """
        while path.exists() or process_active(pid):
            assert time.monotonic() - started < HANG, 'dead shim was never retired'
            time.sleep(.005)
        counts(0, 0)
        return (time.monotonic() - started) * 1000

    try:
        counts(0, 0)
        uid = os.getuid()
        ok, reason = call('terminal.open', dict(uid=uid, cols=0, rows=24))
        assert not ok and reason['reason'] == 'invalid'
        ok, _ = call('host.memory.configure', dict(terminalMemoryFloorMiB=17592186044415, terminalMemoryFloorPercent=5))
        assert ok
        ok, reason = call('terminal.open', dict(uid=uid, cols=80, rows=24))
        assert not ok and reason['reason'] == 'host_memory_low'
        assert reason['session_count'] == 0 and isinstance(reason['available_mib'], int)
        counts(0, 0)
        ok, _ = call('host.memory.configure', dict(terminalMemoryFloorMiB=256, terminalMemoryFloorPercent=5))
        assert ok
        client.open()
        counts(1, 1)
        path, pid, started = kill_shell(client.id)
        detached_ms = retired(path, pid, started)
        client.open()
        counts(1, 1)
        client.attach()
        client.wait_for_shell()
        counts(1, 0)
        client.send(1, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
        counts(1, 1)
        client.attach()
        counts(1, 0)
        path, pid, started = kill_shell(client.id)
        client.wait_event('terminal.exited')
        attached_ms = retired(path, pid, started)
        print(f'Local memory refusal, invalid dimensions, detach/reattach counts, exit delivery and registry retirement: PASS; detached={detached_ms:.1f} ms attached={attached_ms:.1f} ms; load={Path("/proc/loadavg").read_text().strip()}')
    finally:
        client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    run(parser.parse_args().binary)
