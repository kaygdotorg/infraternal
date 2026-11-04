#!/usr/bin/env python3
"""Verify D314 CLI operations against real PTYs and caller-process authority (#251)."""
import json
from pathlib import Path
import shlex
import stat
import subprocess
import socket
import struct
import sys
import time

from agent_fixture import Binary, cleanup, fixture_state, exact

# Detects a hang only. Every wait below is for a condition (a reply, an exit,
# output); no CLI latency is asserted here. On a loaded gate VM a cold start of
# the debug binary alone took 3.6-9.7 s, so a tight guard measured the host (#334).
HANG = 120


def wait_for(condition, what):
    deadline = time.monotonic() + HANG
    while True:
        value = condition()
        if value:
            return value
        assert time.monotonic() < deadline, what
        time.sleep(0.05)


def read_until(binary, state, target, last, needle):
    """Read a session until its retained output contains needle; return that read."""
    def ready():
        read = cli(binary, state, 'read', target, '--last', last)
        return read if needle in read['data']['text'] else None
    return wait_for(ready, f'{target} never showed {needle!r}')


def cli(binary, state, *args, code=0):
    result = subprocess.run([binary, '--json', 'sessions', '--state', str(state), *args],
                            capture_output=True, timeout=HANG, check=False)
    reply = json.loads(result.stdout)
    assert result.returncode == code, (args, result.returncode, reply)
    assert reply['ok'] == (code == 0), reply
    return reply


def inside(binary, state):
    """These subprocesses descend from the real saved shell, not the test runner."""
    cli(binary, state, 'new', 'other-machine', '--name', 'denied', code=3)
    made = cli(binary, state, 'new', 'local', '--name', 'build')
    assert made['data']['session']['name'] == 'build', made
    missing_last = subprocess.run(
        [binary, '--json', 'sessions', '--state', str(state), 'read', 'local:build'],
        capture_output=True, text=True, timeout=HANG, check=False)
    missing_last_reply = json.loads(missing_last.stdout)
    cli(binary, state, 'new', 'local', '--name', 'build', code=2)
    rows = cli(binary, state)['data']['sessions']
    assert any(row['name'] == 'build' for row in rows), rows
    assert [row['id'] for row in rows] == sorted(row['id'] for row in rows), rows
    missing = cli(binary, state, 'send', 'local:biuld', 'x', code=4)
    assert 'Did you mean "build"?' in missing['message'], missing
    sent = cli(binary, state, 'send', 'local:build', "printf 'OUTPUT_%s\\n' READY\n")
    assert sent['data']['bytes_sent'] > 0
    cli(binary, state, 'send', 'local:build', "printf 'OUTPUT_%s\\n' SECOND\n")
    read = read_until(binary, state, 'local:build', '2', 'OUTPUT_SECOND')
    assert len(read['data']['text'].rstrip('\n').split('\n')) <= 2, read
    target = next(row for row in rows if row['name'] == 'build')
    with socket.socket(socket.AF_UNIX) as peer:
        peer.connect(str(state / 'sessions' / f"{target['id'].replace('-', '')}.sock"))
        hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
        shim_pid = struct.unpack('<I', hello[27:31])[0]
        assert struct.unpack('<Q', hello[3:11])[0] & 64, 'close capability missing'
        # A peer that did not negotiate close must be disconnected, without
        # touching the saved shell. Subsequent CLI reads prove it survived.
        peer.settimeout(2)
        for body in [b'\x02' + struct.pack('<Q', 0), b'\x1f']:
            peer.sendall(struct.pack('<I', len(body)) + body)
        assert peer.recv(1) == b'', 'unnegotiated close was accepted'
    shell_pid = (Path(f'/proc/{shim_pid}/task/{shim_pid}/children').read_text().split())[0]
    cli(binary, state, 'send', 'local:build', "sh -c \"printf 'FOREGROUND_%s\\\\n' READY; exec sleep 20\"\n")
    read_until(binary, state, 'local:build', '4', 'FOREGROUND_READY')
    cli(binary, state, 'close', 'local:build')
    # Without close the shell outlives its 20 s foreground job, so the hang
    # bound still separates a working close from a broken one.
    wait_for(lambda: not Path(f'/proc/{shell_pid}').exists(),
             'close left the saved shell running behind its foreground job')
    command = cli(binary, state, 'new', 'local', '--name', 'command', '--',
                  '/bin/sh', '-c', "printf 'ARGV_%s\\n' 'literal; safe'; sleep 20")
    assert command['data']['session']['name'] == 'command'
    read_until(binary, state, 'local:command', '3', 'ARGV_literal; safe')
    cli(binary, state, 'close', 'local:command')
    cli(binary, state, 'new', 'local', '--name', 'ended', '--',
        '/bin/sh', '-c', "printf 'RETAINED_%s\\n' DONE")
    # The command may not have run yet; retained output is the condition.
    read_until(binary, state, 'local:ended', '2', 'RETAINED_DONE')
    cli(binary, state, 'close', 'local:ended')
    return {'operations': ['list', 'new', 'send', 'read', 'close', 'new-command'],
            'authority': 'real saved-shell descendants; cross-machine denied',
            'missing_last_exit': missing_last.returncode,
            'missing_last_message': missing_last_reply.get('message')}


def main(binary):
    state = fixture_state('cs')
    state.mkdir(mode=0o700)
    fixture = None
    try:
        fixture = Binary(binary, state)
        cli(binary, state, code=3)  # CLI actions still require saved-shell ancestry.
        fixture.open()
        sessions_mode = stat.S_IMODE((state / 'sessions').stat().st_mode)
        assert sessions_mode == 0o700, f'session socket directory mode is {sessions_mode:04o}, expected 0700'
        receipt = state / 'receipt.json'
        argv = [sys.executable, str(Path(__file__).resolve()), '--inside', binary,
                str(state), str(receipt)]
        # open() already proves shell readiness. Bootstrap through its frozen
        # local shim protocol so this oracle does not depend on browser input cursors.
        with socket.socket(socket.AF_UNIX) as peer:
            peer.connect(str(state / 'sessions' / f'{fixture.id.hex}.sock'))
            hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
            assert hello[11:27] == fixture.id.bytes
            for body in [b'\x02' + struct.pack('<Q', 0),
                         b'\x10' + (' '.join(map(shlex.quote, argv)) + '\n').encode()]:
                peer.sendall(struct.pack('<I', len(body)) + body)
        deadline = time.monotonic() + 5 * HANG
        while not receipt.exists():
            assert time.monotonic() < deadline, 'saved-shell test receipt timed out'
            time.sleep(0.05)
        reply = json.loads(receipt.read_text())
        assert reply['ok'], reply
        assert reply['missing_last_exit'] == 2, (
            f"sessions read without --last exited {reply['missing_last_exit']} "
            f"({reply['missing_last_message']!r}), expected usage code 2")
        print(json.dumps(reply))
    finally:
        if fixture:
            fixture.kill()
        cleanup(state)


if __name__ == '__main__':
    if sys.argv[1] == '--inside':
        try:
            answer = {'ok': True, **inside(sys.argv[2], Path(sys.argv[3]))}
        except Exception as error:  # Always return evidence to the outer fixture.
            answer = {'ok': False, 'error': repr(error)}
        Path(sys.argv[4]).write_text(json.dumps(answer))
    else:
        main(str(Path(sys.argv[1]).resolve()))
