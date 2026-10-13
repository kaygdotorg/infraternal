#!/usr/bin/env python3
"""Verify D255 shim-first SSH pipes and same-writer handover with the real binary, without timing claims."""
import argparse
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import uuid

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, fixture_state, varint


class Pipes:
    """Supply the fixture socket interface over the bridge's exclusive pipes."""
    def __init__(self, child):
        self.child = child
        self.timeout = 20

    def settimeout(self, value):
        self.timeout = value

    def gettimeout(self):
        return self.timeout

    def recv(self, size):
        assert select.select([self.child.stdout], [], [], self.timeout)[0], 'bridge did not answer'
        return os.read(self.child.stdout.fileno(), size)

    def sendall(self, data):
        self.child.stdin.write(data)
        self.child.stdin.flush()

    def close(self):
        self.child.stdin.close()
        self.child.stdout.close()


class Writer(Binary):
    """Keep the identical even leg-B writer through both actual processes."""
    def send(self, stream, kind, body=b''):
        super().send(2 if stream == 1 else stream, kind, body)
        if stream == 1 and kind == 0x14:
            self.credit_available += struct.unpack('<I', body)[0]

    def read(self):
        stream, kind, body = super().read()
        return (1 if stream == 2 else stream), kind, body


class Bridge(Writer):
    """Launch the real hidden SSH command and retain its canonical session receipt."""
    def start(self):
        env = dict(os.environ, ZDOTDIR=str(Path('crates/infraternal/tests/profile').resolve()))
        self.child = subprocess.Popen(
            [str(self.binary), '__ssh-session', '--state', str(self.state)],
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.sock = Pipes(self.child)
        receipt = bytearray()
        while not receipt.endswith(b'\n') and len(receipt) < 64:
            receipt.extend(self.sock.recv(1))
        assert receipt.startswith(b'SESSION ') and len(receipt) == 45, 'invalid session receipt'
        self.id = uuid.UUID(receipt[8:-1].decode())
        assert self.read()[:2] == (0, 0), 'bridge hello missing'
        self.send(0, 0, struct.pack('<HQ', 1, 0) + varint(6) + b'tracer')
        self.ping(0, 0)


def run(binary):
    state = fixture_state('ss')
    state.mkdir(mode=0o700)
    bridge = installed = None
    try:
        bridge = Bridge(binary, state)
        bridge.attach()
        bridge.until(b'shim-test')
        bridge.input(b"printf 'BEFORE_%s\\n' HANDOVER\n")
        bridge.until(b'BEFORE_HANDOVER\r\n')
        bridge.wait_ack()
        session = bridge.id
        out, entered, acked = bridge.out, bridge.entered, bridge.acked
        # Lose the transport without receiving the next input acknowledgment.
        # Replaying this exact input must execute it once through the same writer.
        pending = b"printf 'PENDING_%s\\n' EXACTLY_ONCE\n"
        bridge.input(pending)
        bridge.kill()
        bridge = None
        installed = Writer(binary, state)
        installed.id = session
        installed.out, installed.entered, installed.acked = out, entered, acked
        installed.attach()
        installed.input(pending)
        installed.until(b'PENDING_EXACTLY_ONCE\r\n')
        installed.wait_ack()
        installed.input(b"printf 'AFTER_%s\\n' HANDOVER\n")
        installed.until(b'AFTER_HANDOVER\r\n')
        installed.wait_ack()
        assert installed.data.count(b'PENDING_EXACTLY_ONCE\r\n') == 1, 'input replay duplicated execution'
        assert installed.id == session
        installed.input(b'exit\n')
        installed.wait_event('terminal.exited')
        print('PASS: shim-owned early shell; same session/writer; pending input executes once; output resumes')
    finally:
        if bridge is not None:
            bridge.kill()
        if installed is not None:
            installed.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    args = parser.parse_args()
    run(args.binary.resolve())
