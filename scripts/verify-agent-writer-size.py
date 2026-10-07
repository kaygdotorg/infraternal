#!/usr/bin/env python3
"""Use real PTY stty to verify that newly accepted input selects each device's size [74]."""
import sys
sys.dont_write_bytecode = True
import os
from pathlib import Path
import struct
from agent_fixture import Binary, cleanup, fixture_state

state = fixture_state('mz')
state.mkdir(mode=0o700)
c = Binary(Path(sys.argv[sys.argv.index('--binary') + 1]).resolve(), state)
try:
    c.open(); c.attach(); c.until(b'shim-test')
    c.send(2, 0x16, c.id.bytes + struct.pack('<QQ', c.out, 0))
    c.send(2, 0x14, struct.pack('<I', 1048576))
    output = {1: bytearray(), 2: bytearray()}
    def receive():
        s, kind, body = c.read()
        if kind == 0x11:
            # Initial 1 MiB per viewer covers these tiny observations. Refunding
            # each prompt fragment can fill the deliberate eight-command queue.
            output[s].extend(body[8:])
            assert len(output[s]) < 1024 * 1024, 'geometry probe exceeded bounded initial credit'
        elif kind == 0x13:
            return s, struct.unpack('<Q', body)[0]
        else:
            raise AssertionError((s, kind))
        return None
    while receive() != (2, 0): pass
    c.send(1, 0x12, struct.pack('<HHHH', 80, 24, 0, 0))
    c.send(2, 0x12, struct.pack('<HHHH', 120, 40, 0, 0))
    c.send(1, 0x10, struct.pack('<Q', 0) + b'stty size\n')
    while any(b'24 80' not in value for value in output.values()): receive()
    c.send(2, 0x10, struct.pack('<Q', 0) + b'stty size\n')
    while any(b'40 120' not in value for value in output.values()): receive()
    print('last typist real PTY: PASS; device A reports 24x80, device B reports 40x120 in both viewers')
finally:
    c.kill(); cleanup(state)
