#!/usr/bin/env python3
"""Use real PTY stty to verify that newly accepted input selects each device's size [74].

Device B attaches from cursor 0, so its replay holds bytes the shell wrote at
device A's 80x24. When B then reports 120x40 while A owns the size, the shim
replaces that replay with one repaint of its screen, announced by one
approximate `terminal.snapshot` notice (#521); B must get exactly one. B used
to attach at A's read cursor, which made the repaint depend on whether the
shell's next prompt had reached A yet, and the probe failed about one run in
four on the unexpected notice (J813).
"""
import sys
sys.dont_write_bytecode = True
import os
from pathlib import Path
import struct
from agent_fixture import Binary, cleanup, event_object, fixture_state, replay_complete_cursor

state = fixture_state('mz')
state.mkdir(mode=0o700)
c = Binary(Path(sys.argv[sys.argv.index('--binary') + 1]).resolve(), state)
try:
    c.open(); c.attach(); c.wait_for_shell()
    c.send(2, 0x16, c.id.bytes + struct.pack('<QQ', 0, 0))
    c.send(2, 0x14, struct.pack('<I', 1048576))
    output = {1: bytearray(), 2: bytearray()}
    repaints = {1: 0, 2: 0}
    notices = []
    def receive():
        s, kind, body = c.read_without_inventory()
        if kind == 0x33:
            event = event_object(body)
            if event.get('type') == 'terminal.snapshot':
                assert event.get('session_id') == str(c.id), event
                assert event.get('approximate') is True, event
                notices.append(s)
            else:
                replay_complete_cursor(event, c.id)
        elif kind == 0x11:
            # Initial 1 MiB per viewer covers these tiny observations. Refunding
            # each prompt fragment can fill the deliberate eight-command queue.
            output[s].extend(body[8:])
            assert len(output[s]) < 1024 * 1024, 'geometry probe exceeded bounded initial credit'
        elif kind == 0x15:
            # A Snapshot replaces the viewer's screen; later output follows it.
            repaints[s] += 1
            output[s] = bytearray(body[8:])
        elif kind == 0x13:
            return s, struct.unpack('<Q', body)[0]
        else:
            raise AssertionError((s, kind))
        return None
    while receive() != (2, 0): pass
    c.send(1, 0x12, struct.pack('<HHHH', 80, 24, 0, 0))
    c.send(2, 0x12, struct.pack('<HHHH', 120, 40, 0, 0))
    c.send(1, 0x10, struct.pack('<Q', c.entered) + b'stty size\n')
    while any(b'24 80' not in value for value in output.values()): receive()
    c.send(2, 0x10, struct.pack('<Q', 0) + b'stty size\n')
    while any(b'40 120' not in value for value in output.values()): receive()
    assert repaints == {1: 0, 2: 1}, ('only the reopened device B gets one repaint', repaints)
    assert len(notices) == 1, ('one approximate repaint notice', notices)
    print('last typist real PTY: PASS; device A reports 24x80, device B reports 40x120 in both viewers')
finally:
    c.kill(); cleanup(state)
