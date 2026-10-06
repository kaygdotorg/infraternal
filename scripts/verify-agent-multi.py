"""Real leg-B multi-writer oracle: independent Acks, simultaneous views and crash replay."""
import sys
sys.dont_write_bytecode = True
import os
from pathlib import Path
import struct
import time
sys.path.insert(0, 'scripts')
from agent_fixture import Binary, cleanup

state = Path(f'target/mw{os.getpid()}')
state.mkdir(mode=0o700)
c = Binary(Path(sys.argv[sys.argv.index('--binary') + 1]).resolve(), state)
try:
    c.open(); c.attach(); c.send(1, 0x14, struct.pack('<I', 1048576)); c.until(b'shim-test')
    c.input(b"stty raw -echo; printf 'MULTI_%s' READY; cat\n")
    c.until(b'MULTI_READY'); c.wait_ack()
    start = c.entered
    offsets = {1: c.out, 2: c.out}
    acks = {1: start, 2: 0}
    data = {1: bytearray(), 2: bytearray()}
    c.send(2, 0x16, c.id.bytes + struct.pack('<QQ', c.out, 0))
    c.send(2, 0x14, struct.pack('<I', 1048576))
    def receive():
        stream, kind, body = c.read()
        assert stream in acks, (stream, kind)
        if kind == 0x13:
            ack = struct.unpack('<Q', body)[0]
            assert ack >= acks[stream]
            acks[stream] = ack
        elif kind == 0x11:
            seq = struct.unpack('<Q', body[:8])[0]
            assert seq == offsets[stream], (stream, seq, offsets[stream])
            offsets[stream] += len(body)-8
            data[stream].extend(body[8:])
            c.send(stream, 0x14, struct.pack('<I', len(body)-8))
        elif kind == 0x15:
            offsets[stream] = struct.unpack('<Q',body[:8])[0]
        else:
            raise AssertionError((stream, kind))
        return stream, kind
    while True:
        stream, kind = receive()
        if (stream, kind) == (2, 0x13):
            assert acks[2] == 0, 'device 2 inherited device 1 Ack'
            break
    payloads = [b'<DEVICE_ONE>', b'<DEVICE_TWO>']
    c.send(1, 0x10, struct.pack('<Q', start)+payloads[0])
    c.send(2, 0x10, struct.pack('<Q', 0)+payloads[1])
    targets = {1: start+len(payloads[0]), 2: len(payloads[1])}
    expected = b''.join(payloads)
    while any(acks[s] < targets[s] or len(data[s]) < len(expected) for s in acks): receive()
    assert bytes(data[1]) in (expected, b''.join(reversed(payloads))), 'lost/duplicate multi-device bytes'
    expected = bytes(data[1])
    assert bytes(data[2]) == expected, 'viewers disagree about PTY output'
    # Kill after real PTY writes and replay full ranges, including acknowledged input.
    c.kill(); c.start()
    for s in acks:
        c.send(s, 0x16, c.id.bytes+struct.pack('<QQ',offsets[s],targets[s]))
        c.send(s, 0x14, struct.pack('<I',1048576))
    for s, seq, payload in [(1,start,payloads[0]),(2,0,payloads[1])]:
        c.send(s,0x10,struct.pack('<Q',seq)+payload)
    fence=b'<AFTER_CRASH>'
    c.send(2,0x10,struct.pack('<Q',targets[2])+fence)
    while acks[2] < targets[2]+len(fence) or any(len(d) < len(expected)+len(fence) for d in data.values()): receive()
    assert all(bytes(d)==expected+fence for d in data.values()), 'crash replay duplicated/lost bytes'
    print(f'multi-device real PTY: PASS; second writer starts Ack0 after first Ack{start}; both viewers receive exactly {len(expected)+len(fence)} bytes; independent Acks and full-range crash replay')
finally:
    c.kill(); cleanup(state)
