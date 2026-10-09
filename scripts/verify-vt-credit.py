"""Real partial-credit repaint detachment and producer progress for #26/#118 [13][41]."""
import os
from pathlib import Path
import struct
import sys
import time

sys.dont_write_bytecode = True
from agent_fixture import Binary, cleanup, fixture_state, varint
from credit_fixture import CreditObservation, completed

binary = Path(sys.argv[1]).resolve()
grant = int(sys.argv[2]) if len(sys.argv) > 2 else 1
faithful = len(sys.argv) > 3 and sys.argv[3] == 'faithful'
state = fixture_state('vc')
state.mkdir(mode=0o700, exist_ok=True)
client = Binary(binary, state)
observation = None
hold_fd = None
try:
    client.open()
    client.attach()
    client.until(b'shim-test')
    client.input(b"stty -echo -opost; PS1=''; printf 'READY_%s' OK\n")
    client.until(b'READY_OK')
    client.wait_ack()
    # Retire the startup viewer before installing the existing real-shim proxy.
    client.send(1, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
    client.fence()
    observation = CreditObservation(state, client.id)
    client.attach()
    client.wait_ack()
    # Restore the measured window exactly; no startup output follows READY_OK.
    if client.credit_pending:
        client.send(1, 0x14, struct.pack('<I', client.credit_pending))
        client.credit_pending = 0
    hold = state / 'hold'
    os.mkfifo(hold)
    # Opening both ends is nonblocking. The emitter reads one release line, so
    # neither test failure nor delayed scheduling can strand the FIFO writer.
    hold_fd = os.open(hold, os.O_RDWR | os.O_NONBLOCK)
    ready = state / 'ready'
    done = state / 'done'
    emitter = state / 'emit.py'
    payload = ((b'A' * 78 + b'\r\n') * (12 * 1024 * 1024 // 80 + 1)
               if faithful else b'A' * (12 * 1024 * 1024))
    fixture = state / 'output.vt'
    fixture.write_bytes(bytes([27]) + b'c' + payload)
    emitter.write_text(
        '"""Controlled output progress fixture."""\nimport sys\nfrom pathlib import Path\n'
        f'sys.stdout.buffer.write(Path({str(fixture.resolve())!r}).read_bytes());'
        f'sys.stdout.buffer.flush();Path({str(ready.resolve())!r}).touch()\n'
        f'open({str(hold.resolve())!r}).readline()\n'
        'sys.stdout.buffer.write(b"B"*(2*1024*1024));sys.stdout.buffer.flush();'
        f'Path({str(done.resolve())!r}).touch()\n')
    client.input(f'python3 {emitter.resolve()}\n'.encode())
    client.drain_credit()
    observation.detached_after(0)
    completed(ready)
    client.fence()
    cursor = client.out
    disconnects = observation.disconnects
    repaints = len(observation.repaints)
    client.send(1, 0x14, struct.pack('<I', grant))
    # Observe the attempted repaint and actual EOF, not a sleep after Credit.
    # The exact 249/250ms timer boundary remains covered by relay unit tests.
    observation.detached_after(disconnects)
    assert len(observation.repaints) == repaints + 1
    assert observation.repaints[-1] > grant, 'fixture must attempt an unaffordable repaint'
    client.fence()
    assert not client.events and not client.snapshots, 'no approximation is announced before forwarding'
    assert client.out == cursor, 'unforwarded repaint must preserve the client cursor'
    start = time.monotonic()
    os.write(hold_fd, b'resume\n')
    completed(done)
    client.fence()
    assert client.out == cursor, 'detached producer output must preserve the client cursor'
    print(f'partial-credit progress: grant={grant} bytes faithful={faithful} '
          f'producer=2097152 bytes completed=True elapsed_ms={(time.monotonic()-start)*1000:.1f} '
          f'notices={len(client.events)} repaints={len(client.snapshots)}', flush=True)
    client.send(1, 0x14, struct.pack('<I', 1024 * 1024))
    while not client.snapshots:
        client.process(credit=False)
    client.fence()
    assert len(client.snapshots) == 1, 'sufficient credit must recover the current head'
    notices = [event for event in client.events if event.get('type') == 'terminal.snapshot']
    assert len(notices) <= 1, 'one forwarded repaint has at most one approximation notice'
    print('partial-credit recovery PASS', flush=True)
finally:
    if hold_fd is not None:
        os.close(hold_fd)
    client.kill()
    if observation is not None:
        observation.close()
    cleanup(state)
