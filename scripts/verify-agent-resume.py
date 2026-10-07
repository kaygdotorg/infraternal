#!/usr/bin/env python3
"""Retained unwritten input and legal interleaved Ack restart regression [13][41]."""
import argparse
import os
from pathlib import Path
import socket
import struct
import sys
import threading
sys.dont_write_bytecode = True
from agent_fixture import AckBarrier, Binary, cleanup, exact


class StateBarrier(AckBarrier):
    """Observe accepted state, then delay restart StateRequest until a real Ack."""
    def __init__(self, *args):
        self.observed = threading.Event()
        self.interleaved = threading.Event()
        self.restart = False
        self.probe = False
        self.state = None
        super().__init__(*args)

    def forward(self, source, destination, direction):
        try:
            while not self.stopped:
                prefix = exact(source, 4)
                body = exact(source, struct.unpack('<I', prefix)[0])
                if direction == 'input' and body[0] == 0x17 and len(body) > 500000 and not self.restart:
                    destination.sendall(prefix + body)
                    self.probe = True
                    destination.sendall(struct.pack('<I', 1) + b'\x19')
                    continue
                if direction == 'output' and body[0] == 0x1a and self.probe:
                    self.state = struct.unpack('<QQ', body[1:])
                    self.probe = False
                    self.observed.set()
                    continue
                if direction == 'input' and body[0] == 0x19 and self.restart:
                    self.held.set()
                    assert self.release.wait(20)
                destination.sendall(prefix + body)
                if direction == 'output' and body[0] == 0x18 and self.restart:
                    self.interleaved.set()
        except (EOFError, OSError):
            pass
        finally:
            for peer in (source, destination):
                try:
                    peer.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


def run(binary):
    state = Path(f'target/tr{os.getpid()}')
    state.mkdir(mode=0o700)
    client = Binary(binary.resolve(), state)
    barrier = None
    try:
        client.open()
        barrier = StateBarrier(state, client.id)
        client.attach()
        client.until(b'shim-test')
        fifo = state.resolve() / 'read-gate'
        os.mkfifo(fifo)
        payload = b'z' * 524288
        # The shell cannot read PTY input until the FIFO is opened by the oracle.
        # Read the whole payload before writing output, so State can be requested
        # while the retained queue drains without output socket backpressure.
        program = (f"import os; print('READY_'+'OK', flush=True); open('{fifo}').read(1); "
                   f"data=b''\nwhile len(data)<{len(payload)}: data+=os.read(0,{len(payload)}-len(data))\n"
                   "os.write(1,data); os.execlp('cat','cat')")
        import shlex
        client.input(("stty raw -echo; python3 -c " + shlex.quote(program) + "\n").encode())
        client.until(b'READY_OK')
        client.wait_ack()
        cursor = client.entered
        client.data.clear()
        client.input(payload)
        assert barrier.observed.wait(20)
        written, accepted = barrier.state
        assert accepted == client.entered and accepted - written > 400000, barrier.state
        client.kill()
        barrier.restart = True
        client.start()
        client.send(1, 0x16, client.id.bytes + struct.pack('<QQ', client.out, client.acked))
        client.send(1, 0x14, struct.pack('<I', 1048576))
        assert barrier.held.wait(20)
        with fifo.open('w') as gate:
            gate.write('x')
        assert barrier.interleaved.wait(20), 'no retained-input Ack before StateRequest'
        barrier.release.set()
        client.send(1, 0x10, struct.pack('<Q', cursor) + payload)
        fence = b'<RESTART_FENCE>'
        client.input(fence)
        while len(client.data) < len(payload) + len(fence) or client.acked < client.entered:
            client.process()
        assert client.data == payload + fence, (len(client.data), client.data[:40], client.data[-40:])
        print(f'abrupt stop/restart: accepted={accepted}, written={written}, surviving unwritten={accepted-written}; real Ack before State; {len(payload)} replay bytes exactly once: PASS', flush=True)
    finally:
        if barrier:
            barrier.close()
        if client.child.poll() is None:
            client.kill()
        cleanup(state)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    run(parser.parse_args().binary)
