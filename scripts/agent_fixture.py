#!/usr/bin/env python3
"""Shared real-binary socket and shim-barrier fixtures for issue #20 [13][41]."""
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import subprocess
import threading
import time
import uuid
from latency_proxy import LatencyConfig, LatencyDuplex


def fixture_state(label):
    """Return a short per-process private state path for real Unix-socket fixtures."""
    root = Path(os.environ.get(
        'INFRATERNAL_TEST_STATE_ROOT',
        Path.home() / '.cache/codex-scratch/infraternal',
    ))
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = root / f'{label}{os.getpid()}'
    socket_path = state / 'sessions' / ('a' * 32 + '.sock')
    # Linux sockaddr_un.sun_path includes the trailing NUL in its 108-byte bound.
    # AckBarrier also connects through a sibling .upstream socket with a longer suffix.
    paths = (socket_path, socket_path.with_suffix('.upstream'))
    longest = max(len(os.fsencode(path)) for path in paths)
    if longest >= 108:
        raise ValueError(f'test state path is too long for an AF_UNIX socket: {longest} bytes')
    return state


def varint(n):
    out = bytearray()
    while n >= 128:
        out.append((n & 127) | 128)
        n >>= 7
    out.append(n)
    return out


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise EOFError('binary closed connection')
        result.extend(part)
    return bytes(result)


def integer(sock):
    value = 0
    for shift in range(0, 35, 7):
        byte = exact(sock, 1)[0]
        value |= (byte & 127) << shift
        if not byte & 128:
            return value
    raise AssertionError('oversized varint')


def rss(pid):
    lines = Path(f'/proc/{pid}/status').read_text().splitlines()
    return next(int(line.split()[1]) for line in lines if line.startswith('VmRSS:'))


class Binary:
    def __init__(self, binary, state):
        self.state = state
        self.binary = binary
        self.out = 0
        self.entered = 0
        self.acked = 0
        self.data = bytearray()
        self.credit_batch = 64 * 1024
        self.credit_pending = 0
        self.events = []
        self.snapshots = []
        self.link = None
        self.start()

    def start(self):
        self.sock, test_peer = socket.socketpair()
        agent_peer, child_peer = socket.socketpair()
        self.sock.settimeout(20)
        config = LatencyConfig.from_environment()
        self.link = LatencyDuplex(test_peer, agent_peer, config)
        self.link.start()
        env = dict(os.environ, ZDOTDIR=str(Path('crates/infraternal/tests/profile').resolve()))
        # Shell duplication closes the original descriptor before exec; the
        # binary's launch wrapper later closes fd 3 before every shim exec.
        # Bash supports closing descriptor numbers above nine, which concurrent
        # fixtures can allocate; POSIX sh redirection only guarantees 0..9.
        self.child = subprocess.Popen([shutil.which('bash'), '-c', 'exec 3<&"$1"; eval "exec $1<&-"; shift; exec "$@"',
            'leg-b', str(child_peer.fileno()), str(self.binary), 'agent', '--fd', '3', '--state', str(self.state)],
            pass_fds=(child_peer.fileno(),), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        child_peer.close()
        stream, kind, _ = self.read()
        assert (stream, kind) == (0, 0)
        self.send(0, 0, struct.pack('<HQ', 1, 0) + varint(6) + b'tracer')
        # Hello is an inbound startup request. Fence it with a real Pong before
        # the scheduler canary starts; otherwise its wakeup is counted as idle.
        self.send(0, 0x08, struct.pack('<QQ', 0, 0))
        stream, kind, _ = self.read()
        assert (stream, kind) == (0, 0x09)

    def send(self, stream, kind, body=b''):
        self.sock.sendall(varint(stream) + varint(1 + len(body)) + bytes([kind]) + body)

    def read(self):
        try:
            stream = integer(self.sock)
            body = exact(self.sock, integer(self.sock))
            return stream, body[0], body[1:]
        except (OSError, EOFError) as error:
            try:
                self.child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise error
            # The daemon emits only static protocol/IO errors; shell output
            # travels exclusively over the fixture socket and is never logged.
            raise AssertionError(f'daemon exit {self.child.returncode}: {self.child.stderr.read().decode()}') from error

    def open(self, cols=80, rows=24):
        action = b'terminal.open'
        self.send(0, 0x30, struct.pack('<I', 1) + varint(len(action)) + action +
            json.dumps(dict(uid=os.getuid(), cols=cols, rows=rows)).encode())
        # A close can race output already queued on the old mux stream. Drain
        # those frames before reusing the stream; the action Result is the fence.
        while True:
            stream, kind, body = self.read()
            if (stream, kind) == (0, 0x31):
                break
            assert stream == 1
        assert (stream, kind) == (0, 0x31) and body[4] == 1, body
        self.id = uuid.UUID(json.loads(body[5:])['session_id'])
        self.out = self.entered = self.acked = 0
        self.credit_pending = 0
        self.data.clear()
        return self.id

    def attach(self):
        self.send(1, 0x16, self.id.bytes + struct.pack('<QQ', self.out, self.acked))
        # Each new attachment owns a fresh explicit credit window. Old batched
        # refunds cannot fund a new connection; no grant is implicit in Attach.
        self.credit_pending = 0
        self.send(1, 0x14, struct.pack('<I', 1048576))
        self.process()

    def input(self, data):
        seq = self.entered
        self.send(1, 0x10, struct.pack('<Q', seq) + data)
        self.entered += len(data)
        return seq

    def process(self, credit=True):
        stream, kind, body = self.read()
        assert stream == 1, (stream, kind)
        if kind == 0x11:
            seq = struct.unpack('<Q', body[:8])[0]
            assert seq == self.out, (seq, self.out)
            self.out += len(body) - 8
            self.data.extend(body[8:])
            if credit:
                # Refund in bounded batches to avoid one scheduling round per
                # tiny PTY read. Initial credit covers the unrefunded suffix.
                self.credit_pending += len(body) - 8
                if self.credit_pending >= self.credit_batch:
                    self.send(1, 0x14, struct.pack('<I', self.credit_pending))
                    self.credit_pending = 0
        elif kind == 0x13:
            ack = struct.unpack('<Q', body)[0]
            assert ack >= self.acked
            self.acked = ack
        elif kind == 0x15:
            seq = struct.unpack('<Q', body[:8])[0]
            assert seq >= self.out
            self.out = seq
            self.snapshots.append((seq, len(body) - 8))
        elif kind == 0x33:
            assert body[:4] == bytes(4)
            self.events.append(json.loads(body[4:]))
        else:
            raise AssertionError((kind, body))
        return kind

    def until(self, marker, credit=True):
        deadline = time.monotonic() + 20
        while marker not in self.data[max(0, len(self.data) - 32768):]:
            assert time.monotonic() < deadline
            self.process(credit)

    def wait_ack(self):
        while self.acked < self.entered:
            self.process()

    def kill(self):
        if self.child.poll() is None:
            self.child.kill()
        self.child.wait()
        self.child.stderr.close()
        if self.link:
            self.link.close()
            self.link = None
        self.sock.close()

    def restart(self):
        self.kill()
        self.start()
        self.attach()


class AckBarrier:
    """Proxy only the local shim leg, holding a real PTY-write Ack before delivery."""
    def __init__(self, state, session, kind=0x18, caps_mask=None):
        self.path = state / 'sessions' / (session.hex + '.sock')
        self.real = self.path.with_suffix('.upstream')
        self.path.rename(self.real)
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self.listener.listen()
        self.held = threading.Event()
        self.release = threading.Event()
        self.caps_mask = caps_mask
        self.kind = kind
        self.threshold = None
        self.phase = {}
        self.active = ()
        self.stopped = False
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def forward(self, source, destination, direction):
        try:
            while not self.stopped:
                self.phase[direction] = 'read'
                prefix = exact(source, 4)
                length = struct.unpack('<I', prefix)[0]
                assert 0 < length <= 1024 * 1024, 'oversized shim proxy frame'
                body = exact(source, length)
                if direction == 'output' and body[0] == 1 and self.caps_mask is not None:
                    caps = struct.unpack('<Q', body[3:11])[0] & self.caps_mask
                    body = body[:3] + struct.pack('<Q', caps) + body[11:]
                if body[0] == self.kind and self.threshold is not None and struct.unpack('<Q', body[1:9])[0] >= self.threshold:
                    self.phase[direction] = 'barrier'
                    self.held.set()
                    assert self.release.wait(20)
                    self.threshold = None
                self.phase[direction] = f'forward type={body[0]:02x} bytes={length}'
                destination.sendall(prefix + body)
        except (EOFError, BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            # Closing either leg interrupts its companion pump, including a
            # partial frame read/write, before the next connection is accepted.
            for sock in (source, destination):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def run(self):
        while not self.stopped:
            try:
                peer, _ = self.listener.accept()
                upstream = socket.socket(socket.AF_UNIX)
                with peer, upstream:
                    self.active = (peer, upstream)
                    upstream.connect(str(self.real))
                    # Two bounded frame pumps prevent the proxy itself creating
                    # a duplex deadlock while the daemon sends a large replay
                    # and the shim simultaneously sends retained output.
                    outbound = threading.Thread(target=self.forward, args=(peer, upstream, 'input'), daemon=True)
                    outbound.start()
                    self.forward(upstream, peer, 'output')
                    outbound.join()
                    self.active = ()
            except (EOFError, BrokenPipeError, ConnectionResetError, OSError):
                continue

    def close(self):
        self.stopped = True
        self.release.set()
        for sock in (*self.active, self.listener):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.listener.close()
        self.thread.join(2)


def cleanup(state):
    """Kill only shim PIDs authenticated by fixture-owned rendezvous sockets."""
    # Discover shim pids from Hello after shutting down the daemon; cleanup
    # never depends on process names or kills unrelated user sessions.
    for path in (state / 'sessions').glob('*'):
        if path.suffix not in ('.sock', '.upstream'):
            continue
        try:
            with socket.socket(socket.AF_UNIX) as peer:
                peer.settimeout(2)
                peer.connect(str(path))
                hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
                if hello[0] == 1:
                    os.kill(struct.unpack('<I', hello[27:31])[0], signal.SIGKILL)
        except (OSError, EOFError):
            pass
    shutil.rmtree(state, ignore_errors=True)
