#!/usr/bin/env python3
"""Shared real-binary socket and shim-barrier fixtures for issue #20 [13][41]."""
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid
from latency_proxy import LatencyConfig, LatencyDuplex


def event_object(body):
    """Decode a mux Event after checking its reserved event id."""
    assert body[:4] == bytes(4)
    return json.loads(body[4:])


def replay_complete_cursor(event, session_id):
    """Validate attach metadata without exposing it as a user-visible event."""
    assert event.get('type') == 'terminal.replay_complete', event
    assert event.get('session_id') == str(session_id), event
    cursor = event.get('out_seq')
    assert (
        isinstance(cursor, str)
        and 1 <= len(cursor) <= 20
        and cursor.isascii()
        and cursor.isdecimal()
    ), event
    value = int(cursor)
    assert value < 1 << 64, event
    return value


_private_state_roots = {}


def fixture_state(label):
    """Return a short per-process private state path for real Unix-socket fixtures."""
    root = Path(os.environ.get(
        'INFRATERNAL_AGENT_TEST_STATE_ROOT',
        os.environ.get(
            'INFRATERNAL_TEST_STATE_ROOT',
            Path.home() / '.cache/codex-scratch/infraternal',
        ),
    ))

    def paths_for(candidate):
        state = candidate / f'{label}{os.getpid()}'
        socket_path = state / 'sessions' / ('a' * 32 + '.sock')
        paths = (socket_path, socket_path.with_suffix('.upstream'))
        return state, paths

    # Linux sockaddr_un.sun_path includes the trailing NUL in its 108-byte bound.
    # AckBarrier also connects through a sibling .upstream socket with a longer suffix.
    state, paths = paths_for(root)
    longest = max(len(os.fsencode(path)) for path in paths)
    private = None
    if longest >= 108:
        # Neither HOME nor tempfile's TMPDIR-dependent default is a bounded
        # fallback. Keep an owner until cleanup (or interpreter shutdown).
        private = tempfile.TemporaryDirectory(prefix='if-', dir='/tmp')
        root = Path(private.name)
        state, paths = paths_for(root)
        longest = max(len(os.fsencode(path)) for path in paths)
    if longest >= 108:
        if private is not None:
            private.cleanup()
        raise ValueError(
            f'test state path is too long for an AF_UNIX socket after fallback: {longest} bytes'
        )
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if private is not None:
        _private_state_roots[state] = private
    return state


def shim_socket_count(pid, path):
    """Count a fixture's bound endpoints without ptrace access to protected FDs [217]."""
    # Accepted Unix sockets keep the listener's pathname in the kernel table.
    # A unique private rendezvous excludes every unrelated namespace endpoint;
    # count only that path, never weaken dumpability or replace detach with sleep.
    return sum(len(fields := line.split(maxsplit=7)) == 8 and fields[7] == str(path)
               for line in Path(f'/proc/{pid}/net/unix').read_text().splitlines())


def process_cpu_weight(pid):
    """Read the actual cgroup weight for one fixture-owned process."""
    group = next(line[3:] for line in Path(f'/proc/{pid}/cgroup').read_text().splitlines()
                 if line.startswith('0::'))
    value = (Path('/sys/fs/cgroup') / group.lstrip('/') / 'cpu.weight').read_text().strip()
    assert value.isdecimal() and 1 <= int(value) <= 10000
    return value


def fixture_cpu_weight():
    """Managed test shims inherit their caller's scheduling, including benchmark scopes."""
    weight = os.environ.get('INFRATERNAL_TEST_CPU_WEIGHT')
    if weight is None:
        # A manager creates an independent scope instead of inheriting this
        # cgroup. Copy its weight in the test launcher, never in production.
        try:
            weight = process_cpu_weight(os.getpid())
        except (OSError, StopIteration):
            return None  # Legacy hierarchies retain the ordinary fixture setup.
    assert weight.isdecimal() and 1 <= int(weight) <= 10000
    return weight


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


def weight_fixture_shim(state, session_id, weight, caller_pid=None, diagnose=False):
    """Weight only a fixture-owned shim; optional diagnostics record actual before/after values."""
    if weight is None:
        return None
    assert weight.isdecimal() and 1 <= int(weight) <= 10000
    if caller_pid is None:
        caller_pid = os.getpid()
    path = state / 'sessions' / f'{session_id.hex}.sock'
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(20)
        peer.connect(str(path))
        hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
    # Authenticate ownership before changing any scope. These are the same
    # content-free Hello identity/PID fields used by fixture cleanup.
    assert hello[0] == 1 and hello[11:27] == session_id.bytes
    pid = struct.unpack('<I', hello[27:31])[0]
    if Path(f'/proc/{pid}/cgroup').read_text() == Path(f'/proc/{caller_pid}/cgroup').read_text():
        return (int(weight), int(weight)) if diagnose else None
    command = ['systemctl']
    if os.geteuid() != 0:
        command.append('--user')
    unit = f'infraternal-session-{session_id.hex}.scope'

    def current_weight():
        # An unset manager property is not a number. The owned process's
        # kernel cgroup value measures actual scheduling, including defaults.
        return int(process_cpu_weight(pid))

    before = current_weight() if diagnose else None
    result = subprocess.run(command + ['set-property', '--runtime', unit, f'CPUWeight={weight}'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=20, check=False)
    assert result.returncode == 0, 'fixture-owned shim benchmark scope could not be weighted'
    if diagnose:
        after = current_weight()
        assert after == int(weight)
        return before, after
    return None


class Binary:
    def __init__(self, binary, state):
        self.state = state
        self.binary = Path(binary).resolve()
        self.out = 0
        self.entered = 0
        self.acked = 0
        self.data = bytearray()
        self.credit_batch = 64 * 1024
        self.credit_pending = 0
        self.credit_available = 0
        self.fence_nonce = 0
        self.cpu_weight = fixture_cpu_weight()
        self.events = []
        self.inventory = None
        self.snapshots = []
        self.link = None
        self.start()

    def start(self):
        # Validate the caller's exact build artifact before opening a relay;
        # otherwise exec failure is hidden behind a socket timeout.
        if not self.binary.is_file():
            raise FileNotFoundError(f'fixture binary not found: {self.binary}')
        if not os.access(self.binary, os.X_OK):
            raise PermissionError(f'fixture binary is not executable: {self.binary}')
        self.sock, test_peer = socket.socketpair()
        agent_peer, child_peer = socket.socketpair()
        self.sock.settimeout(20)
        config = LatencyConfig.from_environment()
        self.link = LatencyDuplex(test_peer, agent_peer, config)
        self.link.start()
        env = dict(os.environ, ZDOTDIR=str(Path('crates/infraternal/tests/profile').resolve()))
        weight = self.cpu_weight
        if weight is not None:
            launcher = shutil.which('systemd-run')
            if launcher is not None:
                directory = self.state / 'benchmark-bin'
                directory.mkdir(mode=0o700, exist_ok=True)
                wrapper = directory / 'systemd-run'
                # Include the unchanged two-second readiness bound in the
                # inherited test scheduling. Detached shims inherit directly.
                wrapper.write_text('#!/bin/sh\n# Propagate the fixture caller CPU weight.\n'
                                   f'exec {shlex.quote(launcher)} -p CPUWeight={weight} "$@"\n')
                wrapper.chmod(0o700)
                env['PATH'] = str(directory.resolve()) + os.pathsep + env['PATH']
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
        self.ping(0, 0)

    def send(self, stream, kind, body=b''):
        self.sock.sendall(varint(stream) + varint(1 + len(body)) + bytes([kind]) + body)
        if stream == 1 and kind == 0x14:
            self.credit_available += struct.unpack('<I', body)[0]

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

    def read_without_inventory(self):
        """Read the next reply while validating censuses within one socket budget."""
        timeout = self.sock.gettimeout()
        assert timeout is not None, 'reply requires a bounded socket'
        deadline = time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                assert remaining > 0, 'reply exceeded the socket budget'
                self.sock.settimeout(remaining)
                frame = self.read()
                if frame[:2] != (0, 0x33):
                    return frame
                self.process(frame=frame)
        finally:
            self.sock.settimeout(timeout)

    def read_ignoring_replay_complete(self, sessions):
        """Skip only validated attach markers, preserving all other event frames."""
        while True:
            frame = self.read_without_inventory()
            stream, kind, body = frame
            if kind != 0x33:
                return frame

            session_id = sessions.get(stream)
            assert session_id is not None, (stream, kind)
            replay_complete_cursor(event_object(body), session_id)

    def inherit_scope_priority(self, weight=None):
        """Apply this test's CPU weight only to its own transient shim scope."""
        weight = fixture_cpu_weight() if weight is None else weight
        if weight is None:
            return
        assert weight.isdecimal() and 1 <= int(weight) <= 10000
        control = ['systemctl'] + ([] if os.geteuid() == 0 else ['--user'])
        unit = f'infraternal-session-{self.id.hex}.scope'
        loaded = subprocess.run(control + ['show', unit, '-p', 'LoadState', '--value'],
                                capture_output=True, text=True, timeout=20)
        if loaded.returncode or loaded.stdout.strip() != 'loaded':
            return  # Detached launch already inherits the fixture's cgroup.
        subprocess.run(control + ['set-property', '--runtime', unit, f'CPUWeight={weight}'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20)

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
            if stream == 0:
                self.process(frame=(stream, kind, body))
            else:
                assert stream == 1
        assert (stream, kind) == (0, 0x31) and body[4] == 1, body
        self.id = uuid.UUID(json.loads(body[5:])['session_id'])
        self.benchmark_scope()
        self.prepare_shell()
        self.out = self.entered = self.acked = 0
        self.credit_pending = 0
        self.credit_available = 0
        self.data.clear()
        return self.id

    def prepare_shell(self):
        """Set a portable prompt through the legacy writer, before test writers attach."""
        # ZDOTDIR isolates zsh only. Configure the real login shell over its
        # PTY so Bash hosts also emit the fixture prompt. Legacy writer zero
        # keeps every daemon test writer's input cursor at its original zero.
        path = self.state / 'sessions' / f'{self.id.hex}.sock'
        with socket.socket(socket.AF_UNIX) as peer:
            peer.settimeout(20)
            peer.connect(str(path))
            hello = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
            assert hello[0] == 1 and hello[11:27] == self.id.bytes
            command = b"PS1='shim-'test'% '; printf 'FIXTURE_%s\\n' READY\n"
            for body in (b'\x02' + struct.pack('<Q', 0), b'\x10' + command,
                         b'\x13' + struct.pack('<Q', 0)):
                peer.sendall(struct.pack('<I', len(body)) + body)
            output = bytearray()
            while b'FIXTURE_READY\r\n' not in output:
                frame = exact(peer, struct.unpack('<I', exact(peer, 4))[0])
                assert frame[0] == 0x11
                output.extend(frame[9:])

    def benchmark_scope(self):
        """Keep the fixture-owned shim at this caller's scheduling weight."""
        weight_fixture_shim(self.state, self.id, self.cpu_weight, self.child.pid)

    def attach(self):
        self.send(1, 0x16, self.id.bytes + struct.pack('<QQ', self.out, self.acked))
        # Each new attachment owns a fresh explicit credit window. Old batched
        # refunds cannot fund a new connection; no grant is implicit in Attach.
        self.credit_pending = 0
        self.credit_available = 0
        self.send(1, 0x14, struct.pack('<I', 1048576))
        self.process()

    def input(self, data):
        seq = self.entered
        self.send(1, 0x10, struct.pack('<Q', seq) + data)
        self.entered += len(data)
        return seq

    def ping(self, nonce, sent_us):
        """Wait for the correlated control reply within the original socket budget."""
        expected = struct.pack('<QQ', nonce, sent_us)
        self.send(0, 0x08, expected)
        timeout = self.sock.gettimeout()
        assert timeout is not None, 'control probe requires a bounded socket'
        deadline = time.monotonic() + timeout
        try:
            while True:
                remaining = deadline - time.monotonic()
                assert remaining > 0, 'control reply exceeded the socket budget'
                self.sock.settimeout(remaining)
                frame = self.read()
                if frame[:2] == (0, 0x09):
                    assert frame[2] == expected, 'Pong did not match the request'
                    return
                # Retry handshakes can publish Ack or recovery metadata before
                # a later Ping. Preserve their cursor/event validation and reject
                # Close, rather than assuming Pong is the very next mux frame.
                self.process(frame=frame)
        finally:
            self.sock.settimeout(timeout)

    def process(self, credit=True, frame=None):
        stream, kind, body = self.read() if frame is None else frame
        if stream == 0 and kind == 0x33:
            # Full host censuses are unsolicited control frames, independent of
            # the one terminal writer. Retain only the latest bounded snapshot.
            assert body[:4] == bytes(4)
            self.inventory = json.loads(body[4:])
            return kind
        assert stream == 1, (stream, kind)
        if kind == 0x11:
            seq = struct.unpack('<Q', body[:8])[0]
            assert seq == self.out, (seq, self.out)
            self.out += len(body) - 8
            self.credit_available -= len(body) - 8
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
            self.credit_available -= len(body) - 8
        elif kind == 0x33:
            event = event_object(body)
            if event.get('type') == 'terminal.replay_complete':
                cursor = replay_complete_cursor(event, self.id)
                # The writer orders this marker after all replay bytes on the stream.
                assert cursor == self.out, (cursor, self.out)
            else:
                self.events.append(event)
        else:
            raise AssertionError((kind, body))
        return kind

    def wait_event(self, event_type):
        """Wait for the named event; replay completion can precede lifecycle events."""
        while True:
            for event in reversed(self.events):
                if event.get('type') == event_type:
                    return event
            self.process()

    def drain_credit(self):
        """Consume the exact funded window; socket silence is not an output fence."""
        while self.credit_available > 0:
            self.process(credit=False)
        assert self.credit_available == 0, 'output exceeded its explicit credit'

    def fence(self):
        """Drain writer messages preceding an ordered control Pong without refunding output."""
        self.fence_nonce += 1
        body = struct.pack('<QQ', self.fence_nonce, 0)
        self.send(0, 0x08, body)
        while True:
            frame = self.read()
            if frame[:2] == (0, 0x09):
                assert frame[2] == body
                return
            # The Pong fences earlier writer traffic; keep it in socket order without refunding credit.
            self.process(credit=False, frame=frame)

    def wait_for_starvation_detach(self, cols=80, rows=24, timeout=5):
        """Prove a zero-credit relay detached by requiring Resize to relink and Ack."""
        self.send(1, 0x14, struct.pack('<I', 1))
        deadline = time.monotonic() + timeout
        while not self.data:
            self.process(credit=False)
            assert time.monotonic() < deadline, 'prompt did not produce funded output'
        assert len(self.data) == 1
        self.fence()
        time.sleep(.35)

        prior_ack = self.acked
        self.send(1, 0x12, struct.pack('<HHHH', cols, rows, 0, 0))
        deadline = time.monotonic() + timeout
        while True:
            frame = self.read()
            if self.process(credit=False, frame=frame) == 0x13:
                assert self.acked == prior_ack
                return
            assert time.monotonic() < deadline, 'detached relay did not acknowledge its resize'

    def until(self, marker, credit=True):
        deadline = time.monotonic() + 20
        while marker not in self.data[max(0, len(self.data) - 32768):]:
            assert time.monotonic() < deadline
            self.process(credit)

    def wait_for_shell(self):
        """Confirm the attached login shell executes input without assuming its prompt."""
        self.input(b"printf 'shell-ready-%s\\n' check\n")
        self.until(b"shell-ready-check")
        self.wait_ack()

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
    def __init__(self, state, session, kind=0x18, caps_mask=None, on_frame=None, on_disconnect=None):
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
        self.on_frame = on_frame
        self.on_disconnect = on_disconnect
        self.threshold = None
        self.phase = {}
        self.active = set()
        self.workers = set()
        self.active_lock = threading.Lock()
        self.stopped = False
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    @staticmethod
    def classify(connection, direction, body):
        """Classify before forwarding Attach so its reply cannot race ownership."""
        if direction == 'input' and body[0] == 0x02:
            # Owner State(0,0) confirms ownership, not a data writer's cursor.
            connection['owner'] = struct.unpack('<Q', body[1:9])[0] == 8

    def forward(self, source, destination, direction, connection):
        try:
            while not self.stopped:
                if not connection['owner']:
                    self.phase[direction] = 'read'
                prefix = exact(source, 4)
                length = struct.unpack('<I', prefix)[0]
                assert 0 < length <= 1024 * 1024, 'oversized shim proxy frame'
                body = exact(source, length)
                self.classify(connection, direction, body)
                if not connection['owner'] and self.on_frame is not None:
                    self.on_frame(direction, body)
                if direction == 'output' and body[0] == 1 and self.caps_mask is not None:
                    caps = struct.unpack('<Q', body[3:11])[0] & self.caps_mask
                    body = body[:3] + struct.pack('<Q', caps) + body[11:]
                if not connection['owner'] and body[0] == self.kind and self.threshold is not None and struct.unpack('<Q', body[1:9])[0] >= self.threshold:
                    self.phase[direction] = 'barrier'
                    self.held.set()
                    assert self.release.wait(20)
                    self.threshold = None
                if not connection['owner']:
                    self.phase[direction] = f'forward type={body[0]:02x} bytes={length}'
                destination.sendall(prefix + body)
        except (EOFError, BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            if direction == 'input' and not connection['owner'] and self.on_disconnect is not None:
                self.on_disconnect()
            # Closing either leg interrupts its companion pump, including a
            # partial frame read/write, before the next connection is accepted.
            for sock in (source, destination):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def serve(self, peer):
        upstream = socket.socket(socket.AF_UNIX)
        connection = dict(owner=False)
        try:
            with peer, upstream:
                with self.active_lock:
                    self.active.update((peer, upstream))
                if self.stopped:
                    return
                upstream.connect(str(self.real))
                # Each connection retains the two bounded duplex pumps. Separate
                # owner/data connections must progress concurrently; otherwise
                # the ownership-installation barrier waits behind its data link.
                outbound = threading.Thread(target=self.forward,
                    args=(peer, upstream, 'input', connection), daemon=True)
                outbound.start()
                self.forward(upstream, peer, 'output', connection)
                outbound.join()
        except (EOFError, BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with self.active_lock:
                self.active.difference_update((peer, upstream))
                self.workers.discard(threading.current_thread())

    def run(self):
        while not self.stopped:
            try:
                peer, _ = self.listener.accept()
                worker = threading.Thread(target=self.serve, args=(peer,), daemon=True)
                with self.active_lock:
                    self.workers.add(worker)
                worker.start()
            except (EOFError, BrokenPipeError, ConnectionResetError, OSError):
                continue

    def close(self):
        self.stopped = True
        self.release.set()
        with self.active_lock:
            active = tuple(self.active)
        for sock in (*active, self.listener):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.listener.close()
        self.thread.join(2)
        with self.active_lock:
            workers = tuple(self.workers)
        for worker in workers:
            worker.join(2)


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
    private = _private_state_roots.pop(state, None)
    if private is not None:
        private.cleanup()


def control(client, number, action, values, expected=True):
    """Send one bounded control action and reject a mismatched reply identity."""
    encoded = action.encode()
    client.send(0, 0x30, struct.pack('<I', number) + varint(len(encoded)) + encoded + json.dumps(values).encode())
    while True:
        frame = client.read()
        if frame[:2] == (0, 0x31):
            body = frame[2]
            if struct.unpack('<I', body[:4])[0] != number:
                raise RuntimeError('control reply identity differs')
            result = json.loads(body[5:])
            if (body[4] == 1) != expected:
                raise RuntimeError('control action result differs: ' + str(result.get('reason', 'unspecified')))
            return result
        client.process(frame=frame)


def select_terminal(client, session):
    """Attach one fixture client to a returned session id with fresh cursors."""
    client.id = uuid.UUID(session)
    client.out = client.entered = client.acked = 0
    client.credit_pending = client.credit_available = 0
    client.data.clear()
    client.attach()


def detach(client):
    """Finish a fixture terminal writer through its normal acknowledged close."""
    client.send(1, 0x0f, struct.pack('<H', 0) + varint(4) + b'done')
    client.fence()


def marker(client, text):
    """Write and observe a fixture-owned shell marker without retaining output."""
    prefix, suffix = text.split('-', 1)
    client.input(f"printf '{prefix}-%s\\n' '{suffix}'\n".encode())
    client.until(text.encode())
    client.wait_ack()
    client.data.clear()
