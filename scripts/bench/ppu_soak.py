#!/usr/bin/env python3
"""Seeded real-shell stability/fault harness for the optional per-person host [D270].

Run only on the named perf VM under the shared flock. JSONL receipts contain
synthetic output counters, never shell output or login environment. Stdlib only;
this harness neither changes product code nor invents a successful upgrade path.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import random
import resource
import signal
import select
import socket
import statistics
import struct
import subprocess
import sys
import time
import threading
from ppu_clock import now as clock_now

MAX_FRAME = 1048576
CAPS = 7  # SEQUENCED_INPUT | MULTI_WRITER | APPROXIMATE_SNAPSHOT in frozen v1.
WRITER = 270205  # Private durable writer, distinct from discovery's legacy zero.


class Wakeups:
    """Private tracefs instance; never reset or consume another job's tracing."""
    def __init__(self, pid):
        self.root = Path('/sys/kernel/tracing/instances') / f'ppu-soak-{os.getpid()}'
        self.count = 0
        self.error = None
        self.stopped = threading.Event()
        self.fd = None
        self.thread = None
        try:
            self.root.mkdir()
            event = self.root / 'events/sched/sched_wakeup'
            (event / 'filter').write_text(f'pid == {pid}')
            (event / 'enable').write_text('1')
            (self.root / 'tracing_on').write_text('1')
            self.fd = os.open(self.root / 'trace_pipe', os.O_RDONLY | os.O_NONBLOCK)
            self.thread = threading.Thread(target=self.drain, daemon=True)
            self.thread.start()
        except OSError as error:
            self.error = type(error).__name__ + ': wakeup trace unavailable'

    def drain(self):
        pending = b''
        while not self.stopped.is_set():
            if select.select([self.fd], [], [], .1)[0]:
                try:
                    # sched_wakeup prints one line per event; text is discarded.
                    pending += os.read(self.fd, 65536)
                    lines = pending.split(b'\n')
                    pending = lines.pop()
                    self.count += sum(b'sched_wakeup:' in line for line in lines)
                except BlockingIOError:
                    pass

    def receipt(self):
        if self.error:
            return dict(wakeups=None, wakeup_error=self.error)
        overruns = 0
        for path in (self.root / 'per_cpu').glob('cpu*/stats'):
            for line in path.read_text().splitlines():
                key, _, value = line.partition(':')
                if key.strip() in ('overrun', 'commit overrun'):
                    overruns += int(value)
        return dict(wakeups=self.count, wakeup_trace_overruns=overruns)

    def close(self):
        self.stopped.set()
        if self.thread:
            self.thread.join()
        if self.fd is not None:
            os.close(self.fd)
        if self.root.exists():
            with contextlib.suppress(OSError):
                (self.root / 'tracing_on').write_text('0')
                (self.root / 'events/sched/sched_wakeup/enable').write_text('0')
                self.root.rmdir()


def percentile(values, fraction):
    return sorted(values)[max(0, math.ceil(len(values) * fraction) - 1)] if values else None


def sample(pid):
    """Read host-only resources; shells and the harness are counted separately."""
    root = Path(f'/proc/{pid}')
    status = dict(line.split(':', 1) for line in (root / 'status').read_text().splitlines())
    memory = dict(line.split(':', 1) for line in (root / 'smaps_rollup').read_text().splitlines()
                  if ':' in line)
    # comm can contain whitespace/parens; counters start after its final ')'.
    fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    return dict(rss_kib=int(memory['Rss'].split()[0]), pss_kib=int(memory['Pss'].split()[0]),
                anon_kib=int(memory['Anonymous'].split()[0]),
                cpu_ticks=int(fields[11]) + int(fields[12]),
                voluntary_switches=int(status['voluntary_ctxt_switches']),
                involuntary_switches=int(status['nonvoluntary_ctxt_switches']),
                threads=int(status['Threads']), fds=len(list((root / 'fd').iterdir())),
                load=Path('/proc/loadavg').read_text().split()[:3])


def stability(rows, warmup, memory_kib, echo_ratio):
    """Compare settled windows, not startup allocations; too few rows is failure."""
    rows = [row for row in rows if row['elapsed_s'] >= warmup]
    if len(rows) < 6:
        return {'pass': False, 'reason': 'need at least six post-warmup samples'}
    width = max(3, len(rows) // 4)
    first, last = rows[:width], rows[-width:]
    growth = statistics.median(r['pss_kib'] for r in last) - statistics.median(r['pss_kib'] for r in first)
    x = [r['elapsed_s'] for r in rows]
    y = [r['pss_kib'] for r in rows]
    mean_x, mean_y = statistics.mean(x), statistics.mean(y)
    slope = sum((a - mean_x) * (b - mean_y) for a, b in zip(x, y)) / sum((a - mean_x)**2 for a in x)
    start_echo = statistics.median(r['echo_p99_ms'] for r in first)
    end_echo = statistics.median(r['echo_p99_ms'] for r in last)
    peak_echo = max(r['echo_p99_ms'] for r in rows)
    # FD samples are taken with every churn peer closed and reader quiescent.
    fd_growth = max(r['fds'] for r in last) - max(r['fds'] for r in first)
    thread_growth = max(r['threads'] for r in rows) - min(r['threads'] for r in rows)
    return dict(pass_=growth <= memory_kib and slope * 3600 <= memory_kib
                and fd_growth <= 0 and thread_growth == 0 and end_echo <= start_echo * echo_ratio
                and peak_echo <= 5,  # D41 local native echo p99, independent of steadiness.
                pss_growth_kib=growth, pss_slope_kib_hour=slope * 3600,
                fd_growth=fd_growth, thread_growth=thread_growth,
                echo_first_p99_ms=start_echo, echo_last_p99_ms=end_echo,
                echo_peak_p99_ms=peak_echo, echo_budget_ms=5,
                memory_tolerance_kib=memory_kib, echo_ratio_limit=echo_ratio)


class Peer:
    """Continuously drain output so the driver never creates artificial backpressure."""
    def __init__(self, reader, writer, head, pid):
        self.reader, self.writer, self.head, self.pid = reader, writer, head, pid
        self.tail = b''
        self.waiters = {}
        self.exit = asyncio.get_running_loop().create_future()
        self.state = asyncio.get_running_loop().create_future()
        self.accepted = 0
        self.bytes = 0
        self.task = asyncio.create_task(self.receive())

    @classmethod
    async def connect(cls, path):
        reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(path), 30)
        peer = None
        try:
            hello = await cls.frame(reader)
            assert len(hello) == 59 and hello[0] == 1, 'invalid frozen Hello'
            pid = struct.unpack_from('<I', hello, 27)[0]
            head = struct.unpack_from('<Q', hello, 43)[0]
            peer = cls(reader, writer, head, pid)
            await peer.send(2, struct.pack('<Q', CAPS))
            await peer.send(0x1b, struct.pack('<I', WRITER))
            await peer.send(0x19)
            peer.accepted = await asyncio.wait_for(peer.state, 30)
            await peer.send(0x13, struct.pack('<Q', head))
            return peer
        except (Exception, asyncio.CancelledError):
            # Churn can be cancelled before the caller receives the new peer.
            # Retire this setup's socket and task here; Host.close cannot find
            # a peer that was never published into its owned session list.
            if peer is not None:
                await peer.close()
            else:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
            raise

    @staticmethod
    async def frame(reader):
        length, = struct.unpack('<I', await reader.readexactly(4))
        assert 0 < length <= MAX_FRAME, 'frame length outside frozen bound'
        return await reader.readexactly(length)

    async def send(self, kind, payload=b''):
        if kind == 0x10:
            # Reserve offsets before drain can yield to another producer. The
            # shell-generated marker, rather than Ack, proves PTY completion.
            kind, payload = 0x17, struct.pack('<Q', self.accepted) + payload
            self.accepted += len(payload) - 8
        self.writer.write(struct.pack('<I', len(payload) + 1) + bytes([kind]) + payload)
        await self.writer.drain()

    async def receive(self):
        try:
            while True:
                frame = await self.frame(self.reader)
                kind = frame[0]
                if kind in (0x11, 0x15, 0x1c):
                    offset, = struct.unpack_from('<Q', frame, 1)
                    payload = frame[10 if kind == 0x1c else 9:]
                    if kind == 0x11:
                        assert offset == self.head, 'output gap/duplicate'
                        self.head += len(payload)
                    else:
                        self.head = offset
                    self.bytes += len(payload)
                    searchable = self.tail + payload
                    for marker, future in list(self.waiters.items()):
                        if marker in searchable and not future.done():
                            future.set_result(clock_now())
                    # Search the entire frame before retaining a bounded suffix;
                    # burst output may place the marker outside the final 8 KiB.
                    self.tail = searchable[-8192:]
                elif kind == 0x20:
                    if not self.exit.done():
                        self.exit.set_result(struct.unpack_from('<i', frame, 1)[0])
                elif kind == 0x1a:
                    if not self.state.done():
                        self.state.set_result(struct.unpack_from('<Q', frame, 9)[0])
                elif kind == 0x7f:
                    raise AssertionError(f'host error code {struct.unpack_from("<H", frame, 1)[0]}')
        except (Exception, asyncio.CancelledError) as error:
            for future in self.waiters.values():
                if not future.done():
                    future.set_exception(error)
            if not self.exit.done():
                self.exit.cancel()
            if not self.state.done():
                self.state.cancel()
            if not isinstance(error, (asyncio.CancelledError, asyncio.IncompleteReadError)):
                raise

    async def echo(self, marker, command=b''):
        # Octal encoding prevents echoed command text from satisfying the probe.
        future = asyncio.get_running_loop().create_future()
        self.waiters[marker] = future
        octal = ''.join(f'\\{byte:03o}' for byte in marker)
        start = clock_now()
        try:
            await self.send(0x10, command + f"printf '{octal}\\n'\n".encode())
            end = await asyncio.wait_for(future, 30)
            return (end - start) * 1000
        finally:
            self.waiters.pop(marker, None)

    async def close(self):
        self.writer.close()
        with contextlib.suppress(OSError):
            await self.writer.wait_closed()
        self.task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self.task


class Host:
    """Fixture ownership is explicit; cleanup signals only captured child identities."""
    def __init__(self, binary, root, count, origin, nofile=None, scope=None, accounting=None):
        self.root, self.count, self.origin = root, count, origin
        root.mkdir(mode=0o700)
        self.log = (root / 'host-stderr.log').open('wb')
        def limits():
            if nofile:
                resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))
        command = [str(binary), '__shim', '--session', f'{origin:032x}',
            '--uid', str(os.getuid()), '--host-sessions', str(count), '--ring-capacity', '65536',
            '--state', str(root)]
        if accounting is not None:
            # A separate numeric receipt is created by the host before any
            # PTY. The driver requests it explicitly, never on idle timers.
            command += ['--host-accounting', str(accounting)]
        if scope:
            command = ['systemd-run', '--quiet', '--scope', '--unit', scope,
                       '-p', 'MemoryAccounting=yes', '-p', 'CPUWeight=10000', '--'] + command
        self.child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=self.log, preexec_fn=limits if nofile else None)
        self.pid = self.child.pid
        self.scope = scope
        self.peers = []
        self.shells = []
        self.closed_output_bytes = 0

    def path(self, index):
        return self.root / 'sessions' / f'{self.origin + index:032x}.sock'

    async def ready(self):
        until = clock_now() + 120
        while not self.path(self.count - 1).exists():
            assert self.child.poll() is None, 'host exited during startup'
            assert clock_now() < until, 'host startup timed out'
            await asyncio.sleep(.05)
        for index in range(self.count):
            peer = await Peer.connect(self.path(index))
            if index == 0 and self.scope:
                self.pid = peer.pid
            assert peer.pid == self.pid, 'sessions do not share host PID'
            self.peers.append(peer)
            await peer.echo(f'init-{index}'.encode(), b"stty -echo; PS1=''; ")
        children = Path(f'/proc/{self.pid}/task/{self.pid}/children').read_text().split()
        self.shells = [(int(pid), Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19])
                       for pid in children]
        assert len(self.shells) == self.count, 'unexpected shell count'

    def owned_shells(self):
        for pid, birth in self.shells:
            try:
                if Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19] == birth:
                    yield pid
            except FileNotFoundError:
                pass

    async def close(self):
        # A protocol failure must not prevent cleanup of the remaining peers,
        # shells and host. Their original failure is already in the receipt.
        await asyncio.gather(*(peer.close() for peer in self.peers), return_exceptions=True)
        # Populate identities even if startup failed part way through.
        if not self.shells and self.child.poll() is None:
            children = Path(f'/proc/{self.pid}/task/{self.pid}/children').read_text().split()
            self.shells = [(int(pid), Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19])
                           for pid in children]
        for pid in self.owned_shells():
            with contextlib.suppress(ProcessLookupError):
                # Shells are session leaders; retire their synthetic pipelines
                # too, rather than leaving output generators in another job.
                if os.getpgid(pid) == pid:
                    os.killpg(pid, signal.SIGKILL)
                else:
                    os.kill(pid, signal.SIGKILL)
        if self.child.poll() is None:
            if self.scope:
                # The wrapper PID is not the host PID in the owned transient scope.
                with contextlib.suppress(ProcessLookupError):
                    os.kill(self.pid, signal.SIGKILL)
            self.child.kill()
        await asyncio.to_thread(self.child.wait)
        self.log.close()


class Recorder:
    """Flush every synthetic sample so a killed run retains its last receipt."""
    def __init__(self, root):
        self.file = (root / 'samples.jsonl').open('w')

    def write(self, kind, **values):
        self.file.write(json.dumps(dict(kind=kind, **values), sort_keys=True) + '\n')
        self.file.flush()


class FaultSampler:
    """Keep ten-second receipts for faults, including a final short-run sample."""
    def __init__(self, host, record, interval):
        self.host, self.record, self.interval = host, record, interval
        self.wakeups = Wakeups(host.pid)
        self.start = clock_now()
        self.previous = sample(host.pid)
        self.previous_time = self.start
        self.number = 0
        self.task = asyncio.create_task(self.run())

    async def tick(self):
        live = [(i, peer) for i, peer in enumerate(self.host.peers) if not peer.exit.done()]
        # The fault's own oracle checks every survivor; this sampler measures
        # their representative echo without sending 1000 probes at each tick.
        selected = live[-min(100, len(live)):]
        echoes = await asyncio.gather(*(peer.echo(f'fault-probe-{self.number}-{i}'.encode())
                                        for i, peer in selected))
        now = clock_now()
        row = sample(self.host.pid)
        row.update(elapsed_s=now - self.start, echo_p99_ms=percentile(echoes, .99),
            echo_samples=len(echoes), cpu_percent=(row['cpu_ticks'] - self.previous['cpu_ticks']) /
            os.sysconf('SC_CLK_TCK') / (now - self.previous_time) * 100,
            output_bytes=sum(peer.bytes for peer in self.host.peers))
        row.update(self.wakeups.receipt())
        self.record.write('sample', **row)
        self.previous, self.previous_time = row, now
        self.number += 1

    async def run(self):
        while True:
            await asyncio.sleep(self.interval)
            await self.tick()

    async def close(self):
        self.task.cancel()
        try:
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
            await self.tick()
        finally:
            self.wakeups.close()


async def soak(host, args, record, rng):
    start = clock_now()
    active_count = max(1, host.count // 10)
    active = list(range(host.count - active_count, host.count))
    burst = set(active[-max(1, host.count // 100):])
    stop = asyncio.Event()
    errors = []
    wakeups = Wakeups(host.pid)
    churn_lock = asyncio.Lock()
    async def workload():
        iteration = 0
        deadline = clock_now()
        try:
            while not stop.is_set():
                await asyncio.gather(*(host.peers[i].echo(f'load-{i}-{iteration}'.encode(),
                    b"seq 1 1024; " if i in burst else b'') for i in active))
                iteration += 1
                # The confirmation itself is the light session's one line.
                # Absolute pacing avoids adding probe duration to every second.
                deadline += 1
                await asyncio.sleep(max(0, deadline - clock_now()))
        except Exception as error:
            errors.append(type(error).__name__ + ': ' + str(error))
            stop.set()
    async def churn():
        try:
            iteration = 0
            while not stop.is_set():
                index = rng.randrange(1 if args.mode == 'corpus' else 0,
                                      max(2, host.count - active_count))
                async with churn_lock:
                    host.closed_output_bytes += host.peers[index].bytes
                    await host.peers[index].close()
                    peer = await Peer.connect(host.path(index))
                    host.peers[index] = peer
                    # Replace the idle writer and fence cleanup before sampling.
                    await peer.send(0x12, struct.pack('<HHHH', 80 + iteration % 2, 24, 0, 0))
                    await peer.echo(f'churn-{iteration}'.encode())
                iteration += 1
                await asyncio.sleep(3)
        except Exception as error:
            errors.append(type(error).__name__ + ': ' + str(error))
            stop.set()
    async def corpus():
        """Feed the checked-in VT fixtures and hostile carry through a real PTY."""
        fixtures = sorted(args.corpus.glob('*.vt'))
        assert fixtures, 'existing terminal-parser corpus missing'
        inputs = [(path.name, path.read_bytes()) for path in fixtures]
        inputs += [('long-osc', b'\x1b]0;' + b'x' * 131072 + b'\x07'),
                   ('many-csi', b'\x1b[' + b'123456789;' * 4096 + b'm'),
                   ('malformed-utf8', b'\xff\xfe\xc0\xaf\xf0\x80\x80\x80' * 4096)]
        payload = host.root / 'parser-input.vt'
        number = 0
        try:
            while not stop.is_set():
                name, data = inputs[number % len(inputs)]
                payload.write_bytes(data + b'\x18\x1bc')
                await host.peers[0].echo(f'corpus-{number}'.encode(),
                    f"cat '{payload}'; ".encode())
                record.write('corpus-case', case=name, iteration=number,
                             input_bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
                number += 1
                await asyncio.sleep(1)
        except Exception as error:
            errors.append(type(error).__name__ + ': ' + str(error))
            stop.set()
    # Exercise both geometries before starting load and probe tasks. Quiet
    # sessions may retain a lazy resize transcript; active output can still
    # materialize VT later, so resource stability is assessed after warmup.
    for peer in host.peers:
        await peer.send(0x12, struct.pack('<HHHH', 81, 24, 0, 0))
        await peer.send(0x12, struct.pack('<HHHH', 80, 24, 0, 0))
    tasks = [asyncio.create_task(workload()), asyncio.create_task(churn())]
    if args.mode == 'corpus':
        tasks.append(asyncio.create_task(corpus()))
    rows = []
    ownership_requested = False
    previous = sample(host.pid)
    previous_time = start
    try:
        number = 0
        while clock_now() - start < args.seconds and not stop.is_set():
            deadline = start + (number + 1) * args.interval
            await asyncio.sleep(max(0, deadline - clock_now()))
            echoes = await asyncio.gather(*(host.peers[i].echo(f'probe-{i}-{number}'.encode())
                                           for i in active))
            completed_ns = time.monotonic_ns()
            now = clock_now()
            async with churn_lock:
                row = sample(host.pid)
            # Preserve the same timed cohort for exact segment percentiles.
            # Receipt serialization starts only after every echo completed.
            row.update(elapsed_s=now - start, echo_p99_ms=percentile(echoes, .99),
                echo_p50_ms=percentile(echoes, .50), echo_ms=echoes,
                monotonic_ns=completed_ns, echo_samples=len(echoes), cpu_percent=(row['cpu_ticks'] - previous['cpu_ticks']) /
                os.sysconf('SC_CLK_TCK') / (now - previous_time) * 100,
                context_switches_per_s=(row['voluntary_switches'] - previous['voluntary_switches']) /
                (now - previous_time),
                output_bytes=host.closed_output_bytes + sum(peer.bytes for peer in host.peers))
            row.update(wakeups.receipt())
            record.write('sample', **row)
            rows.append(row)
            if getattr(args, 'ownership', False) and not ownership_requested and now - start >= args.warmup:
                # Explicit diagnostic only. Request after the timed probe;
                # never charge a 1000-session traversal to an ordinary run.
                os.kill(host.pid, signal.SIGUSR2)
                ownership_requested = True
                record.write('ownership-request', fence='warmup', elapsed_s=now - start)
            previous, previous_time = row, now
            number += 1
            print(f'sample {number}: elapsed={now-start:.0f}s fds={row["fds"]} threads={row["threads"]}', flush=True)
        assert not errors, '; '.join(errors)
        if getattr(args, 'ownership', False):
            os.kill(host.pid, signal.SIGUSR2)
            record.write('ownership-request', fence='end', elapsed_s=clock_now() - start)
            # Fence the synchronous signal callback through a real wire request
            # before cleanup can close the host and its numeric receipt.
            await host.peers[-1].echo(b'ownership-end-fence')
        # Idle terminals must also accept input, not merely retain their PID.
        # Probe them after the timed mix so this census cannot alter idle load.
        confirmations = await asyncio.gather(*(peer.echo(f'final-{i}'.encode())
                                               for i, peer in enumerate(host.peers)))
        record.write('survivors', responsive_sessions=len(confirmations),
                     expected_sessions=host.count, host_alive=host.child.poll() is None)
        assert host.child.poll() is None
        result = stability(rows, args.warmup, args.memory_tolerance_kib, args.echo_ratio)
        passed = result.pop('pass_', result.pop('pass', False))
        passed = passed and now - start >= args.seconds and all(
            r['wakeups'] is not None and r['wakeup_trace_overruns'] == 0 for r in rows)
        record.write('outcome', scenario=args.mode, passed=passed,
                     expected='memory and resources settle; sibling echo stays steady', **result)
        return passed
    finally:
        wakeups.close()
        stop.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def faults(host, args, record, rng):
    results = []
    async def case(name, expected, action):
        try:
            detail = await action()
            passed = True
        except Exception as error:
            detail, passed = f'{type(error).__name__}: {error}', False
        record.write('outcome', scenario=name, expected=expected, passed=passed, detail=detail)
        results.append(passed)
        print(f'{name}: {"PASS" if passed else "FAIL"}', flush=True)
    dead = set()
    async def survivors(label):
        values = await asyncio.gather(*(peer.echo(f'{label}-{i}'.encode())
            for i, peer in enumerate(host.peers) if i not in dead))
        assert host.child.poll() is None
        return f'{len(values)} sibling sessions accepted input'
    async def daemon_restart():
        # Reuse the repository's real daemon handshake/census fixture. Restart
        # no shim and never substitute a direct reconnect for daemon discovery.
        sys.dont_write_bytecode = True
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from agent_fixture import Binary
        os.environ['INFRATERNAL_TEST_RTT'] = '0'
        def restart():
            client = Binary(args.binary, host.root)
            try:
                for attempt in range(2):
                    client.ping(attempt + 1, 0)
                    if client.inventory is None:
                        client.process()
                    ids = set(client.inventory['session_ids'])
                    expected = {f'{host.origin + i:032x}' for i in range(host.count) if i not in dead}
                    import uuid
                    assert {uuid.UUID(identity).hex for identity in ids} == expected, 'census lost sessions'
                    if attempt == 0:
                        client.kill()
                        client.inventory = None
                        client.start()
            finally:
                client.kill()
        await asyncio.to_thread(restart)
        return await survivors('after-daemon-restart')
    await case('infraternal-agent-restart', 'real daemon rediscovers all IDs; every session accepts input', daemon_restart)
    async def abrupt_shell():
        victim = rng.randrange(host.count)
        # The shell reports its own PID through an encoded marker; /proc child
        # ordering is not a session-to-PID mapping.
        peer = host.peers[victim]
        path = host.root / 'victim-pid'
        await peer.echo(b'victim-identified', f"printf '%s' $$ > '{path}'; ".encode())
        pid = int(path.read_text())
        assert pid in list(host.owned_shells()), 'victim not fixture-owned'
        os.kill(pid, signal.SIGKILL)
        assert await asyncio.wait_for(asyncio.shield(peer.exit), 30) == -9
        dead.add(victim)
        return await survivors('after-abrupt-shell')
    await case('shell-sigkill', 'victim Exited(-9); all other sessions accept input', abrupt_shell)
    async def ignores_hup():
        index = next(i for i in range(host.count) if i not in dead)
        peer = host.peers[index]
        await peer.echo(b'hup-ignored-installed', b"trap '' HUP; ")
        await peer.send(0x16, bytes([signal.SIGHUP]))
        return await survivors('after-hup')
    await case('shell-ignores-sighup', 'ignoring shell and every sibling remain responsive', ignores_hup)
    async def child_ignores_hup():
        index = next(i for i in range(host.count) if i not in dead)
        peer = host.peers[index]
        path = host.root / 'hup-child-pid'
        # A foreground shell child installs its disposition before publishing
        # its PID. Protocol Signal must reach that foreground process group.
        program = ('import os,signal; from pathlib import Path; '
                   'signal.signal(signal.SIGHUP, signal.SIG_IGN); '
                   f'p=Path({str(path)!r}); q=p.with_suffix(".pending"); '
                   'q.write_text(str(os.getpid())); q.replace(p); signal.pause()')
        import shlex
        await peer.send(0x10, f'python3 -c {shlex.quote(program)}\n'.encode())
        deadline = clock_now() + 30
        while not path.exists():
            assert clock_now() < deadline, 'child did not install HUP disposition'
            await asyncio.sleep(.01)
        pid = int(path.read_text())
        status = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
        assert int(status[1]) in list(host.owned_shells()), 'child not fixture-owned'
        assert int(status[5]) == os.getpgid(pid), 'child group is not foreground'
        birth = status[19]
        try:
            await peer.send(0x16, bytes([signal.SIGHUP]))
            values = await asyncio.gather(*(other.echo(f'child-hup-{i}'.encode())
                for i, other in enumerate(host.peers) if i not in dead and i != index))
            current = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
            assert current[19] == birth and current[0] != 'Z', 'ignoring child exited'
            record.write('child-hup', child_pid=pid, responsive_siblings=len(values),
                         child_alive=True)
        finally:
            # Retire only this captured child, never unrelated process groups.
            with contextlib.suppress(FileNotFoundError, ProcessLookupError):
                current = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
                if current[19] == birth:
                    os.kill(pid, signal.SIGKILL)
        return 'foreground child survived HUP; ' + await survivors('after-child-hup')
    if args.mode == 'process-events':
        await case('child-ignores-sighup', 'foreground child survives HUP; every sibling accepts input', child_ignores_hup)
    async def pathological():
        index = next(i for i in range(host.count) if i not in dead)
        path = host.root / 'pathological.bin'
        path.write_bytes(b'\x1b]0;' + b'x' * 131072 + b'\x07' +
                         b'\x1b[' + b'123456789;' * 4096 + b'm' +
                         b'\xff\xfe\xc0\xaf\xf0\x80\x80\x80' * 4096 + b'\x18\x1bc')
        await host.peers[index].echo(b'pathological-done', f"cat '{path}'; ".encode())
        return await survivors('after-pathological')
    if args.mode != 'process-events':
        await case('pathological-escapes', 'bounded parser input completes; every sibling accepts input', pathological)
    async def exhausted():
        soft, hard = resource.prlimit(host.child.pid, resource.RLIMIT_NOFILE)
        sockets = []
        try:
            count = sample(host.child.pid)['fds']
            resource.prlimit(host.child.pid, resource.RLIMIT_NOFILE, (count + 8, hard))
            alive = [i for i in range(host.count) if i not in dead]
            for attempt in range(24):
                sock = socket.socket(socket.AF_UNIX)
                sock.setblocking(False)
                sockets.append(sock)
                with contextlib.suppress(OSError):
                    await asyncio.wait_for(asyncio.get_running_loop().sock_connect(
                        sock, str(host.path(alive[attempt % len(alive)]))), 2)
            await asyncio.sleep(.2)
            assert sample(host.child.pid)['fds'] >= count + 8, 'fd limit was not reached'
            detail = await survivors('under-fd-limit')
        finally:
            resource.prlimit(host.child.pid, resource.RLIMIT_NOFILE, (soft, hard))
            for sock in sockets:
                sock.close()
        await asyncio.sleep(.2)
        await survivors('after-fd-limit')
        assert sample(host.child.pid)['fds'] <= count, 'refused peers leaked descriptors'
        return detail
    await case('fd-exhaustion-live', 'existing sessions accept input at EMFILE; refused peers cannot leak', exhausted)
    async def startup_exhausted():
        low = Host(args.binary, host.root.parent / 'low-fds', 32, host.origin + 2000, 32)
        try:
            code = await asyncio.wait_for(asyncio.to_thread(low.child.wait), 30)
            assert code != 0, 'low-fd admission unexpectedly succeeded'
            assert not list((low.root / 'sessions').glob('*.sock')), 'startup left live sockets'
            return f'bounded admission refused with exit={code}'
        finally:
            await low.close()
    await case('fd-exhaustion-startup', 'startup refuses cleanly with no surviving shells/sockets', startup_exhausted)
    async def parser_panic():
        assert args.panic_test_binary is not None, 'provide the existing cfg(test) panic fixture binary'
        test = 'session::user_host::tests::vt_panic_retires_one_real_pty_and_sibling_keeps_its_output'
        def probe():
            # The upstream test creates its unique PID subdirectory; stage only
            # its conventional scratch parent, never touch any live fixture.
            (Path.home() / '.cache/codex-scratch/process-per-user').mkdir(parents=True, exist_ok=True)
            with (args.evidence / 'parser-panic.log').open('wb') as log:
                result = subprocess.run([str(args.panic_test_binary.resolve()), '--exact', test,
                    '--nocapture', '--test-threads=1'], stdout=log, stderr=subprocess.STDOUT, timeout=60)
            assert result.returncode == 0, 'existing panic/sibling fixture failed'
            text = (args.evidence / 'parser-panic.log').read_text()
            assert '1 passed' in text, 'panic fixture was not selected'
        await asyncio.to_thread(probe)
        return 'existing test-only hook retires real PTY; sibling progresses; ' + await survivors('after-panic-fixture')
    if args.mode != 'process-events':
        await case('parser-panic', 'cfg(test) fixture retires exactly one real PTY; sibling accepts output', parser_panic)
    if args.mode == 'process-events':
        async def upgrade():
            detail = await survivors('before-upgrade')
            # No whole-host state/child-status transaction is exposed by the
            # research host. A direct reconnect cannot stand in for D128.
            raise AssertionError('D128 whole-host upgrade adapter unimplemented; ' + detail)
        await case('host-upgrade', 'busy D128 handoff preserves every shell; all siblings accept input', upgrade)
        return all(results)
    # These require product support. A descriptor-only transfer or direct socket
    # reconnect cannot establish terminal-state handoff or daemon restart recovery.
    for name, expected in [('host-upgrade', 'exact terminal/child state and all sessions survive D128 handoff'),
                           ('memory-pressure', 'run separately with --mode memory in an owned cgroup')]:
        record.write('outcome', scenario=name, expected=expected, passed=False,
                     detail='NOT RUN: needs an isolated product/fixture adapter; not a synthetic pass')
        results.append(False)
    return all(results)


async def memory_pressure(host, record):
    """Limit only the named fixture scope; driver/evidence survive a host OOM."""
    expected = 'near-working-set cgroup cap; pathological output cannot stop sibling input'
    control = subprocess.check_output(['systemctl', 'show', host.scope + '.scope',
        '-p', 'ControlGroup', '--value'], text=True).strip()
    group = Path('/sys/fs/cgroup') / control.lstrip('/')
    assert group.name == host.scope + '.scope' and host.scope.startswith('ppu-soak-memory-')
    assert str(host.pid) in (group / 'cgroup.procs').read_text().split(), 'foreign cgroup'
    original = (group / 'memory.max').read_text()
    working = int((group / 'memory.current').read_text())
    limit = working + max(16 * 1024 * 1024, working // 20)
    events_before = (group / 'memory.events').read_text()
    record.write('memory-cap', working_set_bytes=working, limit_bytes=limit, events_before=events_before)
    victim = None
    try:
        (group / 'memory.max').write_text(str(limit))
        before = host.peers[0].bytes
        victim = asyncio.create_task(host.peers[0].echo(b'memory-victim-finished',
            b"printf '\\033]0;'; head -c 33554432 /dev/zero | tr '\\000' x; "
            b"read -r ppu_resume; printf '\\007\\030\\033c'; "))
        # Drain the complete payload, then keep its native parser state open
        # until siblings have accepted input. The explicit stdin release avoids
        # a machine-speed-dependent race against the string's terminator.
        until = clock_now() + 30
        while host.peers[0].bytes - before < 33554436:
            if victim.done():
                await victim
                raise AssertionError('control-string source ended before the held phase')
            assert clock_now() < until, 'control-string source did not drain'
            await asyncio.sleep(.001)
        if victim.done():
            await victim
            raise AssertionError('control string was not held open')
        held_echoes = await asyncio.gather(*(peer.echo(f'memory-open-sibling-{i}'.encode())
                                            for i, peer in enumerate(host.peers[1:], 1)))
        if victim.done():
            await victim
            raise AssertionError('control string ended before sibling confirmation')
        record.write('memory-open-string', input_bytes=33554432,
                     responsive_siblings=len(held_echoes), terminator_released=False)
        await host.peers[0].send(0x10, b'resume\n')
        await victim
        echoes = await asyncio.gather(*(peer.echo(f'memory-sibling-{i}'.encode())
                                       for i, peer in enumerate(host.peers)))
        assert host.child.poll() is None
        record.write('outcome', scenario='memory-pressure', expected=expected, passed=True,
            responsive_sessions=len(echoes), working_set_bytes=working, limit_bytes=limit,
            open_string_responsive_siblings=len(held_echoes),
            peak_bytes=int((group / 'memory.peak').read_text()),
            events_after=(group / 'memory.events').read_text())
        return True
    except Exception as error:
        record.write('outcome', scenario='memory-pressure', expected=expected, passed=False,
            detail=f'{type(error).__name__}: {error}',
            events_after=(group / 'memory.events').read_text() if group.exists() else 'scope exited')
        return False
    finally:
        if victim is not None:
            if not victim.done():
                victim.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await victim
        if group.exists():
            (group / 'memory.max').write_text(original)


async def run(args):
    assert args.sessions >= 2 and args.sessions <= 1000
    args.binary = args.binary.resolve()
    soft_fds, hard_fds = resource.getrlimit(resource.RLIMIT_NOFILE)
    required_fds = args.sessions * 4 + 128
    assert hard_fds == resource.RLIM_INFINITY or hard_fds >= required_fds, 'hard fd limit cannot admit scale'
    # SSH's ordinary soft limit is 1024. Raise only this fixture process's
    # inherited limit; low-limit cases explicitly lower their own host later.
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft_fds, required_fds), hard_fds))
    args.evidence.mkdir(parents=True, exist_ok=False)
    record = Recorder(args.evidence)
    record.write('environment', machine=os.uname().nodename, kernel=os.uname().release,
        cpus=os.cpu_count(), seed=args.seed, sessions=args.sessions,
        seconds=args.seconds, interval=args.interval, warmup=args.warmup,
        nofile_soft=resource.getrlimit(resource.RLIMIT_NOFILE)[0], nofile_hard=hard_fds,
        binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        source=args.source, segmented=('PPU_PAUSE_CLOCK' in os.environ),
        ownership_diagnostic=getattr(args, 'ownership', False), load=Path('/proc/loadavg').read_text().split()[:3],
        expected_idle=args.sessions - max(1, args.sessions // 10),
        expected_light=max(1, args.sessions // 10) - max(1, args.sessions // 100),
        expected_burst=max(1, args.sessions // 100))
    host = Host(args.binary, args.evidence / 'host', args.sessions, args.seed << 64,
                scope=f'ppu-soak-memory-{os.getpid()}' if args.mode == 'memory' else None,
                accounting=args.evidence / 'ownership.log' if getattr(args, 'ownership', False) else None)
    loop = asyncio.get_running_loop()
    if 'PPU_PAUSE_CLOCK' in os.environ:
        loop.time = clock_now
    loop.add_signal_handler(signal.SIGTERM, asyncio.current_task().cancel)
    try:
        await host.ready()
        if args.mode in ('soak', 'corpus'):
            return await soak(host, args, record, random.Random(args.seed))
        if args.mode == 'memory':
            sampler = FaultSampler(host, record, args.interval)
            try:
                return await memory_pressure(host, record)
            finally:
                await sampler.close()
        async def fault_load():
            while True:
                for index in range(host.count - max(1, host.count // 10), host.count):
                    peer = host.peers[index]
                    if peer.exit.done():
                        continue
                    command = (b"head -c 65536 /dev/zero | tr '\\000' x\n"
                               if index >= host.count - max(1, host.count // 100)
                               else b"printf 'fault-load\\n'\n")
                    await peer.send(0x10, command)
                await asyncio.sleep(1)
        load = asyncio.create_task(fault_load())
        sampler = FaultSampler(host, record, args.interval)
        try:
            result = await faults(host, args, record, random.Random(args.seed))
            if load.done():
                await load
            return result
        finally:
            load.cancel()
            await asyncio.gather(load, return_exceptions=True)
            await sampler.close()
    except Exception as error:
        record.write('outcome', scenario=args.mode, passed=False,
                     detail=f'{type(error).__name__}: {error}')
        raise
    finally:
        await host.close()
        record.file.close()
        loop.remove_signal_handler(signal.SIGTERM)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--source', required=True, help='exact build source SHA')
    parser.add_argument('--panic-test-binary', type=Path, help='musl shim --lib cfg(test) executable')
    parser.add_argument('--mode', choices=['soak', 'corpus', 'faults', 'process-events', 'memory'], default='soak')
    parser.add_argument('--corpus', type=Path, help='existing shim tests/fixtures directory')
    parser.add_argument('--sessions', type=int, default=1000)
    parser.add_argument('--seconds', type=float, default=7200)
    parser.add_argument('--interval', type=float, default=10)
    parser.add_argument('--warmup', type=float, default=600)
    parser.add_argument('--seed', type=int, default=270205)
    parser.add_argument('--ownership', action='store_true',
                        help='diagnostic: request per-session ownership after warmup and at completion')
    parser.add_argument('--memory-tolerance-kib', type=int, default=1024)
    parser.add_argument('--echo-ratio', type=float, default=1.25)
    args = parser.parse_args()
    if args.interval <= 0 or args.seconds <= 0 or args.warmup < 0:
        parser.error('duration/interval must be positive and warmup nonnegative')
    if args.mode == 'corpus' and (args.corpus is None or not args.corpus.is_dir()):
        parser.error('--mode corpus needs the existing terminal-parser corpus directory')
    raise SystemExit(0 if asyncio.run(run(args)) else 1)


if __name__ == '__main__':
    main()
