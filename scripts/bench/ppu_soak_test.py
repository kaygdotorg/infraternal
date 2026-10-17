#!/usr/bin/env python3
"""Test receipt admission and protocol probes without substituting a mock host [D270]."""
import asyncio
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
import shlex
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

spec = importlib.util.spec_from_file_location('ppu_soak', Path(__file__).with_name('ppu_soak.py'))
ppu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ppu)
runner_spec = importlib.util.spec_from_loader('ppu_runner', SourceFileLoader(
    'ppu_runner', str(Path(__file__).with_name('ppu-run'))))
runner = importlib.util.module_from_spec(runner_spec)
runner_spec.loader.exec_module(runner)


def rows():
    return [dict(elapsed_s=10 * i, pss_kib=1000, fds=20, threads=1, echo_p99_ms=1)
            for i in range(20)]


class Admission(unittest.TestCase):
    def test_two_hour_run_preserves_one_fixture_between_short_lock_holds(self):
        args = SimpleNamespace(smoke=False, source='fixture-source', run='owned',
                               panic_test_binary=None)
        command = shlex.split(runner.command(args, 'soak', '/owned'))
        self.assertIn('/owned/scripts/bench/ppu_segment.py', command)
        self.assertIn('/owned/scripts/bench/ppu_soak.py', command)
        self.assertEqual(command[command.index('--seconds') + 1], '7200')
        self.assertNotIn('flock', command, 'coordinator owns each lock segment')

    def test_optional_accounting_belongs_to_only_the_fixture_host(self):
        class Root:
            def mkdir(self, **unused):
                pass
            def __truediv__(self, unused):
                return self
            def open(self, unused):
                return object()
            def __str__(self):
                return '/owned-fixture'
        with patch.object(ppu.subprocess, 'Popen') as spawn:
            spawn.return_value.pid = 42
            ppu.Host('binary', Root(), 10, 1, accounting=Path('/owned-receipt'))
            command = spawn.call_args.args[0]
            self.assertEqual(command[-2:], ['--host-accounting', '/owned-receipt'])
            ppu.Host('binary', Root(), 10, 1)
            self.assertNotIn('--host-accounting', spawn.call_args.args[0])

    def test_every_phase_fits_a_linux_socket_with_the_longest_run_id(self):
        args = SimpleNamespace(smoke=False, source='fixture-source', run='abcdefghij',
                               panic_test_binary=None)
        for phase in ('soak', 'corpus', 'faults', 'process-events', 'memory'):
            with self.subTest(phase=phase):
                command = shlex.split(runner.command(args, phase,
                    '/root/infraternal-bench/ppu-soak/abcdefghij'))
                evidence = Path(command[command.index('--evidence') + 1])
                socket_path = evidence / 'host/sessions' / ('a' * 32 + '.sock')
                self.assertLess(len(str(socket_path).encode()), 108,
                                'allowed run ID exceeds Linux sun_path including NUL')

    def test_warmup_cannot_pass_without_settled_samples(self):
        self.assertFalse(ppu.stability(rows(), 180, 1024, 1.25)['pass'])

    def test_flat_resources_pass(self):
        self.assertTrue(ppu.stability(rows(), 30, 1024, 1.25)['pass_'])

    def test_slow_leak_is_rejected_by_slope(self):
        data = rows()
        for row in data:
            row['pss_kib'] += row['elapsed_s']
        self.assertFalse(ppu.stability(data, 30, 1024, 1.25)['pass_'])

    def test_steady_echo_still_obeys_the_native_p99_budget(self):
        data = rows()
        for row in data:
            row['echo_p99_ms'] = 5.1
        self.assertFalse(ppu.stability(data, 30, 1024, 1.25)['pass_'])

    def test_fd_thread_and_echo_growth_are_rejected(self):
        for field, value in [('fds', 21), ('threads', 2), ('echo_p99_ms', 1.5)]:
            with self.subTest(field=field):
                data = rows()
                for row in data[-5:]:
                    row[field] = value
                self.assertFalse(ppu.stability(data, 30, 1024, 1.25)['pass_'])


class ReceiptClock(unittest.IsolatedAsyncioTestCase):
    async def test_echo_timestamp_precedes_resource_sampling(self):
        # Counter reads can be delayed across a frozen boundary. Segment
        # assignment belongs to completed echoes, not later receipt work.
        import random
        clock = SimpleNamespace(active=0, ns=1_000_000_000, samples=0)
        original_sleep = asyncio.sleep
        async def sleep(delay):
            clock.active += delay
            await original_sleep(0)
        class Peer:
            bytes = 0
            async def echo(self, *unused):
                return 1.0
            async def send(self, *unused):
                pass
            async def close(self):
                pass
        class Wakeups:
            def __init__(self, unused):
                pass
            def receipt(self):
                return dict(wakeups=0, wakeup_trace_overruns=0)
            def close(self):
                pass
        def sample(unused):
            clock.samples += 1
            if clock.samples == 2:
                clock.ns += 1_000_000_000
            return dict(pss_kib=1, cpu_ticks=0, voluntary_switches=0,
                        fds=1, threads=1)
        host = SimpleNamespace(count=2, peers=[Peer(), Peer()], pid=42,
            closed_output_bytes=0, child=SimpleNamespace(poll=lambda: None),
            path=lambda index: str(index))
        records = []
        recorder = SimpleNamespace(write=lambda kind, **fields: records.append((kind, fields)))
        args = SimpleNamespace(mode='soak', seconds=10, interval=10, warmup=0,
                               memory_tolerance_kib=1024, echo_ratio=1.25)
        with patch.object(ppu, 'sample', sample), patch.object(ppu, 'Wakeups', Wakeups), \
             patch.object(ppu, 'clock_now', lambda: clock.active), \
             patch.object(ppu.time, 'monotonic_ns', lambda: clock.ns), \
             patch.object(ppu.asyncio, 'sleep', sleep), \
             patch.object(ppu.Peer, 'connect', AsyncMock(return_value=Peer())):
            await ppu.soak(host, args, recorder, random.Random(270205))
        samples = [fields for kind, fields in records if kind == 'sample']
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0]['monotonic_ns'], 1_000_000_000)
        self.assertEqual(samples[0]['echo_ms'], [1.0])


class MemoryPhases(unittest.IsolatedAsyncioTestCase):
    """Sibling input must complete while the oversized string is still open."""
    async def test_open_string_is_held_until_every_sibling_echoes(self):
        release = asyncio.Event()
        drained = asyncio.Event()
        held = []
        class Peer:
            bytes = 0
            def __init__(self, index):
                self.index = index
                self.waiters = {}
            async def echo(self, marker, command=b''):
                if marker == b'memory-victim-finished':
                    # Framing/shell output may advance the byte count before
                    # the source reaches its explicit post-payload fence.
                    self.bytes = 33554436 + 4096
                    fence = self.waiters.get(b'memory-open-drained')
                    if fence is not None:
                        drained.set()
                        fence.set_result(0)
                    await release.wait()
                elif marker.startswith(b'memory-open-sibling-'):
                    self_assert_false(release.is_set())
                    self_assert_true(drained.is_set())
                    held.append(self.index)
                return 1.0
            async def send(self, kind, payload):
                self_assert_equal(set(held), set(range(1, 20)))
                release.set()
        self_assert_equal = self.assertEqual
        self_assert_false = self.assertFalse
        self_assert_true = self.assertTrue
        host = SimpleNamespace(scope='ppu-soak-memory-fixture', pid=42,
            peers=[Peer(i) for i in range(20)], child=SimpleNamespace(poll=lambda: None))
        contents = {'memory.max': 'max', 'memory.current': '10000000',
                    'memory.events': 'oom 0\n', 'memory.peak': '10010000',
                    'cgroup.procs': '42\n'}
        records = []
        recorder = SimpleNamespace(write=lambda kind, **fields: records.append((kind, fields)))
        with patch.object(ppu.subprocess, 'check_output', return_value='/owned/ppu-soak-memory-fixture.scope\n'), \
             patch.object(ppu.Path, 'read_text', lambda path: contents[path.name]), \
             patch.object(ppu.Path, 'write_text', lambda path, value: contents.update({path.name: value})), \
             patch.object(ppu.Path, 'exists', return_value=True):
            self.assertTrue(await asyncio.wait_for(ppu.memory_pressure(host, recorder), 3))
        self.assertEqual(contents['memory.max'], 'max')
        outcome = next(fields for kind, fields in records if kind == 'outcome')
        self.assertEqual(outcome['open_string_responsive_siblings'], 19)
        self.assertEqual(outcome['responsive_sessions'], 20)

    async def test_periodic_sampler_never_releases_the_held_source(self):
        called = []
        class Peer:
            bytes = 0
            exit = SimpleNamespace(done=lambda: False)
            def __init__(self, index):
                self.index = index
            async def echo(self, marker):
                called.append(self.index)
                return 1
        sampler = ppu.FaultSampler.__new__(ppu.FaultSampler)
        sampler.host = SimpleNamespace(pid=42, peers=[Peer(i) for i in range(3)])
        sampler.exclude = frozenset({0})
        sampler.record = SimpleNamespace(write=lambda *args, **fields: None)
        sampler.wakeups = SimpleNamespace(receipt=lambda: {})
        sampler.number, sampler.start, sampler.previous_time = 0, 0, 0
        sampler.previous = {'cpu_ticks': 0}
        with patch.object(ppu, 'sample', return_value={'cpu_ticks': 0}), \
             patch.object(ppu, 'clock_now', return_value=1):
            await sampler.tick()
        self.assertEqual(called, [1, 2])


class Framing(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_connect_closes_the_writer_and_joins_its_reader(self):
        for phase in ('hello', 'state'):
            with self.subTest(phase=phase):
                reader = asyncio.StreamReader()
                ready = asyncio.Event()
                before = asyncio.all_tasks()
                class Writer:
                    closed = False
                    def write(self, frame):
                        if frame[4] == 0x19:
                            ready.set()
                    async def drain(self):
                        pass
                    def close(self):
                        self.closed = True
                    async def wait_closed(self):
                        pass
                writer = Writer()
                read = reader.readexactly
                async def receiving(length):
                    if phase == 'hello':
                        ready.set()
                    return await read(length)
                reader.readexactly = receiving
                async def opened(*unused):
                    return reader, writer
                if phase == 'state':
                    hello = struct.pack('<BHQ16sIHHQQQ', 1, 1, 31, bytes(16), 42, 80, 24, 0, 0, 0)
                    reader.feed_data(struct.pack('<I', len(hello)) + hello)
                with patch.object(ppu.asyncio, 'open_unix_connection', side_effect=opened):
                    connecting = asyncio.create_task(ppu.Peer.connect('unused'))
                    try:
                        await asyncio.wait_for(ready.wait(), 3)
                        connecting.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await connecting
                        self.assertTrue(writer.closed, 'cancelled setup retained its viewer socket')
                        self.assertFalse(asyncio.all_tasks() - before,
                                         'cancelled setup retained its receive task')
                    finally:
                        # A red test still owns and retires every task it made.
                        pending = asyncio.all_tasks() - before
                        for task in pending:
                            task.cancel()
                        await asyncio.gather(*pending, return_exceptions=True)

    async def test_oversized_or_zero_frame_rejected_before_payload(self):
        for length in (0, ppu.MAX_FRAME + 1):
            reader = asyncio.StreamReader()
            reader.feed_data(struct.pack('<I', length))
            with self.assertRaises(AssertionError):
                await ppu.Peer.frame(reader)

    async def test_marker_survives_large_frame_and_boundary_split(self):
        class Writer:
            def close(self):
                pass
            async def wait_closed(self):
                pass
        for parts in [(b'marker' + b'x' * 16384,), (b'mar', b'ker' + b'x' * 16384)]:
            with self.subTest(parts=len(parts)):
                reader = asyncio.StreamReader()
                peer = ppu.Peer(reader, Writer(), 0, 1)
                future = asyncio.get_running_loop().create_future()
                peer.waiters[b'marker'] = future
                offset = 0
                for part in parts:
                    frame = bytes([0x11]) + struct.pack('<Q', offset) + part
                    reader.feed_data(struct.pack('<I', len(frame)) + frame)
                    offset += len(part)
                await asyncio.sleep(0)
                try:
                    self.assertTrue(future.done(), 'probe was lost inside a large output frame')
                finally:
                    peer.waiters.clear()
                    await peer.close()

    async def test_peer_failure_cannot_skip_remaining_fixture_cleanup(self):
        closed = []
        class Peer:
            async def close(self):
                closed.append('peer')
                if len(closed) == 1:
                    raise AssertionError('prior protocol failure')
        host = ppu.Host.__new__(ppu.Host)
        host.peers = [Peer(), Peer()]
        host.shells = []
        host.child = SimpleNamespace(poll=lambda: 0, wait=lambda: 0)
        host.log = SimpleNamespace(close=lambda: closed.append('log'))
        await host.close()
        self.assertEqual(closed, ['peer', 'peer', 'log'])

    async def test_connect_uses_a_nonzero_durable_writer_before_replay(self):
        class Writer:
            def __init__(self):
                self.frames = []
            def write(self, frame):
                self.frames.append(frame[4:])
            async def drain(self):
                pass
            def close(self):
                pass
            async def wait_closed(self):
                pass
        reader = asyncio.StreamReader()
        hello = struct.pack('<BHQ16sIHHQQQ', 1, 1, 31, bytes(16), 42, 80, 24, 0, 0, 0)
        state = bytes([0x1a]) + struct.pack('<QQ', 10, 10)
        reader.feed_data(struct.pack('<I', len(hello)) + hello + struct.pack('<I', len(state)) + state)
        writer = Writer()
        with patch.object(ppu.asyncio, 'open_unix_connection', AsyncMock(return_value=(reader, writer))):
            peer = await ppu.Peer.connect('unused')
        try:
            self.assertEqual(writer.frames[0], bytes([2]) + struct.pack('<Q', 7))
            self.assertEqual(writer.frames[1], bytes([0x1b]) + struct.pack('<I', 270205))
            self.assertEqual(peer.accepted, 10)
        finally:
            await peer.close()

    async def test_fragmented_frozen_frame(self):
        reader = asyncio.StreamReader()
        for byte in struct.pack('<I', 3) + b'abc':
            reader.feed_data(bytes([byte]))
        self.assertEqual(await ppu.Peer.frame(reader), b'abc')


if __name__ == '__main__':
    unittest.main()
