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


class Framing(unittest.IsolatedAsyncioTestCase):
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
