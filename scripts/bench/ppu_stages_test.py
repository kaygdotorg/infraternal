#!/usr/bin/env python3
"""Check diagnostic probe offsets across real framing boundaries and input reservations [#205]."""
import asyncio
import io
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import ppu_stages as stages


class StageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        stages.READERS.clear()
        stages.RECEIVED.clear()
        stages.PROBES.clear()

    async def test_short_workload_cannot_claim_a_late_capture(self):
        with patch.object(stages.trace, 'Trace') as create, \
             patch.object(stages, 'ORIGINAL_SOAK', AsyncMock(return_value=True)):
            with self.assertRaisesRegex(RuntimeError, 'before bounded capture'):
                await stages.soak(SimpleNamespace(pid=123),
                    SimpleNamespace(mode='soak', seconds=900), None, None, profile_after=600)
            create.assert_not_called()

    async def test_original_failure_before_activation_is_preserved(self):
        with patch.object(stages.trace, 'Trace') as create, \
             patch.object(stages, 'ORIGINAL_SOAK', AsyncMock(side_effect=ConnectionError('lost fixture'))):
            with self.assertRaisesRegex(ConnectionError, 'lost fixture'):
                await stages.soak(SimpleNamespace(pid=123),
                    SimpleNamespace(mode='soak', seconds=900), None, None, profile_after=600)
            create.assert_not_called()

    async def test_delayed_capture_keeps_one_original_workload_invocation(self):
        scratch = Path.home() / '.cache/codex-scratch/process-per-user/tests'
        scratch.mkdir(parents=True, exist_ok=True)
        active = asyncio.Event()
        async def prepare():
            active.set()
        async def workload(*_):
            await active.wait()
            stamp = time.monotonic_ns()
            stages.PROBES.append(dict(session=900, number=540, send_before_ns=stamp, completed_ns=stamp))
            stages.RECEIVED[(900, 540)] = dict(receive_ns=stamp)
            return False
        scheduler = Mock(events=[])
        scheduler.close.return_value = dict(complete=True, overruns=0)
        with tempfile.TemporaryDirectory(dir=scratch) as directory, \
             patch.object(stages.trace, 'Trace', return_value=scheduler) as create, \
             patch.object(stages, 'ORIGINAL_SOAK', AsyncMock(side_effect=workload)) as original, \
             patch.object(stages.os, 'kill'):
            host = SimpleNamespace(pid=123, origin=1, peers=[SimpleNamespace(echo=AsyncMock())])
            record = SimpleNamespace(file=SimpleNamespace(name=str(Path(directory) / 'samples.jsonl')))
            self.assertFalse(await stages.soak(host, SimpleNamespace(mode='soak', seconds=1, warmup=0),
                record, object(), profile_after=.001, before_profile=prepare))
            original.assert_awaited_once()
            create.assert_called_once_with(123)
            scheduler.close.assert_called_once()

    async def test_failed_activation_never_leaves_an_unowned_trace(self):
        attempted = asyncio.Event()
        async def prepare():
            attempted.set()
            raise ConnectionError('boundary refused')
        async def workload(*_):
            await attempted.wait()
            return True
        with patch.object(stages.trace, 'Trace') as create, \
             patch.object(stages, 'ORIGINAL_SOAK', workload), \
             patch.object(stages.os, 'kill') as send:
            with self.assertRaisesRegex(ConnectionError, 'boundary refused'):
                await stages.soak(SimpleNamespace(pid=123), SimpleNamespace(mode='soak', seconds=1),
                    None, None, profile_after=.001, before_profile=prepare)
            create.assert_not_called()
            send.assert_not_called()

    def test_missing_or_other_format_is_refused_before_diagnostic_signals(self):
        for text in ['', '{}', '{"kind":"stage-format","version":2}', '[]']:
            with self.assertRaises(ValueError):
                stages.read_header(io.StringIO(text))
        self.assertEqual(stages.read_header(io.StringIO('{"kind":"stage-format","version":1}'))['version'], 1)

    async def test_aged_capture_is_bounded_to_one_short_lock_hold(self):
        scheduler = Mock()
        async def workload(*_):
            return None
        async def fence(*_):
            raise ConnectionError('synthetic host closed')
        host = SimpleNamespace(pid=123, peers=[SimpleNamespace(echo=fence)])
        with patch.object(stages.trace, 'Trace', return_value=scheduler) as create, \
             patch.object(stages, 'ORIGINAL_SOAK', workload), \
             patch.object(stages.os, 'kill'):
            with self.assertRaises(ConnectionError):
                await stages.soak(host, SimpleNamespace(mode='soak', seconds=900), None, None)
            scheduler.close.assert_called_once()
            create.reset_mock()
            with self.assertRaises(AssertionError):
                await stages.soak(host, SimpleNamespace(mode='soak', seconds=901), None, None)
            create.assert_not_called()

    async def test_failed_final_fence_still_closes_private_scheduler(self):
        scheduler = Mock()
        async def workload(*_):
            return None
        async def fence(*_):
            raise ConnectionError('synthetic host closed')
        host = SimpleNamespace(pid=123, peers=[SimpleNamespace(echo=fence)])
        args = SimpleNamespace(mode='soak', seconds=1)
        with patch.object(stages.trace, 'Trace', return_value=scheduler), \
             patch.object(stages, 'ORIGINAL_SOAK', workload), \
             patch.object(stages.os, 'kill'):
            with self.assertRaises(ConnectionError):
                await stages.soak(host, args, None, None)
        scheduler.close.assert_called_once()

    async def test_failed_periodic_signal_still_closes_private_scheduler(self):
        scheduler = Mock()
        async def workload(*_):
            await asyncio.sleep(0)
        host = SimpleNamespace(pid=123)
        args = SimpleNamespace(mode='soak', seconds=1)
        with patch.object(stages.trace, 'Trace', return_value=scheduler), \
             patch.object(stages, 'ORIGINAL_SOAK', workload), \
             patch.object(stages.os, 'kill', side_effect=ProcessLookupError):
            with self.assertRaises(ProcessLookupError):
                await stages.soak(host, args, None, None)
        scheduler.close.assert_called_once()

    async def test_fragmented_marker_has_the_original_output_offset(self):
        reader = object()
        first = b'prefixprobe-900-'
        second = b'12\r\nsuffix'
        frames = iter([b'\x11' + (123).to_bytes(8, 'little') + first,
                       b'\x11' + (123 + len(first)).to_bytes(8, 'little') + second])
        async def receive(_):
            return next(frames)
        stages.READERS[reader] = dict(session=900, tail=b'', head=123,
            peer=SimpleNamespace(waiters={b'probe-900-12': asyncio.get_running_loop().create_future()}))
        with patch.object(stages, 'ORIGINAL_FRAME', receive), \
             patch.object(stages.time, 'thread_time_ns', return_value=900) as cpu_clock:
            await stages.frame(reader)
            await stages.frame(reader)
        cpu_clock.assert_called_once()
        row = stages.RECEIVED[(900, 12)]
        self.assertEqual(row['output_end'], 123 + len(first) + len(b'12'))
        self.assertGreater(row['receive_ns'], 0)
        self.assertEqual(row['receive_thread_cpu_ns'], 900)

    async def test_registered_marker_receipt_does_not_wait_for_its_newline(self):
        reader = object()
        marker = b'probe-900-12'
        future = asyncio.get_running_loop().create_future()
        peer = SimpleNamespace(waiters={marker: future})
        frames = iter([b'\x11' + (0).to_bytes(8, 'little') + marker,
                       b'\x11' + len(marker).to_bytes(8, 'little') + b'\r\n'])
        async def receive(_):
            return next(frames)
        stages.READERS[reader] = dict(session=900, tail=b'', head=0, peer=peer)
        with patch.object(stages, 'ORIGINAL_FRAME', receive):
            await stages.frame(reader)
            self.assertIn((900, 12), stages.RECEIVED,
                          'the timed waiter completes on marker bytes, before newline')
            first = stages.RECEIVED[(900, 12)].copy()
            self.assertEqual(first['output_end'], len(marker))
            future.set_result(0)
            await stages.frame(reader)
        self.assertEqual(stages.RECEIVED[(900, 12)], first)

    async def test_output_gap_cannot_complete_an_earlier_marker(self):
        reader = object()
        first = b'probe-900-'
        frames = iter([b'\x11' + (0).to_bytes(8, 'little') + first,
                       b'\x11' + (len(first) + 1).to_bytes(8, 'little') + b'12\r\n'])
        async def receive(_):
            return next(frames)
        stages.READERS[reader] = dict(session=900, tail=b'', head=0,
            peer=SimpleNamespace(waiters={b'probe-900-12': asyncio.get_running_loop().create_future()}))
        with patch.object(stages, 'ORIGINAL_FRAME', receive):
            await stages.frame(reader)
            await stages.frame(reader)
        self.assertFalse(stages.RECEIVED)

    async def test_send_records_the_reserved_input_range_before_yielding(self):
        peer = SimpleNamespace(accepted=17)
        probe = dict(session=900, number=12)
        async def send(peer, kind, data):
            peer.accepted += len(data)
            await asyncio.sleep(0)
        token = stages.CURRENT.set(probe)
        try:
            with patch.object(stages, 'ORIGINAL_SEND', send), \
                 patch.object(stages.time, 'thread_time_ns', return_value=700):
                await stages.send(peer, 0x10, b'seed\n')
        finally:
            stages.CURRENT.reset(token)
        self.assertEqual((probe['input_start'], probe['input_end'], peer.accepted), (17, 22, 22))
        self.assertGreaterEqual(probe['send_after_ns'], probe['send_before_ns'])
        self.assertEqual(probe['send_before_thread_cpu_ns'], 700)


if __name__ == '__main__':
    unittest.main()
