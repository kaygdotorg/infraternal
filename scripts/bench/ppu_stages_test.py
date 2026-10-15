#!/usr/bin/env python3
"""Check diagnostic probe offsets across real framing boundaries and input reservations [#205]."""
import asyncio
import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ppu_stages as stages


class StageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        stages.READERS.clear()
        stages.RECEIVED.clear()

    def test_missing_or_other_format_is_refused_before_diagnostic_signals(self):
        for text in ['', '{}', '{"kind":"stage-format","version":2}', '[]']:
            with self.assertRaises(ValueError):
                stages.read_header(io.StringIO(text))
        self.assertEqual(stages.read_header(io.StringIO('{"kind":"stage-format","version":1}'))['version'], 1)

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

    async def test_fragmented_marker_has_the_original_output_offset(self):
        reader = object()
        first = b'prefixprobe-900-'
        second = b'12\r\nsuffix'
        frames = iter([b'\x11' + (123).to_bytes(8, 'little') + first,
                       b'\x11' + (123 + len(first)).to_bytes(8, 'little') + second])
        async def receive(_):
            return next(frames)
        stages.READERS[reader] = dict(session=900, tail=b'', head=123)
        with patch.object(stages, 'ORIGINAL_FRAME', receive):
            await stages.frame(reader)
            await stages.frame(reader)
        row = stages.RECEIVED[(900, 12)]
        self.assertEqual(row['output_end'], 123 + len(first) + len(b'12\r\n'))
        self.assertGreater(row['receive_ns'], 0)

    async def test_output_gap_cannot_complete_an_earlier_marker(self):
        reader = object()
        first = b'probe-900-'
        frames = iter([b'\x11' + (0).to_bytes(8, 'little') + first,
                       b'\x11' + (len(first) + 1).to_bytes(8, 'little') + b'12\r\n'])
        async def receive(_):
            return next(frames)
        stages.READERS[reader] = dict(session=900, tail=b'', head=0)
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
            with patch.object(stages, 'ORIGINAL_SEND', send):
                await stages.send(peer, 0x10, b'seed\n')
        finally:
            stages.CURRENT.reset(token)
        self.assertEqual((probe['input_start'], probe['input_end'], peer.accepted), (17, 22, 22))
        self.assertGreaterEqual(probe['send_after_ns'], probe['send_before_ns'])


if __name__ == '__main__':
    unittest.main()
