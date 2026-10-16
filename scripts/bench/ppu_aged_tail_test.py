#!/usr/bin/env python3
"""Check a continuous aged workload and explicit diagnostic log boundaries [D270].

SPDX-License-Identifier: AGPL-3.0-only
"""
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import ppu_aged_tail as aged

SCRATCH = Path.home() / '.cache/codex-scratch/process-per-user-tests'


def setUpModule():
    SCRATCH.mkdir(parents=True, exist_ok=True)


class Aging(unittest.IsolatedAsyncioTestCase):
    async def test_one_continuous_workload_keeps_original_arguments_and_state(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            await self.exercise(Path(directory))

    async def exercise(self, root):
        host = SimpleNamespace(count=1000)
        args = SimpleNamespace(mode='soak', seconds=900, warmup=600, interval=10)
        record = SimpleNamespace(file=io.StringIO())
        record.file.name = str(root / 'samples.jsonl')
        rng = object()
        capture = AsyncMock(return_value=False)
        with patch.object(aged.stages, 'soak', capture), \
             patch.object(aged, 'boundary', AsyncMock(return_value={'stage_log_offset': 100})), \
             patch.object(aged.stages, 'register_readers'):
            result = await aged.soak(host, args, record, rng)
        capture.assert_awaited_once()
        actual_host, options, actual_record, actual_rng = capture.await_args.args
        self.assertIs(actual_host, host)
        self.assertIs(actual_record, record)
        self.assertIs(actual_rng, rng)
        self.assertEqual(options.seconds, 6300)
        self.assertEqual(args.seconds, 900)
        self.assertEqual(capture.await_args.kwargs['profile_after'], 5400)
        self.assertFalse(result)

    async def test_extended_capture_is_refused_before_any_work(self):
        with patch.object(aged.stages, 'soak', AsyncMock()) as capture:
            with self.assertRaises(AssertionError):
                await aged.soak(None, SimpleNamespace(mode='soak', seconds=901, warmup=600), None, None)
            capture.assert_not_awaited()


class StageWindow(unittest.TestCase):
    def test_warmup_overflow_is_preserved_and_excluded_only_by_explicit_byte_boundary(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            root = Path(directory)
            source, destination = root / 'raw', root / 'window'
            header = b'{"kind":"stage-format","version":1}\n'
            before = header + b'{"kind":"stages","records":0,"dropped":99}\n'
            after = b'{"kind":"stages","records":0,"dropped":0}\n'
            source.write_bytes(before + after)
            aged.stage_window(source, destination, len(before))
            self.assertEqual(source.read_bytes(), before + after)
            self.assertEqual(destination.read_bytes(), header + after)
            for offset in (-1, True, 1, len(before) - 1, len(before + after) + 1):
                with self.subTest(offset=offset), self.assertRaises(ValueError):
                    aged.stage_window(source, root / f'bad-{offset}', offset)


if __name__ == '__main__':
    unittest.main()
