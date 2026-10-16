#!/usr/bin/env python3
"""Check retained-host preconditioning and explicit diagnostic log boundaries [D270].

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
    async def exercise(self, root, fail=False, complete=True):
        host = SimpleNamespace(count=1000)
        args = SimpleNamespace(mode='soak', seconds=900, warmup=600, interval=10)
        record = SimpleNamespace(file=io.StringIO())
        record.file.name = str(root / 'samples.jsonl')
        rng = object()
        original_echo = aged.suite.Peer.echo
        original_wakeups = aged.suite.Wakeups
        seen = []

        async def precondition(actual, options, receipt, random):
            self.assertIs(actual, host)
            self.assertIs(random, rng)
            self.assertEqual(options.seconds, 5400)
            self.assertEqual(args.seconds, 900)
            self.assertIs(aged.suite.Peer.echo, aged.stages.ORIGINAL_ECHO)
            self.assertIs(aged.suite.Wakeups, aged.tail.ORIGINAL_WAKEUPS)
            seen.append(receipt)
            if fail:
                raise ConnectionError('synthetic session ended')
            receipt.write('sample', elapsed_s=5400 if complete else 5390)
            receipt.write('survivors', expected_sessions=1000, responsive_sessions=1000, host_alive=True)
            return False  # An echo-budget failure must not be disguised as lost sessions.

        capture = AsyncMock(return_value=False)
        with patch.object(aged.stages, 'ORIGINAL_SOAK', precondition), \
             patch.object(aged.stages, 'soak', capture), \
             patch.object(aged, 'boundary', AsyncMock(return_value={'stage_log_offset': 100})), \
             patch.object(aged.stages, 'register_readers'), \
             patch.object(aged.compare, 'write', lambda *_args, **_kwargs: None):
            try:
                result = await aged.soak(host, args, record, rng)
            except BaseException:
                capture.assert_not_awaited()
                raise
            finally:
                self.assertIs(aged.suite.Peer.echo, original_echo)
                self.assertIs(aged.suite.Wakeups, original_wakeups)
                self.assertTrue(seen[0].file.closed)
        capture.assert_awaited_once_with(host, args, record, rng)
        self.assertFalse(result)

    async def test_same_host_reaches_capture_despite_preconditioning_echo_failure(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            await self.exercise(Path(directory))

    async def test_preconditioning_failure_restores_hooks_without_starting_capture(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            with self.assertRaises(ConnectionError):
                await self.exercise(Path(directory), fail=True)

    async def test_incomplete_preconditioning_cannot_claim_an_aged_capture(self):
        with tempfile.TemporaryDirectory(dir=SCRATCH) as directory:
            with self.assertRaisesRegex(RuntimeError, 'incomplete preconditioning'):
                await self.exercise(Path(directory), complete=False)


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
