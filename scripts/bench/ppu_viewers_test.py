#!/usr/bin/env python3
"""Verify extra-viewer identity, byte validation and receipt admission [D270, #205].

SPDX-License-Identifier: AGPL-3.0-only
Local fixtures validate the driver only; they provide no performance evidence.
"""
import asyncio
from pathlib import Path
import re
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import ppu_viewers as viewers
from ppu_soak import Peer, WRITER


class Lines(unittest.TestCase):
    def test_split_frames_validate_every_numbered_72_column_line(self):
        oracle = viewers.NumberedLines(3)
        data = b''.join(viewers.numbered_line(i) + b'\r\n' for i in range(1, 4))
        for index in range(0, len(data), 13):
            oracle.feed(data[index:index + 13])
        oracle.finish()
        self.assertEqual(oracle.count, 3)
        self.assertEqual(len(viewers.numbered_line(1)), 72)

    def test_missing_duplicate_or_modified_line_invalidates_fill(self):
        for data in (viewers.numbered_line(2) + b'\r\n',
                     viewers.numbered_line(1) + b'\r\n' + viewers.numbered_line(1) + b'\r\n',
                     viewers.numbered_line(1)[:-1] + b'x\r\n'):
            with self.subTest(data=data[:8]), self.assertRaises(AssertionError):
                oracle = viewers.NumberedLines(2)
                oracle.feed(data)
                oracle.finish()

    def test_completion_marker_cannot_hide_truncated_output(self):
        oracle = viewers.NumberedLines(2)
        oracle.feed(viewers.numbered_line(1) + b'\r\nfill-complete\r\n')
        with self.assertRaises(AssertionError):
            oracle.finish()

    def test_idle_cpu_and_extra_viewer_delta_use_real_intervals(self):
        self.assertEqual(viewers.cpu_percent({'cpu_ticks': 10}, {'cpu_ticks': 30}, 2, 100), 10)
        previous = {'viewers': 3, 'idle_pss_kib': 1000, 'idle_rss_kib': 2000}
        current = {'viewers': 5, 'idle_pss_kib': 1020, 'idle_rss_kib': 2040}
        self.assertEqual(viewers.increment(current, previous),
                         {'added_viewers': 2, 'pss_kib_per_extra_viewer': 10,
                          'rss_kib_per_extra_viewer': 20})


class Protocol(unittest.IsolatedAsyncioTestCase):
    async def test_snapshot_rejects_invalid_flags_lengths_and_regressed_offset(self):
        invalid = [bytes([0x15]) + bytes(7),
                   bytes([0x1c]) + struct.pack('<QB', 20, 2) + b'screen',
                   bytes([0x15]) + struct.pack('<Q', 19) + b'screen',
                   bytes([0x15]) + struct.pack('<Q', 20)]
        for body in invalid:
            with self.subTest(body=body):
                reader = asyncio.StreamReader()
                reader.feed_data(struct.pack('<I', len(body)) + body)
                peer = viewers.ViewerPeer.__new__(viewers.ViewerPeer)
                peer.head = 20
                peer.snapshot = asyncio.get_running_loop().create_future()
                with self.assertRaises(AssertionError):
                    await peer.frame(reader)
                self.assertFalse(peer.snapshot.done())

    async def test_fill_observer_fences_an_already_pending_original_reader(self):
        reader = asyncio.StreamReader()
        class Writer:
            head = 0
            def write(self, frame):
                command = frame[13:]
                octals = re.search(rb"printf '((?:\\[0-7]{3})+)\\n'", command).group(1)
                marker = bytes(int(octals[index + 1:index + 4], 8)
                               for index in range(0, len(octals), 4))
                output = marker + b'\r\n'
                if b'timeout 120 cat' in command:
                    output = viewers.numbered_line(1) + b'\r\n' + output
                body = bytes([0x11]) + struct.pack('<Q', self.head) + output
                self.head += len(output)
                reader.feed_data(struct.pack('<I', len(body)) + body)
            async def drain(self):
                pass
            def close(self):
                pass
            async def wait_closed(self):
                pass
        class Root:
            def __truediv__(self, name):
                return self
            def write_bytes(self, data):
                self.data = data
            def __str__(self):
                return '/fixture-fill'
        peer = Peer(reader, Writer(), 0, 1)
        await asyncio.sleep(0)  # receive() is now blocked inside its original frame().
        receipts = []
        record = SimpleNamespace(write=lambda kind, **row: receipts.append((kind, row)))
        try:
            await viewers.fill(SimpleNamespace(root=Root(), peers=[peer]), 1, record)
            self.assertEqual(receipts[0][1]['ordered_lines'], 1)
        finally:
            await peer.close()

    async def test_extra_viewers_select_distinct_durable_writer_before_snapshot(self):
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
        writers = []
        peers = []
        try:
            for number in (1, 2, 3, 5):
                reader, writer = asyncio.StreamReader(), Writer()
                hello = struct.pack('<BHQ16sIHHQQQ', 1, 1, 31, bytes(16), 42, 80, 24, 0, 500, 400)
                state = bytes([0x1a]) + struct.pack('<QQ', 0, 0)
                snapshot = bytes([0x1c]) + struct.pack('<QB', 500, 1) + b'screen'
                reader.feed_data(b''.join(struct.pack('<I', len(frame)) + frame
                                          for frame in (hello, state, snapshot)))
                with patch('ppu_viewers.asyncio.open_unix_connection',
                           AsyncMock(return_value=(reader, writer))):
                    peer = await viewers.ViewerPeer.connect(Path('/unused'), viewers.writer_id(number))
                peers.append(peer)
                writers.append(writer)
                self.assertEqual(writer.frames[0], bytes([2]) + struct.pack('<Q', 7))
                self.assertEqual(writer.frames[1], bytes([0x1b]) + struct.pack('<I', WRITER + number))
                self.assertEqual(writer.frames[2], bytes([0x19]))
                self.assertEqual(writer.frames[3], bytes([0x14]))
                self.assertEqual(peer.head, 500)
                self.assertTrue(peer.snapshot_receipt['approximate'])
                self.assertEqual(peer.snapshot_receipt['bytes'], 6)
            self.assertEqual(len({writer.frames[1] for writer in writers}), 4)
        finally:
            for peer in peers:
                await peer.close()

    async def test_disconnected_viewer_invalidates_sample(self):
        reader = asyncio.StreamReader()
        writer = type('Writer', (), {'close': lambda self: None,
                                     'wait_closed': AsyncMock()})()
        peer = Peer(reader, writer, 0, 1)
        try:
            reader.feed_eof()
            await asyncio.sleep(0)
            with self.assertRaises(AssertionError):
                viewers.require_live([[peer]], 1)
        finally:
            await peer.close()

    async def test_every_viewer_must_observe_the_typed_confirmation(self):
        class Sender:
            waiters = {}
            async def echo(self, marker):
                return .1
        sender = Sender()
        receiver = type('Receiver', (), {'waiters': {}})()
        with self.assertRaises(TimeoutError):
            await viewers.confirm(sender, [sender, receiver], b'confirmation', timeout=.01)
        self.assertEqual(receiver.waiters, {})


if __name__ == '__main__':
    unittest.main()
