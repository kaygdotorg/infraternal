#!/usr/bin/env python3
"""Check numeric reader delivery and release of inherited fixture sockets [#205]."""
import os
import socket
import unittest
from unittest.mock import patch

from ppu_trace_process import Drain


class Observer:
    """Small reader boundary with a real inherited fixture descriptor."""
    def __init__(self, fd=None):
        self.fd = fd
        self.events = []
        self.error = None

    def read(self):
        try:
            os.fstat(self.fd)
        except OSError:
            self.events.append((1, 'socket-copy-closed', ''))
        else:
            raise RuntimeError('fixture socket retained')

    def fail(self):
        raise ValueError('synthetic details must stay in the child')

    def trace_files(self):
        os.fstat(self.fd)
        try:
            os.fstat(self.older_counter)
        except OSError:
            self.events.append((1, 'older-counter-copy-closed', ''))
        else:
            raise RuntimeError('older counter descriptor retained')


class ReaderTests(unittest.TestCase):
    def test_child_keeps_its_trace_but_releases_an_older_counter_descriptor(self):
        own_read, own_write = os.pipe()
        older_read, older_write = os.pipe()
        original_link = os.readlink
        def trace_link(path):
            if str(path) == f'/proc/self/fd/{own_read}':
                return '/sys/kernel/tracing/instances/ppu-stalls-owned/trace_pipe'
            if str(path) == f'/proc/self/fd/{older_read}':
                return '/sys/kernel/tracing/instances/ppu-soak-owned/trace_pipe'
            return original_link(path)
        try:
            observer = Observer(own_read)
            observer.older_counter = older_read
            reader = Drain(observer.trace_files, daemon=True)
            with patch('ppu_trace_process.os.readlink', side_effect=trace_link):
                reader.start()
                reader.join()
            self.assertIsNone(observer.error)
            self.assertEqual(observer.events, [(1, 'older-counter-copy-closed', '')])
            self.assertFalse(reader.process.is_alive())
            # Closing the child's copies cannot close either parent descriptor.
            os.fstat(own_read)
            os.fstat(older_read)
        finally:
            for fd in (own_read, own_write, older_read, older_write):
                os.close(fd)

    def test_child_releases_its_socket_copy_and_returns_numeric_events(self):
        local, remote = socket.socketpair()
        with local, remote:
            inode = os.fstat(local.fileno()).st_ino
            observer = Observer(local.fileno())
            reader = Drain(observer.read, daemon=True)
            reader.start()
            reader.join()
            self.assertEqual(observer.events, [(1, 'socket-copy-closed', '')])
            self.assertIsNone(observer.error)
            self.assertFalse(reader.process.is_alive())
            self.assertEqual(os.fstat(local.fileno()).st_ino, inode)

    def test_child_reports_exception_type_without_exception_text(self):
        observer = Observer()
        reader = Drain(observer.fail, daemon=True)
        reader.start()
        reader.join()
        self.assertEqual(observer.error, 'ValueError')
        self.assertEqual(observer.events, [])
        self.assertFalse(reader.process.is_alive())


if __name__ == '__main__':
    unittest.main()
