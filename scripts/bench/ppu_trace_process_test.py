#!/usr/bin/env python3
"""Check numeric reader delivery and release of inherited fixture sockets [#205]."""
import os
import socket
import unittest

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


class ReaderTests(unittest.TestCase):
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
