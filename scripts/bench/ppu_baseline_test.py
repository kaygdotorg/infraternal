#!/usr/bin/env python3
"""Check the independent-session adapter without changing the timed workload [D270]."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import ppu_baseline as baseline


class Baseline(unittest.TestCase):
    def test_child_census_rejects_any_lost_session(self):
        children = [SimpleNamespace(poll=lambda: None), SimpleNamespace(poll=lambda: 0)]
        self.assertIsNotNone(baseline.Children(children).poll())
        self.assertIsNone(baseline.Children(children[:1]).poll())

    def test_sample_sums_independent_hosts_and_keeps_machine_load(self):
        row = dict(rss_kib=1, pss_kib=2, anon_kib=3, cpu_ticks=4,
                   voluntary_switches=5, involuntary_switches=6, threads=1, fds=7,
                   load=['1', '2', '3'])
        with patch.object(baseline, 'original_sample', return_value=row):
            result = baseline.aggregate([10, 20])
        self.assertEqual(result['pss_kib'], 4)
        self.assertEqual(result['fds'], 14)
        self.assertEqual(result['load'], row['load'])

    def test_launcher_uses_the_shipping_shim_without_host_flags(self):
        command = baseline.command('binary', '/state', 3)
        self.assertNotIn('--host-sessions', command)
        self.assertEqual(command[command.index('--session') + 1], f'{3:032x}')
        self.assertEqual(command[-2:], ['--ring-capacity', '65536'])


class Cleanup(unittest.IsolatedAsyncioTestCase):
    async def test_one_dead_shim_does_not_skip_retiring_live_siblings(self):
        from unittest.mock import Mock
        host = baseline.Host.__new__(baseline.Host)
        host.peers = []
        host.shells = []
        dead = Mock()
        dead.poll.return_value = 0
        live = Mock()
        live.poll.return_value = None
        live.pid = 999999999
        host.children = [dead, live]
        host.child = baseline.Children(host.children)
        host.log = Mock()
        await host.close()
        dead.kill.assert_not_called()
        live.kill.assert_called_once()
        dead.wait.assert_called_once()
        live.wait.assert_called_once()

    async def test_reused_shell_pid_is_never_signalled_during_cleanup(self):
        from unittest.mock import Mock
        host = baseline.Host.__new__(baseline.Host)
        host.peers = []
        host.shells = [(100, '123')]
        live = Mock()
        live.poll.return_value = None
        live.pid = 555
        host.children = [live]
        host.child = baseline.Children(host.children)
        host.log = Mock()
        def read(path):
            if path.name == 'children':
                return '100'
            fields = ['0'] * 20
            fields[19] = '456'  # The numeric PID now names another birth.
            return '100 (fixture) ' + ' '.join(fields)
        with patch.object(baseline.Path, 'read_text', read), \
             patch.object(baseline.os, 'getpgid', return_value=100), \
             patch.object(baseline.os, 'killpg') as group_signal, \
             patch.object(baseline.os, 'pidfd_open', return_value=99), \
             patch.object(baseline.os, 'close'), \
             patch.object(baseline.signal, 'pidfd_send_signal') as pinned_signal:
            await host.close()
        group_signal.assert_not_called()
        pinned_signal.assert_not_called()

    def test_real_captured_child_is_retired_through_its_pinned_identity(self):
        import subprocess
        import sys
        from pathlib import Path
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        try:
            birth = Path(f'/proc/{child.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
            baseline.retire_shell(child.pid, birth)
            self.assertEqual(child.wait(timeout=5), -baseline.signal.SIGKILL)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()


class Readiness(unittest.IsolatedAsyncioTestCase):
    """A published socket path can precede its listener becoming ready."""
    def setUp(self):
        from pathlib import Path
        from unittest.mock import AsyncMock, Mock
        self.host = baseline.Host.__new__(baseline.Host)
        self.host.binary, self.host.root = Path('binary'), Path('unused-state')
        self.host.count, self.host.origin = 1, 3
        self.host.children, self.host.peers, self.host.shells = [], [], []
        self.host.log = Mock()
        self.host.path = lambda index: SimpleNamespace(exists=lambda: True)
        self.child = SimpleNamespace(pid=424242, poll=Mock(return_value=None))
        self.peer = SimpleNamespace(pid=424242, echo=AsyncMock())
        self.connect = AsyncMock(side_effect=[ConnectionRefusedError(), self.peer])
        def read(path):
            if path.name == 'children':
                return '424243'
            fields = ['0'] * 20
            fields[19] = '123'
            return '424243 (shell) ' + ' '.join(fields)
        patches = [patch.object(baseline.subprocess, 'Popen', return_value=self.child),
                   patch.object(baseline.suite.Peer, 'connect', self.connect),
                   patch.object(baseline.Path, 'read_text', read),
                   patch.object(baseline.asyncio, 'sleep', AsyncMock()),
                   patch.object(baseline.suite, 'sample')]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    async def test_live_shim_waits_for_listen_after_socket_publication(self):
        await self.host.ready()
        self.assertEqual(self.connect.await_count, 2)
        self.assertEqual(self.host.peers, [self.peer])
        self.peer.echo.assert_awaited_once()

    async def test_exited_shim_is_not_hidden_by_a_listen_retry(self):
        self.child.poll.side_effect = [None, 0]
        with self.assertRaisesRegex(AssertionError, 'shipping shim exited'):
            await self.host.ready()
        self.assertEqual(self.connect.await_count, 1)


if __name__ == '__main__':
    unittest.main()
