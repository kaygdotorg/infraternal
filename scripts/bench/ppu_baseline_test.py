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


if __name__ == '__main__':
    unittest.main()
