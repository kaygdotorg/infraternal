#!/usr/bin/env python3
"""Verify contention exclusions and segment ownership independently of echo values [D270]."""
import unittest
from ppu_compare_report import contamination, windows


def receipt(foreign_cpu=10):
    return dict(owner='process-per-user ppu-soak-own now', locks=[['FLOCK']],
                control_scopes=['control.scope'],
                scope_cpu={'idle.scope': dict(usage_usec=str(foreign_cpu)),
                           'control.scope': dict(usage_usec='100')})


class Reports(unittest.TestCase):
    def test_idle_foreign_scope_is_kept_but_foreign_cpu_discards_the_batch(self):
        self.assertEqual(contamination(receipt(), receipt(), 'ppu-soak-own'), [])
        self.assertEqual(contamination(receipt(), receipt(11), 'ppu-soak-own'),
                         ['foreign-scope-cpu:idle.scope'])

    def test_verified_own_observer_scope_is_explicit_not_a_foreign_job(self):
        before, after = receipt(), receipt(11)
        after['scope_cpu']['other.scope'] = dict(usage_usec='1')
        before['scope_cpu']['other.scope'] = dict(usage_usec='0')
        result = contamination(before, after, 'ppu-soak-own', observer_scopes={'idle.scope'})
        self.assertEqual(result, ['foreign-scope-cpu:other.scope'])

    def test_missing_lock_and_scope_transitions_are_never_a_clean_batch(self):
        self.assertTrue(contamination(None, receipt(), 'ppu-soak-own'))
        self.assertTrue(contamination(receipt(), receipt(), 'ppu-soak-other'))
        after = receipt()
        del after['scope_cpu']['idle.scope']
        self.assertTrue(contamination(receipt(), after, 'ppu-soak-own'))

    def test_exit_then_release_cannot_duplicate_the_last_segment(self):
        rows = [dict(kind=kind, monotonic_ns=stamp) for kind, stamp in
                [('lock-acquired', 1), ('freeze', 3), ('lock-acquired', 7),
                 ('exit', 9), ('lock-released', 10)]]
        self.assertEqual(windows(rows), [(1, 3), (7, 9)])
        with self.assertRaises(AssertionError):
            windows(rows[:1])


if __name__ == '__main__':
    unittest.main()
