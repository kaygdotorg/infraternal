#!/usr/bin/env python3
"""Check diagnostic event identity filtering and argument disposal [D270]."""
import unittest
import ppu_tail as tail


class Events(unittest.TestCase):
    def test_switch_keeps_both_owned_roles_and_sleep_state(self):
        rows = tail.numeric_events(b' shell-10 [000] 1.000000: sched_switch: prev_pid=10 prev_state=S next_pid=20', {10, 20})
        self.assertEqual(rows, [(1., 10, 'sched_switch', 'out-sleeping'), (1., 20, 'sched_switch', 'in')])

    def test_fault_addresses_and_syscall_arguments_are_discarded(self):
        for body, kind in [(b'page_fault_user: address=12345678 ip=87654321', 'page_fault_user'),
                           (b'sys_enter_read: fd=7 buf=12345678', 'sys_enter_read')]:
            with self.subTest(kind=kind):
                rows = tail.numeric_events(b' host-10 [000] 1.500000: ' + body, {10})
                self.assertEqual(rows, [(1.5, 10, kind, '')])
                self.assertEqual(tail.numeric_events(b' foreign-11 [000] 1.500000: ' + body, {10}), [])

    def test_stack_header_and_waking_event_retain_only_owned_identity(self):
        self.assertEqual(tail.numeric_events(b' host-10 [000] 2.000000: <stack trace>', {10}),
                         [(2., 10, 'stack', '')])
        line = b' other-99 [000] 2.000000: sched_waking: comm=private pid=10 prio=120'
        self.assertEqual(tail.numeric_events(line, {10}), [(2., 10, 'sched_waking', '')])
        self.assertEqual(tail.numeric_events(line, {99}), [])


class Futex(unittest.TestCase):
    def test_counter_and_reader_share_identity_without_exposing_address(self):
        identities = {}
        line = b'sys_futex(uaddr: deadbeef, op: 89)'
        first = tail.futex_fields(line, 'sys_enter_futex', 10, 10, 20, identities)
        second = tail.futex_fields(line, 'sys_enter_futex', 20, 10, 20, identities)
        other = tail.futex_fields(line, 'sys_enter_futex', 30, 10, 20, identities)
        self.assertEqual(first, dict(futex_lock=1, futex_op=137))
        self.assertEqual(first, second)
        self.assertNotEqual(first['futex_lock'], other['futex_lock'])
        self.assertNotIn('deadbeef', str(first))

    def test_timeout_result_supports_both_kernel_printers(self):
        for line in (b'sys_exit_futex: ret=-110', b'sys_futex -> 0xffffffffffffff92'):
            self.assertEqual(tail.futex_fields(line, 'sys_exit_futex', 10, 10, 20, {}),
                             dict(futex_result=-110))


if __name__ == '__main__':
    unittest.main()
