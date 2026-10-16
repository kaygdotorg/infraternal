#!/usr/bin/env python3
"""Verify shipping-control reports retain scheduling and omit nonexistent stages [D270]."""
import json
from pathlib import Path
import tempfile
import unittest
from ppu_baseline_tail_report import report
from ppu_stages import MARKER_RECEIPT


class Reports(unittest.TestCase):
    def capture(self, foreign_cpu):
        probe = dict(session=900, number=0, rtt_ms=1., send_before_s=10.,
                     receive_active_s=10.0005, send_before_ns=10, receive_ns=90)
        before = dict(owner='process-per-user owned now', locks=[['FLOCK']],
                      scope_cpu={'foreign.scope': dict(usage_usec='1')})
        after = before | dict(scope_cpu={'foreign.scope': dict(usage_usec=str(foreign_cpu))})
        records = [dict(kind='environment', machine_receipt=before),
                   dict(kind='sample', elapsed_s=1, machine_receipt=after)]
        meta = dict(complete=True, overruns=0, native_host_stages=False,
                    marker_receipt=MARKER_RECEIPT, started_ns=0, probes=[probe])
        roles = {'host-900': 1, 'session-900': 2, 'reader': 3}
        events = [dict(pid=pid, ns=stamp, kind='sched_switch', state=state)
                  for pid in roles.values() for stamp, state in [(0, 'in'), (100, 'out-sleeping')]]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, data in [('baseline-probes.json', meta), ('tail-roles.json', roles)]:
                (root / name).write_text(json.dumps(data))
            (root / 'tail-events.jsonl').write_text('\n'.join(map(json.dumps, events)))
            (root / 'samples.jsonl').write_text('\n'.join(map(json.dumps, records)))
            return report(root, 0, 'owned')

    def test_control_cannot_invent_native_vt_or_frame_timestamps(self):
        result = self.capture(1)
        self.assertFalse(result['native_host_stages'])
        self.assertEqual(result['probes'], 1)
        self.assertIn('scheduler_ms', result['slowest'][0])
        self.assertNotIn('parse_ms', result['slowest'][0])

    def test_foreign_activity_excludes_the_same_native_probe(self):
        result = self.capture(2)
        self.assertEqual(result['probes'], 0)
        self.assertEqual(result['discarded_batches'][0]['number'], 0)


if __name__ == '__main__':
    unittest.main()
