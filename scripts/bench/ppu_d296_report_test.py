#!/usr/bin/env python3
"""Check matched native admission from numeric receipts, without a substitute host [D296]."""
import json
from pathlib import Path
import tempfile
import unittest

from ppu_d296_report import report_round


class Round(unittest.TestCase):
    """Incomplete, diagnostic or mismatched cells cannot become admission evidence."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pairs = [('d0', 'p0'), ('d1', 'p1'), ('d2', 'p2')]
        for number, pair in enumerate(self.pairs):
            self.cell(pair[0], 'shipping', [1, 1, 100][number])
            self.cell(pair[1], 'prototype', 50)

    def cell(self, name, role, value):
        root = self.root / name
        root.mkdir()
        machine = dict(owner=f'process-per-user ppu-soak-d296-{name} now',
                       locks=[['FLOCK']], scope_cpu={})
        environment = dict(kind='environment', machine='infraternal-perf-test',
            kernel='numeric-fixture', cpus=4, sessions=1000, seconds=900,
            warmup=600, interval=10, seed=270205, expected_idle=900,
            expected_light=90, expected_burst=10, segmented=True,
            source=role, binary_sha256=('a' if role == 'shipping' else 'b') * 64,
            driver_sha256='c' * 64, machine_receipt=machine,
            architecture='independent-session-processes' if role == 'shipping' else 'shared-user-process')
        records = [environment]
        records += [dict(kind='sample', elapsed_s=second, monotonic_ns=second * 10**9,
                         echo_ms=[value] * 100, echo_p99_ms=value,
                         machine_receipt=machine, load=['0', '0', '0'])
                    for second in range(10, 901, 10)]
        records += [dict(kind='survivors', responsive_sessions=1000, host_alive=True),
                    dict(kind='outcome', scenario='soak', passed=False, echo_budget_ms=5)]
        self.save(name, records)
        segments = self.root / (name + 's')
        segments.mkdir()
        (segments / 'segments.jsonl').write_text('\n'.join(json.dumps(row) for row in [
            dict(kind='lock-acquired', monotonic_ns=0),
            dict(kind='exit', monotonic_ns=1000 * 10**9)]) + '\n')

    def read(self, cell):
        return [json.loads(line) for line in (self.root / cell / 'samples.jsonl').read_text().splitlines()]

    def save(self, cell, records):
        (self.root / cell / 'samples.jsonl').write_text('\n'.join(map(json.dumps, records)) + '\n')

    def test_pool_original_echoes_and_preserve_the_false_legacy_outcome(self):
        before = (self.root / 'p0/samples.jsonl').read_bytes()
        result = report_round(self.root, self.pairs)
        self.assertTrue(result['d296_pass'])
        self.assertEqual(result['roles']['shipping']['p99_ms'], 100)
        self.assertEqual(result['roles']['prototype']['p99_ms'], 50)
        self.assertEqual(result['roles']['prototype']['probes'], 9300)
        self.assertFalse(result['roles']['prototype']['runs'][0]['native_legacy_outcome']['passed'])
        self.assertEqual((self.root / 'p0/samples.jsonl').read_bytes(), before)
        for _, cell in self.pairs:
            records = self.read(cell)
            for row in records:
                if row['kind'] == 'sample':
                    row.update(echo_ms=[150] * 100, echo_p99_ms=150)
            self.save(cell, records)
        self.assertFalse(report_round(self.root, self.pairs)['d296_pass'])

    def test_exactly_three_disjoint_pairs_are_required(self):
        for pairs in (self.pairs[:2], self.pairs + [self.pairs[0]], [self.pairs[0]] * 3):
            with self.subTest(pairs=pairs), self.assertRaises(ValueError):
                report_round(self.root, pairs)

    def test_changed_workload_or_image_and_diagnostic_cells_are_rejected(self):
        original = self.read('p2')
        for field, value in [('seed', 1), ('seconds', 180), ('driver_sha256', 'd' * 64),
                             ('binary_sha256', 'e' * 64), ('source', 'other'),
                             ('machine', 'build-host'), ('segmented', False),
                             ('diagnostic_only', True), ('ownership_diagnostic', True)]:
            with self.subTest(field=field):
                changed = self.read('p2')
                changed[0][field] = value
                self.save('p2', changed)
                with self.assertRaises(ValueError):
                    report_round(self.root, self.pairs)
                self.save('p2', original)

    def test_truncation_lost_sessions_and_invalid_values_are_rejected(self):
        original = self.read('p1')
        variants = [original[:-2], [r for r in original if r.get('elapsed_s') != 900],
                    [r for r in original if r.get('elapsed_s') != 650]]
        duplicate = self.read('p1')
        duplicate[60] = duplicate[59].copy()
        variants.append(duplicate)
        for value in [float('nan'), -1, True]:
            changed = self.read('p1')
            changed[60]['echo_ms'][0] = value
            variants.append(changed)
        lost = self.read('p1')
        lost[-2]['responsive_sessions'] = 999
        variants.append(lost)
        for changed in variants:
            self.save('p1', changed)
            with self.assertRaises(ValueError):
                report_round(self.root, self.pairs)
        self.save('p1', original)

    def test_foreign_cpu_excludes_only_affected_original_cohorts(self):
        records = self.read('p1')
        for record in records:
            if record['kind'] in ('environment', 'sample'):
                usage = 5 if record.get('elapsed_s', 0) >= 610 else 0
                record['machine_receipt']['scope_cpu'] = {'other.scope': {'usage_usec': str(usage)}}
        self.save('p1', records)
        result = report_round(self.root, self.pairs)
        self.assertEqual(result['roles']['prototype']['runs'][1]['excluded_cohorts'], 1)
        self.assertEqual(result['roles']['prototype']['probes'], 9200)


if __name__ == '__main__':
    unittest.main()
