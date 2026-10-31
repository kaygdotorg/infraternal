#!/usr/bin/env python3
"""Compare three matched native echo runs under D296, retaining raw outcomes [#205].

Recompute the existing lock/scope exclusions from original receipts. Percentiles
pool retained echoes, never per-run percentiles. This echo comparison does not
certify production login integration, restart survival or historical aging.
SPDX-License-Identifier: AGPL-3.0-only
"""
import argparse
import json
import math
from pathlib import Path
import re

from ppu_compare_report import report as segment_report
from ppu_soak import percentile

MATCHED = ('machine', 'kernel', 'cpus', 'sessions', 'seconds', 'warmup', 'interval',
           'seed', 'driver_sha256', 'expected_idle', 'expected_light', 'expected_burst')
ARCHITECTURE = {'shipping': 'independent-session-processes', 'prototype': 'shared-user-process'}


def require(condition, message):
    """Malformed or incomplete measurement input never becomes a passing round."""
    if not condition:
        raise ValueError(message)


def load_cell(root, cell, role, unit_prefix):
    require(re.fullmatch('[a-z0-9]{1,12}', cell), 'invalid cell name')
    path = root / cell
    records = [json.loads(line) for line in (path / 'samples.jsonl').read_text().splitlines()]
    try:
        environment = next(row for row in records if row['kind'] == 'environment')
        census = next(row for row in records if row['kind'] == 'survivors')
        outcome = next(row for row in reversed(records)
                       if row['kind'] == 'outcome' and row.get('scenario') == 'soak')
    except (KeyError, StopIteration) as error:
        raise ValueError('incomplete native cell') from error
    require(not environment.get('diagnostic_only') and not environment.get('ownership_diagnostic'),
            'diagnostic cells cannot decide admission')
    require(environment.get('segmented') is True, 'missing segmented ownership')
    require(environment.get('machine') == 'infraternal-perf-test', 'wrong measurement venue')
    require(environment.get('architecture') == ARCHITECTURE[role], 'wrong process layout')
    require(census.get('responsive_sessions') == environment.get('sessions') == 1000
            and census.get('host_alive') is True, 'incomplete final input census')
    require(bool(environment.get('source')), 'missing native source identity')
    for field in ('binary_sha256', 'driver_sha256'):
        require(isinstance(environment.get(field), str)
                and re.fullmatch('[0-9a-f]{64}', environment[field]), 'missing image/driver digest')
    samples = [row for row in records if row['kind'] == 'sample']
    require(samples and samples[-1]['elapsed_s'] >= environment['seconds'], 'truncated native run')
    require(environment['seconds'] > environment['warmup'] >= 0 and environment['interval'] > 0,
            'invalid measurement window')
    require(len(samples) == math.ceil(environment['seconds'] / environment['interval']),
            'missing original cohorts')
    require(all(first['elapsed_s'] < last['elapsed_s']
                and first['monotonic_ns'] < last['monotonic_ns']
                for first, last in zip(samples, samples[1:])), 'unordered original cohorts')
    for sample in samples:
        values = sample.get('echo_ms', [])
        require(len(values) == 100 and all(isinstance(value, (int, float)) and not isinstance(value, bool)
                and math.isfinite(value) and value >= 0 for value in values), 'invalid original echoes')
    try:
        audited = segment_report(path, root / (cell + 's'), unit_prefix + cell)
    except (AssertionError, KeyError, StopIteration) as error:
        raise ValueError('incomplete ownership receipts') from error
    excluded = {row['elapsed_s'] for row in audited['discarded']}
    retained = [row for row in samples if row['elapsed_s'] >= environment['warmup']
                and row['elapsed_s'] not in excluded]
    require(len(retained) >= 6, 'insufficient uncontended settled cohorts')
    values = [value for row in retained for value in row['echo_ms']]
    require(len(values) == sum(row['probes'] for row in audited['segments']), 'segment census differs')
    run = dict(cell=cell, source=environment['source'], binary_sha256=environment['binary_sha256'],
               driver_sha256=environment['driver_sha256'], probes=len(values),
               excluded_cohorts=len(excluded), p50_ms=percentile(values, .5),
               p99_ms=percentile(values, .99), native_legacy_outcome=outcome,
               segments=audited['segments'], exclusions=audited['discarded'],
               load_first=retained[0]['load'], load_last=retained[-1]['load'])
    return environment, run, values


def report_round(root, pairs, unit_prefix='ppu-soak-d296-'):
    """Require three disjoint pairs with identical venue/workload and stable images."""
    require(len(pairs) == 3 and all(len(pair) == 2 for pair in pairs), 'exactly three pairs required')
    require(len({cell for pair in pairs for cell in pair}) == 6, 'reused native cell')
    roles = {}
    signature = None
    for role, column in [('shipping', 0), ('prototype', 1)]:
        runs, pooled = [], []
        for pair in pairs:
            environment, run, values = load_cell(root, pair[column], role, unit_prefix)
            try:
                current = tuple(environment[field] for field in MATCHED)
            except KeyError as error:
                raise ValueError('incomplete workload identity') from error
            if signature is None:
                signature = current
            require(current == signature, 'mixed venue or workload')
            if runs:
                require(all(run[field] == runs[0][field] for field in ('source', 'binary_sha256')),
                        'mixed native source or image')
            runs.append(run)
            pooled.extend(values)
        roles[role] = dict(runs=runs, probes=len(pooled), p50_ms=percentile(pooled, .5),
                           p99_ms=percentile(pooled, .99))
    return dict(complete=True, pairs=3, workload=dict(zip(MATCHED, signature)), roles=roles,
                d296_pass=roles['prototype']['p99_ms'] <= roles['shipping']['p99_ms'],
                pooled_difference_ms=roles['prototype']['p99_ms'] - roles['shipping']['p99_ms'],
                caveat='Echo comparison only. Original outcomes and exclusions retained; no causal '
                       'subtraction or production/restart certification. A shorter round does not '
                       'recertify historical 7200-second aging.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--pair', action='append', required=True, metavar='SHIPPING:PROTOTYPE')
    parser.add_argument('--unit-prefix', default='ppu-soak-d296-')
    args = parser.parse_args()
    result = report_round(args.root, [tuple(pair.split(':')) for pair in args.pair], args.unit_prefix)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['d296_pass'] else 1)
