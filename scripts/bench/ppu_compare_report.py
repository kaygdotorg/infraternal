#!/usr/bin/env python3
"""Report native echo cohorts per lock segment with explicit contention exclusions [D270].

Percentiles always use original echo samples. Lock metadata is sampled after
cohorts, not a continuous certification of arbitrary work outside the flock.
SPDX-License-Identifier: AGPL-3.0-only
"""
import argparse
import json
from pathlib import Path

from ppu_soak import percentile


def contamination(previous, current, unit, observer_scopes=()):
    """Reject missing ownership and observed foreign-scope CPU work conservatively."""
    if not previous or not current:
        return ['missing-machine-receipt']
    owner = (current.get('owner') or '').split()
    if owner[:2] != ['process-per-user', unit] or not current.get('locks'):
        return ['uncertified-perf-lock']
    allowed = set(observer_scopes) | {'init.scope', unit + '.scope'} | set(previous.get('control_scopes', [])) | set(current.get('control_scopes', []))
    before, after = previous.get('scope_cpu', {}), current.get('scope_cpu', {})
    reasons = []
    for name in (before.keys() | after.keys()) - allowed:
        first, last = before.get(name), after.get(name)
        if first is None or last is None:
            reasons.append('foreign-scope-transition:' + name)
        elif int(last['usage_usec']) != int(first['usage_usec']):
            reasons.append('foreign-scope-cpu:' + name)
    return reasons


def audit_batches(records, warmup, unit, observer_scopes=()):
    """Use the same ownership exclusions for percentile and causal reports."""
    previous = None
    number = 0
    discarded = []
    for sample in records:
        if sample['kind'] == 'environment':
            previous = sample.get('machine_receipt')
        elif sample['kind'] == 'sample':
            current = sample.get('machine_receipt')
            reasons = contamination(previous, current, unit, observer_scopes)
            previous = current
            if reasons and sample['elapsed_s'] >= warmup:
                discarded.append(dict(number=number, elapsed_s=sample['elapsed_s'], reasons=reasons))
            number += 1
    return discarded


def windows(events):
    """Use certified wall-clock lock windows, never post-sample resource timestamps."""
    result = []
    begin = None
    for row in events:
        if row['kind'] == 'lock-acquired':
            assert begin is None, 'overlapping lock windows'
            begin = row['monotonic_ns']
        elif row['kind'] in ('freeze', 'exit', 'lock-released') and begin is not None:
            result.append((begin, row['monotonic_ns']))
            begin = None
    assert begin is None, 'unfinished lock window'
    return result


def report(root, segment_root, unit, observer_scopes=()):
    records = [json.loads(line) for line in (root / 'samples.jsonl').read_text().splitlines()]
    environment = next(row for row in records if row['kind'] == 'environment')
    segments = windows([json.loads(line) for line in (segment_root / 'segments.jsonl').read_text().splitlines()])
    previous = environment.get('machine_receipt')
    kept, discarded = [], []
    for row in records:
        if row['kind'] != 'sample':
            continue
        current = row.get('machine_receipt')
        reasons = contamination(previous, current, unit, observer_scopes)
        previous = current
        if row['elapsed_s'] < environment['warmup']:
            continue
        segment = [number + 1 for number, (first, last) in enumerate(segments)
                   if first <= row['monotonic_ns'] <= last]
        if len(segment) != 1:
            reasons.append('no-unique-lock-window')
        entry = row | dict(segment=segment[0] if len(segment) == 1 else None, discard_reasons=reasons)
        (discarded if reasons else kept).append(entry)
    table = []
    for number in range(1, len(segments) + 1):
        rows = [row for row in kept if row['segment'] == number]
        excluded = [row for row in discarded if row['segment'] == number]
        values = [value for row in rows for value in row['echo_ms']]
        peak = max((row['echo_p99_ms'] for row in rows), default=None)
        table.append(dict(segment=number, cohorts=len(rows), discarded_cohorts=len(excluded),
            probes=len(values), p50_ms=percentile(values, .5), p99_ms=percentile(values, .99),
            peak_batch_p99_ms=peak, above_5ms=sum(value > 5 for value in values),
            echo_gate=bool(rows) and peak <= 5))
    outcome = next((row for row in reversed(records) if row['kind'] == 'outcome'), None)
    result = dict(source=environment['source'], binary_sha256=environment['binary_sha256'],
        architecture=environment['architecture'], seconds=environment['seconds'],
        sessions=environment['sessions'], seed=environment['seed'], warmup=environment['warmup'],
        native_outcome=outcome, segments=table,
        discarded=[dict(elapsed_s=row['elapsed_s'], segment=row['segment'],
                        reasons=row['discard_reasons']) for row in discarded],
        declared_observer_scopes=sorted(observer_scopes),
        contention_audit='post-cohort lock/scope snapshots; idle foreign scopes retained only with zero CPU delta')
    (root / 'comparison-report.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('segments', type=Path)
    parser.add_argument('--unit', required=True)
    parser.add_argument('--observer-scope', action='append', default=[],
                        help='own observer scope verified separately; retained as explicit overhead')
    args = parser.parse_args()
    print(json.dumps(report(args.root, args.segments, args.unit, args.observer_scope), indent=2))
