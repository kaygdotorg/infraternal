#!/usr/bin/env python3
"""Locate scheduling/wait time in native current-dev probes without invented stages [D270].

The control lacks native host-stage receipts. Overall shim/shell/reader state
intervals overlap; they identify locations and cannot be added or subtracted
from the shared host's admission percentiles.
SPDX-License-Identifier: AGPL-3.0-only
"""
import argparse
from collections import defaultdict
import json
from pathlib import Path

from ppu_baseline_tail import receipts
from ppu_compare_report import audit_batches
from ppu_stages import MARKER_RECEIPT
from ppu_tail_report import Timeline, waits


def report(root, warmup, unit):
    meta = json.loads((root / 'baseline-probes.json').read_text())
    assert meta['complete'] and not meta['overruns'], 'incomplete baseline trace'
    assert meta['marker_receipt'] == MARKER_RECEIPT and meta['native_host_stages'] is False
    # Revalidate the same native clock bounds when reading saved receipts.
    probes = receipts(meta['probes'], {(row['session'], row['number']): row for row in meta['probes']})
    records = [json.loads(line) for line in (root / 'samples.jsonl').read_text().splitlines()]
    discarded = audit_batches(records, warmup, unit)
    excluded = {row['number'] for row in discarded}
    roles = json.loads((root / 'tail-roles.json').read_text())
    events = defaultdict(list)
    for line in (root / 'tail-events.jsonl').read_text().splitlines():
        row = json.loads(line)
        events[row['pid']].append(row)
    timelines = {pid: Timeline(data) for pid, data in events.items()}
    blocked = {pid: waits(data) for pid, data in events.items()}
    rows = [row for row in probes if row['send_before_ns'] >= meta['started_ns'] + warmup * 1e9
            and row['number'] not in excluded]
    for row in rows:
        begin, end = row['send_before_ns'], row['receive_ns']
        identities = dict(host=roles[f"host-{row['session']}"],
                          shell=roles[f"session-{row['session']}"], reader=roles['reader'])
        row['scheduler_ms'] = {name: timelines[pid].overlap(begin, end)
                               for name, pid in identities.items()}
        row['kernel_waits'] = {name: [wait | dict(overlap_ms=(min(end, wait['end_ns']) -
            max(begin, wait['begin_ns'])) / 1e6) for wait in blocked[pid]
            if wait['end_ns'] > begin and wait['begin_ns'] < end]
            for name, pid in identities.items()}
    result = dict(diagnostic_only=True, complete=True, native_host_stages=False,
        probes=len(rows), discarded_batches=discarded, unit=unit,
        caveat='Overall shim/shell/reader intervals overlap. Kernel sleep-to-schedule spans include runnable time; no native VT/frame timestamps exist.',
        slowest=sorted(rows, key=lambda row: row['rtt_ms'], reverse=True)[:20])
    (root / 'baseline-tail-report.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--warmup', type=float, default=600)
    parser.add_argument('--unit', required=True)
    args = parser.parse_args()
    result = report(args.root, args.warmup, args.unit)
    print(json.dumps(dict(complete=result['complete'], probes=result['probes'],
        slowest_ms=result['slowest'][0]['rtt_ms'] if result['slowest'] else None)))
    raise SystemExit(0 if result['probes'] else 1)
