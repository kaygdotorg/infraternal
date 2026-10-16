#!/usr/bin/env python3
"""Observe current-dev scheduling with the same independent-session echo workload [D270].

The shipping image has no host-stage instrumentation. Match original native
probe markers and observe verified shim/shell/reader scheduling and wait stacks;
never manufacture VT or frame timestamps for this control.
SPDX-License-Identifier: AGPL-3.0-only
"""
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace

import ppu_baseline as baseline
import ppu_soak as suite
import ppu_stages as stages
import ppu_tail as tail
import ppu_trace as trace
from ppu_stage_report import validate_receipt
from ppu_trace_process import CONTEXT, Drain

ORIGINAL_READY = baseline.Host.ready
ORIGINAL_SOAK = suite.soak


async def ready(host):
    """Independent launch records the shell belonging to each exact shim handle."""
    assert host.count == 1000
    await ORIGINAL_READY(host)
    tail.ROOT = host.root.parent
    tail.ROLES.update(host=host.children[971].pid, reader=os.getpid(),
                      **{'wakeup-host': host.pid})
    for index in range(900, 1000):
        tail.ROLES[f'session-{index}'] = host.shells[index][0]
        tail.ROLES[f'host-{index}'] = host.children[index].pid
    stages.register_readers(host)


def receipts(probes, received):
    """Require every native timed endpoint; no host-stage format exists here."""
    rows = []
    for probe in probes:
        marker = received.get((probe['session'], probe['number']))
        if marker is None:
            raise ValueError('missing native baseline marker receipt')
        row = probe | marker
        validate_receipt(row)
        rows.append(row)
    return rows


async def soak(host, args, record, rng):
    assert args.mode == 'soak' and args.seconds <= 900
    scheduler = tail.RoleTrace(host.pid)
    started = time.monotonic_ns()
    try:
        return await ORIGINAL_SOAK(host, args, record, rng)
    finally:
        # Close the owned trace before serializing, including after a lost peer.
        summary = scheduler.close()
        rows = receipts(stages.PROBES, stages.RECEIVED)
        summary.update(diagnostic_only=True, marker_receipt=stages.MARKER_RECEIPT,
                       started_ns=started, probes=rows, matched=len(rows),
                       ended_ns=max((row['completed_ns'] for row in rows), default=started),
                       native_host_stages=False)
        root = Path(record.file.name).parent
        (root / 'baseline-probes.json').write_text(json.dumps(summary, indent=2) + '\n')
        assert summary['complete'] and rows, 'incomplete baseline scheduler capture'


def write(record, kind, **fields):
    if kind == 'environment':
        fields.update(architecture='independent-session-processes',
                      resource_scope='all-shim-processes-excludes-shells',
                      wakeup_scope='first-shim-only', native_host_stages=False)
    return tail.write(record, kind, **fields)


if __name__ == '__main__':
    trace.threading = SimpleNamespace(Event=CONTEXT.Event, Thread=Drain)
    suite.Host = baseline.Host
    suite.Host.ready = ready
    suite.Peer.frame = staticmethod(stages.frame)
    suite.Peer.send = stages.send
    suite.Peer.echo = stages.echo
    suite.soak = soak
    suite.Recorder.write = write
    suite.Wakeups = tail.Wakeups
    suite.main()
