#!/usr/bin/env python3
"""Age one real host before a bounded late-life stage/scheduler capture [D270].

Keep the original mixed workload running continuously for 6,300 active seconds,
including its reader, tasks and accumulated samples. Enable the full kernel
capture only after 5,400 seconds. Observer overhead makes this diagnostic, never
an unchanged admission run. Use ppu_segment.py around the whole fixture.
SPDX-License-Identifier: AGPL-3.0-only
"""
import asyncio
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import time
from types import SimpleNamespace

import ppu_soak as suite
import ppu_stages as stages
import ppu_tail as tail
import ppu_trace as trace
from ppu_trace_process import CONTEXT, Drain

AGE_SECONDS = 5400


async def boundary(host, root):
    """Fence the old bounded ring's dump without truncating its open native file."""
    path = root / 'stages.log'
    with path.open() as source:
        stages.read_header(source)
    sent = time.monotonic_ns()
    os.kill(host.pid, signal.SIGUSR1)
    await host.peers[-1].echo(b'aging-stage-boundary')
    deadline = suite.clock_now() + 10
    while suite.clock_now() < deadline:
        with path.open('rb') as source:
            source.seek(max(0, path.stat().st_size - 4096))
            data = source.read()
            offset = source.tell()
        if data.endswith(b'\n'):
            row = json.loads(data.splitlines()[-1])
            if row.get('kind') == 'stage-dump' and row['end_ns'] >= sent:
                return dict(stage_log_offset=offset, signal_sent_ns=sent, stage_dump=row)
        await asyncio.sleep(.01)
    raise TimeoutError('preconditioning stage dump was not fenced')


async def soak(host, args, record, rng):
    """Retain the original loop and its observer history through late capture."""
    assert args.mode == 'soak' and 0 < args.seconds <= 900 and args.warmup < AGE_SECONDS
    root = Path(record.file.name).parent
    async def prepare():
        checkpoint = await boundary(host, root)
        checkpoint.update(preconditioning_seconds=AGE_SECONDS, capture_seconds=args.seconds,
            diagnostic_only=True, budget_admission=False, workload_restarted=False,
            original_stage_log='stages.log',
            prefix_policy='retain full raw log; derive capture view after this explicit byte offset')
        (root / 'preconditioning.json').write_text(json.dumps(checkpoint, indent=2) + '\n')
        # Release only extra diagnostic endpoints. Original workload samples,
        # peer readers, tasks and terminal state continue without a new census.
        stages.PROBES.clear()
        stages.RECEIVED.clear()
    options = SimpleNamespace(**(vars(args) | dict(seconds=AGE_SECONDS + args.seconds)))
    return await stages.soak(host, options, record, rng, profile_after=AGE_SECONDS, before_profile=prepare)


def stage_window(source, destination, offset):
    """Derive a capture-only view; preserve preconditioning's raw overflow receipt."""
    with source.open('rb') as original:
        header = original.readline(512)
        stages.read_header(io.StringIO(header.decode()))
        if type(offset) is not int or not len(header) <= offset <= source.stat().st_size:
            raise ValueError('invalid stage log byte boundary')
        original.seek(offset - 1)
        if original.read(1) != b'\n':
            raise ValueError('stage log boundary splits a record')
        with destination.open('xb') as output:
            output.write(header)
            shutil.copyfileobj(original, output)
        original.seek(0)
        digest = hashlib.file_digest(original, 'sha256').hexdigest()
    return dict(offset=offset, source_sha256=digest)


def write(record, kind, **fields):
    if kind == 'environment':
        fields.update(preconditioning_seconds=AGE_SECONDS, capture_seconds=fields['seconds'],
                      seconds=AGE_SECONDS + fields['seconds'], workload_restarted=False)
    return tail.write(record, kind, **fields)


def main():
    """Install the diagnostic hooks without changing the original workload body."""
    assert os.uname().nodename == 'infraternal-perf-test'
    trace.Trace = tail.RoleTrace
    trace.threading = SimpleNamespace(Event=CONTEXT.Event, Thread=Drain)
    suite.Host.__init__ = stages.init
    suite.Host.ready = tail.ready
    suite.Peer.frame = staticmethod(stages.frame)
    suite.Peer.send = stages.send
    suite.Peer.echo = stages.echo
    suite.soak = soak
    suite.Recorder.write = write
    suite.Wakeups = tail.Wakeups
    suite.main()


if __name__ == '__main__':
    main()
