#!/usr/bin/env python3
"""Age one real host before a bounded late-life stage/scheduler capture [D270].

Retain the original mixed workload for 5,400 active seconds, then run the existing
900-second diagnostic on those same PTYs and terminal states. The phase boundary
includes the original census, task restart and resize pair: this is diagnostic
preconditioning, never an unchanged admission run. Use ppu_segment.py around the
whole 6,300-second fixture; the kernel capture still fits one short lock hold.
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

import ppu_compare as compare
import ppu_soak as suite
import ppu_stages as stages
import ppu_tail as tail
import ppu_trace as trace
from ppu_trace_process import CONTEXT, Drain

AGE_SECONDS = 5400


class PreludeRecorder(suite.Recorder):
    """Keep age/census evidence separate from the subsequent diagnostic clock."""
    def __init__(self, root, count):
        super().__init__(root)
        self.elapsed = 0
        self.count = count
        self.survived = False

    def write(self, kind, **fields):
        if kind == 'sample':
            self.elapsed = fields['elapsed_s']
        elif kind == 'survivors':
            self.survived = (fields['expected_sessions'] == fields['responsive_sessions'] == self.count
                             and fields['host_alive'] is True)
        return compare.write(self, kind, **fields)


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
    """A failed/short prelude cannot authorize a purported mature-host capture."""
    assert args.mode == 'soak' and 0 < args.seconds <= 900 and args.warmup < AGE_SECONDS
    root = Path(record.file.name).parent
    prelude_root = root / 'preconditioning'
    prelude_root.mkdir()
    receipt = PreludeRecorder(prelude_root, host.count)
    hooks = (suite.Peer.frame, suite.Peer.send, suite.Peer.echo, suite.Wakeups)
    try:
        # No full scheduler/syscall capture or extra marker matcher while aging.
        suite.Peer.frame = staticmethod(stages.ORIGINAL_FRAME)
        suite.Peer.send = stages.ORIGINAL_SEND
        suite.Peer.echo = stages.ORIGINAL_ECHO
        suite.Wakeups = tail.ORIGINAL_WAKEUPS
        receipt.write('environment', seconds=AGE_SECONDS, warmup=args.warmup,
            sessions=host.count, seed=getattr(args, 'seed', None), interval=args.interval,
            diagnostic_only=True, budget_admission=False, phase='preconditioning')
        options = SimpleNamespace(**(vars(args) | dict(seconds=AGE_SECONDS)))
        await stages.ORIGINAL_SOAK(host, options, receipt, rng)
    finally:
        suite.Peer.frame = staticmethod(hooks[0])
        suite.Peer.send, suite.Peer.echo, suite.Wakeups = hooks[1:]
        receipt.file.close()
    if receipt.elapsed < AGE_SECONDS or not receipt.survived:
        raise RuntimeError('incomplete preconditioning; refuse an aged capture')
    checkpoint = await boundary(host, root)
    checkpoint.update(preconditioning_seconds=receipt.elapsed, capture_seconds=args.seconds,
        diagnostic_only=True, budget_admission=False,
        boundary_effects='original census, load-task restart and resize pair; same host/PTYs/state',
        original_stage_log='stages.log',
        prefix_policy='retain full raw log; derive capture view after this explicit byte offset')
    (root / 'preconditioning.json').write_text(json.dumps(checkpoint, indent=2) + '\n')
    stages.READERS.clear()
    stages.PROBES.clear()
    stages.RECEIVED.clear()
    stages.register_readers(host)
    return await stages.soak(host, args, record, rng)


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
        fields.update(preconditioning_seconds=AGE_SECONDS, full_fixture_active_seconds=AGE_SECONDS + fields['seconds'])
    return tail.write(record, kind, **fields)


if __name__ == '__main__':
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
