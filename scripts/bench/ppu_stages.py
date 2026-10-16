#!/usr/bin/env python3
"""Correlate original shell probes with bounded host stages and off-CPU events [D270].

Requires a host-diagnostics image. This changes scheduling and is diagnostic
only. No output/input bytes enter the receipt; only synthetic marker identities,
stream offsets, descriptor numbers and monotonic timestamps are retained.
"""
import asyncio
import contextlib
import contextvars
import json
import os
from pathlib import Path
import signal
import time
from types import SimpleNamespace

import ppu_soak as suite
import ppu_trace as trace
from ppu_trace_process import CONTEXT, Drain

READERS = {}
PROBES = []
RECEIVED = {}
CURRENT = contextvars.ContextVar('probe', default=None)
ORIGINAL_INIT = suite.Host.__init__
ORIGINAL_READY = suite.Host.ready
ORIGINAL_ECHO = suite.Peer.echo
ORIGINAL_SEND = suite.Peer.send
ORIGINAL_FRAME = suite.Peer.frame
ORIGINAL_SOAK = suite.soak
ORIGINAL_WRITE = suite.Recorder.write
MARKER_RECEIPT = 'registered-marker-bytes'


def init(host, binary, root, *args, **kwargs):
    kwargs['accounting'] = root.parent / 'stages.log'
    ORIGINAL_INIT(host, binary, root, *args, **kwargs)


def read_header(stream):
    try:
        header = json.loads(stream.readline(512))
    except (ValueError, TypeError) as error:
        raise ValueError('image did not publish a stage format header') from error
    if not isinstance(header, dict) or header.get('kind') != 'stage-format' or header.get('version') != 1:
        raise ValueError('unsupported stage format')
    return header


async def ready(host):
    await ORIGINAL_READY(host)
    with (host.root.parent / 'stages.log').open() as source:
        read_header(source)
    for index, peer in enumerate(host.peers):
        READERS[peer.reader] = dict(session=index, tail=b'', head=peer.head, peer=peer)


async def frame(reader):
    result = await ORIGINAL_FRAME(reader)
    stamp = time.monotonic_ns()
    state = READERS.get(reader)
    if state is not None and result[0] == 0x11:
        offset = int.from_bytes(result[1:9], 'little')
        payload = result[9:]
        tail = state['tail'] if offset == state['head'] else b''
        combined = tail + payload
        # Match the same unfinished waiter as Peer.receive. Waiting for a
        # delimiter can select a later frame after the timed echo already ended.
        for marker, future in list(state['peer'].waiters.items()):
            if not marker.startswith(b'probe-') or future.done():
                continue
            position = combined.find(marker)
            if position >= 0:
                _, session, number = marker.split(b'-')
                session, number = int(session), int(number)
                if session != state['session']:
                    raise ValueError('probe waiter belongs to another session')
                end = offset - len(tail) + position + len(marker)
                RECEIVED.setdefault((session, number), dict(receive_ns=stamp, output_end=end,
                    receive_active_s=suite.clock_now()))
        state.update(tail=combined[-64:], head=offset + len(payload))
    return result


async def send(peer, kind, data=b''):
    probe = CURRENT.get()
    if kind == 0x10 and probe is not None:
        probe.update(input_start=peer.accepted, input_end=peer.accepted + len(data),
                     send_before_ns=time.monotonic_ns(), send_before_s=suite.clock_now())
        await ORIGINAL_SEND(peer, kind, data)
        probe['send_after_ns'] = time.monotonic_ns()
    else:
        await ORIGINAL_SEND(peer, kind, data)


async def echo(peer, marker, command=b''):
    if not marker.startswith(b'probe-'):
        return await ORIGINAL_ECHO(peer, marker, command)
    _, session, number = marker.split(b'-')
    probe = dict(session=int(session), number=int(number), writer=suite.WRITER)
    token = CURRENT.set(probe)
    try:
        result = await ORIGINAL_ECHO(peer, marker, command)
        probe.update(rtt_ms=result, completed_ns=time.monotonic_ns())
        PROBES.append(probe)
        return result
    finally:
        CURRENT.reset(token)


async def soak(host, args, record, rng):
    assert args.mode == 'soak' and args.seconds <= 900
    scheduler = trace.Trace(host.pid)
    async def flush():
        while True:
            os.kill(host.pid, signal.SIGUSR1)
            await asyncio.sleep(.5)
    task = asyncio.create_task(flush())
    started = time.monotonic_ns()
    try:
        return await ORIGINAL_SOAK(host, args, record, rng)
    finally:
        task.cancel()
        try:
            with contextlib.suppress(asyncio.CancelledError):
                await task
            os.kill(host.pid, signal.SIGUSR1)
            await host.peers[-1].echo(b'stage-final-fence')
        finally:
            # A failed host or final fence must still release our private
            # scheduler instance and its owned reader process.
            summary = scheduler.close()
        root = Path(record.file.name).parent
        rows = [probe | RECEIVED.get((probe['session'], probe['number']), {}) for probe in PROBES]
        ended = max((row['completed_ns'] for row in rows), default=started)
        settled = [(stamp, kind, state) for stamp, kind, state in scheduler.events
                   if started + args.warmup * 1_000_000_000 <= stamp * 1_000_000_000 <= ended]
        summary.update(diagnostic_only=True, marker_receipt=MARKER_RECEIPT, full_trace_includes_census=True,
                       settled_scheduler=trace.summarize(settled), ended_ns=ended,
                       started_ns=started, origin=host.origin, probes=rows,
                       matched=sum('receive_ns' in probe for probe in rows))
        (root / 'stage-probes.json').write_text(json.dumps(summary, indent=2) + '\n')
        with (root / 'stage-offcpu.log').open('w') as output:
            for event in scheduler.events:
                output.write(json.dumps(event) + '\n')
        assert summary['complete'] and summary['matched'] == len(rows) and rows, 'incomplete stage correlation'


def write(record, kind, **fields):
    if kind == 'environment':
        fields.update(diagnostic_only=True, budget_admission=False, marker_receipt=MARKER_RECEIPT, stage_capacity=65536,
                      stage_flush_interval_s=.5)
    return ORIGINAL_WRITE(record, kind, **fields)


if __name__ == '__main__':
    assert os.uname().nodename == 'infraternal-perf-test'
    trace.threading = SimpleNamespace(Event=CONTEXT.Event, Thread=Drain)
    suite.Host.__init__ = init
    suite.Host.ready = ready
    suite.Peer.frame = staticmethod(frame)
    suite.Peer.send = send
    suite.Peer.echo = echo
    suite.soak = soak
    suite.Recorder.write = write
    suite.main()
