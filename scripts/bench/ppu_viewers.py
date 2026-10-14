#!/usr/bin/env python3
"""Measure host cost for 1, 2, 3 and 5 native viewers of 50 filled PTYs [D270, #205].

SPDX-License-Identifier: AGPL-3.0-only
Run only on infraternal-perf-test, under /var/lock/perf-bench.lock in the
caller's CPUWeight=10000, MemoryMax=5G, MemorySwapMax=0, OOMPolicy=kill scope.
Build locally and copy artifacts; never build on the performance VM.

Each viewer owns one distinct durable writer on each of the 50 terminals.
All sockets continuously drain through the existing frozen-v1 Peer driver.
The Python driver, shells, kernel sockets and control plane are outside the
host-only PSS/RSS numbers. This UNIX-socket path has no browser/WebSocket
equivalence. Every terminal is filled and validated before measurement;
the prototype's 64-MiB history budget is divided among terminals and does
not promise 10,000 retained VT lines. Its separate 64-MiB ring ceiling is
also divided, but this reused Host fixture requests only 64 KiB per ring.
Snapshot bytes/approximation are recorded; repaint size is not a VT history
line census. Successful stage receipts alone do not admit an incomplete run.
"""
import argparse
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import signal
import statistics
import struct
import time

from ppu_soak import CAPS, Host, Peer, Recorder, WRITER, percentile, sample


def numbered_line(number):
    """Fixed printable 72-column line: six-digit ordinal and deterministic body."""
    return f'{number:06d} '.encode() + b'0123456789' * 6 + b'01234'


class NumberedLines:
    """Streaming fill oracle; a shell marker cannot certify missing PTY output."""
    def __init__(self, expected):
        self.expected, self.count, self.tail = expected, 0, b''

    def feed(self, data):
        self.tail += data
        lines = self.tail.split(b'\n')
        self.tail = lines.pop()
        assert len(self.tail) < 8192, 'unterminated fill output'
        for line in lines:
            line = line.removesuffix(b'\r')
            if len(line) >= 7 and line[:6].isdigit() and line[6:7] == b' ':
                self.count += 1
                assert self.count <= self.expected and line == numbered_line(self.count), \
                    'numbered fill missing, duplicated, reordered or modified'

    def finish(self):
        assert self.count == self.expected, f'fill incomplete: {self.count}/{self.expected}'


def writer_id(viewer):
    assert 1 <= viewer <= 5
    return WRITER + viewer


class ViewerPeer(Peer):
    """Reuse byte draining/input cursors; add explicit writer and repaint barriers."""
    def __init__(self, reader, writer, head, pid):
        self.snapshot = asyncio.get_running_loop().create_future()
        self.snapshot_receipt = None
        super().__init__(reader, writer, head, pid)

    async def frame(self, reader):
        frame = await Peer.frame(reader)
        if frame[0] in (0x15, 0x1c) and not self.snapshot.done():
            flagged = frame[0] == 0x1c
            header = 10 if flagged else 9
            assert len(frame) > header, 'filled terminal returned empty/malformed snapshot'
            assert not flagged or frame[9] & ~1 == 0, 'reserved snapshot flags set'
            head = struct.unpack_from('<Q', frame, 1)[0]
            assert head >= self.head, 'snapshot output offset regressed'
            self.snapshot_receipt = dict(bytes=len(frame) - header, head=head,
                approximate=bool(frame[9] & 1) if flagged else False)
            self.snapshot.set_result(time.monotonic())
        return frame

    @classmethod
    async def connect(cls, path, identity):
        start = time.monotonic()
        reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(str(path)), 30)
        peer = None
        try:
            hello = await Peer.frame(reader)
            hello_time = time.monotonic()
            assert len(hello) == 59 and hello[0] == 1, 'invalid frozen Hello'
            assert struct.unpack_from('<H', hello, 1)[0] == 1, 'unsupported frozen version'
            assert struct.unpack_from('<Q', hello, 3)[0] & CAPS == CAPS, 'missing viewer capabilities'
            assert identity != 0 and identity != WRITER, 'extra viewer would replace filler'
            head = struct.unpack_from('<Q', hello, 43)[0]
            peer = cls(reader, writer, head, struct.unpack_from('<I', hello, 27)[0])
            peer.ring_receipt = dict(head=head, start=struct.unpack_from('<Q', hello, 51)[0])
            assert peer.ring_receipt['start'] <= head, 'invalid Hello ring offsets'
            await peer.send(2, struct.pack('<Q', CAPS))
            await peer.send(0x1b, struct.pack('<I', identity))
            await peer.send(0x19)
            peer.accepted = await asyncio.wait_for(peer.state, 30)
            # An explicit repaint fence avoids assuming the whole numbered fill
            # still fits the bounded ring, or treating current-head attach as repaint.
            await peer.send(0x14)
            snapshot_time = await asyncio.wait_for(peer.snapshot, 30)
            peer.attach_receipt = dict(hello_ms=(hello_time - start) * 1000,
                snapshot_ms=(snapshot_time - start) * 1000)
            return peer
        except BaseException:
            if peer is not None:
                await peer.close()
            else:
                writer.close()
                with contextlib.suppress(OSError):
                    await writer.wait_closed()
            raise


def require_live(groups, count):
    """A dead/replaced viewer invalidates the sample even when siblings work."""
    assert groups and all(len(group) == count for group in groups), 'missing viewer terminals'
    for group in groups:
        for peer in group:
            if peer.task.done():
                peer.task.result()  # Surface a framing failure before generic admission failure.
                raise AssertionError('viewer reader disconnected')
            assert not peer.exit.done() and not peer.writer.is_closing(), 'viewer/session exited'


async def confirm(sender, receivers, marker, timeout=30):
    """Input must complete on its writer and be observed by every live viewer."""
    observers = []
    for peer in receivers:
        if peer is not sender:
            future = asyncio.get_running_loop().create_future()
            peer.waiters[marker] = future
            observers.append((peer, future))
    start = time.monotonic()
    try:
        writer_ms = await sender.echo(marker)
        observed = await asyncio.wait_for(asyncio.gather(*(future for _, future in observers)), timeout)
        return dict(writer_echo_ms=writer_ms,
                    all_viewers_echo_ms=max([writer_ms] + [(end - start) * 1000 for end in observed]))
    finally:
        for peer, future in observers:
            peer.waiters.pop(marker, None)
            if not future.done():
                future.cancel()
            elif not future.cancelled():
                future.exception()  # Retrieve failures even when the sending writer failed first.


def cpu_percent(before, after, elapsed, ticks=None):
    return (after['cpu_ticks'] - before['cpu_ticks']) / (ticks or os.sysconf('SC_CLK_TCK')) / elapsed * 100


def increment(current, previous):
    added = current['viewers'] - previous['viewers']
    assert added > 0
    return dict(added_viewers=added,
        pss_kib_per_extra_viewer=(current['idle_pss_kib'] - previous['idle_pss_kib']) / added,
        rss_kib_per_extra_viewer=(current['idle_rss_kib'] - previous['idle_rss_kib']) / added)


async def fill(host, lines, record):
    path = host.root / 'numbered-fill.txt'
    path.write_bytes(b''.join(numbered_line(i) + b'\n' for i in range(1, lines + 1)))
    for index, peer in enumerate(host.peers):
        oracle = NumberedLines(lines)
        async def frame(reader, oracle=oracle):
            body = await Peer.frame(reader)
            if body[0] == 0x11:
                oracle.feed(body[9:])
            return body
        peer.frame = frame
        # receive() may already be awaiting its original frame reader. This
        # shell fence consumes that outstanding read before numbered output,
        # so even a one-frame fill is inspected by the newly installed oracle.
        await peer.echo(f'fill-observer-{index}'.encode())
        before = peer.bytes
        await peer.echo(f'filled-{index}'.encode(), f'timeout 120 cat {shlex.quote(str(path))}; '.encode())
        oracle.finish()
        record.write('filled-terminal', terminal=index, ordered_lines=oracle.count,
                     columns=72, drained_bytes=peer.bytes - before, retained_vt_lines=None)
        # The per-terminal oracle is no longer needed after its fence completes.
        del peer.frame


async def add_viewer(host, groups, number, record):
    group = []
    groups.append(group)  # Cleanup also owns peers when attachment fails midway.
    for index in range(host.count):
        peer = await ViewerPeer.connect(host.path(index), writer_id(number))
        group.append(peer)
        assert peer.pid == host.pid, 'viewer attached to foreign host'
        start = time.monotonic()
        echo = await confirm(peer, [other[index] for other in groups], f'attach-{number}-{index}'.encode())
        record.write('attach', viewer=number, terminal=index, writer=writer_id(number),
            typable_ms=peer.attach_receipt['snapshot_ms'] + (time.monotonic() - start) * 1000,
            **peer.attach_receipt, snapshot=peer.snapshot_receipt, ring=peer.ring_receipt, **echo)
    require_live(groups, host.count)


async def measure(host, groups, args, record):
    count = len(groups)
    require_live(groups, host.count)
    idle = []
    before, start = sample(host.pid), time.monotonic()
    for tick in range(args.idle_samples):
        await asyncio.sleep(args.interval)
        require_live(groups, host.count)
        row = sample(host.pid)
        idle.append(row)
        record.write('idle-sample', viewers=count, tick=tick, **row)
    elapsed = time.monotonic() - start
    summary = dict(viewers=count, connections=count * host.count,
        idle_pss_kib=statistics.median(row['pss_kib'] for row in idle),
        idle_rss_kib=statistics.median(row['rss_kib'] for row in idle),
        idle_cpu_percent=cpu_percent(before, idle[-1], elapsed), idle_window_s=elapsed,
        idle_cpu_ticks=idle[-1]['cpu_ticks'] - before['cpu_ticks'],
        cpu_ticks_per_second=os.sysconf('SC_CLK_TCK'))
    echoes, seen = [], []
    before, start = sample(host.pid), time.monotonic()
    for probe in range(args.samples):
        terminal = probe % host.count
        writer = (probe // host.count) % count
        echo = await confirm(groups[writer][terminal], [group[terminal] for group in groups],
                             f'probe-{count}-{probe}'.encode())
        echoes.append(echo['writer_echo_ms'])
        seen.append(echo['all_viewers_echo_ms'])
        require_live(groups, host.count)
        record.write('echo', viewers=count, probe=probe, terminal=terminal, writer=writer + 1, **echo)
    elapsed = time.monotonic() - start
    after = sample(host.pid)
    summary.update(echo_samples=len(echoes), echo_p50_ms=percentile(echoes, .5),
        echo_p99_ms=percentile(echoes, .99), echo_max_ms=max(echoes),
        all_viewers_echo_p99_ms=percentile(seen, .99),
        active_cpu_percent=cpu_percent(before, after, elapsed), active_window_s=elapsed,
        active_cpu_ticks=after['cpu_ticks'] - before['cpu_ticks'],
        active_host=after, responsive_terminals=host.count,
        responsive_writer_terminal_pairs=min(args.samples, count * host.count))
    record.write('stage', admitted=True, **summary)
    return summary


async def run(args):
    assert os.uname().nodename == 'infraternal-perf-test', 'performance VM required'
    assert args.sessions == 50 and args.lines == 10000 and args.samples >= 1000
    assert args.idle_samples >= 10 and args.interval >= 1
    socket_path = args.evidence / 's' / 'sessions' / ('0' * 32 + '.sock')
    assert len(str(socket_path).encode()) < 108, 'evidence path exceeds Linux sun_path; use a shorter path'
    args.binary = args.binary.resolve()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    needed = args.sessions * 8 + 128
    assert hard == resource.RLIM_INFINITY or hard >= needed, 'insufficient hard fd limit'
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, needed), hard))
    args.evidence.mkdir(parents=True, exist_ok=False)
    record = Recorder(args.evidence)
    record.write('environment', source=args.source, machine=os.uname().nodename,
        kernel=os.uname().release, cpus=os.cpu_count(), sessions=args.sessions,
        lines_per_terminal=args.lines, columns=72, samples_per_stage=args.samples,
        binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        shared_driver_sha256=hashlib.sha256(Path(__file__).with_name('ppu_soak.py').read_bytes()).hexdigest(),
        load=os.getloadavg(), host_only=True, browser_equivalent=False,
        configured_history_budget_bytes=64 * 1024 * 1024,
        configured_history_bytes_per_terminal=(64 * 1024 * 1024) // args.sessions,
        configured_ring_budget_bytes=64 * 1024 * 1024,
        requested_ring_bytes_per_terminal=65536, retained_vt_lines=None,
        retention_note='real 10k fill validated; retained VT history may be shorter; snapshot is bounded')
    host = Host(args.binary, args.evidence / 's', args.sessions, 0x2702056000)
    groups, stages = [], []
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, asyncio.current_task().cancel)
    try:
        await host.ready()
        await fill(host, args.lines, record)
        await asyncio.gather(*(peer.close() for peer in host.peers))
        host.peers.clear()
        await asyncio.sleep(1)
        record.write('filled-no-viewers', **sample(host.pid))
        for count in (1, 2, 3, 5):
            while len(groups) < count:
                await add_viewer(host, groups, len(groups) + 1, record)
            stage = await measure(host, groups, args, record)
            if stages:
                stage.update(increment(stage, stages[-1]))
            stages.append(stage)
            print(json.dumps(stage, sort_keys=True), flush=True)
        require_live(groups, host.count)
        result = dict(admitted=True, host_only=True, browser_equivalent=False, stages=stages)
        (args.evidence / 'viewers.json').write_text(json.dumps(result, indent=2) + '\n')
        record.write('outcome', admitted=True, completed_viewer_counts=[row['viewers'] for row in stages])
        return True
    except BaseException as error:
        record.write('outcome', admitted=False, completed_viewer_counts=[row['viewers'] for row in stages],
                     detail=f'{type(error).__name__}: {error}')
        raise
    finally:
        await asyncio.gather(*(peer.close() for group in groups for peer in group), return_exceptions=True)
        await host.close()
        record.file.close()
        loop.remove_signal_handler(signal.SIGTERM)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--source', required=True, help='exact source SHA of the copied image')
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--sessions', type=int, default=50)
    parser.add_argument('--lines', type=int, default=10000)
    parser.add_argument('--samples', type=int, default=1000)
    parser.add_argument('--idle-samples', type=int, default=10)
    parser.add_argument('--interval', type=float, default=1)
    raise SystemExit(0 if asyncio.run(run(parser.parse_args())) else 1)


if __name__ == '__main__':
    main()
