#!/usr/bin/env python3
"""Separate shipping-host idle PSS slopes from Linux PTY ownership [D270, #205].

Run on the named perf VM under its shared lock and a private memory scope.
Hello-only probes never allocate terminal state or durable input writers.
Shells, fixed image pages, allocator slack and kernel PTYs stay separate.
SPDX-License-Identifier: AGPL-3.0-only
"""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import resource
import select
import shutil
import signal
import struct

from ppu_soak import Host, Peer, sample


def mappings(pid):
    """Aggregate mapping classes without recording account paths or contents."""
    result = {}
    group = None
    for line in Path(f'/proc/{pid}/smaps').read_text().splitlines():
        fields = line.split()
        if '-' in fields[0] and fields[0][0] in '0123456789abcdef':
            name = fields[5] if len(fields) > 5 else ''
            group = ('stack' if name == '[stack]' else
                     'heap' if name == '[heap]' else
                     'image' if name.startswith('/') else 'anonymous')
        elif fields[0] in ('Pss:', 'Private_Dirty:', 'Anonymous:'):
            target = result.setdefault(group, {})
            key = fields[0][:-1] + '_kib'
            target[key] = target.get(key, 0) + int(fields[1])
    return result


def kernel_memory():
    return {key: int(value.split()[0]) for line in Path('/proc/meminfo').read_text().splitlines()
            for key, value in [line.split(':', 1)]
            if key in ('VmallocUsed', 'Slab', 'SUnreclaim', 'PageTables', 'KernelStack')}


def cgroup_memory():
    """The caller's private scope excludes other jobs from slab attribution."""
    relative = next(line[3:] for line in Path('/proc/self/cgroup').read_text().splitlines()
                    if line.startswith('0::'))
    path = Path('/sys/fs/cgroup') / relative.lstrip('/') / 'memory.stat'
    return {key: int(value) for line in path.read_text().splitlines()
            for key, value in [line.split()] if key in ('kernel', 'slab', 'slab_unreclaimable', 'vmalloc')}


def kernel(count):
    """No shells: raw pairs, then epoll, then a first 13-byte output burst."""
    pairs = []
    rows = [dict(phase='empty', memory_kib=kernel_memory(), cgroup_bytes=cgroup_memory())]
    epoll = select.epoll()
    try:
        for _ in range(count):
            pairs.append(os.openpty())
        rows.append(dict(phase='open', memory_kib=kernel_memory(), cgroup_bytes=cgroup_memory()))
        for master, _ in pairs:
            epoll.register(master, select.EPOLLIN)
        rows.append(dict(phase='registered', memory_kib=kernel_memory(), cgroup_bytes=cgroup_memory()))
        for _, slave in pairs:
            os.write(slave, b'prompt-123456')
        # PTY flip work is asynchronous. Fence readiness for every pair rather
        # than sampling before its first output has reached the line discipline.
        ready = set()
        while len(ready) < count:
            ready.update(fd for fd, _ in epoll.poll(10, count))
            assert ready, 'PTY output never became ready'
        rows.append(dict(phase='first-output', memory_kib=kernel_memory(), cgroup_bytes=cgroup_memory()))
    finally:
        epoll.close()
        for pair in pairs:
            for fd in pair:
                os.close(fd)
    return dict(kind='kernel-pty', count=count, rows=rows,
                per_pair_delta_kib={key: (rows[-1]['memory_kib'][key] - rows[0]['memory_kib'][key]) / count
                                    for key in rows[0]['memory_kib']})


async def host_row(args, count, repeat):
    root = args.runtime_root if args.runtime_root is not None else args.evidence / f'n{count:04}r{repeat:02}'
    receipt = args.evidence / f'n{count}r{repeat}-ownership.jsonl'
    host = Host(args.binary.resolve(), root, count, 0x2702050000, accounting=receipt)
    try:
        deadline = asyncio.get_running_loop().time() + 120
        while not host.path(count - 1).exists():
            assert host.child.poll() is None, 'host startup failed'
            assert asyncio.get_running_loop().time() < deadline, 'host startup deadline'
            await asyncio.sleep(.05)
        # Census every session and leave all disconnected. No snapshot/input/
        # resize can contaminate the lazy-VT floor. The prompt arrives naturally.
        for index in range(count):
            reader, writer = await asyncio.open_unix_connection(str(host.path(index)))
            try:
                hello = await Peer.frame(reader)
                assert len(hello) == 59 and hello[0] == 1
                assert struct.unpack_from('<I', hello, 27)[0] == host.pid
            finally:
                writer.close()
                await writer.wait_closed()
        await asyncio.sleep(2)
        os.kill(host.pid, signal.SIGUSR2)
        # Wait for complete numeric receipt, without inducing any VT work.
        while len(receipt.read_text().splitlines()) < count:
            assert asyncio.get_running_loop().time() < deadline, 'ownership receipt deadline'
            await asyncio.sleep(.01)
        ownership = [json.loads(line) for line in receipt.read_text().splitlines()]
        assert len(ownership) == count
        assert all(row['native_page_bytes'] == row['native_ordinary_bytes'] == 0 for row in ownership)
        before = sample(host.pid)
        await asyncio.sleep(2)
        after = sample(host.pid)
        return dict(kind='host', sessions=count, repeat=repeat, before=before, after=after,
                    mappings=mappings(host.pid),
                    reactor_ownership=next((row['reactor'] for row in ownership if 'reactor' in row), None),
                    owned_bytes={key: sum(row[key] for row in ownership) for key in ownership[0]
                                 if key.endswith('_bytes')},
                    idle_cpu_ticks=after['cpu_ticks'] - before['cpu_ticks'])
    finally:
        try:
            await host.close()
        finally:
            if args.runtime_root is not None:
                shutil.rmtree(root)


async def run(args):
    assert os.uname().nodename == 'infraternal-perf-test'
    assert not (args.host_only and args.kernel_only)
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, 16384), hard))
    args.evidence.mkdir(parents=True, exist_ok=False)
    with (args.evidence / 'idle.jsonl').open('w') as output:
        def emit(row):
            row.update(machine=os.uname().nodename, kernel=os.uname().release,
                       cpus=os.cpu_count(), load_average=os.getloadavg())
            output.write(json.dumps(row, sort_keys=True) + '\n')
            output.flush()
            print(json.dumps(row, sort_keys=True), flush=True)
        emit(dict(kind='environment', binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(),
                  driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  runtime_root=str(args.runtime_root) if args.runtime_root is not None else None))
        if not args.kernel_only:
            for repeat in range(args.repeats):
                for count in (1, 10, 100, 1000):
                    emit(await host_row(args, count, repeat))
        if not args.host_only:
            for _ in range(args.repeats):
                emit(kernel(2000))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--kernel-only', action='store_true')
    parser.add_argument('--host-only', action='store_true')
    parser.add_argument('--runtime-root', type=Path, help='fresh private directory reused and removed after each row; keeps path size classes identical')
    asyncio.run(run(parser.parse_args()))
