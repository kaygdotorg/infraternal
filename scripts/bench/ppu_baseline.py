#!/usr/bin/env python3
"""Run the unchanged mixed echo workload against independent shipping shims [D270].

Only fixture launch, liveness and resource aggregation differ. Peer.echo, the
shell commands, marker reader, concurrency, random seed and cadence are reused.
The existing wakeup counter observes the first shim only; it is not a total
baseline wakeup count. Resource reads happen after each timed cohort.
SPDX-License-Identifier: AGPL-3.0-only
"""
import asyncio
import contextlib
import os
from pathlib import Path
import subprocess
import signal

import ppu_soak as suite

original_sample = suite.sample
original_write = suite.Recorder.write


def command(binary, root, session):
    """Use only the existing shipping per-session entry and frozen wire contract."""
    return [str(binary), '__shim', '--session', f'{session:032x}', '--uid',
            str(os.getuid()), '--state', str(root), '--ring-capacity', '65536']


def aggregate(pids):
    """A disappeared process is a failed run, never a smaller memory sample."""
    rows = [original_sample(pid) for pid in pids]
    return {key: rows[0][key] if key == 'load' else sum(row[key] for row in rows)
            for key in rows[0]}


def retire_shell(pid, birth):
    """Pin a captured shell identity before checking birth and sending a signal."""
    with contextlib.suppress(ProcessLookupError, FileNotFoundError):
        handle = os.pidfd_open(pid)
        try:
            current = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
            if current == birth:
                signal.pidfd_send_signal(handle, signal.SIGKILL)
        finally:
            os.close(handle)


class Children:
    """Present the shared fixture's liveness interface for all owned shim children."""
    def __init__(self, children):
        self.children = children

    def poll(self):
        return next((code for child in self.children if (code := child.poll()) is not None), None)

    def kill(self):
        for child in self.children:
            if child.poll() is None:
                child.kill()

    def wait(self):
        for child in self.children:
            child.wait()


class Host(suite.Host):
    """Keep every socket/session identity while replacing only process ownership."""
    def __init__(self, binary, root, count, origin, nofile=None, scope=None, accounting=None):
        assert scope is None and accounting is None and nofile is None, 'soak-only baseline'
        self.binary, self.root, self.count, self.origin = binary, root, count, origin
        root.mkdir(mode=0o700)
        self.log = (root / 'host-stderr.log').open('wb')
        self.children = []
        self.child = Children(self.children)
        self.scope = None
        self.peers, self.shells = [], []
        self.closed_output_bytes = 0

    async def ready(self):
        for index in range(self.count):
            child = subprocess.Popen(command(self.binary, self.root, self.origin + index),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=self.log)
            self.children.append(child)
            if index == 0:
                self.pid = child.pid
            until = suite.clock_now() + 120
            while not self.path(index).exists():
                assert child.poll() is None, 'shipping shim exited during startup'
                assert suite.clock_now() < until, 'shipping shim startup timed out'
                await asyncio.sleep(.01)
            peer = await suite.Peer.connect(self.path(index))
            assert peer.pid == child.pid, 'unexpected shipping shim identity'
            self.peers.append(peer)
            children = Path(f'/proc/{child.pid}/task/{child.pid}/children').read_text().split()
            assert len(children) == 1, 'unexpected shipping shell count'
            pid = int(children[0])
            birth = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
            self.shells.append((pid, birth))
            await peer.echo(f'init-{index}'.encode(), b"stty -echo; PS1=''; ")
        pids = [child.pid for child in self.children]
        suite.sample = lambda unused: aggregate(pids)

    async def close(self):
        # A dead shim must not make the aggregate liveness check skip its live
        # siblings. Direct Popen handles keep cleanup scoped to this fixture.
        await asyncio.gather(*(peer.close() for peer in self.peers), return_exceptions=True)
        for pid, birth in self.shells:
            retire_shell(pid, birth)
        self.child.kill()
        await asyncio.to_thread(self.child.wait)
        self.log.close()


def write(record, kind, **fields):
    if kind == 'environment':
        fields.update(architecture='independent-session-processes',
                      resource_scope='all-shim-processes-excludes-shells',
                      wakeup_scope='first-shim-only')
    return original_write(record, kind, **fields)


if __name__ == '__main__':
    suite.Host = Host
    suite.Recorder.write = write
    suite.main()
