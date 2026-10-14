#!/usr/bin/env python3
"""Compare shell/driver echo over bare PTYs, never host admission evidence [D270].

The same marker routine and mixed active-shell commands bypass the shared host,
VT, frozen frames and sockets. The reader differs from the framed driver, so this is not a mathematical
lower bound. It has no attach/resize churn and cannot replace the unchanged
two-hour reliability workload.
SPDX-License-Identifier: AGPL-3.0-only
"""
import argparse
import asyncio
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import pwd
import resource
import signal
import struct
import subprocess
import termios
import time

from ppu_soak import Peer, percentile


class DirectPeer:
    """A synthetic shell's owned master; only numeric results leave this fixture."""
    echo = Peer.echo

    def __init__(self, master):
        self.master = master
        self.waiters = {}
        self.tail = b''
        self.write_lock = asyncio.Lock()
        os.set_blocking(master, False)
        asyncio.get_running_loop().add_reader(master, self.receive)

    def receive(self):
        try:
            payload = os.read(self.master, 16384)
            if not payload:
                raise EOFError('fixture slave closed')
        except BlockingIOError:
            return
        except (OSError, EOFError) as error:
            for future in self.waiters.values():
                if not future.done():
                    future.set_exception(error)
            asyncio.get_running_loop().remove_reader(self.master)
            return
        searchable = self.tail + payload
        for marker, future in self.waiters.items():
            if marker in searchable and not future.done():
                future.set_result(time.monotonic())
        self.tail = searchable[-8192:]

    async def send(self, kind, payload):
        assert kind == 0x10
        async with self.write_lock:
            while payload:
                try:
                    used = os.write(self.master, payload)
                    assert used > 0
                    payload = payload[used:]
                except BlockingIOError:
                    loop = asyncio.get_running_loop()
                    ready = loop.create_future()
                    def writable():
                        if not ready.done():
                            ready.set_result(None)
                    loop.add_writer(self.master, writable)
                    try:
                        await ready
                    finally:
                        loop.remove_writer(self.master)

    def close(self):
        asyncio.get_running_loop().remove_reader(self.master)
        os.close(self.master)


def terminal_child():
    """Single-threaded fixture startup follows the production PTY session order."""
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


async def run(args):
    assert os.uname().nodename == 'infraternal-perf-test'
    resource.setrlimit(resource.RLIMIT_NOFILE, (16384, resource.getrlimit(resource.RLIMIT_NOFILE)[1]))
    user = pwd.getpwuid(os.getuid())
    shell = user.pw_shell or '/bin/sh'
    environment = dict(HOME=user.pw_dir, USER=user.pw_name, LOGNAME=user.pw_name,
                       SHELL=shell, TERM='xterm-256color', PATH='/usr/local/bin:/usr/bin:/bin')
    if 'ZDOTDIR' in os.environ:
        environment['ZDOTDIR'] = os.environ['ZDOTDIR']
    peers, children, tasks = [], [], []
    try:
        for index in range(args.sessions):
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
            try:
                child = subprocess.Popen(['-' + Path(shell).name], executable=shell,
                    stdin=slave, stdout=slave, stderr=slave, cwd=user.pw_dir,
                    env=environment, preexec_fn=terminal_child)
            except BaseException:
                os.close(master)
                raise
            finally:
                os.close(slave)
            children.append(child)
            peer = DirectPeer(master)
            peers.append(peer)
            await peer.echo(f'init-{index}'.encode(), b"stty -echo; PS1=''; ")
        active = peers[-max(1, args.sessions // 10):]
        start = time.monotonic()
        async def workload():
            iteration = 0
            while True:
                await asyncio.gather(*(peer.echo(f'load-{i}-{iteration}'.encode(),
                    b'seq 1 1024; ' if i >= len(active) - max(1, args.sessions // 100) else b'')
                    for i, peer in enumerate(active)))
                iteration += 1
                await asyncio.sleep(max(0, start + iteration - time.monotonic()))
        tasks.append(asyncio.create_task(workload()))
        rows = []
        for number in range(args.seconds):
            await asyncio.sleep(max(0, start + number + 1 - time.monotonic()))
            values = await asyncio.gather(*(peer.echo(f'probe-{i}-{number}'.encode())
                                           for i, peer in enumerate(active)))
            rows.append(dict(elapsed_s=time.monotonic() - start,
                             echo_p99_ms=percentile(values, .99), echo_samples=len(values)))
        print(json.dumps(dict(machine=os.uname().nodename, load=os.getloadavg(),
            driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            diagnostic_only=True, sessions=args.sessions, active=len(active),
            surviving_shells=sum(child.poll() is None for child in children), samples=rows)), flush=True)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for peer in peers:
            peer.close()
        for child in children:
            if child.poll() is None:
                # Each owned shell created its own session. Bursts are finite,
                # but retire that shell's synthetic jobs along with the shell.
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
                with contextlib.suppress(ProcessLookupError):
                    child.kill()
            child.wait()
        assert all(child.poll() is not None for child in children)
        print(json.dumps(dict(cleanup_owned_shells=len(children), cleanup_remaining=0)), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sessions', type=int, default=1000)
    parser.add_argument('--seconds', type=int, default=90)
    args = parser.parse_args()
    assert 10 <= args.sessions <= 1000 and 1 <= args.seconds <= 120
    asyncio.run(run(args))
