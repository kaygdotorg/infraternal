#!/usr/bin/env python3
"""Freeze one owned fixture between short perf-lock holds; retain its state [D270].

The coordinator stays outside the fixture's cgroup. Only fully frozen time is
removed from its monotonic clock. Wall time, lock waits, freeze/thaw transitions
and scope identity remain explicit receipts. No fixture runs without the lock.
"""
import argparse
import contextlib
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import struct
import subprocess
import time


def frozen(group, value, timeout=30):
    """Wait for the kernel's acknowledgement, never infer a successful freeze."""
    (group / 'cgroup.freeze').write_text(str(int(value)))
    deadline = time.monotonic() + timeout
    while f'frozen {int(value)}' not in (group / 'cgroup.events').read_text().splitlines():
        if time.monotonic() >= deadline:
            raise TimeoutError('owned fixture freeze transition timed out')
        time.sleep(.01)


def publish_pause(path, total_ns):
    """The reader is frozen; preserve the inode backing its existing mapping."""
    with path.open('r+b', buffering=0) as target:
        assert target.write(struct.pack('<Q', total_ns)) == 8


def run(args):
    if not re.fullmatch(r'ppu-soak-[a-z0-9-]{1,60}', args.unit) or not 1 <= args.segment_seconds <= 1740:
        raise ValueError('invalid private unit or segment duration')
    if not args.command:
        raise ValueError('missing fixture command')
    args.receipts.mkdir(parents=True, exist_ok=False)
    clock = (args.receipts / 'pause-clock').resolve()
    with clock.open('xb') as target:
        target.write(bytes(8))
    os.chmod(clock, 0o600)
    log = (args.receipts / 'segments.jsonl').open('x')
    child = None
    group = None
    paused_at = None
    total_ns = 0
    held = False
    active_start = None
    active_elapsed = 0

    def record(kind, **fields):
        log.write(json.dumps(dict(kind=kind, wall_utc=datetime.datetime.now(
            datetime.timezone.utc).isoformat(), **fields), sort_keys=True) + '\n')
        log.flush()

    def interrupted(signum, frame):
        raise InterruptedError(f'coordinator received signal {signum}')

    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    lock = Path('/var/lock/perf-bench.lock').open('a')
    try:
        while True:
            # Waiting and all coordinator work are outside the fixture scope.
            subprocess.run(['flock', '-w', '3600', str(lock.fileno())],
                           pass_fds=(lock.fileno(),), check=True)
            held = True
            Path('/var/lock/perf-bench.owner').write_text(
                f'process-per-user {args.unit} {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n')
            record('lock-acquired', active_seconds=active_elapsed)
            if child is None:
                environment = dict(os.environ, PPU_PAUSE_CLOCK=str(clock))
                child = subprocess.Popen(['systemd-run', '--quiet', '--scope', '--unit', args.unit,
                    '-p', 'CPUWeight=10000', '-p', 'MemoryMax=5G', '-p', 'MemorySwapMax=0',
                    '-p', 'OOMPolicy=kill', *args.command], env=environment)
                until = time.monotonic() + 30
                while group is None:
                    if child.poll() is not None:
                        return child.returncode
                    control = subprocess.check_output(['systemctl', 'show', args.unit + '.scope',
                        '-p', 'ControlGroup', '--value'], text=True).strip()
                    if control:
                        candidate = Path('/sys/fs/cgroup') / control.lstrip('/')
                        if candidate.name != args.unit + '.scope':
                            raise ValueError('refuse foreign cgroup')
                        if (candidate / 'cgroup.freeze').exists():
                            group = candidate
                    if time.monotonic() >= until:
                        raise TimeoutError('scope startup timed out')
                    time.sleep(.05)
            else:
                total_ns += time.monotonic_ns() - paused_at
                publish_pause(clock, total_ns)
                record('thaw', excluded_nanoseconds=total_ns, scope=str(group))
                frozen(group, False)
                paused_at = None
            active_start = time.monotonic()
            while child.poll() is None and time.monotonic() - active_start < args.segment_seconds:
                if active_elapsed + time.monotonic() - active_start >= args.timeout:
                    raise TimeoutError('fixture active-time limit')
                time.sleep(.1)
            active_elapsed += time.monotonic() - active_start
            if child.poll() is not None:
                record('exit', code=child.returncode, active_seconds=active_elapsed)
                return child.returncode
            frozen(group, True)
            paused_at = time.monotonic_ns()
            record('freeze', active_seconds=active_elapsed, scope=str(group))
            fcntl.flock(lock, fcntl.LOCK_UN)
            held = False
            # Let already-waiting jobs acquire the lock before rejoining.
            time.sleep(1)
    finally:
        # A failed coordinator must never leave its own scope frozen or running.
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)
        if group is not None and group.exists():
            with contextlib.suppress(OSError):
                (group / 'cgroup.freeze').write_text('0')
        if child is not None and child.poll() is None:
            subprocess.run(['systemctl', 'kill', '--kill-whom=all', '--signal=TERM',
                            args.unit + '.scope'], check=False)
            try:
                child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                subprocess.run(['systemctl', 'kill', '--kill-whom=all', '--signal=KILL',
                                args.unit + '.scope'], check=False)
                child.wait(timeout=30)
        if held:
            record('lock-released', active_seconds=active_elapsed)
        lock.close()
        log.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--unit', required=True)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--segment-seconds', type=float, default=1740)
    parser.add_argument('--timeout', type=float, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ['--']:
        args.command.pop(0)
    raise SystemExit(run(args))


if __name__ == '__main__':
    main()
