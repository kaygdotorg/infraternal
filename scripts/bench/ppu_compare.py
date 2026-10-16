#!/usr/bin/env python3
"""Observe identical echo cohorts in shared or independent session fixtures [D270].

Append lock/load receipts after the original timed cohort and resource sample.
No timed operation, shell command, cadence or acceptance threshold is replaced.
SPDX-License-Identifier: AGPL-3.0-only
"""
import os
from pathlib import Path
import subprocess
import sys

import ppu_soak as suite
import ppu_baseline as baseline

original_write = suite.Recorder.write
INDEPENDENT = False


def control_scopes():
    """Recognize this fixture's control connection by captured process ancestry."""
    result = set()
    pid = os.getpid()
    while pid > 0:
        root = Path('/proc') / str(pid)
        try:
            result.update(part for line in (root / 'cgroup').read_text().splitlines()
                          for part in line.split('/') if part.endswith('.scope'))
            pid = int((root / 'stat').read_text().rsplit(')', 1)[1].split()[1])
        except FileNotFoundError:
            break
    return sorted(result)


def lock_receipt():
    """Preserve lock inode/holder and active scope names to audit VM contention."""
    path = Path('/var/lock/perf-bench.lock')
    identity = path.stat()
    key = f'{os.major(identity.st_dev):02x}:{os.minor(identity.st_dev):02x}:{identity.st_ino}'
    locks = [line.split() for line in Path('/proc/locks').read_text().splitlines()
             if key in line.split()]
    owner_path = Path('/var/lock/perf-bench.owner')
    scopes = subprocess.check_output(['systemctl', 'list-units', '--type=scope',
        '--state=running', '--plain', '--no-legend', '--no-pager'], text=True)
    names = [line.split()[0] for line in scopes.splitlines() if line.split()]
    groups = subprocess.check_output(['systemctl', 'show', *names,
        '-p', 'Id', '-p', 'ControlGroup'], text=True)
    scope_cpu = {}
    for block in groups.strip().split('\n\n'):
        properties = dict(line.split('=', 1) for line in block.splitlines() if '=' in line)
        group = properties.get('ControlGroup', '')
        if group:
            counters = Path('/sys/fs/cgroup') / group.lstrip('/') / 'cpu.stat'
            try:
                scope_cpu[properties['Id']] = dict(line.split() for line in counters.read_text().splitlines())
            except FileNotFoundError:
                scope_cpu[properties['Id']] = None  # Scope ended during observation.
    return dict(control_scopes=control_scopes(), scope_cpu=scope_cpu, lock_identity=key, locks=locks,
                owner=owner_path.read_text().strip() if owner_path.exists() else None,
                running_scopes=names,
                load=Path('/proc/loadavg').read_text().strip())


def write(record, kind, **fields):
    if kind == 'environment':
        fields.update(architecture='independent-session-processes' if INDEPENDENT else 'shared-user-process',
                      wakeup_scope='first-shim-only' if INDEPENDENT else 'shared-host',
                      cohort_metadata='post-timed-cohort', machine_receipt=lock_receipt())
    elif kind == 'sample':
        fields['machine_receipt'] = lock_receipt()
    return original_write(record, kind, **fields)


if __name__ == '__main__':
    INDEPENDENT = '--independent-sessions' in sys.argv
    if INDEPENDENT:
        sys.argv.remove('--independent-sessions')
        suite.Host = baseline.Host
    suite.Recorder.write = write
    suite.main()
