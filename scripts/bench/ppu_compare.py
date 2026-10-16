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
    return dict(lock_identity=key, locks=locks,
                owner=owner_path.read_text().strip() if owner_path.exists() else None,
                running_scopes=[line.split()[0] for line in scopes.splitlines() if line.split()],
                load=Path('/proc/loadavg').read_text().strip())


def write(record, kind, **fields):
    if kind == 'environment':
        fields.update(architecture='independent-session-processes' if INDEPENDENT else 'shared-user-process',
                      wakeup_scope='first-shim-only' if INDEPENDENT else 'shared-host',
                      cohort_metadata='post-timed-cohort')
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
