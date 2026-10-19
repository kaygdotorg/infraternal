#!/usr/bin/env python3
"""Classify exact-history residency externally, with no sampler heap in the terminal [D270].

The private child pipe carries a stack-location hint solely to identify its
worker mapping. Neither that address nor raw smaps text enters the receipt.
Run only on the named perf VM under its lock and a private memory scope.
SPDX-License-Identifier: AGPL-3.0-only
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def mappings(pid, binary, stack):
    """Aggregate numeric residency while the terminal is paused between operations."""
    return parse_mappings(Path(f'/proc/{pid}/smaps').read_text(), binary, stack)


def parse_mappings(raw, binary, stack):
    """Keep stack attribution distinct from anonymous terminal allocations."""
    groups = {}
    group = None
    for line in raw.splitlines():
        header = re.match(r'^([0-9a-f]+)-([0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+\d+\s*(.*)$', line)
        if header:
            start, end, name = header.groups()
            group = ('worker_stack' if int(start, 16) <= stack < int(end, 16) else
                     'image' if name == str(binary) else
                     'main_stack' if name == '[stack]' else
                     'heap' if name == '[heap]' else
                     'anonymous' if not name else 'other')
            groups.setdefault(group, {})
        elif group is not None:
            key, _, rest = line.partition(':')
            if key in ('Pss', 'Rss', 'Private_Dirty', 'Anonymous', 'AnonHugePages'):
                groups[group][key + '_kib'] = groups[group].get(key + '_kib', 0) + int(rest.split()[0])
    return groups


def run(args):
    assert os.uname().nodename == 'infraternal-perf-test'
    args.evidence.mkdir(parents=True, exist_ok=False)
    binary = args.binary.resolve()
    case = 'decimal_history_resident_increment' if args.body == 'decimal' else 'numbered_history_resident_increment'
    child = subprocess.Popen([str(binary), '--exact', 'terminal::compact_history::' + case,
        '--ignored', '--nocapture', '--test-threads=1'], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        env={'PPU_HISTORY_FENCE': '1'})
    phases = {}
    try:
        with (args.evidence / 'transcript.log').open('w') as log:
            for line in child.stdout:
                at = line.find('HISTORY_FENCE ')
                if at >= 0:
                    fields = dict(item.split('=', 1) for item in line[at + 14:].split())
                    assert int(fields['pid']) == child.pid
                    phase = fields['phase']
                    assert phase in ('ready', 'empty', 'full') and phase not in phases
                    if phase != 'ready':
                        phases[phase] = mappings(child.pid, binary, int(fields['stack'], 16))
                    else:
                        phases[phase] = {}
                    # Remove the address even from the raw transcript.
                    log.write(f'HISTORY_FENCE body={fields["body"]} phase={phase} pid={child.pid}\n')
                    child.stdin.write('1')
                    child.stdin.flush()
                else:
                    log.write(line)
            assert child.wait() == 0, 'history fixture failed'
        assert set(phases) == {'ready', 'empty', 'full'}, 'fixture must support every measurement fence'
        row = dict(machine=os.uname().nodename, kernel=os.uname().release,
            cpus=os.cpu_count(), load=os.getloadavg(), body=args.body, source=args.source,
            binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), phases=phases)
        (args.evidence / 'residency.json').write_text(json.dumps(row, indent=2) + '\n')
        print(json.dumps(row), flush=True)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdin.close()
        child.stdout.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--body', choices=['repeated', 'decimal'], required=True)
    run(parser.parse_args())
