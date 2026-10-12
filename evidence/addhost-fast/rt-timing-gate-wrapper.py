#!/usr/bin/python3
"""Forward the unchanged RTT self-test to this job's locked perf VM; keep other Python calls local."""
import os
import shlex
import subprocess
import sys

if len(sys.argv) > 2 and sys.argv[1].endswith('/scripts/latency_proxy.py') and sys.argv[2] == 'self-test':
    command = shlex.join([
        'flock', '/var/lock/perf-bench.lock', 'python3',
        '/root/infraternal-bench/addhost-fast/scripts/latency_proxy.py', *sys.argv[2:]
    ])
    # NetBird's client can report zero despite a remote command failure. Require
    # an explicit status receipt so the unchanged repository gate cannot go green
    # after a lock timeout or failed remote self-test.
    command += '; result=$?; printf "\\nPERF_GATE_EXIT=%s\\n" "$result"'
    run = subprocess.run(['netbird', 'ssh', '--no-browser', 'root@10.69.69.208', command], capture_output=True, text=True)
    print(run.stdout, end='')
    print(run.stderr, end='', file=sys.stderr)
    receipt = run.stdout.rstrip().splitlines()
    if run.returncode != 0 or not receipt or receipt[-1] != 'PERF_GATE_EXIT=0':
        raise SystemExit(1)
    raise SystemExit(0)
os.execv('/home/kayg/.nix-profile/bin/python3', ['/home/kayg/.nix-profile/bin/python3', *sys.argv[1:]])
