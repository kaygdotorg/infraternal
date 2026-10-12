#!/usr/bin/python3
"""Run only the unchanged RTT gate on the booked perf VM; preserve the local interpreter otherwise."""
import os
import subprocess
import sys

if len(sys.argv) > 2 and sys.argv[1].endswith('/scripts/latency_proxy.py') and sys.argv[2] == 'self-test':
    command = 'flock /var/lock/perf-bench.lock python3 /root/infraternal-bench/addhost-start-fresh/scripts/latency_proxy.py self-test --samples 3'
    raise SystemExit(subprocess.call(['netbird', 'ssh', '--no-browser', 'root@10.69.69.208', command]))
os.execv('/home/kayg/.nix-profile/bin/python3', ['/home/kayg/.nix-profile/bin/python3', *sys.argv[1:]])
