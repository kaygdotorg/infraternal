#!/usr/bin/env python3
"""Compare the real double-fork boundary at 200 launches without build overlap, #154."""
from pathlib import Path
import json
import statistics
import subprocess
import time

root = Path('/home/kayg/.cache/codex-scratch/prod-batch')
print('load_before=' + Path('/proc/loadavg').read_text().strip(), flush=True)
rows = {'before': [], 'after': []}
count = 200
for round in range(7):
    for label in (('before', 'after') if round % 2 == 0 else ('after', 'before')):
        start = time.monotonic_ns()
        for index in range(count):
            result = root / 'detach-result.txt'
            subprocess.run([str(root / 'artifacts' / ('detach-' + label)), str(result), '0'],
                           check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            deadline = time.monotonic() + 5
            while not result.exists() or not result.read_bytes().endswith(b'\n'):
                if time.monotonic() > deadline:
                    raise RuntimeError('detached probe did not finish')
                time.sleep(.001)
            result.unlink()
        elapsed = (time.monotonic_ns() - start) / 1e6
        rows[label].append(elapsed)
        print(json.dumps(dict(round=round, label=label, launches=count, batch_ms=elapsed)), flush=True)
before, after = (statistics.median(rows[label]) for label in ('before', 'after'))
print(f'METRIC name=double_fork_signal_reset launches=200 rounds=7 before_batch_p50_ms={before:.3f} after_batch_p50_ms={after:.3f} observed_delta_per_launch_us={(after-before)*1000/count:.3f} observed_delta_at_200_launches_ms={after-before:.3f} profile=GNU-debug persistent_reset_state_bytes=0', flush=True)
print('load_after=' + Path('/proc/loadavg').read_text().strip(), flush=True)
