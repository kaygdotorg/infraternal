#!/usr/bin/env python3
"""Record pinned-VM metadata before running the fast gate's unchanged RTT self-test."""
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys

root = Path(__file__).resolve().parent
probe = root / 'scripts/latency_proxy.py'
print('ENVIRONMENT phase=fast-rtt machine=' + platform.node()
      + ' cores=' + str(os.cpu_count())
      + ' load=' + ' '.join(Path('/proc/loadavg').read_text().split()[:3])
      + ' probe_sha256=' + hashlib.sha256(probe.read_bytes()).hexdigest(), flush=True)
sys.exit(subprocess.call([sys.executable, str(probe), 'self-test', '--samples', '3']))
