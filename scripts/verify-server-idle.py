#!/usr/bin/env python3
"""Observe a fresh real server beyond SQLx's former 600-second idle reaper [41]."""
import argparse
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
sys.dont_write_bytecode = True
from idle_canary import assert_process_idle

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=Path, required=True)
parser.add_argument('--seconds', type=float, default=620)
args = parser.parse_args()
state = Path(f'target/si{os.getpid()}')
state.mkdir(mode=0o700)
runtime = state / 'runtime'
runtime.mkdir(mode=0o700)
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
env = dict(os.environ, XDG_RUNTIME_DIR=str(runtime))
p = subprocess.Popen([str(args.binary.resolve()), 'server', '--listen', f'127.0.0.1:{port}',
    '--data', str(state / 'data'), '--public-origin', 'https://auth.example.test',
    '--behind-proxy', '--trusted-proxy', '127.0.0.1'], env=env,
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
try:
    for _ in range(200):
        if (state / 'data/setup-token.sock').exists():
            break
        assert p.poll() is None, 'server failed startup'
        time.sleep(.05)
    else:
        raise AssertionError('server did not publish its private setup socket')
    # Fence startup; the observation sends no health/auth/terminal requests.
    time.sleep(1)
    m = assert_process_idle(p.pid, 'long-running server', args.seconds)
    assert p.poll() is None, 'server exited during observation'
    print(f'fresh long-running server: {m.total_slices} scheduler activations / {m.elapsed_seconds:.3f}s; machine={os.uname().machine}; cores={os.cpu_count()}; load={os.getloadavg()}')
finally:
    if p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
        p.wait()
    shutil.rmtree(state)
