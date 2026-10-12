#!/usr/bin/env python3
"""Measure key-free release startup and run existing synthetic CA tests under D244 limits."""

import hashlib
import json
import os
from pathlib import Path
import socket
import resource
import statistics
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
assert os.geteuid() == 0
assert resource.getrlimit(resource.RLIMIT_MEMLOCK) == (8388608, 8388608)
print('uid=0 memlock_bytes=8388608 cores=' + str(os.cpu_count()), flush=True)
print('machine=' + os.uname().nodename, 'kernel=' + os.uname().release, flush=True)
print('load_before=' + Path('/proc/loadavg').read_text().strip(), flush=True)


def summary(mode, kind, values):
    ordered = sorted(values)
    print(json.dumps(dict(mode=mode, measurement=kind, n=len(values),
                          p50_ms=statistics.median(values), max_ms=ordered[-1])), flush=True)


if '--tests-only' not in sys.argv:
    # Same hidden diagnostic in both images isolates the provider build policy from
    # the added CLI dispatch. Alternate pairs on the quiet VM, without compilation.
    checks = {'baseline': [], 'candidate': []}
    for iteration in range(31):
        modes = ('baseline', 'candidate') if iteration % 2 == 0 else ('candidate', 'baseline')
        for mode in modes:
            binary = ROOT / ('disabled-diagnostic-x86' if mode == 'baseline' else 'candidate-x86')
            start = time.perf_counter_ns()
            result = subprocess.run([str(binary), '__key-memory-check', '--json'],
                                    capture_output=True, check=False)
            checks[mode].append((time.perf_counter_ns() - start) / 1e6)
            record = json.loads(result.stdout)
            assert result.returncode == (1 if mode == 'baseline' else 0)
            assert record['state'] == ('refused' if mode == 'baseline' else 'ready')
    for mode, values in checks.items():
        summary(mode, 'process_key_memory_check', values)
    
    
    for mode in ('baseline', 'candidate'):
        binary = ROOT / f'{mode}-x86'
        print(json.dumps(dict(mode=mode, bytes=binary.stat().st_size,
                              sha256=hashlib.sha256(binary.read_bytes()).hexdigest())), flush=True)
        starts = []
        for iteration in range(21):
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            data = ROOT / mode / f'data-{iteration}'
            data.mkdir(mode=0o700, parents=True, exist_ok=True)
            start = time.perf_counter_ns()
            child = subprocess.Popen(
                [str(binary), 'server', '--data', str(data), '--listen', f'127.0.0.1:{port}',
                 '--behind-proxy', '--trusted-proxy', '127.0.0.1', '--public-origin', 'https://localhost'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=dict(os.environ, XDG_RUNTIME_DIR=str(ROOT / 'runtime')),
            )
            try:
                deadline = time.monotonic() + 10
                while True:
                    status = child.poll()
                    if mode == 'baseline':
                        if status is not None:
                            assert status == 1
                            break
                    else:
                        assert status is None, 'candidate server refused'
                        try:
                            with urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=0.2) as response:
                                if response.status == 200:
                                    break
                        except OSError:
                            pass
                    assert time.monotonic() < deadline, 'startup deadline exceeded'
                    time.sleep(0.001)
                starts.append((time.perf_counter_ns() - start) / 1e6)
                if mode == 'candidate':
                    status = Path(f'/proc/{child.pid}/status').read_text()
                    locked = int(next(line for line in status.splitlines() if line.startswith('VmLck:')).split()[1])
                    assert locked >= 1024, 'key memory lacks locked pages'
                    # Observe real mappings without printing addresses or contents.
                    maps = Path(f'/proc/{child.pid}/smaps').read_text()
                    size = 0
                    protected = 0
                    for line in maps.splitlines():
                        if line.startswith('Size:'):
                            size = int(line.split()[1])
                        elif line.startswith('VmFlags:'):
                            flags = line.split()[1:]
                            if 'lo' in flags and 'dd' in flags:
                                protected += size
                    assert protected >= 1024, 'key memory lacks dump exclusion'
                    if iteration == 0:
                        print(json.dumps(dict(mode=mode, server_health=200, vm_lck_kib=locked,
                                              locked_dump_excluded_kib=protected, servers=1)), flush=True)
            finally:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=10)
        summary(mode, 'server_refusal' if mode == 'baseline' else 'server_health_ready', starts)
    
if '--startup-only' not in sys.argv:
    # This is the pinned musl release test executable, not a GNU substitute. Existing
    # tests use real encrypted copies and passkey proofs; only public counters print.
    tests = ROOT / 'server-tests-x86'
    environment = dict(os.environ, TMPDIR=str(ROOT / 'fixtures'))
    Path(environment['TMPDIR']).mkdir(mode=0o700, exist_ok=True)
    for name in (
        'ca_update_audit_tests::unlocked_signer_requires_persistent_locked_pages',
        'auth::tests::ca_administration_tests::http_tests::ca_http_real_passkey_unlock_returns_only_lock_status_without_a_session_cookie',
        'ca_update_audit_tests::secure_heap_capacity_at_10000_live_keys',
    ):
        arguments = [str(tests), '--exact', name, '--nocapture']
        if name.endswith('secure_heap_capacity_at_10000_live_keys'):
            arguments.append('--ignored')
        result = subprocess.run(arguments,
                                env=environment, capture_output=True, check=False)
        print(result.stdout.decode(), end='', flush=True)
        assert result.returncode == 0 and b'1 passed' in result.stdout, 'real CA test did not pass'
        assert b'0 failed' in result.stdout
print('load_after=' + Path('/proc/loadavg').read_text().strip(), flush=True)
