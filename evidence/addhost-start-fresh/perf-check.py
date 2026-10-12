"""Measure the shipped fixed setup check and bounded lease on the booked perf VM only."""
import os
from pathlib import Path
import re
import socket
import statistics
import subprocess
import tempfile
import time

root = Path(__file__).resolve().parents[2]
source = (root / 'crates/plugins/ssh/src/probe.rs').read_text()
check = re.search(r'pub const CHECK_SCRIPT: &str = r#"(.*?)"#;', source, re.S)[1]
lock = (root / 'crates/plugins/ssh/src/setup_lock.sh').read_text()
inspect = lock + (root / 'crates/plugins/ssh/src/previous_attempt.sh').read_text()
print('machine', os.uname().nodename, 'cores', os.cpu_count(), 'load', Path('/proc/loadavg').read_text().strip())
assert os.uname().nodename == 'infraternal-perf-test', 'timings require the booked VM'
with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temp:
    base = Path(temp) / 'infraternal'
    prefix = f'set -euC\numask 077\nbase="{base}"\n'
    combined = check + '\n' + prefix + inspect + '\ninspect_previous'
    samples = {'baseline': [], 'combined': []}
    for i in range(111):
        for name, script in ([('baseline', check), ('combined', combined)] if i % 2 == 0 else [('combined', combined), ('baseline', check)]):
            before = time.perf_counter_ns()
            result = subprocess.run(['/bin/sh', '-c', script], capture_output=True, check=True)
            elapsed = (time.perf_counter_ns() - before) / 1e6
            if name == 'combined':
                assert result.stdout.endswith(b'INFRATERNAL_SETUP_CLEAR\n')
            if i >= 10:
                samples[name].append(elapsed)
    for name, values in samples.items():
        ordered = sorted(values)
        print(f'{name} n={len(values)} p50_ms={statistics.median(values):.3f} p99_ms={ordered[int(.99 * (len(ordered)-1))]:.3f}')
    deltas = [b-a for a,b in zip(samples['baseline'],samples['combined'])]
    print(f'paired_delta n={len(deltas)} p50_ms={statistics.median(deltas):.3f} max_ms={max(deltas):.3f} additional_ssh_roundtrips=0')
    base.mkdir(mode=0o700)
    owner = base / '.bootstrap-owner'
    owner.write_text('1' * 32 + '\n')
    owner.chmod(0o600)
    receipt = Path(str(base) + '.bootstrap-rollback-' + '2' * 32)
    receipt.write_text(f"{'1' * 32} {'2' * 32} fresh {base.stat().st_dev}:{base.stat().st_ino}\n")
    receipt.chmod(0o600)
    sessions = base / 'sessions'
    sessions.mkdir(mode=0o700)
    rendezvous = sessions / ('3' * 32 + '.sock')
    with socket.socket(socket.AF_UNIX) as listener:
        previous_directory = Path.cwd()
        os.chdir(sessions)
        try:
            listener.bind(rendezvous.name)
        finally:
            os.chdir(previous_directory)
        rendezvous.chmod(0o600)
    stale = []
    for _ in range(31):
        before = time.perf_counter_ns()
        result = subprocess.run(['/bin/sh', '-c', combined], capture_output=True, check=True)
        stale.append((time.perf_counter_ns() - before) / 1e6)
        assert b'INFRATERNAL_SETUP_STALE' in result.stdout
    print(f'stale n=31 p50_ms={statistics.median(stale):.3f} p99_ms={max(stale):.3f} additional_ssh_roundtrips=0')
    print(f'clear_check_increment_at_1600_hosts_serial_ms={statistics.median(deltas)*1600:.3f} global_concurrent_hosts=8')
    rendezvous.unlink()
    sessions.rmdir()
    owner.unlink()
    receipt.unlink()
    stage = base / '.bootstrap-lock'
    stage.mkdir(mode=0o700)
    script = prefix + f'stage="{stage}"\n' + lock + '\nsetup_guard\nstart_setup_lease\n'
    subprocess.run(['/bin/sh','-c',script],check=True)
    pid = (stage/'lease').read_text().split()[0]
    status = Path(f'/proc/{pid}/status').read_text()
    rss = int(re.search(r'VmRSS:\s+(\d+)',status)[1])
    print(f'setup_lease rss_kib={rss} global_concurrent_hosts=8 scale_rss_kib={rss*8} deadline_seconds=180 periodic_work=none')
    result = subprocess.run(['/bin/sh','-c',prefix+inspect+'\ninspect_previous'],capture_output=True)
    assert result.returncode == 73
    subprocess.run(['/bin/sh','-c',prefix+f'stage="{stage}"\n'+lock+'\nsetup_guard\nretire_setup_lease'],check=True)
    print('live_lease_refusal=PASS lease_retirement=PASS')
print('final_load',Path('/proc/loadavg').read_text().strip())
