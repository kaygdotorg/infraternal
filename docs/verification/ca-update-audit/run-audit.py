#!/usr/bin/env python3
"""Run real compiled custody/admission regressions and preserve expected failing evidence, #154."""
import argparse
import os
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--target', type=Path, required=True)
parser.add_argument('--phase', choices=['before', 'after', 'hardening'], required=True)
args = parser.parse_args()
root = Path(__file__).resolve().parents[3]
evidence = root / ('evidence/ca-update-hardening' if args.phase == 'hardening' else 'evidence/ca-update-audit')
evidence.mkdir(parents=True, exist_ok=True)

def binary(stem, marker):
    for candidate in sorted((args.target / 'debug/deps').glob(stem + '-*'), key=lambda path: path.stat().st_mtime, reverse=True):
        if '.' in candidate.name or not os.access(candidate, os.X_OK):
            continue
        listing = subprocess.run([str(candidate), '--list'], capture_output=True, text=True, check=False)
        if marker in listing.stdout:
            return candidate
    raise RuntimeError('compiled audit test binary not found')

server = binary('infraternal_server', 'ca_update_audit_tests::')
cli = binary('infraternal', 'restart_binary::audit_tests::')
cases = [
    (server, 'ca_update_audit_tests::unlocked_signer_requires_persistent_locked_pages', args.phase != 'hardening', args.phase == 'hardening'),
    (server, 'auth::tests::ca_administration_tests::http_tests::audit_tests::sequential_unlock_starts_require_a_temporal_budget', args.phase != 'hardening', args.phase == 'hardening'),
    (cli, 'restart_binary::audit_tests::unsigned_or_tampered_replacement_is_refused_before_exec', True, False),
    (cli, 'restart_binary::audit_tests::admitted_inode_cannot_change_in_place_before_execution', True, False),
    (cli, 'restart_binary::audit_tests::unusable_admitted_image_keeps_the_existing_service_running', True, False),
    (server, 'auth::tests::ca_administration_tests::audit_tests::unlock_audit_records_principal_time_outcome_without_material', args.phase == 'before', args.phase != 'before'),
    (server, 'ca_update_audit_tests', False, True),
    (cli, 'restart_binary::audit_tests', False, True),
    (server, 'ca_handoff::tests', False, True),
    (server, 'auth::tests::ca_administration_tests', False, True),
    (cli, 'startup_tests::process_dumpability_is_disabled_before_dispatch', False, True),
]
print(f'machine={os.uname().nodename} cpus={os.cpu_count()} phase={args.phase} load_before={Path("/proc/loadavg").read_text().strip()}', flush=True)
mismatch = False
for executable, name, ignored, expect_success in cases:
    command = [str(executable), name, '--nocapture', '--test-threads=1']
    if ignored:
        command += ['--ignored', '--exact']
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=240)
    output = result.stdout + result.stderr
    path = evidence / f'{args.phase}-{name.split("::")[-1]}.txt'
    path.write_text(output)
    # Guard against a misspelled filter passing by running zero tests.
    success = result.returncode == 0 and 'running 0 tests' not in output
    matches = success == expect_success and 'running 0 tests' not in output
    mismatch |= not matches
    print(f'test={name} exit={result.returncode} elapsed_s={time.monotonic()-started:.3f} expected={"PASS" if expect_success else "FAIL"} matched={matches} evidence={path.relative_to(root)}', flush=True)
print(f'load_after={Path("/proc/loadavg").read_text().strip()}', flush=True)
raise SystemExit(1 if mismatch else 0)
