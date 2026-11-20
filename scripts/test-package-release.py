#!/usr/bin/env python3
"""Check both host/session architecture profiles and refusal of partial publication (#87)."""
import os
from pathlib import Path
import subprocess
import tempfile

scratch = Path(os.environ.get('INFRATERNAL_TEST_STATE_ROOT', str(Path.home() / '.cache/codex-scratch/release-addhost')))
scratch.mkdir(parents=True, exist_ok=True)
target = Path(os.environ.get('CARGO_TARGET_DIR', 'target')).resolve()
with tempfile.TemporaryDirectory(prefix='package-', dir=scratch) as work:
    bundle = Path(work) / 'release'
    subprocess.run(['scripts/package-release', str(bundle), 'x86_64', '--built'], check=True)
    subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=bundle, check=True)
    subprocess.run(
        [
            'python3',
            'scripts/test-vt-release-notices.py',
            '--binary',
            str(target / 'x86_64-unknown-linux-musl/release/infraternal'),
        ],
        check=True,
    )
    assert (bundle / 'infraternal').read_bytes() == (target / 'x86_64-unknown-linux-musl/release/infraternal').read_bytes()
    for arch in ('x86_64', 'aarch64'):
        assert (bundle / f'infraternal-{arch}-musl').read_bytes() == (target / f'bootstrap/{arch}-unknown-linux-musl/release/infraternal').read_bytes()
        assert (bundle / f'infraternal-{arch}-session-musl').read_bytes() == (target / f'session/{arch}-unknown-linux-musl/release/infraternal-session').read_bytes()
    assert all((bundle / name).stat().st_mode & 0o111 for name in ['infraternal', 'infraternal-x86_64-musl', 'infraternal-aarch64-musl', 'infraternal-x86_64-session-musl', 'infraternal-aarch64-session-musl'])
    # A missing session profile is a partial release even when all traditional
    # host payloads are present. Symlinks here reference only built public test artifacts.
    partial_target = Path(work) / 'partial-target'
    for relative in (
        'x86_64-unknown-linux-musl/release/infraternal',
        'bootstrap/x86_64-unknown-linux-musl/release/infraternal',
        'bootstrap/aarch64-unknown-linux-musl/release/infraternal',
        'session/x86_64-unknown-linux-musl/release/infraternal-session',
    ):
        link = partial_target / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target / relative)
    missing_session_bundle = Path(work) / 'missing-session-release'
    refused_session = subprocess.run(['scripts/package-release', str(missing_session_bundle), 'x86_64', '--built'], env={**os.environ, 'CARGO_TARGET_DIR': str(partial_target)}, capture_output=True)
    assert refused_session.returncode != 0 and not missing_session_bundle.exists()
    assert b'session/aarch64-unknown-linux-musl' in refused_session.stderr
    empty = Path(work) / 'empty-target'
    partial = Path(work) / 'partial-release'
    refused = subprocess.run(['scripts/package-release', str(partial), 'x86_64', '--built'], env={**os.environ, 'CARGO_TARGET_DIR': str(empty)}, capture_output=True)
    assert refused.returncode != 0 and not partial.exists()
    assert b'x86_64' in refused.stderr and str(empty).encode() in refused.stderr
print('PASS: release includes server + both executable host/session architecture profiles; checksums match; incomplete bundle never publishes')
