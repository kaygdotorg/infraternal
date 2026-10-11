#!/usr/bin/env python3
"""Check release completeness, both payloads and refusal of partial publication (#87)."""
import os
from pathlib import Path
import subprocess
import tempfile

scratch = Path.home() / '.cache/codex-scratch/release-addhost'
target = Path(os.environ.get('CARGO_TARGET_DIR', 'target')).resolve()
with tempfile.TemporaryDirectory(prefix='package-', dir=scratch) as work:
    bundle = Path(work) / 'release'
    subprocess.run(['scripts/package-release', str(bundle), 'x86_64', '--built'], check=True)
    subprocess.run(['sha256sum', '--check', 'SHA256SUMS'], cwd=bundle, check=True)
    assert (bundle / 'infraternal').read_bytes() == (bundle / 'infraternal-x86_64-musl').read_bytes()
    assert all((bundle / name).stat().st_mode & 0o111 for name in ['infraternal', 'infraternal-x86_64-musl', 'infraternal-aarch64-musl'])
    empty = Path(work) / 'empty-target'
    partial = Path(work) / 'partial-release'
    refused = subprocess.run(['scripts/package-release', str(partial), 'x86_64', '--built'], env={**os.environ, 'CARGO_TARGET_DIR': str(empty)}, capture_output=True)
    assert refused.returncode != 0 and not partial.exists()
    assert b'x86_64' in refused.stderr and str(empty).encode() in refused.stderr
print('PASS: release includes server + both executable host payloads; checksums match; incomplete bundle never publishes')
