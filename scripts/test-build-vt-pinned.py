#!/usr/bin/env python3
"""Exercise the VT recipe without an ambient Zig compiler (D94/D213, #87)."""
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
scratch = Path.home() / '.cache/codex-scratch/release-addhost/build-vt-test'
scratch.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(dir=scratch) as temporary:
    target = Path(temporary)
    zig = target / 'auth-tools/zig/zig'
    zig.parent.mkdir(parents=True)
    zig.write_text('#!/bin/sh\n# Test compiler only proves selection before source download.\nprintf "0.15.2\\n"\n')
    zig.chmod(0o700)
    env = {**os.environ, 'PATH': '/usr/bin:/bin', 'CARGO_TARGET_DIR': str(target), 'TARGET': 'unsupported-test-target'}
    result = subprocess.run(['bash', str(root / 'scripts/build-vt'), str(target / 'out')], env=env, capture_output=True, text=True)
    assert 'unsupported libghostty-vt target: unsupported-test-target' in result.stderr, result.stderr
print('PASS: build-vt selects pinned Zig without Zig on PATH')
