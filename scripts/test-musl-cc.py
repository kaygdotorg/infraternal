#!/usr/bin/env python3
"""Exercise the pinned C wrapper's exact D244 argument policy for both musl targets."""

import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(os.environ.get('CARGO_TARGET_DIR', ROOT / 'target'))
SCRATCH.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='wrapper-test-', dir=SCRATCH) as directory:
    tool = Path(directory) / 'auth-tools/zig/zig'
    tool.parent.mkdir(parents=True)
    tool.write_text('#!/usr/bin/env python3\nimport sys\nprint("\\n".join(sys.argv[1:]))\n')
    tool.chmod(0o755)
    for target, zig_target in (
        ('x86_64-unknown-linux-musl', 'x86_64-linux-musl'),
        ('aarch64-unknown-linux-musl', 'aarch64-linux-musl'),
    ):
        environment = dict(os.environ, CARGO_TARGET_DIR=directory, TARGET=target)
        retained = ['-DOPENSSL_NO_SECURE_MEMORY=1', '-DOTHER=1', '-O3', 'input with spaces.c']
        result = subprocess.run(
            [str(ROOT / '.cargo/musl-cc.sh'), f'--target={target}',
             '-DOPENSSL_NO_SECURE_MEMORY', *retained],
            env=environment, check=True, capture_output=True, text=True,
        )
        assert result.stdout.splitlines() == ['cc', '-target', zig_target, *retained], target
        result = subprocess.run(
            [str(ROOT / '.cargo/musl-cc.sh'), '--target=unowned-target'],
            env=environment, capture_output=True, text=True,
        )
        assert result.returncode != 0 and not result.stdout, target
        print(f'{target}: exact define removed; other arguments preserved; override refused')
