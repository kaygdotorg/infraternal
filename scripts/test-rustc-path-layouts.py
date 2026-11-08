#!/usr/bin/env python3
"""Exercise the release path-leak control with physical and symlinked targets (#421)."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
SCRATCH.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix="remap-layouts-", dir=SCRATCH) as directory:
    physical = Path(directory).resolve() / "physical"
    physical.mkdir()
    symlink = physical.parent / "symlink"
    symlink.symlink_to(physical, target_is_directory=True)
    for target in (physical, symlink):
        print(f"Rust remapping target layout: {target.name}", flush=True)
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/test-rustc-paths.py")],
            cwd=ROOT, env={**os.environ, "CARGO_TARGET_DIR": str(target)}, check=True,
        )
