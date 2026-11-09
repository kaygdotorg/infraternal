#!/usr/bin/env python3
"""Compile identical sources in differently named roots and compare stripped artifacts [D243], #201."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
SCRATCH.mkdir(parents=True, exist_ok=True)
# The compiler wrapper maps its physical checkout root (pwd -P). Keep absolute
# source arguments in that same tree when a job's target is a symlink (#421).
SCRATCH = SCRATCH.resolve()
with tempfile.TemporaryDirectory(prefix="remap-test-", dir=SCRATCH) as directory:
    artifacts = []
    for name in ("short", "a-deliberately-longer-checkout-location"):
        checkout = Path(directory) / name
        (checkout / ".cargo").mkdir(parents=True)
        shutil.copy2(ROOT / ".cargo/rust-remap-flags.sh", checkout / ".cargo/rust-remap-flags.sh")
        shutil.copy2(ROOT / ".cargo/rustc.sh", checkout / ".cargo/rustc.sh")
        shutil.copy2(ROOT / "rust-toolchain.toml", checkout / "rust-toolchain.toml")
        source = checkout / "source.rs"
        source.write_text('//! Reproducible source location control.\nfn main() { println!("{}", file!()); }\n')
        binary = checkout / "control"
        subprocess.run([
            str(checkout / ".cargo/rustc.sh"), str(source), "--crate-name", "path_control",
            "-C", "strip=symbols", "-o", str(binary),
        ], cwd=checkout, env=dict(os.environ, CARGO_TARGET_DIR=str(checkout / "build")), check=True)
        assert subprocess.check_output([str(binary)], text=True).strip() == "/infraternal/source.rs"
        artifacts.append(binary.read_bytes())
    assert artifacts[0] == artifacts[1], "different checkout roots changed the stripped artifact"
print("Rust remapping: differently named checkout roots produce identical stripped artifacts")
