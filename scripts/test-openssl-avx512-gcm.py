#!/usr/bin/env python3
"""Run a known AES-GCM vector against the patched static x86_64 crypto archive [D264]."""

import os
from pathlib import Path
import subprocess
import sys


TARGET = "x86_64-unknown-linux-musl"
ZIG_TARGET = "x86_64-linux-musl"
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "scripts/test-openssl-avx512-gcm.c"


def main() -> int:
    """Compile and run the AES-GCM known-vector check using the shipping archive."""
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
    build_root = target_root / TARGET / "release/build"
    archives = list(build_root.glob("openssl-sys-*/out/openssl-build/install/lib/libcrypto.a"))
    if not archives:
        raise SystemExit(f"static OpenSSL archive is missing under {build_root}")
    archive = max(archives, key=lambda path: path.stat().st_mtime_ns)
    include = archive.parents[1] / "include"
    zig = target_root / "auth-tools/zig/zig"
    executable = target_root / "infraternal-openssl-avx512-gcm-test"
    environment = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(target_root / "auth-tools/cache"))
    command = [
        str(zig),
        "cc",
        "-target",
        ZIG_TARGET,
        "-static",
        "-I",
        str(include),
        str(SOURCE),
        str(archive),
        "-pthread",
        "-ldl",
        "-o",
        str(executable),
    ]
    subprocess.run(command, cwd=ROOT, env=environment, check=True)
    subprocess.run([str(executable)], check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
