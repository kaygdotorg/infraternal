#!/usr/bin/env python3
"""Build a static provider diagnostic and an unshipped memory-option candidate for #154."""
import argparse
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("target_root", type=Path)
parser.add_argument("target", choices=["x86_64", "aarch64"])
args = parser.parse_args()
root = args.target_root.resolve()
provider = next(root.glob(f"{args.target}-unknown-linux-musl/release/build/openssl-sys-*/out/openssl-build/install"))
source = Path("/home/kayg/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/openssl-src-300.6.1+3.6.3/openssl")
probe = Path(__file__).resolve().with_name("heap_probe.c")
compiler = [str(root / "auth-tools/zig/zig"), "cc", "-target", f"{args.target}-linux-musl", "-O2", "-ffunction-sections", "-fdata-sections"]
env = os.environ.copy()
env["ZIG_GLOBAL_CACHE_DIR"] = str(root / "auth-tools/cache")


def run(command):
    print("command:", " ".join(command), flush=True)
    subprocess.run(command, env=env, check=True)


# The candidate object precedes the original archive, replacing only the
# disabled secure-memory implementation. This is a measurement, never shipped.
obj = root / f"enabled-mem-sec-{args.target}.o"
run(compiler + ["-I" + str(provider / "include"), "-I" + str(source / "include"), "-DOPENSSL_BUILDING_OPENSSL", "-DNDEBUG", "-c", str(source / "crypto/mem_sec.c"), "-o", str(obj)])
for mode, objects in [("baseline", []), ("candidate", [str(obj)])]:
    binary = root / f"heap-probe-{args.target}-{mode}"
    run(compiler + ["-static", "-Wl,--gc-sections", "-s", "-Wall", "-Wextra", "-Werror", "-I" + str(provider / "include"), str(probe)] + objects + [str(provider / "lib/libcrypto.a"), "-lpthread", "-ldl", "-o", str(binary)])
    run(["file", str(binary)])
    print(f"size mode={mode} target={args.target} bytes={binary.stat().st_size}", flush=True)
