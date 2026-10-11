"""Reproduce optimized release-channel measurements locally with real engines and 50 callers [224,226]."""
from pathlib import Path
import argparse
import os
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--target-dir", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parents[2]
args.output.mkdir(parents=True, exist_ok=True)
env = dict(os.environ, CARGO_TARGET_DIR=str(args.target_dir.resolve()), RUST_TEST_THREADS="1")
env.setdefault("TRACER_TEST_PORT", "4357")
for package, fixture in [
    ("infraternal-server", "bench_bounded_metadata_verification"),
    ("infraternal-server", "bench_latest_fifty_callers"),
    ("infraternal-plugin-release", "channel_reads_at_fifty_concurrent_callers"),
]:
    receipt = args.output / (fixture + ".log")
    command = ["systemd-run", "--user", "--scope", "-p", "CPUWeight=10000",
               "nix", "shell", "nixpkgs#gnumake", "nixpkgs#perl", "-c",
               "cargo", "test", "--release", "-p", package, fixture,
               "--", "--ignored", "--nocapture"]
    with receipt.open("w") as out:
        subprocess.run(command, cwd=root, env=env, stdout=out,
                       stderr=subprocess.STDOUT, check=True)
    result = receipt.read_text()
    if "test result: ok. 1 passed;" not in result:
        raise RuntimeError("measurement fixture did not run: " + fixture)
    print(receipt)
