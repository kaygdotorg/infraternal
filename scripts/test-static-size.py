#!/usr/bin/env python3
"""Exercise shipping artifacts at the exact static size ceiling and one byte over (#198)."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", type=Path, default=Path("scripts/verify.d/rust.sh"))
    args = parser.parse_args()
    source = Path(os.environ["CARGO_TARGET_DIR"]).resolve()
    scratch = source / "static-size-fixtures"
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="size-boundary-", dir=scratch) as directory:
        fixture = Path(directory)
        environment = dict(os.environ, CARGO_TARGET_DIR=str(fixture))
        def check(target):
            return subprocess.run(["bash", "-c",
                'source "$1"; rust_check_static_binary "$2"', "static-size-test",
                str(args.gate.resolve()), target], env=environment, capture_output=True, text=True)
        for target in ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"):
            binary = fixture / target / "release/infraternal"
            binary.parent.mkdir(parents=True)
            shutil.copy2(source / target / "release/infraternal", binary)
            result = check(target)
            assert result.returncode == 0, f"shipping {target} rejected:\n{result.stdout}{result.stderr}"
            cap = int(re.search(r"max (\d+)", result.stdout)[1])
            with binary.open("ab") as image:
                image.truncate(cap)
            result = check(target)
            assert result.returncode == 0, result.stdout + result.stderr
            with binary.open("ab") as image:
                image.write(b"\0")
            result = check(target)
            assert result.returncode != 0 and "exceeds" in result.stderr, result.stdout + result.stderr
            # Override only the reported byte count for the shrink case; keep
            # the ELF fixture intact while exercising the downward-ratchet rule.
            result = subprocess.run(["bash", "-c",
                'source "$1"; test_size=$3; stat() { printf "%s\\n" "$test_size"; }; rust_check_static_binary "$2"',
                "static-size-shrink-test", str(args.gate.resolve()), target, str(cap - 1)],
                env=environment, capture_output=True, text=True)
            assert result.returncode != 0 and "ratchet" in result.stderr, result.stdout + result.stderr
            print(f"{target}: exact {cap}-byte cap PASS; {cap + 1} bytes rejected PASS; smaller artifact requires ratchet PASS")
        target = "unsupported-unknown-linux-musl"
        binary = fixture / target / "release/infraternal"
        binary.parent.mkdir(parents=True)
        shutil.copy2(source / "x86_64-unknown-linux-musl/release/infraternal", binary)
        result = check(target)
        assert result.returncode != 0 and "no static binary size" in result.stderr
        print("unsupported target: rejected PASS")


if __name__ == "__main__":
    main()
