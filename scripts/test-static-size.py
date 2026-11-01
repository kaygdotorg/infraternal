#!/usr/bin/env python3
"""Check report-only size deltas and reject defective shipping artifacts (D243, #284)."""
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
        def check(target, overrides=""):
            """Run the real artifact checker, optionally replacing one inspection tool."""
            return subprocess.run(["bash", "-c",
                'source "$1"; eval "$3"; rust_check_static_binary "$2"', "static-size-test",
                str(args.gate.resolve()), target, overrides], env=environment, capture_output=True, text=True)
        for target in ("x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"):
            binary = fixture / target / "release/infraternal"
            binary.parent.mkdir(parents=True)
            shutil.copy2(source / target / "release/infraternal", binary)
            result = check(target)
            assert result.returncode == 0, f"shipping {target} rejected:\n{result.stdout}{result.stderr}"
            baseline_match = re.search(r"baseline (\d+);", result.stdout)
            assert baseline_match, result.stdout + result.stderr
            baseline = int(baseline_match[1])
            original_size = binary.stat().st_size
            size = original_size + 102400
            with binary.open("ab") as image:
                image.truncate(size)
            result = check(target)
            assert result.returncode == 0, result.stdout + result.stderr
            assert f"size: {size} bytes; baseline {baseline}; delta {size - baseline:+d} bytes" in result.stdout
            assert "report only, D243 amended 2026-11-01" in result.stdout
            # Preserve the ELF while testing exact and negative reported deltas.
            for size in (baseline, baseline - 1):
                result = check(target, f'stat() {{ printf "%s\\n" {size}; }}')
                assert result.returncode == 0, result.stdout + result.stderr
                assert f"delta {size - baseline:+d} bytes" in result.stdout
            result = check(target, 'readelf() { if [[ "$1" == -l ]]; then echo INTERP; else command readelf "$@"; fi; }')
            assert result.returncode != 0 and "unexpected PT_INTERP" in result.stderr
            result = check(target, 'readelf() { return 1; }')
            assert result.returncode != 0, "failed ELF inspection accepted"
            binary.chmod(0o644)
            result = check(target)
            assert result.returncode != 0 and "expected executable not found" in result.stderr
            binary.unlink()
            result = check(target)
            assert result.returncode != 0 and "expected executable not found" in result.stderr
            foreign = "aarch64-unknown-linux-musl" if target.startswith("x86_64") else "x86_64-unknown-linux-musl"
            shutil.copy2(source / foreign / "release/infraternal", binary)
            result = check(target)
            assert result.returncode != 0 and "wrong ELF target" in result.stderr
            shutil.copy2("/bin/true", binary)
            result = check(target)
            assert result.returncode != 0 and "static executable" in result.stderr
            print(f"{target}: +102400 bytes accepted with delta; zero/negative deltas reported; missing/wrong/dynamic/PT_INTERP/inspection defects rejected PASS")
        target = "unsupported-unknown-linux-musl"
        binary = fixture / target / "release/infraternal"
        binary.parent.mkdir(parents=True)
        shutil.copy2(source / "x86_64-unknown-linux-musl/release/infraternal", binary)
        result = check(target)
        assert result.returncode != 0 and "no static binary size" in result.stderr
        print("unsupported target: rejected PASS")


if __name__ == "__main__":
    main()
