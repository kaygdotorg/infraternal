#!/usr/bin/env python3
"""Check that only the x86 build VM runs the static release gate (#264)."""

from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def main():
    """Exercise dispatch without compiling or executing foreign artifacts."""
    for host in ("x86_64", "aarch64"):
        for mode in ("final", "iterate"):
            result = subprocess.run(
                [
                    "bash", "-c",
                    'source "$1"; test_host=$2; uname() { echo "$test_host"; }; '
                    'rust_run_gate() { printf "RUN %s\\n" "$1"; }; '
                    'rust_verify_fast "$3"',
                    "verify-architecture", str(ROOT / "scripts/verify.d/rust.sh"),
                    host, mode,
                ],
                cwd=ROOT, capture_output=True, text=True, check=True,
            )
            runs_static = "RUN static builds\n" in result.stdout
            assert runs_static == (host == "x86_64" and mode == "final"), result.stdout
            if host == "aarch64" and mode == "final":
                assert "SKIP (x86)" in result.stdout, result.stdout
            assert "RUN test\n" in result.stdout, result.stdout
            print(f"{host} {mode}: native tests run; static dispatch PASS")

    # Size reporting must not turn an unsuccessful build into a successful row.
    result = subprocess.run(
        ["bash", "-c",
         'source "$1"; scripts/auth-toolchain() { :; }; '
         'python3() { :; }; scripts/static-cargo() { return 37; }; '
         'rust_check_static_binary() { echo UNEXPECTED_ARTIFACT_CHECK; }; '
         'rust_static_build_check',
         "verify-build-failure", str(ROOT / "scripts/verify.d/rust.sh")],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 37, result.stdout + result.stderr
    assert "UNEXPECTED_ARTIFACT_CHECK" not in result.stdout, result.stdout
    print("static build failure: rejected before artifact reporting PASS")


if __name__ == "__main__":
    main()
