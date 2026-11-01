#!/usr/bin/env python3
"""Check static gate dispatch and native runtime probes on both build hosts (#296)."""

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
            assert runs_static == (mode == "final"), result.stdout
            assert "RUN test\n" in result.stdout, result.stdout
            print(f"{host} {mode}: native tests run; static dispatch PASS")

    # Exercise runtime selection without executing a foreign image. The real
    # key-memory dispatcher must call prlimit only for the host's shipping target.
    for host, native in (("x86_64", "x86_64"), ("aarch64", "aarch64")):
        result = subprocess.run(
            ["bash", "-c",
             'source "$1"; CARGO_TARGET_DIR=target; test_host=$2; uname() { echo "$test_host"; }; '
             'scripts/auth-toolchain() { :; }; scripts/static-cargo() { :; }; '
             'python3() { printf "PY %s\\n" "$*"; }; bun() { :; }; '
             'rust_check_static_binary() { :; }; '
             'prlimit() { printf "EXEC %s\\n" "$*"; }; '
             'rust_check_cli_stub() { printf "CLI %s\\n" "$1"; }; '
             'rust_check_cli_group() { printf "CLI %s\\n" "$1"; }; '
             'rust_static_build_check',
             "verify-native-runtime", str(ROOT / "scripts/verify.d/rust.sh"), host],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        binary = f"target/{native}-unknown-linux-musl/release/infraternal"
        assert result.stdout.count(f"CLI {binary}\n") == 2, result.stdout
        assert result.stdout.count("EXEC ") == 1, result.stdout
        assert f"-- {binary} __key-memory-check" in result.stdout, result.stdout
        assert "SKIP key memory:" in result.stdout, result.stdout
        runs_x86_vector = "PY scripts/test-openssl-avx512-gcm.py\n" in result.stdout
        assert runs_x86_vector == (host == "x86_64"), result.stdout
        if host == "aarch64":
            assert "SKIP x86 AES-GCM runtime vector:" in result.stdout, result.stdout
        print(f"{host}: native CLI/key-memory execution; foreign runtime skips PASS")

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
