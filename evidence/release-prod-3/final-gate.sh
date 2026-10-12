#!/usr/bin/env bash
# Run the complete branch-head gate and separate TS dispatch when static size stops it.
set -uo pipefail
umask 022
export CARGO_TARGET_DIR=/home/kayg/.cache/codex-scratch/release-prod-3/target
export INFRATERNAL_TEST_STATE_ROOT=/home/kayg/.cache/codex-scratch/rp3/s
unset TMPDIR
export TRACER_TEST_PORT=4933
export RUST_TEST_THREADS=1
export CARGO_BUILD_JOBS=4
export PATH=/home/kayg/.nix-profile/bin:$CARGO_TARGET_DIR/auth-tools/zig:$PATH
export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_NO_VENDOR=1
export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_LIB_DIR=/home/kayg/.cache/codex-scratch/release-prod-3/target/debug/build/openssl-sys-7d62292d94d91236/out/openssl-build/install/lib
export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_INCLUDE_DIR=/home/kayg/.cache/codex-scratch/release-prod-3/target/debug/build/openssl-sys-7d62292d94d91236/out/openssl-build/install/include
export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_STATIC=1
scripts/verify fast
