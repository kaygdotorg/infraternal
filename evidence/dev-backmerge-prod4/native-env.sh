#!/usr/bin/env bash
# Configure this merge's private build/fixture paths and reuse its exact locked GNU OpenSSL archives.
set -euo pipefail
umask 022
export CARGO_TARGET_DIR=/home/kayg/.cache/codex-scratch/dev-backmerge-prod4/target
native_openssl_dir="$CARGO_TARGET_DIR/debug/build/openssl-sys-d2d829c0e4d0d016/out/openssl-build/install"
# A resumed cold run uses Cargo's locked vendored build after this job's cache is removed.
if [[ -d "$native_openssl_dir/lib" ]]; then
    export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_DIR="$native_openssl_dir"
    export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_STATIC=1
    export X86_64_UNKNOWN_LINUX_GNU_OPENSSL_NO_VENDOR=1
fi
export PATH="$CARGO_TARGET_DIR/auth-tools/zig:$PATH"
export INFRATERNAL_TEST_STATE_ROOT=/home/kayg/.cache/codex-scratch/dbp4
export RUST_TEST_THREADS=4
export TRACER_TEST_PORT=4987
mkdir -p "$INFRATERNAL_TEST_STATE_ROOT" target
chmod 700 "$INFRATERNAL_TEST_STATE_ROOT"
