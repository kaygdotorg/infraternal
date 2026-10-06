#!/usr/bin/env bash
# Locate the LLD shipped with the active pinned Rust toolchain and select its GNU linker personality.
set -euo pipefail

sysroot="$(rustc --print sysroot)"
host="$(rustc -vV | sed -n 's/^host: //p')"
rust_lld="${sysroot}/lib/rustlib/${host}/bin/rust-lld"

if [[ ! -x "$rust_lld" ]]; then
    printf 'rust-lld not found in active toolchain: %s\n' "$rust_lld" >&2
    exit 1
fi

exec -a ld.lld "$rust_lld" "$@"
