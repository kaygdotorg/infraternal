#!/usr/bin/env bash
# Normalize source locations in static artifacts while preserving the pinned compiler and cache [D243], #201.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# Query rustup, rather than PATH's rustc: Cargo uses this file as its compiler.
# The existing RUSTC_WRAPPER remains outside this driver, including sccache.
compiler="$(cd "$root" && rustup which rustc)"
cargo_root="${CARGO_HOME:-$HOME/.cargo}"
target_root="${CARGO_TARGET_DIR:-$root/target}"
[[ "$target_root" = /* ]] || target_root="$root/$target_root"
# Registry checkout names vary by Cargo mirror; normalize each source root too.
registry_maps=()
for registry in "$cargo_root"/registry/src/*; do
    [[ ! -d "$registry" ]] || registry_maps+=("--remap-path-prefix=$registry=/cargo")
done
exec "$compiler" "$@" \
    "--remap-path-prefix=$root=/infraternal" \
    "--remap-path-prefix=$cargo_root=/cargo" \
    "--remap-path-prefix=$target_root=/build" \
    "${registry_maps[@]}"
