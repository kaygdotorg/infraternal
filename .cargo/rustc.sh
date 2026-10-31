#!/usr/bin/env bash
# Normalize source locations in static artifacts while preserving the pinned compiler and cache [D243], #201.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$root/.cargo/rust-remap-flags.sh"
# Query rustup, rather than PATH's rustc: Cargo uses this file as its compiler.
# The existing RUSTC_WRAPPER remains outside this driver, including sccache.
compiler="$(cd "$root" && rustup which rustc)"
cargo_root="${CARGO_HOME:-$HOME/.cargo}"
target_root="${CARGO_TARGET_DIR:-$root/target}"
rustup_root="${RUSTUP_HOME:-$HOME/.rustup}"
[[ "$cargo_root" = /* ]] || cargo_root="$root/$cargo_root"
[[ "$target_root" = /* ]] || target_root="$root/$target_root"
[[ "$rustup_root" = /* ]] || rustup_root="$root/$rustup_root"
remap_flags=()
infraternal_append_path_remap_flags remap_flags "--remap-path-prefix=" \
    "$root" "$cargo_root" "$target_root" "$rustup_root"

# Static builds supply these flags through Cargo so sccache keys the paths
# before this wrapper runs. Host build tools still receive the mappings here.
if [[ "${INFRATER_CARGO_TARGET_REMAPPINGS:-}" == "1" ]]; then
    requested_target=""
    previous_arg=""
    for argument in "$@"; do
        if [[ "$previous_arg" == "--target" ]]; then
            requested_target="$argument"
            break
        fi
        case "$argument" in
            --target=*)
                requested_target="${argument#--target=}"
                break
                ;;
        esac
        previous_arg="$argument"
    done
    case "$requested_target" in
        x86_64-unknown-linux-musl|aarch64-unknown-linux-musl)
            exec "$compiler" "$@"
            ;;
    esac
fi

exec "$compiler" "$@" "${remap_flags[@]}"
