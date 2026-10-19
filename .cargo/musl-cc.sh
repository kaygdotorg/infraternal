#!/usr/bin/env bash
# Compile vendored C with the same pinned musl sysroot for both Rust targets [7,20].
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
source "$root/.cargo/rust-remap-flags.sh"
cargo_root="${CARGO_HOME:-$HOME/.cargo}"
target_root="${CARGO_TARGET_DIR:-$root/target}"
[[ "$cargo_root" = /* ]] || cargo_root="$root/$cargo_root"
[[ "$target_root" = /* ]] || target_root="$root/$target_root"
case "${TARGET:?Cargo must supply the build target}" in
    x86_64-unknown-linux-musl) zig_target=x86_64-linux-musl ;;
    aarch64-unknown-linux-musl) zig_target=aarch64-linux-musl ;;
    *) printf 'unsupported musl C target\n' >&2; exit 1 ;;
esac
export ZIG_GLOBAL_CACHE_DIR="$target_root/auth-tools/cache"
# cc-rs detects Clang and adds Rust's target spelling, which Zig does not
# accept. Reject mismatches and translate only the target this wrapper owns.
# Only the generated build output is normalized; dependency sources stay intact.
# Upstream records the whole compiler command as a C array, so file-prefix
# mapping alone cannot remove that absolute path from the version string.
for arg in "$@"; do
    if [[ "$arg" == crypto/cversion.c ]]; then
        python3 "$root/scripts/normalize-native-metadata.py" crypto/buildinf.h
    fi
done
args=()
native_remap_flags=()
infraternal_append_path_remap_flags native_remap_flags "-ffile-prefix-map=" "$root" "$cargo_root" "$target_root" ""
for flag in "${native_remap_flags[@]}"; do
    already_present=false
    for argument in "$@"; do
        if [[ "$argument" == "$flag" ]]; then
            already_present=true
            break
        fi
    done
    [[ "$already_present" == true ]] || args+=("$flag")
done
for arg in "$@"; do
    case "$arg" in
        # openssl-src adds this historical musl workaround. Our pinned Zig
        # sysroot supports the provider's locked, dump-excluded key heap;
        # D244/#154 requires it in the shipping static binaries. Remove only
        # this exact argument, leaving OpenSSL sources and all other flags intact.
        -DOPENSSL_NO_SECURE_MEMORY) ;;
        -DENGINESDIR=*|-DMODULESDIR=*)
            directory="${arg#*=}"
            directory="${directory#\"}"
            directory="${directory%\"}"
            # These are build-only installation paths, never deployed assets.
            # Keep them absolute and inert; explicit runtime locations and the
            # system configuration directory remain unchanged. This removes
            # checkout/target paths from native version and directory metadata.
            case "${arg%%=*}:$directory" in
                "-DENGINESDIR:$target_root"/*/install/lib/engines-3)
                    args+=('-DENGINESDIR="/infraternal/build-only/engines-3"') ;;
                "-DMODULESDIR:$target_root"/*/install/lib/ossl-modules)
                    args+=('-DMODULESDIR="/infraternal/build-only/ossl-modules"') ;;
                *) args+=("$arg") ;;
            esac
            ;;
        --target="$TARGET") ;;
        --target=*) printf 'unexpected C target override
' >&2; exit 1 ;;
        *) args+=("$arg") ;;
    esac
done
exec "$target_root/auth-tools/zig/zig" cc -target "$zig_target" "${args[@]}"
