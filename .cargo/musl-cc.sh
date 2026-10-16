#!/usr/bin/env bash
# Compile vendored C with the same pinned musl sysroot for both Rust targets [7,20].
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
target_root="${CARGO_TARGET_DIR:-$root/target}"
[[ "$target_root" = /* ]] || target_root="$root/$target_root"
case "${TARGET:?Cargo must supply the build target}" in
    x86_64-unknown-linux-musl) zig_target=x86_64-linux-musl ;;
    aarch64-unknown-linux-musl) zig_target=aarch64-linux-musl ;;
    *) printf 'unsupported musl C target\n' >&2; exit 1 ;;
esac
# Configure probes the compiler before generating the provider's build metadata.
# Canonicalize only its embedded wrapper path; compile options remain unchanged.
if [[ -f util/mkbuildinf.pl && ! -f .infraternal-build-metadata ]]; then
    python3 "$root/scripts/patch-openssl-build-metadata.py" "$(pwd -P)"
fi
export ZIG_GLOBAL_CACHE_DIR="$target_root/auth-tools/cache"
# cc-rs detects Clang and adds Rust's target spelling, which Zig does not
# accept. Reject mismatches and translate only the target this wrapper owns.
args=()
for arg in "$@"; do
    case "$arg" in
        # openssl-src adds this historical musl workaround. Our pinned Zig
        # sysroot supports the provider's locked, dump-excluded key heap;
        # D244/#154 requires it in the shipping static binaries. Remove only
        # this exact argument, leaving OpenSSL sources and all other flags intact.
        -DOPENSSL_NO_SECURE_MEMORY) ;;
        # Static images never install the provider's temporary build tree.
        # Keep its absolute module defaults stable across checkout/target roots;
        # explicit runtime configuration remains the library's responsibility.
        -DENGINESDIR=*) args+=('-DENGINESDIR="/usr/local/lib/infraternal/engines-3"') ;;
        -DMODULESDIR=*) args+=('-DMODULESDIR="/usr/local/lib/infraternal/ossl-modules"') ;;
        --target="$TARGET") ;;
        --target=*) printf 'unexpected C target override
' >&2; exit 1 ;;
        *) args+=("$arg") ;;
    esac
done
exec "$target_root/auth-tools/zig/zig" cc -target "$zig_target" "${args[@]}"
