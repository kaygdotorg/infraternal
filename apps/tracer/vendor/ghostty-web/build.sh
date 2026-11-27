#!/usr/bin/env bash
# Role: rebuild and compare the tracer's pinned Ghostty browser artifacts.
set -euo pipefail

readonly upstream_url="https://github.com/coder/ghostty-web.git"
readonly upstream_commit="835eb2749f640a139693bb64fd67de3c1b50a598"
# The Ghostty core is NOT the submodule upstream records (5714ed07, 2025-12-01). It is
# the signed libghostty-vt release that the native engine uses too: the same source
# and dependency archives, the same pinned SHA-256 values (scripts/libghostty-vt.sha256)
# and the same minisign key as scripts/build-vt, so both engines move together.
readonly vt_version="1.0.2"
readonly minisign_public_key="RWQlAjJC23149WL2sEpT/l0QKy7hMIFhYdQOFy0Z7z7PbneUgvlsnYcV"
# The libghostty-vt features the page needs: key encoding only. Everything else is
# compiled out (about 250 KB of WebAssembly); the page never calls it.
readonly vt_features="-all,+input_encode"
readonly required_bun="1.4.4"
readonly required_zig="0.17.1"
readonly vendor_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd -- "${vendor_dir}/../../../.." && pwd)"

mode="check"
if [[ $# -gt 1 ]]; then
    printf 'usage: %s [--check|--update]\n' "$0" >&2
    exit 2
fi
if [[ $# -eq 1 ]]; then
    case "$1" in
        --check) mode="check" ;;
        --update) mode="update" ;;
        *)
            printf 'usage: %s [--check|--update]\n' "$0" >&2
            exit 2
            ;;
    esac
fi

bun_bin="${BUN:-bun}"
# The development shell (nix develop) exports the pinned Zig as a folder, not on PATH.
zig_bin="${ZIG:-zig}"
if [[ -z "${ZIG:-}" && -n "${INFRATERNAL_ZIG:-}" ]]; then zig_bin="${INFRATERNAL_ZIG}/zig"; fi
if ! command -v "$bun_bin" >/dev/null 2>&1; then
    printf 'required build tool is missing: bun %s\n' "$required_bun" >&2
    exit 1
fi
if ! command -v "$zig_bin" >/dev/null 2>&1; then
    printf 'required build tool is missing: zig %s\n' "$required_zig" >&2
    exit 1
fi
if ! command -v minisign >/dev/null 2>&1; then
    printf 'required build tool is missing: minisign (it verifies the libghostty-vt release)\n' >&2
    exit 1
fi

actual_bun="$("$bun_bin" --version)"
actual_zig="$("$zig_bin" version)"
if [[ "$actual_bun" != "$required_bun" || "$actual_zig" != "$required_zig" ]]; then
    printf 'toolchain mismatch: required Bun %s and Zig %s; found Bun %s and Zig %s\n' \
        "$required_bun" "$required_zig" "$actual_bun" "$actual_zig" >&2
    exit 1
fi

scratch_root="${GHOSTTY_BUILD_SCRATCH_ROOT:-${HOME}/.cache/codex-scratch/fix-cell-metrics/ghostty-builds}"
mkdir -p "$scratch_root"
build_dir="$(mktemp -d "${scratch_root}/source.XXXXXX")"
trap 'rm -rf "$build_dir"' EXIT

source_dir="${build_dir}/ghostty-web"
git -C "$build_dir" init --quiet "$source_dir"
git -C "$source_dir" remote add origin "$upstream_url"
git -C "$source_dir" fetch --quiet --depth=1 origin "$upstream_commit"
git -C "$source_dir" checkout --quiet --detach FETCH_HEAD
if [[ "$(git -C "$source_dir" rev-parse HEAD)" != "$upstream_commit" ]]; then
    printf 'upstream checkout did not resolve to the pinned commit\n' >&2
    exit 1
fi

# TypeScript patches apply to the ghostty-web checkout, in this order.
# This local bridge patch (TypeScript side) sets theme colors directly in the terminal.
git -C "$source_dir" apply "$vendor_dir/local-theme-api.patch"
# Apply font geometry after the theme renderer changes so both fixes build together.
git -C "$source_dir" apply "$vendor_dir/cell-metrics.patch"
# Link underlines use the active accent and render only while revealed.
git -C "$source_dir" apply "$vendor_dir/link-underline.patch"
# Dispose global input listeners even when opening failed or the renderer was hidden.
git -C "$source_dir" apply "$vendor_dir/renderer-disposal.patch"
# Control boundaries share one scoped input copy and one set of write effects.
git -C "$source_dir" apply "$vendor_dir/buffered-writes.patch"
# The engine calls the page makes are named ghostty_web_*; last, so the patches above still read as upstream.
git -C "$source_dir" apply "$vendor_dir/web-api-names.patch"
# Align KeyEncoder calls, option/key enums and GhosttyString UTF-8 ABI with libghostty-vt 1.0.2 (#607).
git -C "$source_dir" apply "$vendor_dir/key-encoder-102.patch"

# The core: the signed libghostty-vt release, checked against the same pinned hashes and
# key as scripts/build-vt, then built offline from its own dependency archive.
fetch_release() {
    local name="$1" expected actual
    expected="$(awk -v file="$name" '$2 == file { print $1 }' "$repo_root/scripts/libghostty-vt.sha256")"
    [[ -n "$expected" ]] || { printf 'no pinned checksum for %s\n' "$name" >&2; exit 1; }
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        "https://release.files.ghostty.org/libghostty-vt/${vt_version}/${name}" -o "${build_dir}/${name}"
    actual="$(sha256sum "${build_dir}/${name}")"
    [[ "${actual%% *}" == "$expected" ]] || { printf '%s does not match its pinned SHA-256\n' "$name" >&2; exit 1; }
}
core_source="libghostty-vt-${vt_version}.tar.gz"
core_deps="libghostty-vt-${vt_version}-deps.tar.gz"
for asset in "$core_source" "$core_source.minisig" "$core_deps" "$core_deps.minisig"; do fetch_release "$asset"; done
minisign -V -P "$minisign_public_key" -m "${build_dir}/${core_source}" -x "${build_dir}/${core_source}.minisig" >/dev/null
minisign -V -P "$minisign_public_key" -m "${build_dir}/${core_deps}" -x "${build_dir}/${core_deps}.minisig" >/dev/null
core_dir="${source_dir}/ghostty"
deps_dir="${build_dir}/deps"
mkdir -p "$core_dir" "$deps_dir"
tar -xzf "${build_dir}/${core_source}" --strip-components=1 -C "$core_dir"
tar -xzf "${build_dir}/${core_deps}" --strip-components=1 -C "$deps_dir"
# Our engine entry points are one added file plus one line in the library root.
cp -- "$vendor_dir/web-engine.zig" "$core_dir/src/terminal/c/web.zig"
# A repository of its own, so git apply resolves paths from the core's root, not ghostty-web's.
git init --quiet "$core_dir"
git -C "$core_dir" apply "$vendor_dir/wasm-core.patch"

zig_path="$(command -v "$zig_bin")"
export PATH="$(dirname -- "$zig_path"):$PATH"
(
    cd -- "$source_dir"
    "$bun_bin" install --frozen-lockfile
    # The upstream aggregate build invokes its mutable prebuild installer, and its
    # build-wasm.sh patches a git submodule. Run the locked constituent steps and our
    # own offline Zig build instead (--system keeps it to the signed dependency archive).
    "$bun_bin" run clean
    (
        cd -- "$core_dir"
        ZIG_GLOBAL_CACHE_DIR="${build_dir}/zig-global-cache" "$zig_bin" build \
            -Demit-lib-vt=true -Demit-xcframework=false \
            -Dtarget=wasm32-freestanding -Doptimize=ReleaseSmall \
            -Dvt-features="$vt_features" \
            --system "$deps_dir" --cache-dir "${build_dir}/zig-cache"
        cp -- zig-out/bin/ghostty-vt.wasm "${source_dir}/ghostty-vt.wasm"
    )
    "$bun_bin" run build:lib
    "$bun_bin" run build:wasm-copy
)

(
    cd -- "$source_dir"
    sha256sum dist/ghostty-web.js dist/ghostty-vt.wasm dist/index.d.ts
) >"${build_dir}/SHA256SUMS"
if [[ "$mode" == "update" ]]; then
    cp -- "$source_dir/dist/ghostty-web.js" "$vendor_dir/dist/ghostty-web.js"
    cp -- "$source_dir/dist/ghostty-vt.wasm" "$vendor_dir/dist/ghostty-vt.wasm"
    cp -- "$source_dir/dist/index.d.ts" "$vendor_dir/dist/index.d.ts"
    cp -- "${build_dir}/SHA256SUMS" "$vendor_dir/SHA256SUMS"
else
    if ! cmp -s "${build_dir}/SHA256SUMS" "${vendor_dir}/SHA256SUMS"; then
        printf 'rebuilt artifacts do not match the checked-in SHA256SUMS\n' >&2
        diff -u "${vendor_dir}/SHA256SUMS" "${build_dir}/SHA256SUMS" || true
        exit 1
    fi
    for artifact in ghostty-web.js ghostty-vt.wasm index.d.ts; do
        if ! cmp -s "${source_dir}/dist/${artifact}" "${vendor_dir}/dist/${artifact}"; then
            printf 'rebuilt dist/%s differs from the checked-in artifact\n' "$artifact" >&2
            exit 1
        fi
    done
fi

action="reproduced"
if [[ "$mode" == "update" ]]; then action="updated"; fi
printf '%s ghostty-web %s with libghostty-vt %s (Bun %s, Zig %s)\n' \
    "$action" \
    "${upstream_commit:0:7}" "$vt_version" "$actual_bun" "$actual_zig"
