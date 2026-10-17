#!/usr/bin/env bash
# Role: rebuild and compare the tracer's pinned Ghostty browser artifacts.
set -euo pipefail

readonly upstream_url="https://github.com/coder/ghostty-web.git"
readonly upstream_commit="5f0c6b7720e5ac241208afe7a2335981ded1b486"
readonly ghostty_commit="5714ed07a1012573261b7b7e3ed2add9c1504496"
readonly required_bun="1.4.2"
readonly required_zig="0.15.2"
readonly vendor_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

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
zig_bin="${ZIG:-zig}"
if ! command -v "$bun_bin" >/dev/null 2>&1; then
    printf 'required build tool is missing: bun %s\n' "$required_bun" >&2
    exit 1
fi
if ! command -v "$zig_bin" >/dev/null 2>&1; then
    printf 'required build tool is missing: zig %s\n' "$required_zig" >&2
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

# This local bridge patch sets theme colors directly in the existing terminal state.
git -C "$source_dir" apply "$vendor_dir/local-theme-api.patch"
# Apply font geometry after the theme renderer changes so both fixes build together.
git -C "$source_dir" apply "$vendor_dir/cell-metrics.patch"
# Link underlines use the active accent and render only while revealed.
git -C "$source_dir" apply "$vendor_dir/link-underline.patch"

git -C "$source_dir" submodule update --quiet --init --recursive --depth=1
if [[ "$(git -C "$source_dir/ghostty" rev-parse HEAD)" != "$ghostty_commit" ]]; then
    printf 'Ghostty submodule does not match its pinned commit\n' >&2
    exit 1
fi

zig_path="$(command -v "$zig_bin")"
export PATH="$(dirname -- "$zig_path"):$PATH"
(
    cd -- "$source_dir"
    "$bun_bin" install --frozen-lockfile
    # The upstream aggregate build invokes its mutable prebuild installer. Run
    # its locked constituent build steps so this exact source lock drives Vite.
    "$bun_bin" run clean
    "$bun_bin" run build:wasm
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
printf '%s ghostty-web %s with Ghostty %s (Bun %s, Zig %s)\n' \
    "$action" \
    "${upstream_commit:0:7}" "${ghostty_commit:0:7}" "$actual_bun" "$actual_zig"
