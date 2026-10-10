#!/usr/bin/env bash
# Archive cross-compiled C objects without a host-specific binutils cross prefix.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
target_root="${CARGO_TARGET_DIR:-$root/target}"
[[ "$target_root" = /* ]] || target_root="$root/$target_root"
exec "$target_root/auth-tools/zig/zig" ar "$@"
