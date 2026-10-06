#!/usr/bin/env bash
# Archive cross-compiled C objects without a host-specific binutils cross prefix.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
exec "$root/target/auth-tools/zig/zig" ar "$@"
