#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Run the Linux fault matrix with private network, mount and runtime namespaces.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../.." && pwd)
cd "$repo_root"

exec unshare -Urnm bash -c '
  set -euo pipefail
  mount -t tmpfs -o size=64m,nosuid,nodev,mode=0755 tmpfs /run
  mkdir -m 0700 /run/infraternal
  exec python3 "$@"
' j526-linux-matrix "$script_dir/linux_matrix.py" "$@"
