#!/bin/sh
# Role: one command that measures the App Windows encoder modes on this Mac (#146, J1078, J1115).
#
# It builds the J1078 encode probe and the J1115 encoder-mode probe with this Mac's own Swift
# compiler, runs the sections that decide the encoder mode, and writes one log to attach to #146.
# Nothing is installed, no setting or permission changes, and only the hardware encoder and
# decoder are used (no screen capture). It needs the Xcode command line tools (`swiftc`).
#
# Usage, from anywhere in the repository:
#   research/app-windows/j1115/run-encoder-probes.sh            # about 12 minutes
#   research/app-windows/j1115/run-encoder-probes.sh --quick    # about 3 minutes, fewer sizes
# Keep the Mac on power, awake, and otherwise idle while it runs.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
quick=""
if [ "${1:-}" = "--quick" ]; then quick=1; fi

work=$(mktemp -d "${TMPDIR:-/tmp}/infraternal-encoder-probes.XXXXXX")
# The build folder holds only the two probe binaries; remove it on every exit.
trap 'rm -rf "$work"' EXIT INT TERM
log="$PWD/encoder-probes-$(sysctl -n hw.model)-$(date -u +%Y%m%dT%H%M%SZ).log"

command -v swiftc >/dev/null 2>&1 || { echo "swiftc not found: install the Xcode command line tools (xcode-select --install)" >&2; exit 1; }
echo "building probes in $work"
swiftc -O -swift-version 5 -o "$work/j1078" "$repo/research/app-windows/j1078/encode-probe/main.swift" \
  "$repo/crates/plugins/desktop/native/FramePixels.swift"
swiftc -O -swift-version 5 -o "$work/j1115" "$here/encoder-mode-probe/main.swift"

{
  echo "INFO repo_head=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo unknown) date=$(date -u +%FT%TZ)"
  echo "INFO power=$(pmset -g batt | head -1 | tr -d "'") load=$(sysctl -n vm.loadavg)"
  echo "== J1078 encode probe: encode time against size, and session variants"
  if [ -n "$quick" ]; then QUICK=1 ONLY=size,variant "$work/j1078"; else ONLY=size,variant "$work/j1078"; fi
  echo "== J1078 encode probe: what the viewer sees, and typing after a gap"
  if [ -n "$quick" ]; then QUICK=1 ONLY=quality,sparse "$work/j1078"; else ONLY=quality,sparse "$work/j1078"; fi
  echo "== J1115 encoder-mode probe: modes and caps, typing after a gap, sharp refresh"
  if [ -n "$quick" ]; then QUICK=1 "$work/j1115"; else "$work/j1115"; fi
} 2>&1 | tee "$log"
echo "wrote $log: attach it to #146"
