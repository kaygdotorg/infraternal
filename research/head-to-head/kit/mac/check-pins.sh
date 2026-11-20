#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Refuse a Mac window whose third-party clients are not the pinned versions (#260, J733).
#
#   check-pins.sh <pins.txt> <bin-dir> <engine>...
#
# For `tailscale` and `netbird` it reads the `<name>-src darwin-arm64` line of pins.txt, takes the
# version from the pinned source URL (the `vX.Y.Z` tag) and compares it with what the installed
# client binary in <bin-dir> reports. Any mismatch, missing pin or missing binary prints a
# `PIN_MISMATCH` line and exits 1, so mac-window.sh stops before it measures the wrong client.
# `pin` and `cand` are the product harness (their pin is the checkout's Cargo.lock) and are skipped.
# A reported version may carry a build suffix ("1.104.4-ERR-BuildInfo"); the number must match
# exactly, so 1.104.40 never passes for 1.104.4.
set -uo pipefail
PINS=${1:?pins.txt}; BIN=${2:?bin dir}; shift 2
rc=0

# Version the pins file asks for on darwin-arm64, e.g. "1.104.4"; empty when unpinned.
pinned() { awk -v n="$1-src" '$1 == n && $2 == "darwin-arm64" {print $3}' "$PINS" | sed -nE 's#.*/v([0-9][0-9.]*)\.tar\.gz$#\1#p' | head -1; }
# First version-looking number the installed binary reports.
installed() {
  case $1 in
    tailscale) "$BIN/tailscale" version 2>/dev/null | head -1 ;;
    netbird) "$BIN/netbird" version 2>/dev/null | head -1 ;;
  esac | sed -nE 's/^v?([0-9]+(\.[0-9]+)+).*/\1/p'
}

for e in "$@"; do
  case $e in
    tailscale|netbird)
      want=$(pinned "$e"); have=$(installed "$e")
      if [ -z "$want" ]; then echo "PIN_MISMATCH $e: no darwin-arm64 pin in $PINS"; rc=1
      elif [ "$want" != "$have" ]; then echo "PIN_MISMATCH $e: pinned $want, installed ${have:-none}"; rc=1
      else echo "PIN_OK $e $want"; fi ;;
  esac
done
exit $rc
