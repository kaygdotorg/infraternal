#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Sets the Mac VM's system appearance (light or dark) for one real-device QA run, as the logged-in user and WITHOUT
# AppleScript to the console session (System Events times out there; J745, #510). The user's global default
# `AppleInterfaceStyle` is what Safari reads for `prefers-color-scheme`: measured on 2026-11-15, after writing it and
# reloading, `matchMedia('(prefers-color-scheme: dark)')` is true in a safaridriver session. Light is the VM's normal
# state, which is "key absent", so `light` deletes the key and leaves the VM as found.
# Usage: real-device-qa-mac-appearance.sh light|dark   (run as lume, under /tmp/mac-bench.lock)
set -euo pipefail
case "${1:-}" in
  dark) defaults write -g AppleInterfaceStyle Dark;;
  light) defaults delete -g AppleInterfaceStyle 2>/dev/null || true;;
  *) echo "usage: $0 light|dark" >&2; exit 2;;
esac
killall -HUP cfprefsd 2>/dev/null || true
sleep 1
echo "appearance: $(defaults read -g AppleInterfaceStyle 2>/dev/null || echo Light)"
