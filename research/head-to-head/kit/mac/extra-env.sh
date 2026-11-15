#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Turn a space-separated `NAME=value ...` list (PIN_ENV / CAND_ENV of mac-window.sh) into shell-safe
# `NAME=<quoted value>` lines for the harness's root-only env file (#260, J733).
#
#   extra-env.sh "J614_CREDITS=32 FOO=bar"     prints one line per pair
#
# The lines are sourced by a root shell, so a value must never be able to run code: every value is
# quoted with `printf %q`, and a token that is not `NAME=value` (NAME = a shell identifier) makes
# the script exit 1 with nothing printed. Values cannot contain spaces (the list is split on them).
set -uo pipefail
out=""
for kv in $1; do
  [[ $kv =~ ^[A-Za-z_][A-Za-z0-9_]*= ]] || { echo "bad extra environment entry: $kv" >&2; exit 1; }
  out+=$(printf '%s=%q' "${kv%%=*}" "${kv#*=}")$'\n'
done
printf '%s' "$out"
