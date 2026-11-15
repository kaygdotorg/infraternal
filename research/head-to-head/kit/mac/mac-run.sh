#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Run counterbalanced Mac windows from a fresh checkout (#260, J674). Run as `lume` on the Mac VM:
#
#   PEER=<linux ip> PSSH=<ssh target> bash mac-run.sh <run-id> <engine>...
#
# One window per Williams order of the engines (mac_pool.py orders). The Mac lock is taken per
# window and released between windows so another job can use the Mac. `SMOKE=1` runs one
# window in the given engine order with 5 s cases: functional evidence only. Outputs:
# $KIT_HOME/ev/<run-id>-w<N>/ and a pooled report at $KIT_HOME/ev/<run-id>-report.md.
set -uo pipefail
RUN=$1; shift
here=$(cd "$(dirname "$0")" && pwd)
J=${KIT_HOME:-/Users/Shared/h2h-mac}
mkdir -p "$J/ev"
if [ -n "${SMOKE:-}" ]; then orders=$(echo "$*" | tr ' ' ','); export LAN_SECS=${LAN_SECS:-5}
else orders=$(python3 "$here/mac_pool.py" orders "$@"); fi
i=0; wins=()
for order in $orders; do
  i=$((i+1)); w="$RUN-w$i"
  lockf -k /tmp/mac-bench.lock bash "$here/mac-window.sh" "$w" ${order//,/ } < /dev/null > "$J/ev/$w-outer.log" 2>&1
  wins+=("$J/ev/$w")
  sleep 30   # sleep: gap so another job can take the Mac lock between windows
done
python3 "$here/mac_pool.py" report "${1}" "${wins[@]}" > "$J/ev/$RUN-report.md"
echo "RUN_DONE $RUN ${#wins[@]} windows"
