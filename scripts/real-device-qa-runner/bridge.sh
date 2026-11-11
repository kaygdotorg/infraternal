#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Runs INSIDE `run.sh session`, so the simulator lock is held for the whole time. It executes queued runs one after the
# other and so lets an operator work interactively without losing the lock between steps:
#   bridge dir:  ~/Developer/infraternal-sim/bridge
#   submit:      write in.<n> (line 1 = run name, the rest = the ACTIONS script); read out.<n>, then out.<n>.done appears
#   stop:        create the file `stop` (or wait: the bridge ends after 3300 s so the lock is never held for long)
set -uo pipefail
cd "$(dirname "$0")"
B="$HOME/Developer/infraternal-sim/bridge"
mkdir -p "$B"
end=$((SECONDS + 3300))
while [ "$SECONDS" -lt "$end" ] && [ ! -e "$B/stop" ]; do
  for f in "$B"/in.*; do
    [ -e "$f" ] || continue
    n="${f##*.}"
    name="$(head -1 "$f")"
    actions="$(tail -n +2 "$f")"
    rm -f "$f"
    printf 'started %s\n' "$(date -u +%T)" > "$B/out.$n"
    QA_APPEARANCE=light ./run.sh run "$name" "$actions" >> "$B/out.$n" 2>&1
    printf 'finished %s\n' "$(date -u +%T)" >> "$B/out.$n"
    touch "$B/out.$n.done"
  done
  sleep 2
done
