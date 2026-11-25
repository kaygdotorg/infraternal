#!/bin/bash
# J1199: run the remaining holds one after another (hd01 driver). Between holds, stage binaries that
# changed (only while no hold is active anywhere; retried until it is).
set -uo pipefail
J=$HOME/.cache/codex-scratch/j1199
cd $J
for spec in "p1:I.1 T N I.2" "e4:G.1 J K W G.2" "p2:I.1 N T I.2" "e5:G.1 K W J G.2"; do
    hold=${spec%%:*} rows=${spec#*:}
    for i in $(seq 1 120); do scripts/stage.sh > stage-$hold.log 2>&1 && break; sleep 30; done
    echo "[$(date -u +%T)] start $hold: $rows"
    kit/series.sh $hold $rows > series-$hold.log 2>&1
    echo "[$(date -u +%T)] end $hold: $(tail -1 series-$hold.log)"
done
echo CHAIN_DONE
