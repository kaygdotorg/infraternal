#!/bin/bash
# J1204 (#260) macro driver on hd01: for each hold, wait until no other job's hold is on the two
# VMs, stage the binaries (never during a hold), then run the series (it takes the locks itself).
#   macro.sh <hold> <row>...
set -uo pipefail
J=$HOME/.cache/codex-scratch/j1204
hold=$1; shift
until $J/stage-macro.sh > $J/stage-macro.log 2>&1; do sleep 60; done
cat $J/stage-macro.log
cd $J/kit-macro && DIRS="f r" CFS="cubic:1 cubic:8" ./series.sh "$hold" "$@"
