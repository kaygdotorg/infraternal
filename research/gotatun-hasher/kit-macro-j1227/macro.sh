#!/bin/bash
# J1227 (#260) macro driver on hd01: for each hold, wait until no other job's hold is on the two
# VMs, stage the binaries (never during a hold), then run the series (it takes the locks itself).
#   macro.sh <hold> <row>...
set -uo pipefail
J=$HOME/.cache/codex-scratch/j1227
hold=$1; shift
cd $J/kit-macro && DIRS="f r" CFS="cubic:1 cubic:8" ./series.sh "$hold" "$@"
