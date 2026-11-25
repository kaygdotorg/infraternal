#!/bin/bash
# J1227 (#260) macro driver on hd01: run one hold's series (series.sh takes the locks itself and
# stages the binaries inside the hold). Queue the next hold only after others waiting have had a turn.
#   macro.sh <hold> <row>...
set -uo pipefail
J=$HOME/.cache/codex-scratch/j1227
hold=$1; shift
cd $J/kit-macro && DIRS="f r" CFS="cubic:1 cubic:8" ./series.sh "$hold" "$@"
