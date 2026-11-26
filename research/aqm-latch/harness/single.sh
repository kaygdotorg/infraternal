#!/bin/bash
# Single-flow check (#260, J1241): is the unpaced single flow after an overload slower than on a fresh
# engine, and what does drop signalling cost it? Run as: perf-run --root -- single.sh DIR
set -u
D=${1:?out dir}
H=$(dirname "$(readlink -f "$0")")
run() { # tag, extra args...
  tag=$1; shift
  python3 "$H/run.py" --hub "$H/bin/gotatun" --iperf "$H/bin/iperf3" --wg "$H/bin/wg" --out "$D" --tag "$tag" \
    --flows 100 --base-flows 10 --secs 10 --hub-cpus 1 --server-cpus 2 --client-cpus 3 --proto tcp "$@" 2>&1 | tee -a "$D/matrix.log"
}
mkdir -p "$D"
for r in 1 2 3; do
  for aqm in default off; do
    run "fresh-$aqm-r$r" --aqm "$aqm" --flows 1 --phases single
    run "after-$aqm-r$r" --aqm "$aqm" --phases overload,single
  done
done
echo MATRIX-DONE | tee -a "$D/matrix.log"
