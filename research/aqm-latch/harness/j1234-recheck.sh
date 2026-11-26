#!/bin/bash
# Reruns J1234's own harness at its lossy cells with the engine's AQM counters on, and with AQM off
# (#260, J1241). Run as: perf-run --root -- j1234-recheck.sh OUTDIR
# Beside this script: j34/hubbin/{hubtest,peersim} (J1234's hub-bench.patch on de6f9dce6) and
# j34/hub/research/many-peer-hub/harness/run.py (branch j1234-many-peer-hub).
set -u
D=${1:?out dir}
H=$(dirname "$(readlink -f "$0")")/j34
run() { # tag peers aqm
  tag=$1 n=$2 aqm=$3
  extra=()
  if [ "$aqm" = off ]; then extra+=(--hub-env GOTATUN_AQM=off); else
    extra+=(--hub-env GOTATUN_AQM_STATS_MS=500 --hub-env "GOTATUN_AQM_STATS_PATH=$D/$tag.aqm"); fi
  python3 "$H/hub/research/many-peer-hub/harness/run.py" --hub "$H/hubbin/hubtest" --sim "$H/hubbin/peersim" \
    --out "$D/$tag" --peers "$n" --tag "$tag" --mode spread --ks 1,10 --idle 3 "${extra[@]}" 2>&1 | tail -3 >> "$D/run.log"
  echo "RAN $tag" >> "$D/run.log"
}
mkdir -p "$D"
run ecn-n10 10 ecn
run off-n10 10 off
run ecn-n1000 1000 ecn
run off-n1000 1000 off
echo MATRIX-DONE >> "$D/run.log"
