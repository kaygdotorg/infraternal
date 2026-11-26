#!/bin/bash
# Exact repeat of J1234's r2 conditions at 1,000 peers (default idle windows, 1/10/100 senders):
# AQM as shipped without counters, with counters, and off (#260, J1241).
# Run as: perf-run --root -- j1234-recheck2.sh OUTDIR
set -u
D=${1:?out dir}
H=$(dirname "$(readlink -f "$0")")/j34
run() { # tag mode
  tag=$1 mode=$2
  extra=()
  case $mode in
    off) extra=(--hub-env GOTATUN_AQM=off) ;;
    stats) extra=(--hub-env GOTATUN_AQM_STATS_MS=500 --hub-env "GOTATUN_AQM_STATS_PATH=$D/$tag.aqm") ;;
    plain) ;;
  esac
  python3 "$H/hub/research/many-peer-hub/harness/run.py" --hub "$H/hubbin/hubtest" --sim "$H/hubbin/peersim" \
    --out "$D/$tag" --peers 1000 --tag "$tag" --mode spread --ks 1,10,100 "${extra[@]}" 2>&1 | tail -3 >> "$D/run.log"
  echo "RAN $tag" >> "$D/run.log"
}
mkdir -p "$D"
run plain-n1000 plain
run stats-n1000 stats
run off-n1000 off
echo MATRIX-DONE >> "$D/run.log"
