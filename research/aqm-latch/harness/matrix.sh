#!/bin/bash
# One perf-run holds the lock for the whole matrix (#260, J1241). Run as: perf-run --root -- matrix.sh DIR
set -u
D=${1:?out dir}
H=$(dirname "$(readlink -f "$0")")
run() { # tag, extra args...
  tag=$1; shift
  python3 "$H/run.py" --hub "$H/bin/gotatun" --iperf "$H/bin/iperf3" --wg "$H/bin/wg" --out "$D" --tag "$tag" \
    --flows 100 --base-flows 10 --secs 10 --hub-cpus 1 --server-cpus 2 --client-cpus 3 "$@" 2>&1 | tee -a "$D/matrix.log"
}
mkdir -p "$D"
run tcp-default  --proto tcp --aqm default --aqm-stats-ms 500
run tcp-off      --proto tcp --aqm off
run tcp-ecn1     --proto tcp --aqm default --tcp-ecn 1 --aqm-stats-ms 500
run udp-default  --proto udp --aqm default --udp-rate 30 --aqm-stats-ms 500
run udp-off      --proto udp --aqm off --udp-rate 30
echo MATRIX-DONE | tee -a "$D/matrix.log"
