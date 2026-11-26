#!/usr/bin/env bash
# J1255 before/after idle matrix on the perf VM, all in one `perf-run --root` hold (J1253's
# harness, unchanged). usage: perf-all.sh <outdir>
# Connected-silent first, paired and in both orders; then every other J1253 scenario once.
J=/home/claude/j1255
OUT=$1
L=$J/lib
cd $J/research/mesh-idle-wakeups/harness || exit 1
one() { # one <peers> <scenario> <secs> <candidates> <bin> <tag>
  timeout $(($3 + 600)) python3 idle.py \
    --hub "$L/ld-linux-x86-64.so.2 --library-path $L $J/bin/hub-$5" \
    --sim "$L/ld-linux-x86-64.so.2 --library-path $L $J/bin/peersim" \
    --out $OUT --peers $1 --scenario $2 --secs $3 --tag $6 --candidates $4 \
    > $OUT/log-$2-$1-$6.txt 2>&1
  echo "$(date -u +%T) $1 $2 $6 exit=$?" >> $OUT/status.txt
}
for n in 4096 1000; do
  for r in base:a head:a head:b base:b; do
    one $n connected 200 0 ${r%:*} ${r%:*}-${r#*:}
  done
done
for n in 4096 1000; do
  for spec in realistic:150:0 afterload:90:0 keepalive:90:0 offline:180:0 offline:180:2; do
    IFS=: read -r scen secs cand <<<"$spec"
    for bin in base head; do
      tag=$bin; [ $cand != 0 ] && tag=$bin-c$cand
      one $n $scen $secs $cand $bin $tag
    done
  done
done
ip netns list
echo ALL_DONE >> $OUT/status.txt
