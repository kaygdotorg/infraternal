#!/usr/bin/env bash
# J1255: paired repeats of the realistic-peers cell at 4,096, whose datagram counts differed
# between the two rows of the matrix. usage: perf-repeat.sh <outdir>
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
for r in head:r2 base:r2 base:r3 head:r3; do
  one 4096 realistic 150 0 ${r%:*} ${r%:*}-${r#*:}
done
ip netns list
echo ALL_DONE >> $OUT/status.txt
