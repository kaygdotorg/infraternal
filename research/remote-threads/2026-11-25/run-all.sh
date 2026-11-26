#!/bin/bash
# J1246: the fixture server on the shipped runtime (production) and on a current-thread runtime
# (J1220's shape), alternating, at 50 x 8 and 200 x 2. One perf-run lock slot for all of it.
cd $HOME/j1246
for round in 1 2; do
  for rt in production current; do
    INFRATERNAL_MANY_RUNTIME=$rt bash matrix.sh ${rt}$round "50:8 200:2"
  done
done
echo ALL_DONE
