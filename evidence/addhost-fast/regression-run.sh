#!/bin/sh
# Exercise real SSH/rootless/root setup and rollback on freshly owned VM targets (#190/#169).
set -eu
cd /root/infraternal-bench/addhost-fast
export BREAKIT2_SCRATCH=/root/infraternal-bench/addhost-fast/scratch
export INFRATERNAL_TEST_RTT=0
unset BREAKIT2_FDPASS_CANDIDATE BREAKIT2_HTTPS_CANDIDATE
mkdir -p regressions
run() {
    name=$1
    shift
    python3 docs/verification/addhost-breakit2/measure.py --fresh \
        --container-name addhost-fast-target --controller-ip 172.17.0.1 \
        --test-binary ./final/controller --payload ./final/infraternal \
        --rtt 150 "$@" > "regressions/$name.log" 2>&1
}
for shell in bash zsh fish sh; do run "shell-$shell" --shell "$shell"; done
run root --mode root --user root
for case in tiny-disk readonly-home foreign-base no-manager; do
    run "$case" --case "$case" --expect-failure
done
run noexec-tmp --case noexec-tmp
run linger-off --case linger-off
BREAKIT2_RETRY=1 run retry
BREAKIT2_CANCEL_UPLOAD=1 run cancel-upload
docker rm -f addhost-fast-target > regressions/fixture-cleanup.log
