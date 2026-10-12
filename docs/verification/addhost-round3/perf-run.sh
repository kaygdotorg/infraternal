#!/bin/sh
# Runs serial provisioning measurements on the pinned VM while its caller holds the shared lock (#169).
set -eu
cd /root/infraternal-bench/addhost-round3
export BREAKIT2_SCRATCH=/root/infraternal-bench/addhost-round3/scratch
export INFRATERNAL_TEST_RTT=0
measure() {
    python3 docs/verification/addhost-breakit2/measure.py \
        --fresh --container-name addhost-round3-target --controller-ip 172.17.0.1 \
        --test-binary ./run-server-test --payload ./infraternal "$@"
}
for sample in 1 2 3 4 5 6 7 8 9 10; do
    measure --ssh-server netbird --netbird-binary ./netbird-ssh-fixture > "netbird-local-$sample.log" 2>&1
done
for sample in 1 2 3 4 5; do
    measure --ssh-server netbird --netbird-binary ./netbird-ssh-fixture --rtt 150 > "netbird-delay-$sample.log" 2>&1
done
BREAKIT2_RETRY=1 measure --ssh-server netbird --netbird-binary ./netbird-ssh-fixture > retry-local.log 2>&1
BREAKIT2_RETRY=1 measure --ssh-server netbird --netbird-binary ./netbird-ssh-fixture --rtt 150 > retry-delay.log 2>&1
measure --ssh-server netbird --netbird-binary ./netbird-ssh-fixture --case foreign-base --expect-failure > foreign-refusal.log 2>&1
./run-server-test destination_reservation_admission_at_1600_pending_hosts --ignored --nocapture > admission.log 2>&1
./run-server-test review_cancelled_committed_invitation_survives_temporary_writer_contention --nocapture > writer-retirement.log 2>&1
./run-server-test cancelled_invitation_retires_after_sqlite_busy_timeout --nocapture > sqlite-retirement.log 2>&1
sudo -n docker rm -f addhost-round3-target > fixture-cleanup.log 2>&1
printf '21 pass, 0 fail\n'
