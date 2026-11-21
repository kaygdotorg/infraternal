#!/usr/bin/env bash
# The S4 proof's runner inside the microVM (#211 S4); vm.nix starts it at every boot.
#
# Boot 1 runs phase 1 of the proof (`auto_update_failure_matrix`). When that leaves
# the `reboot` release on trial, this script records "phase 2" on the VM's own disk
# and hard-resets the machine with sysrq 'b': no clean shutdown, no global sync, so
# whatever the server had not made durable is really lost. Boot 2 runs phase 2
# (`auto_update_after_reboot`), copies the server's journal out and powers off.
#
# Inputs, from the host through the /share shared folder: `releases/`, `versions`,
# `server-tests`. Outputs: /share/out/{runner,phase1,phase2,journal*}.log and
# /share/out/DONE ("PROOF_DONE rc=<n> phase=<n>"), which the host waits for.
set -u
share=/share
out=$share/out
state=/var/lib/iproof-runner
mkdir -p "$out"
mkdir -p -m 700 "$state"
# The unit's boot-pointer chain, element by element, for the record.
chain() { namei -l /var/lib/infraternal-proof/current/infraternal-x86_64-musl >> "$out/chain-$1.log" 2>&1; sync "$out/chain-$1.log"; }
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >> "$out/runner.log"; sync "$out/runner.log"; }
finish() {
    journalctl -u infraternal-proof.service --no-pager -o short-iso > "$out/journal.log" 2>&1
    printf 'PROOF_DONE rc=%s phase=%s\n' "$1" "$2" > "$out/DONE"
    sync "$out"/*
    systemctl poweroff
    exit 0
}
tests=auth::tests::ca_administration_tests::shipping_cli_tests::deploy_staging::update_staging
phase=$(cat "$state/phase" 2>/dev/null || echo 1)
log "runner start phase=$phase boot=$(cat /proc/sys/kernel/random/boot_id) nproc=$(nproc) mem_kb=$(awk '/MemTotal/{print $2}' /proc/meminfo)"

if [ "$phase" = 1 ]; then
    # A root the harness accepts (staging_root_is_allowed), on the VM's disk so it
    # survives the reset.
    mkdir -p -m 700 /root/infraternal-bench /root/infraternal-bench/j1043 /root/infraternal-bench/j1043/signed
    run=/root/infraternal-bench/j1043/signed/r$(date +%s)
    mkdir -m 700 "$run"
    cp -a "$share/releases" "$run/"
    cp "$share/server-tests" "$run/server-tests"
    chown -R root:root "$run"
    chmod -R go-rwx "$run"
    printf '%s\n' "$run" > "$state/root"
    sync "$state/root"
else
    run=$(cat "$state/root")
fi
export INFRATERNAL_DEPLOY_TEST_ROOT=$run INFRATERNAL_CA_TEST_ROOT=$run/f
export INFRATERNAL_UPDATE_TEST_VERSIONS="$(cat "$share/versions")"
export TRACER_TEST_PORT=4391 RUST_BACKTRACE=0
export TMPDIR=/root/.iproof-tmp
mkdir -p -m 700 "$TMPDIR" "$run/f"
cd "$run"
# The server's journal, live, so a stuck run can be read from the host.
journalctl -f -n 0 -u infraternal-proof.service -o short-iso > "$out/journal-live-$phase.log" 2>&1 &

if [ "$phase" = 1 ]; then
    log "phase 1 start run=$run"
    timeout 2400 ./server-tests --ignored --exact "$tests::auto_update_failure_matrix" \
        --nocapture --test-threads=1 > "$out/phase1.log" 2>&1
    rc=$?
    log "phase 1 rc=$rc"
    if [ "$rc" = 0 ] && grep -q '^UPDATE case=reboot_armed' "$out/phase1.log"; then
        printf '2\n' > "$state/phase"
        sync "$state/phase"
        journalctl -u infraternal-proof.service --no-pager -o short-iso > "$out/journal-boot1.log" 2>&1
        sync "$out"/*
        chain before-reset
        log "hard reset during the reboot release's trial"
        echo b > /proc/sysrq-trigger
        sleep 30
    fi
    finish "$rc" 1
fi

chain after-boot
log "phase 2 start run=$run"
timeout 1200 ./server-tests --ignored --exact "$tests::auto_update_after_reboot" \
    --nocapture --test-threads=1 > "$out/phase2.log" 2>&1
rc=$?
log "phase 2 rc=$rc"
finish "$rc" 2
