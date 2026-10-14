#!/bin/sh
# Record fixed target boundaries in a disposable fixture; input and output pass unchanged (#189).
set -u
# Public fixture programs are ASCII; C locale makes the argument length bytes.
export LC_ALL=C
if [ "$#" != 2 ] || [ "$1" != -c ]; then exec /bin/sh "$@"; fi
case "$2" in
    *'CHECK ready'*) step=check_channel;;
    *'setup_step upload'*) step=setup_program;;
    *'INFRATERNAL_CHECK_V1'*) step=readonly_admission;;
    *'CAPS %s'*) step=transfer_probe;;
    *'TRANSFER %s'*) step=payload_verify;;
    *'__ssh-session'*) step=shim_exec;;
    *'--enroll-only'*) step=join;;
    *) exec /bin/sh "$@";;
esac
program_bytes=${#2}
mark() {
    printf '{"source":"target","step":"%s","state":"%s","epoch_ns":"%s","program_bytes":%s}\n' "$step" "$1" "$(date +%s%N)" "$program_bytes" >> /run/addhost-fast-step-times
}
mark start
/bin/sh "$@"
status=$?
mark end
exit "$status"
