#!/bin/sh
# Record only fixed setup-step names/status/durations on the disposable target; never arguments or stdin (#190).
set -u
if [ "$#" != 2 ] || [ "$1" != -c ]; then exec /bin/sh "$@"; fi
case "$2" in
    '# INFRATERNAL_TRANSFER_SETUP_V1'*|'# INFRATERNAL_SETUP_STEPS_V1'*) exec /bin/sh "$@";;
    *'--enroll-only'*) step=join;;
    *': > "$stage/activating"'*) step=install;;
    *'enable --now infraternal-agent.service'*) step=start;;
    *'enable-linger'*) step=linger;;
    *'> "$stage/payload"'*) step=upload;;
    *) exec /bin/sh "$@";;
esac
started=$(date +%s%N)
/bin/sh "$@"
status=$?
finished=$(date +%s%N)
printf 'REMOTE_STEP name=%s elapsed_ns=%s status=%s\n' "$step" "$((finished - started))" "$status" >> /run/addhost-fast-step-times
exit "$status"
