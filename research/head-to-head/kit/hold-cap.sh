#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# hold-cap.sh CAP -- COMMAND [ARG...]
#
# Runs COMMAND (one measured hold) for at most CAP (`90`, `90s`, `17m` or `1h`) and guarantees
# that nothing of the hold is still running when this script returns. Put it INSIDE perf-run, as
# the measured command, so the stop happens before perf-run releases the lock (#260, J676).
#
# Why: a plain `timeout` signals only its direct child. The case, its engines and its load
# generators kept running as root for up to 20 minutes after the cap and could overlap the next
# job's hold on the shared machine.
#
# How: COMMAND starts in its own session (`setsid`), so its process group id is its pid and every
# descendant shares that session. A stop sends TERM to the whole group, waits up to
# H2H_CAP_GRACE_S seconds (default 30), then sends KILL to the group and to any session member
# that left the group. Processes are found by group and session id, never by name. If something
# is still alive after that, the script says so and exits 125.
#
# Exit status: COMMAND's own status when it finishes in time; 124 when the cap stopped it; 143
# when this script was told to stop; 125 when processes were left running (a leak is a failure
# even after a clean exit); 2 for a bad call.
set -uo pipefail

usage() { echo 'usage: hold-cap.sh CAP -- COMMAND [ARG...]' >&2; exit 2; }
(($# >= 3)) && [[ $2 == -- ]] || usage
cap=$1
shift 2
[[ $cap =~ ^([1-9][0-9]*)([smh]?)$ ]] || usage
case ${BASH_REMATCH[2]} in
    m) seconds=$((BASH_REMATCH[1] * 60)) ;;
    h) seconds=$((BASH_REMATCH[1] * 3600)) ;;
    *) seconds=${BASH_REMATCH[1]} ;;
esac
grace=${H2H_CAP_GRACE_S:-30}

# Pids of the hold's live processes: its process group and its session. Zombies are not alive.
members() {
    ps -eo pid=,pgid=,sid=,stat= | awk -v g="$1" '($2 == g || $3 == g) && $4 !~ /^Z/ {print $1}'
}

# Stop everything of the hold; sets `left` to what could not be stopped.
stop_hold() {
    local pid=$1 waited=0 member
    kill -TERM -- "-$pid" 2>/dev/null || true
    while [[ -n $(members "$pid") ]] && ((waited < grace * 5)); do
        sleep 0.2  # sleep: give the engines their grace period to exit on TERM
        waited=$((waited + 1))
    done
    if [[ -n $(members "$pid") ]]; then
        kill -KILL -- "-$pid" 2>/dev/null || true
        for member in $(members "$pid"); do kill -KILL "$member" 2>/dev/null || true; done
        sleep 1  # sleep: let the kernel finish tearing the killed processes down
    fi
    wait "$pid" 2>/dev/null || true
    left=$(members "$pid" | paste -sd, -)
}

signalled=0
trap 'signalled=143' TERM INT HUP

setsid "$@" &
hold=$!
# setsid makes the child its own session leader a moment after the fork: wait for it, or a stop
# that arrives right away would signal a group that does not exist yet.
for _ in $(seq 50); do
    [[ $(ps -o sid= -p "$hold" 2>/dev/null | tr -d ' ') == "$hold" ]] && break
    sleep 0.1  # sleep: the child becomes a session leader right after the fork
done
sleep "$seconds" &
timer=$!

done_pid=
wait -n -p done_pid "$hold" "$timer"
status=$?
kill "$timer" 2>/dev/null || true
wait "$timer" 2>/dev/null || true

left=
if ((signalled != 0)); then
    echo "hold-cap: told to stop; stopping the hold's process group $hold" >&2
    stop_hold "$hold"
    status=$signalled
elif [[ $done_pid == "$timer" ]]; then
    echo "hold-cap: cap $cap reached; stopping the hold's process group $hold" >&2
    stop_hold "$hold"
    status=124
else
    # The hold ended by itself. Anything it left behind is a leak and must not run on unlocked.
    leftover=$(members "$hold" | paste -sd, -)
    if [[ -n $leftover ]]; then
        echo "hold-cap: the hold exited with processes left running ($leftover); stopping them" >&2
        stop_hold "$hold"
        status=125
    fi
fi
if [[ -n $left ]]; then
    echo "hold-cap: processes survived the stop: $left" >&2
    exit 125
fi
exit "$status"
