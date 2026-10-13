# Manage the bounded setup lease while the shared guard protects journal mutation.
# A bounded lease holds the transaction directory across SSH command gaps. Its
# public PID/start-time receipt is not authority by itself: retirement also
# requires the process's inherited descriptor to refer to this exact directory.
start_setup_lease() {
    exec 7< "$stage"
    flock -n 7 || exit 73
    (exec 9<&-; exec sleep 180) >/dev/null 2>&1 &
    lease_pid=$!
    lease_birth=$(awk '{print $22}' "/proc/$lease_pid/stat")
    printf '%s %s\n' "$lease_pid" "$lease_birth" > "$stage/lease"
    # Fork publication can precede the child's descriptor teardown. A following
    # setup step must not collide with our own inherited parent guard. Keep the
    # recovery receipt first, then bound the readiness checks and require the
    # exact transaction descriptor before releasing our copy of that lock.
    # The child closes it within microseconds; a short sleep keeps this off
    # the add-host critical path (#189) under about the same two-second bound.
    lease_checks=0
    while [ -L "/proc/$lease_pid/fd/9" ]; do
        lease_checks=$((lease_checks + 1))
        [ "$lease_checks" -le 1000 ] || exit 73
        sleep 0.001
    done
    [ "$(readlink "/proc/$lease_pid/fd/7" 2>/dev/null || :)" = "$stage" ] || exit 73
    exec 7<&-
}
retire_setup_lease() {
    if [ -e "$stage/lease" ] || [ -L "$stage/lease" ]; then
        [ -f "$stage/lease" ] && [ ! -L "$stage/lease" ] && [ -O "$stage/lease" ] && [ "$(stat -c '%a:%h' "$stage/lease")" = 600:1 ] || exit 71
        [ "$(stat -c '%s' "$stage/lease")" -le 64 ] || exit 71
        read -r lease_pid lease_birth extra < "$stage/lease"
        [ -z "$extra" ] || exit 71
        case "$lease_pid:$lease_birth" in *[!0-9:]*|:*|*:) exit 71;; esac
        if [ -r "/proc/$lease_pid/stat" ] && [ "$(awk '{print $22}' "/proc/$lease_pid/stat")" = "$lease_birth" ]; then
            [ "$(readlink "/proc/$lease_pid/fd/7" 2>/dev/null || :)" = "$stage" ] || exit 73
            kill "$lease_pid" || exit 73
        fi
    fi
    # Also detect a holder whose creation was interrupted before PID journaling.
    # Such an unrecorded lease expires at the same bounded setup deadline.
    if [ -d "$stage" ] && [ ! -L "$stage" ]; then
        exec 7< "$stage"
        flock -w 2 7 || exit 73
    fi
}
