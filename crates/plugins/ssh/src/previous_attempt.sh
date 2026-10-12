# Classify earlier host provisioning using private ownership receipts; never adopt foreign data.
# This program emits only fixed records and public ids, never process arguments or file contents.
private_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ -O "$1" ] && [ "$(stat -c '%a:%h' "$1")" = 600:1 ] || exit 71
    [ "$(stat -c '%s' "$1")" -le 128 ] || exit 71
}
hex_id() {
    [ "${#1}" = 32 ] || exit 75
    case "$1" in *[!0-9a-f]*) exit 75;; esac
}
not_live() {
    if [ -d "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ]; then
        exec 8< "$base/.bootstrap-lock"
        flock -n 8 || exit 73
        exec 8<&-
    fi
    [ -r /proc/net/unix ] || exit 75
    # Match listeners by canonical path or the exact UUID basename. The latter
    # also covers a listener bound through a relative path or a directory alias.
    # A collision refuses conservatively; it never authorizes removal.
    while read -r num refs protocol flags type state inode path; do
        [ "$flags" = 00010000 ] || continue
        case "$path" in "$base"/*) exit 73;; esac
        for entry in "$base/sessions"/*.sock "$base/sessions/sessions"/*.sock; do
            [ -S "$entry" ] || continue
            case "$path" in "${entry##*/}"|*/"${entry##*/}") exit 73;; esac
        done
    done < /proc/net/unix
    # Inspect executable and open-descriptor links in one native traversal,
    # never argv or environments. Per-link shell subprocesses grow with every
    # other workload's open files. Bound the process table and refuse paths
    # that cannot be represented literally by find's link-pattern predicate.
    case "$base" in *[\*\?\[]*) exit 75;; esac
    set -- /proc/[0-9]*/exe /proc/[0-9]*/fd
    [ "$#" -le 8192 ] || exit 75
    command -v find >/dev/null 2>&1 || exit 75
    if live=$(find "$@" -maxdepth 1 -lname "$base/*" -print -quit 2>/dev/null); then
        :
    else
        # Processes can exit or belong to another uid during traversal. Other
        # failures (missing utility, oversized argv) cannot prove absence.
        [ "$?" = 1 ] || exit 75
    fi
    [ -z "$live" ] || exit 73

}
inspect_previous() {
    setup_guard
    receipt=
    for candidate in "$base".bootstrap-rollback-*; do
        [ -e "$candidate" ] || [ -L "$candidate" ] || continue
        [ -z "$receipt" ] || exit 75
        receipt=$candidate
    done
    if [ -z "$receipt" ] && [ ! -e "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ] && [ ! -e "$base/.bootstrap-acquiring" ] && [ ! -L "$base/.bootstrap-acquiring" ]; then
        printf 'INFRATERNAL_SETUP_CLEAR\n'
        return
    fi
    [ -d "$base" ] && [ ! -L "$base" ] && [ -O "$base" ] && [ "$(stat -c '%a' "$base")" = 700 ] || exit 71
    not_live
    private_file "$base/.bootstrap-owner"
    [ "$(stat -c '%s' "$base/.bootstrap-owner")" = 33 ] || exit 75
    previous_host=$(cat "$base/.bootstrap-owner")
    hex_id "$previous_host"
    identity=$(stat -c '%d:%i' "$base")
    if [ -n "$receipt" ]; then
        private_file "$receipt"
        previous_transaction=${receipt#"$base.bootstrap-rollback-"}
        hex_id "$previous_transaction"
        # Old receipts without an inode binding cannot prove which directory
        # they own. Refuse explicitly rather than reinterpret an older format.
        [ "$(cat "$receipt")" = "$previous_host $previous_transaction fresh $identity" ] || exit 75
    else
        # An interrupted fresh lock is recoverable through its original journal.
        # An upgrade owns previous enrolled data and is never a start-fresh target.
        if [ -e "$base/.bootstrap-acquiring" ] || [ -L "$base/.bootstrap-acquiring" ]; then
            private_file "$base/.bootstrap-acquiring"
            record=$(cat "$base/.bootstrap-acquiring")
            previous_transaction=${record% fresh}
            [ "$record" = "$previous_transaction fresh" ] || exit 75
        else
            [ -d "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ] && [ -O "$base/.bootstrap-lock" ] && [ "$(stat -c '%a' "$base/.bootstrap-lock")" = 700 ] || exit 71
            private_file "$base/.bootstrap-lock/transaction"
            private_file "$base/.bootstrap-lock/kind"
            [ "$(cat "$base/.bootstrap-lock/kind")" = fresh ] || exit 75
            previous_transaction=$(cat "$base/.bootstrap-lock/transaction")
        fi
        hex_id "$previous_transaction"
    fi
    if [ -e "$base/.bootstrap-lock" ] || [ -L "$base/.bootstrap-lock" ]; then
        stage="$base/.bootstrap-lock"
        [ -d "$stage" ] && [ ! -L "$stage" ] && [ -O "$stage" ] && [ "$(stat -c '%a' "$stage")" = 700 ] || exit 71
        # Receipt and any surviving lock must describe the same fresh attempt.
        if [ -e "$stage/transaction" ] || [ -L "$stage/transaction" ]; then
            private_file "$stage/transaction"
            [ "$(cat "$stage/transaction")" = "$previous_transaction" ] || exit 75
            private_file "$stage/kind"
            [ "$(cat "$stage/kind")" = fresh ] || exit 75
            # Fresh acquisition receipts own only these staging artifacts.
            # More advanced/unknown layouts need their original rollback; do not
            # recursively delete foreign files just because a lock is marked ours.
            for entry in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
                [ -e "$entry" ] || [ -L "$entry" ] || continue
                case "${entry##*/}" in
                    transaction|kind) private_file "$entry";;
                    lease) private_file "$entry";;
                    payload)
                        [ -f "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] || exit 71
                        case "$(stat -c '%a' "$entry")" in 600|700) :;; *) exit 71;; esac;;
                    *) exit 75;;
                esac
            done
        else
            private_file "$base/.bootstrap-acquiring"
            [ "$(cat "$base/.bootstrap-acquiring")" = "$previous_transaction fresh" ] || exit 75
            # Only the acquisition journal proves an otherwise empty lock.
            for entry in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
                [ ! -e "$entry" ] && [ ! -L "$entry" ] || exit 71
            done
        fi
    fi
    # Any unjournaled root entry refuses the entire recovery before mutation,
    # including sockets elsewhere that would otherwise be safe to retire.
    for entry in "$base"/* "$base"/.[!.]* "$base"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        case "${entry##*/}" in
            .bootstrap-owner|.bootstrap-lock|.bootstrap-acquiring|sessions) :;;
            .bootstrap-ready)
                private_file "$entry"
                [ "$(cat "$entry")" = "$previous_host" ] || exit 75;;
            bin)
                [ -d "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a' "$entry")" = 700 ] || exit 71
                for child in "$entry"/* "$entry"/.[!.]* "$entry"/..?*; do
                    [ ! -e "$child" ] && [ ! -L "$child" ] || exit 71
                done;;
            *) exit 71;;
        esac
    done
    # Validate every socket before deleting any. Only these session rendezvous
    # names and empty directories belong to this legacy fresh-install receipt.
    sockets=0
    for directory in "$base/sessions" "$base/sessions/sessions"; do
        [ -e "$directory" ] || [ -L "$directory" ] || continue
        [ -d "$directory" ] && [ ! -L "$directory" ] && [ -O "$directory" ] && [ "$(stat -c '%a' "$directory")" = 700 ] || exit 71
        for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
            [ -e "$entry" ] || [ -L "$entry" ] || continue
            [ "$entry" != "$base/sessions/sessions" ] || continue
            [ -S "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a' "$entry")" = 600 ] || exit 71
            name=${entry##*/}
            socket_id=${name%.sock}
            [ "$name" = "$socket_id.sock" ] || exit 71
            hex_id "$socket_id"
            sockets=$((sockets + 1))
            [ "$sockets" -le 1024 ] || exit 75
        done
    done
    printf 'INFRATERNAL_SETUP_STALE %s %s %s %s\n' "$previous_host" "$previous_transaction" "$identity" "$sockets"
}
