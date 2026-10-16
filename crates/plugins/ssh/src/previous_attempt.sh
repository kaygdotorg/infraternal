# Classify earlier host provisioning using private ownership receipts; never adopt foreign data.
# Proof notes are beside INSPECT in previous_attempt.rs [17][243].
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
    if [ -e "$base" ] || [ -L "$base" ]; then
        base_real=$(CDPATH= cd -P "$base" 2>/dev/null && pwd -P) || exit 75
    else
        base_real=$(CDPATH= cd -P "$(dirname "$base")" && pwd -P)/${base##*/}
    fi
    [ -r /proc/net/unix ] || exit 75
    while read -r num refs protocol flags type state inode path; do
        for entry in "$base/sessions"/*.sock "$base/sessions/sessions"/*.sock; do
            [ -S "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] || continue
            [ "$entry" != "$base/sessions/plugins.sock" ] || continue
            case "$path" in "$entry"|"$base_real/${entry#"$base/"}"|"${entry##*/}"|*/"${entry##*/}") exit 73;; esac
        done
    done < /proc/net/unix
    case "$base" in *[\*\?\[]*) exit 75;; esac
    case "$base_real" in *[\*\?\[]*) exit 75;; esac
    set --
    for process in /proc/[0-9]*; do
        [ -O "$process" ] || continue
        set -- "$@" "$process/exe" "$process/fd"
        [ "$#" -le 8192 ] || exit 75
    done
    [ "$#" -le 8192 ] || exit 75
    command -v find >/dev/null 2>&1 || exit 75
    if live=$(find "$@" -maxdepth 1 \( -lname "$base/*" -o -lname "$base_real/*" \) -print -quit 2>/dev/null); then
        :
    else
        [ "$?" = 1 ] || exit 75
    fi
    [ -z "$live" ] || exit 73

}
no_redirect() {
    path=
    rest=${base#/}
    while [ -n "$rest" ]; do
        part=${rest%%/*}
        [ "$part" = "$rest" ] && rest= || rest=${rest#*/}
        path="$path/$part"
        if [ -L "$path" ]; then
            case "$HOME/" in "$path"/*) ;; *) exit 71;; esac
        fi
    done
}
inspect_previous() {
    no_redirect
    setup_guard
    receipt=
    for candidate in "$base".bootstrap-rollback-*; do
        [ -e "$candidate" ] || [ -L "$candidate" ] || continue
        [ -z "$receipt" ] || exit 75
        receipt=$candidate
    done
    if [ -z "$receipt" ] && [ ! -e "$base/.bootstrap-lock" ] && [ ! -L "$base/.bootstrap-lock" ] && [ ! -e "$base/.bootstrap-acquiring" ] && [ ! -L "$base/.bootstrap-acquiring" ]; then
        if [ -e "$base" ] || [ -L "$base" ]; then
            private_file "$base/.bootstrap-owner"
            [ "$(stat -c '%s' "$base/.bootstrap-owner")" = 33 ] || exit 75
            hex_id "$(cat "$base/.bootstrap-owner")"
        fi
        printf 'INFRATERNAL_SETUP_CLEAR\n'
        return
    fi
    if [ -n "$receipt" ]; then
        private_file "$receipt"
        previous_transaction=${receipt#"$base.bootstrap-rollback-"}
        hex_id "$previous_transaction"
        read -r previous_host recorded_transaction kind identity extra < "$receipt"
        hex_id "$previous_host"
        [ "$(cat "$receipt")" = "$previous_host $previous_transaction fresh $identity" ] || exit 75
        case "$identity" in ''|:*|*:|*:*:*|*[!0-9:]*) exit 75;; esac
        case "$identity" in *:*) :;; *) exit 75;; esac
        if [ ! -e "$base" ] && [ ! -L "$base" ]; then
            not_live
            printf 'INFRATERNAL_SETUP_STALE %s %s %s 0\n' "$previous_host" "$previous_transaction" "$identity"
            return
        fi
        [ -d "$base" ] && [ ! -L "$base" ] && [ -O "$base" ] && [ "$(stat -c '%a' "$base")" = 700 ] || exit 71
        [ "$(stat -c '%d:%i' "$base")" = "$identity" ] || exit 75
        if [ ! -e "$base/.bootstrap-owner" ] && [ ! -L "$base/.bootstrap-owner" ]; then
            for entry in "$base"/* "$base"/.[!.]* "$base"/..?*; do
                [ ! -e "$entry" ] && [ ! -L "$entry" ] || exit 71
            done
        else
            private_file "$base/.bootstrap-owner"
            [ "$(stat -c '%s' "$base/.bootstrap-owner")" = 33 ] || exit 75
            [ "$(cat "$base/.bootstrap-owner")" = "$previous_host" ] || exit 75
        fi
    else
        [ -d "$base" ] && [ ! -L "$base" ] && [ -O "$base" ] && [ "$(stat -c '%a' "$base")" = 700 ] || exit 71
        private_file "$base/.bootstrap-owner"
        [ "$(stat -c '%s' "$base/.bootstrap-owner")" = 33 ] || exit 75
        previous_host=$(cat "$base/.bootstrap-owner")
        hex_id "$previous_host"
        identity=$(stat -c '%d:%i' "$base")
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
    not_live
    if [ -n "$receipt" ]; then
        validate_retired_stage "$previous_transaction" "$previous_host"
    elif [ -e "$base/.bootstrap-lock" ] || [ -L "$base/.bootstrap-lock" ]; then
        stage="$base/.bootstrap-lock"
        [ -d "$stage" ] && [ ! -L "$stage" ] && [ -O "$stage" ] && [ "$(stat -c '%a' "$stage")" = 700 ] || exit 71
        if [ -e "$stage/transaction" ] || [ -L "$stage/transaction" ]; then
            private_file "$stage/transaction"
            [ "$(cat "$stage/transaction")" = "$previous_transaction" ] || exit 75
            private_file "$stage/kind"
            [ "$(cat "$stage/kind")" = fresh ] || exit 75
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
            for entry in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
                [ ! -e "$entry" ] && [ ! -L "$entry" ] || exit 71
            done
        fi
    fi
    if [ -e "$base/.bootstrap-acquiring" ] || [ -L "$base/.bootstrap-acquiring" ]; then
        private_file "$base/.bootstrap-acquiring"
        [ "$(stat -c '%s' "$base/.bootstrap-acquiring")" = 39 ] || exit 75
        [ "$(cat "$base/.bootstrap-acquiring")" = "$previous_transaction fresh" ] || exit 75
    fi
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
    sockets=0
    for directory in "$base/sessions" "$base/sessions/sessions"; do
        [ -e "$directory" ] || [ -L "$directory" ] || continue
        [ -d "$directory" ] && [ ! -L "$directory" ] && [ -O "$directory" ] && [ "$(stat -c '%a' "$directory")" = 700 ] || exit 71
        for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
            [ -e "$entry" ] || [ -L "$entry" ] || continue
            [ "$entry" != "$base/sessions/sessions" ] || continue
            if [ "$entry" = "$base/sessions/plugins.sock" ]; then
                validate_control_socket
                sockets=$((sockets + 1))
                [ "$sockets" -le 1024 ] || exit 75
                continue
            fi
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
