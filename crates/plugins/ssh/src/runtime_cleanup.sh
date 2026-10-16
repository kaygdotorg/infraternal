# Validate and retire only the stopped daemon's fixed local control socket (#230).
validate_control_socket() {
    control="$base/sessions/plugins.sock"
    [ -e "$base/sessions" ] || [ -L "$base/sessions" ] || return 0
    # These checks precede every lookup below sessions; links never authorize cleanup.
    [ -d "$base/sessions" ] && [ ! -L "$base/sessions" ] && [ -O "$base/sessions" ] || exit 71
    [ -e "$control" ] || [ -L "$control" ] || return 0
    [ "$(stat -c '%a' "$base/sessions")" = 700 ] || exit 71
    # The service manager supplies the umask, so socket mode is not an ownership
    # receipt. The real private parent protects it for every inherited mode.
    [ -S "$control" ] && [ ! -L "$control" ] && [ -O "$control" ] && [ "$(stat -c '%h' "$control")" = 1 ] || exit 71
    control_identity=$(stat -c '%d:%i' "$control")
    control_real=$(CDPATH= cd -P "$base/sessions" && pwd -P)/plugins.sock
    [ -r /proc/net/unix ] || exit 71
    # A bind without listen and an accepted connection are live too. A relative
    # basename collision refuses conservatively, even outside this installation.
    while read -r num refs protocol flags type state inode path; do
        case "$path" in "$base"/*|"${control_real%/plugins.sock}"/*|plugins.sock|./plugins.sock) exit 73;; esac
    done < /proc/net/unix
}
retire_control_socket() {
    validate_control_socket
    if [ -e "$control" ] || [ -L "$control" ]; then
        [ ! -L "$control" ] && [ "$(stat -c '%d:%i' "$control")" = "$control_identity" ] || exit 71
        rm -- "$control"
    fi
}
