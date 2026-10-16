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
    # Unix diagnostics bridge the filesystem inode to the kernel socket inode
    # used by /proc/net/unix and socket:[inode] descriptors. Path resolution
    # cannot do this after a relative bind, chdir or rename. Missing diagnostics
    # cannot prove staleness. Inode collisions on other devices refuse safely.
    rows=$(ss -x -a -n -e -p -H 2>&1) || exit 75
    live=$(printf '%s\n' "$rows" | awk -v wanted="ino:${control_identity#*:}" '
        NF {
            if ($1 !~ /^u_/) exit 2
            mapped = 0
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^ino:/) mapped = 1
                if ($i == wanted) found = 1
            }
            if ($5 != "*" && substr($5, 1, 1) != "@" && !mapped) exit 2
        }
        END { if (found) print "live" }
    ') || exit 75
    [ -z "$live" ] || exit 73
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
