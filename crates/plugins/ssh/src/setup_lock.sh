# Serialize host provisioning shell commands without creating an unowned lock file.
# Proof notes are beside Installation::script in install.rs [17][243].
setup_guard() {
    [ "${setup_guarded:-no}" != yes ] || return 0
    parent=$(dirname "$base")
    if [ -e "$parent" ] || [ -L "$parent" ]; then
        [ -d "$parent" ] && [ ! -L "$parent" ] && [ -O "$parent" ] || exit 71
        permissions=$(stat -c '%a' "$parent")
        [ "$((0$permissions & 022))" = 0 ] || exit 71
        exec 9< "$parent"
        flock -n 9 || exit 73
        setup_guarded=yes
    fi
}
start_setup_lease() {
    exec 7< "$stage"
    flock -n 7 || exit 73
    (exec 9<&-; exec sleep 180) >/dev/null 2>&1 &
    lease_pid=$!
    lease_birth=$(awk '{print $22}' "/proc/$lease_pid/stat")
    printf '%s %s\n' "$lease_pid" "$lease_birth" > "$stage/lease"
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
    if [ -d "$stage" ] && [ ! -L "$stage" ]; then
        exec 7< "$stage"
        flock -w 2 7 || exit 73
    fi
}
