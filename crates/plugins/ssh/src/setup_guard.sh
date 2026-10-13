# Serialize host provisioning shell commands without creating an unowned lock file.
setup_guard() {
    [ "${setup_guarded:-no}" != yes ] || return 0
    parent=$(dirname "$base")
    if [ -e "$parent" ] || [ -L "$parent" ]; then
        [ -d "$parent" ] && [ ! -L "$parent" ] && [ -O "$parent" ] || exit 71
        permissions=$(stat -c '%a' "$parent")
        [ "$((0$permissions & 022))" = 0 ] || exit 71
        # Every new installer command takes this same directory lock. It leaves
        # no lock file and serializes admission, recovery and journal mutation.
        exec 9< "$parent"
        flock -n 9 || exit 73
        setup_guarded=yes
    fi
}
