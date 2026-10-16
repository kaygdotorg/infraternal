# Probe owned control sockets directly before retiring failed setup (#230).
control_socket() {
    control="$base/sessions/plugins.sock"
    [ -e "$base/sessions" ] || [ -L "$base/sessions" ] || return 0
    [ -d "$base/sessions" ] && [ ! -L "$base/sessions" ] && [ -O "$base/sessions" ] || exit 71
    [ -e "$control" ] || [ -L "$control" ] || return 0
    command -v python3 >/dev/null 2>&1 || exit 76
    python3 -I -S -B - "$base" "$1" "$identity" <<'PYTHON' || exit $?
import errno,os,socket,stat,sys
try:
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    root=os.open(sys.argv[1],flags)
    base=os.fstat(root)
    if base.st_uid!=os.geteuid() or stat.S_IMODE(base.st_mode)!=0o700 or '%d:%d'%(base.st_dev,base.st_ino)!=sys.argv[3]: sys.exit(71)
    fd=os.open('sessions',flags,dir_fd=root)
    parent=os.fstat(fd)
    if parent.st_uid!=os.geteuid() or stat.S_IMODE(parent.st_mode)!=0o700: sys.exit(71)
    def checked():
        entry=os.stat('plugins.sock',dir_fd=fd,follow_symlinks=False)
        if not stat.S_ISSOCK(entry.st_mode) or entry.st_uid!=os.geteuid() or entry.st_nlink!=1: sys.exit(71)
        return entry.st_dev,entry.st_ino
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
        peer.settimeout(0.25)
        before=checked()
        try:
            peer.connect('/proc/self/fd/%d/plugins.sock'%fd)
        except OSError as error:
            if error.errno!=errno.ECONNREFUSED: sys.exit(77)
        else: sys.exit(73)
    if checked()!=before: sys.exit(77)
    if sys.argv[2]=='retire': os.unlink('plugins.sock',dir_fd=fd)
except OSError: sys.exit(77)
PYTHON
}
validate_control_socket() { control_socket inspect; }
retire_control_socket() { control_socket retire; }

validate_retired_stage() {
    stage="$base/.bootstrap-lock"
    [ -e "$stage" ] || [ -L "$stage" ] || return 0
    [ -d "$stage" ] && [ ! -L "$stage" ] && [ -O "$stage" ] && [ "$(stat -c '%a' "$stage")" = 700 ] || exit 71
    for entry in "$stage"/* "$stage"/.[!.]* "$stage"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        case "${entry##*/}" in
            state|cache)
                [ -d "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a' "$entry")" = 700 ] || exit 71
                bad=$(find "$entry" \( ! -uid "$(id -u)" -o ! \( -type d -o -type f \) -o -perm /077 -o \( -type d ! -perm 0700 \) \) -print -quit) || exit 71
                [ -z "$bad" ] || exit 71
                count=$(find "$entry" -printf . | wc -c)
                [ "$count" -le 1024 ] || exit 75
                continue;;
            current|launcher)
                [ -L "$entry" ] || exit 71
                case "${entry##*/}:$(readlink "$entry")" in
                    "current:$base/bin/live"|"launcher:$base/bin/current") continue;;
                    *) exit 71;;
                esac;;
            payload)
                [ -f "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] || exit 71
                case "$(stat -c '%a' "$entry")" in 600|700) continue;; *) exit 71;; esac;;
            transaction|kind|lease|unit|activating|stopping|stop-refused|had-binary|had-state|had-launcher|was-active|was-enabled|replacing-binary|replacing-state|replacing-unit|replacing-launcher|linger-requested) :;;
            *) exit 75;;
        esac
        [ -f "$entry" ] && [ ! -L "$entry" ] && [ -O "$entry" ] && [ "$(stat -c '%a:%h' "$entry")" = 600:1 ] || exit 71
        [ "$(stat -c '%s' "$entry")" -le 4096 ] || exit 71
        case "${entry##*/}" in
            transaction) [ "$(cat "$entry")" = "$1" ] || exit 75;;
            kind) [ "$(cat "$entry")" = fresh ] || exit 75;;
            unit) grep -Fxq "# infraternal bootstrap $2" "$entry" || exit 71;;
            lease) [ "$(stat -c '%s' "$entry")" -le 64 ] || exit 71;;
            *) [ "$(stat -c '%s' "$entry")" = 0 ] || exit 71;;
        esac
    done
}
