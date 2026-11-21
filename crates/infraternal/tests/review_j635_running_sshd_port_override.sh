#!/bin/bash
# J635 review (#483, D386): a console `server init` must not save a
# default-drop host table that drops the port sshd is RUNNING on, when that
# port differs from sshd's configuration file.
#
# Run as REAL root inside a private mount and network namespace:
# `unshare -nm env BIN=<infraternal binary built with plugin-server> bash <this script>`.
# Nothing outside the namespaces changes: the sshd_config bind mount, the
# tmpfs over the service manager's sockets and the 2222 sshd all vanish with
# them.
#
# The shape: sshd_config says `Port 22`, but the running sshd was started
# with `-p 2222`. That is a supported channel on Debian/Ubuntu
# (`SSHD_OPTS` in /etc/default/ssh, read by ssh.service's ExecStart) and on
# Fedora/RHEL (`OPTIONS` in /etc/sysconfig/sshd), and it is what a systemd
# drop-in with its own ExecStart does. It is also the state after someone
# edits Port in sshd_config but has not restarted sshd yet. `sshd_ports`
# asks `sshd -G` first, which reads only the file, says 22, and wins; the
# running listener on 2222 is never consulted. `*,*,tcp,22` then passes the
# console check, and the saved table drops every SSH login on 2222 as soon
# as it is applied.
#
# The holder is the real /usr/sbin/sshd (`-D -p 2222`) when it starts in
# the namespace, else a python process named `sshd` (the code only looks at
# /proc comm and socket ownership, so both are the same input).
#
# Checks (exit 0 when they hold):
# - `*,*,tcp,22` alone is refused (exit 1 = the J635 red: a drop table was
#   planned that drops the running sshd on 2222);
# - `*,*,tcp,2222` alone is refused too: a restart would bring sshd back
#   on the configured 22 (J662);
# - rules for both 22 and 2222 are planned, so the check is not simply
#   refusing everything (J662).
set -u
BIN=${BIN:?set BIN to the infraternal binary}
if [ "$(id -u)" != 0 ] || ! grep -Eq '^ +0 +0 +4294967295$' /proc/self/uid_map; then
    echo "SETUP_FAILED: run as real root under unshare -nm"; exit 2
fi
SCRATCH=${J635_SCRATCH:-$HOME/.j635}/run-$$
mkdir -p -m 700 "$SCRATCH/d" "$SCRATCH/u"
ip link set lo up
[ -e /etc/ssh/sshd_config ] || { echo "SETUP_FAILED: no /etc/ssh/sshd_config to bind over"; exit 2; }
printf 'Port 22\n' > "$SCRATCH/sshd_config"
mount --bind "$SCRATCH/sshd_config" /etc/ssh/sshd_config
mount -t tmpfs none /run/systemd
[ -d /run/dbus ] && mount -t tmpfs none /run/dbus
HOLDER_KIND=real-sshd
# The real sshd needs its privilege-separation directory; never create it on
# the host (/run is shared with it), so fall back when it is missing.
if [ -d /run/sshd ] && [ -x /usr/sbin/sshd ]; then
    /usr/sbin/sshd -D -p 2222 -o PidFile=none -E "$SCRATCH/sshd.log" & HOLDER_PID=$!
else
    sleep 0 & HOLDER_PID=$!
fi
for _ in $(seq 1 50); do
    grep -q ':08AE .* 0A ' /proc/net/tcp6 /proc/net/tcp 2>/dev/null && break
    # sleep: poll until the holder has bound 2222 (0x08AE).
    sleep 0.1
done
if ! grep -q ':08AE .* 0A ' /proc/net/tcp6 /proc/net/tcp 2>/dev/null; then
    kill "$HOLDER_PID" 2>/dev/null
    HOLDER_KIND=python-named-sshd
    python3 -I -c '
import ctypes, socket, time
ctypes.CDLL(None).prctl(15, b"sshd", 0, 0, 0)  # PR_SET_NAME
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(("::", 2222)); s.listen(4)
time.sleep(60)' & HOLDER_PID=$!
    for _ in $(seq 1 50); do
        [ "$(cat /proc/$HOLDER_PID/comm)" = sshd ] && grep -q ':08AE .* 0A ' /proc/net/tcp6 && break
        # sleep: poll until the fallback holder has renamed itself and bound 2222.
        sleep 0.1
    done
fi
echo "HOLDER=$HOLDER_KIND comm=$(cat /proc/$HOLDER_PID/comm 2>/dev/null) config_port=22 listening_2222=$(grep -c ':08AE .* 0A ' /proc/net/tcp6 /proc/net/tcp | paste -sd' ')"
if ! grep -q ':08AE .* 0A ' /proc/net/tcp6 /proc/net/tcp 2>/dev/null; then
    echo "SETUP_FAILED: nothing named sshd listened on 2222"
    kill "$HOLDER_PID" 2>/dev/null; rm -rf "$SCRATCH"; exit 2
fi
# console_init LABEL RULE... : plan a console `server init` with these allow rules.
console_init() {
    local label=$1; shift
    local rules=()
    for rule in "$@"; do rules+=(--host-firewall-allow "$rule"); done
    env -i PATH=/usr/bin:/bin HOME="$SCRATCH" \
        INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR="$SCRATCH/u" \
        "$BIN" --json server init --system --dry-run --data "$SCRATCH/d" \
        "${rules[@]}" > "$SCRATCH/out" 2> "$SCRATCH/err"
    local status=$?
    if [ "$status" -eq 0 ] && grep -q 'host-firewall-server.json' "$SCRATCH/out"; then
        echo "$label=planned: $(grep -o '\\"admin_rules\\": \[[^]]*\]' "$SCRATCH/out" | head -1)"
        return 0
    fi
    echo "$label=refused (status $status): $(cat "$SCRATCH/err" "$SCRATCH/out" | tr '\n' ' ' | head -c 600)"
    return 1
}
RESULT=0
if console_init CONSOLE_INIT_22 '*,*,tcp,22'; then
    echo "RED: planned a default-drop table admitting only tcp/22 while the running sshd listens on 2222"
    RESULT=1
fi
if console_init CONSOLE_INIT_2222 '*,*,tcp,2222'; then
    echo "RED: planned a table admitting only tcp/2222 while sshd's configuration (the next restart) says 22"
    RESULT=1
fi
if ! console_init CONSOLE_INIT_BOTH '*,*,tcp,22' '*,*,tcp,2222'; then
    echo "RED: refused rules that admit both the configured and the running port"
    RESULT=1
fi
kill "$HOLDER_PID" 2>/dev/null
wait "$HOLDER_PID" 2>/dev/null
rm -rf "$SCRATCH"
echo "RESULT=$RESULT"
exit "$RESULT"
