#!/bin/bash
# J608 review (#483, D386): a console `server init` must not save a
# default-drop host table that drops sshd's real port.
#
# Run as REAL root (it must trust root-owned sshd and systemctl) inside a
# private mount and network namespace: `unshare -nm env BIN=<infraternal
# binary built with plugin-server> bash <this script>`. Nothing outside the
# namespaces changes: the sshd_config bind mount, the tmpfs over the
# service manager's sockets and the 2222 listener all vanish with them.
# Under `unshare -Urnm` (fake root) every root-owned binary looks owned by
# nobody, so no sshd port can be learned and the accept check fails.
#
# The shape: sshd is configured on 2222 and the listener belongs to a
# process that is not named `sshd` (the service manager, for socket
# activation, the default on current Ubuntu server installs), or sshd is
# stopped. The check used to see no `sshd` socket, fall back to 22, and plan
# a table that drops every SSH login on 2222.
#
# Checks (exit 0 when both hold):
# - `*,*,tcp,22` is refused (exit 1 = the J608 red: a drop table was planned);
# - `*,*,tcp,2222` is planned (exit 3 = the right port is refused too).
#
# HIDE_SYSTEMD=1 (default) mounts empty tmpfs over /run/systemd and /run/dbus
# so the host's own ssh.socket cannot answer and the port must come from
# `sshd -G`/`-T`. HIDE_SYSTEMD=0 lets an active ssh.socket answer first
# (on a host whose ssh.socket listens on 22, expect exit 1 and 3: the socket
# unit is the truth there). HOLDER=sshd names the 2222 holder `sshd`.
set -u
BIN=${BIN:?set BIN to the infraternal binary}
HOLDER=${HOLDER:-systemd}
HIDE_SYSTEMD=${HIDE_SYSTEMD:-1}
if [ "$(id -u)" != 0 ] || ! grep -Eq '^ +0 +0 +4294967295$' /proc/self/uid_map; then
    echo "SETUP_FAILED: run as real root under unshare -nm"; exit 2
fi
SCRATCH=${J608_SCRATCH:-$HOME/.j608}/sock-$$
mkdir -p -m 700 "$SCRATCH/d" "$SCRATCH/u"
ip link set lo up
printf 'Port 2222\n' > "$SCRATCH/sshd_config"
if [ -e /etc/ssh/sshd_config ]; then
    mount --bind "$SCRATCH/sshd_config" /etc/ssh/sshd_config
fi
if [ "$HIDE_SYSTEMD" = 1 ]; then
    mount -t tmpfs none /run/systemd
    [ -d /run/dbus ] && mount -t tmpfs none /run/dbus
fi
python3 -I -c '
import ctypes, socket, sys, time
ctypes.CDLL(None).prctl(15, sys.argv[1].encode(), 0, 0, 0)  # PR_SET_NAME
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(("::", 2222)); s.listen(4)
time.sleep(60)' "$HOLDER" & HOLDER_PID=$!
for _ in $(seq 1 50); do
    [ "$(cat /proc/$HOLDER_PID/comm)" = "$HOLDER" ] && grep -q ':08AE .* 0A ' /proc/net/tcp6 && break
    # sleep: poll until the holder has renamed itself and bound 2222 (0x08AE).
    sleep 0.1
done
echo "HOLDER=$HOLDER HIDE_SYSTEMD=$HIDE_SYSTEMD comm=$(cat /proc/$HOLDER_PID/comm) listening_2222=$(grep -c ':08AE .* 0A ' /proc/net/tcp6)"
if ! grep -q ':08AE .* 0A ' /proc/net/tcp6 || [ "$(cat /proc/$HOLDER_PID/comm)" != "$HOLDER" ]; then
    echo "SETUP_FAILED: the holder never listened on 2222 as $HOLDER"
    kill "$HOLDER_PID"; rm -rf "$SCRATCH"; exit 2
fi
# console_init <rule> <tag>: dry-run a console server init; prints the outcome, returns 0 when planned.
console_init() {
    env -i PATH=/usr/bin:/bin HOME="$SCRATCH" \
        INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR="$SCRATCH/u" \
        "$BIN" --json server init --system --dry-run --data "$SCRATCH/d" \
        --host-firewall-allow "$1" > "$SCRATCH/out" 2> "$SCRATCH/err"
    local status=$?
    if [ "$status" -eq 0 ] && grep -q 'host-firewall-server.json' "$SCRATCH/out"; then
        echo "$2=planned: $(grep -o '\\"admin_rules\\": \[[^]]*\]' "$SCRATCH/out" | head -1)"
        return 0
    fi
    echo "$2=refused (status $status): $(cat "$SCRATCH/err" "$SCRATCH/out" | tr '\n' ' ' | head -c 600)"
    return 1
}
RESULT=0
if console_init '*,*,tcp,22' CONSOLE_INIT_22; then
    echo "RED: planned a default-drop table admitting only tcp/22 while sshd is on 2222"
    RESULT=1
fi
if ! console_init '*,*,tcp,2222' CONSOLE_INIT_2222; then
    echo "RED: refused the rule for sshd's configured port 2222"
    [ "$RESULT" -eq 0 ] && RESULT=3
fi
kill "$HOLDER_PID"
rm -rf "$SCRATCH"
echo "RESULT=$RESULT"
exit "$RESULT"
