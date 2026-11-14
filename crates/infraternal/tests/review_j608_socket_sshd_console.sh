#!/bin/bash
# J608 review (#483, D386): a console `server init` must not save a
# default-drop host table that drops sshd's real port.
#
# Run under `unshare -Urnm` with BIN=<infraternal binary built with
# plugin-server>. Exit 1 = red (the drop table was planned), exit 0 = refused.
#
# The shape: sshd listens on 2222 through socket activation, the default on
# current Ubuntu server installs. Before the first connection the listening
# socket belongs to the service manager, so no process named `sshd` holds it,
# and `sshd_listening_ports` sees nothing. `admits_sshd` then falls back to
# 22, so an operator who passes `*,*,tcp,22` from the console gets a table
# that drops every SSH login on 2222. sshd's own config says 2222 (bind
# mounted here over /etc/ssh/sshd_config, when the host has one), so a fix
# can learn the port without a running sshd.
#
# HOLDER=sshd is the control: the same listener held by a process named
# `sshd`, which the current check sees, so it refuses (exit 0). That proves
# the harness reaches the check. The default HOLDER=systemd is the red case.
set -u
BIN=${BIN:?set BIN to the infraternal binary}
HOLDER=${HOLDER:-systemd}
SCRATCH=${J608_SCRATCH:-$HOME/.j608}/sock-$$
mkdir -p -m 700 "$SCRATCH/d" "$SCRATCH/u"
ip link set lo up
printf 'Port 2222\n' > "$SCRATCH/sshd_config"
if [ -e /etc/ssh/sshd_config ]; then
    mount --bind "$SCRATCH/sshd_config" /etc/ssh/sshd_config
fi
python3 -I -c '
import ctypes, socket, sys, time
ctypes.CDLL(None).prctl(15, sys.argv[1].encode(), 0, 0, 0)  # PR_SET_NAME
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.bind(("::", 2222)); s.listen(4)
time.sleep(60)' "$HOLDER" & HOLDER_PID=$!
# sleep: let the holder bind its listener before server init reads /proc.
sleep 0.5
echo "HOLDER=$HOLDER comm=$(cat /proc/$HOLDER_PID/comm) listening=$(grep -c ' 0A ' /proc/net/tcp6)"
env -i PATH=/usr/bin:/bin HOME="$SCRATCH" \
    INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR="$SCRATCH/u" \
    "$BIN" --json server init --system --dry-run --data "$SCRATCH/d" \
    --host-firewall-allow '*,*,tcp,22' > "$SCRATCH/out" 2> "$SCRATCH/err"
STATUS=$?
kill "$HOLDER_PID"
if [ "$STATUS" -eq 0 ] && grep -q 'host-firewall-server.json' "$SCRATCH/out"; then
    echo "CONSOLE_INIT=planned a default-drop table admitting only tcp/22 while sshd is on 2222"
    grep -o '\\"admin_rules\\": \[[^]]*\]' "$SCRATCH/out" | head -1
    rm -rf "$SCRATCH"
    exit 1
fi
echo "CONSOLE_INIT=refused (status $STATUS): $(tr '\n' ' ' < "$SCRATCH/err" | head -c 400)"
rm -rf "$SCRATCH"
exit 0
