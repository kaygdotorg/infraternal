#!/bin/bash
# J771 (#483, #516): real-root proof of `server init --system`'s one install
# order, with the real binary and the real default paths.
#
# Run as real root, inside private mount and network namespaces:
#   BIN=<infraternal> unshare -nm --propagation private $0
# Nothing outside the namespaces changes: /var/lib, /etc/systemd/system and
# /usr/local/bin are scratch mounts, /run/systemd is hidden (as in
# review_j671_sshd_invariant.sh), and /usr/bin/systemctl is a stub that only
# logs its arguments, so no real unit is reloaded, enabled or restarted and no
# host table is loaded. A private sshd on port 22 gives the admission check a
# known port.
#
# Cases, each printing `CASE <name> expect=<x> got=<y> ok|BAD`:
#   REFUSED_*   a firewall that would drop sshd's port is refused and leaves
#               no data folder, no unit, no policy and no PATH link (J755 P3-1).
#   FRESH_*     a fresh install creates /var/lib/infraternal 0700 before the
#               policy is saved (c161b0897), writes both units, runs systemctl
#               in order, and publishes the PATH link on this firewall path
#               (J755 P1).
#   RERUN_*     an unchanged re-run keeps the unit's inode and mtime (J692).
#   OFF_*       --host-firewall-off (with --force: its unit differs) also
#               publishes the PATH link.
# The last line is RESULT=<number of BAD cases>.
set -u
BIN=${BIN:?set BIN to the infraternal binary under test}
BAD=0
[ "$(id -u)" = 0 ] && grep -Eq '^ +0 +0 +4294967295$' /proc/self/uid_map \
    || { echo "SETUP_FAILED: needs real root under unshare -nm"; exit 2; }
S=$(mktemp -d /root/.j771-XXXXXX)
chmod 700 "$S"

# check NAME EXPECT GOT: count a mismatch.
check() {
    local verdict=ok
    [ "$2" = "$3" ] || { verdict=BAD; BAD=$((BAD + 1)); }
    echo "CASE $1 expect=$2 got=$3 $verdict"
}

ip link set lo up
mount -t tmpfs none /run/systemd
[ -d /run/dbus ] && mount -t tmpfs none /run/dbus
mount -t tmpfs -o mode=755 none /var/lib
mkdir -m 755 "$S/units" "$S/localbin"
mount --bind "$S/units" /etc/systemd/system
mount --bind "$S/localbin" /usr/local/bin
# The stub answers `show` the way systemctl does when systemd is hidden, so
# sshd's ports come from sshd itself, and logs every other call.
printf '#!/bin/sh\ncase "$1" in show) echo "System has not been booted with systemd" >&2; exit 1;; is-enabled) exit 1;; esac\necho "$*" >> %s/systemctl.log\n' "$S" > "$S/systemctl"
chmod 755 "$S/systemctl"
mount --bind "$S/systemctl" /usr/bin/systemctl
printf 'Port 22\n' > "$S/cfg"
mount --bind "$S/cfg" /etc/ssh/sshd_config
/usr/sbin/sshd -D -f /etc/ssh/sshd_config -o PidFile=none -E "$S/sshd.log" &
SSHD=$!
sleep 0.5 # sleep: let sshd bind before /proc/net is read
trap 'kill $SSHD 2>/dev/null; wait $SSHD 2>/dev/null; rm -rf "$S"' EXIT

# init ARGS...: run the real install with a clean environment.
init() {
    env -i PATH=/usr/bin:/bin HOME="$S" "$BIN" server init --system --yes \
        --behind-proxy --trusted-proxy 127.0.0.1 "$@" > "$S/out" 2> "$S/err"
}
D=/var/lib/infraternal
U=/etc/systemd/system/infraternal-server.service

echo "### refused: the firewall would admit only tcp/2299, sshd uses 22"
init --host-firewall-allow '*,*,tcp,2299'
status=$?
echo "    exit=$status: $(head -c 300 "$S/err")"
check REFUSED_FOR_SSHD_PORT 1 "$([ $status -ne 0 ] && grep -q "admits sshd's port 22" "$S/err" "$S/out" && echo 1 || echo 0)"
check REFUSED_NO_DATA_FOLDER absent "$([ -e $D ] && echo present || echo absent)"
check REFUSED_NO_UNIT absent "$([ -e $U ] && echo present || echo absent)"
check REFUSED_NO_LINK absent "$([ -e /usr/local/bin/infraternal ] && echo present || echo absent)"
check REFUSED_NO_SYSTEMCTL 0 "$(cat "$S/systemctl.log" 2>/dev/null | wc -l)"

echo "### fresh install, default data folder, tcp/22 admitted"
init --host-firewall-allow '*,*,tcp,22'
status=$?
echo "    exit=$status stderr: $(tr '\n' ' ' < "$S/err" | head -c 300)"
check FRESH_EXIT 0 "$status"
check FRESH_DATA_FOLDER_MODE 700 "$(stat -c %a $D 2>/dev/null)"
check FRESH_POLICY_MODE 600 "$(stat -c %a $D/host-firewall-server.json 2>/dev/null)"
check FRESH_UNITS 2 "$(ls /etc/systemd/system | grep -c '^infraternal-\(server\|firewall\)\.service$')"
check FRESH_SYSTEMCTL_ORDER \
    "daemon-reload|enable infraternal-firewall.service|restart infraternal-firewall.service|daemon-reload|enable --now infraternal-server.service" \
    "$(paste -sd'|' "$S/systemctl.log")"
check FRESH_PATH_LINK "$(readlink -f "$BIN")" "$(readlink /usr/local/bin/infraternal)"

echo "### re-run with the same flags: the unit is left as it was"
before=$(stat -c '%i %Y.%y' $U 2>/dev/null || echo missing-before)
sleep 1.1 # sleep: a rewrite within the same second could keep the mtime's seconds
init --host-firewall-allow '*,*,tcp,22'
status=$?
check RERUN_EXIT 0 "$status"
check RERUN_UNIT_UNTOUCHED "$before" "$(stat -c '%i %Y.%y' $U 2>/dev/null || echo missing-after)"

echo "### --host-firewall-off: the PATH link is published on this path too"
rm -f /usr/local/bin/infraternal
init --host-firewall-off --force
status=$?
echo "    exit=$status stderr: $(tr '\n' ' ' < "$S/err" | head -c 300)"
check OFF_EXIT 0 "$status"
check OFF_PATH_LINK "$(readlink -f "$BIN")" "$(readlink /usr/local/bin/infraternal)"

echo "RESULT=$BAD"
exit "$BAD"
