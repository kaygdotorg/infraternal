#!/bin/bash
# J803 (#516, #483): real-root proof that `server init --system`'s D395 data
# move keeps the host firewall's install invariants on dev.
#
# Run as real root, inside private mount and network namespaces:
#   BIN=<infraternal> unshare -nm --propagation private $0
# The harness is J771's review_j771_install_order.sh: /var/lib,
# /etc/systemd/system and /usr/local/bin are scratch mounts, /run/systemd is
# hidden, /usr/bin/systemctl is a stub that logs its arguments (and answers
# the move's `show -p ActiveState` with "active"), and a private sshd listens
# on port 22. Nothing outside the namespaces changes.
#
# A second `systemctl` sits first in PATH and logs `EVIL ...`: the move must
# never run it (J658's rule, J803 finding 4).
#
# NO_SETUP_FILES=1 leaves out the SSH setup's hidden files (.bootstrap-owner,
# .promotion-transaction, .superseded-unit), so a binary from before J803's
# reserved-name fix reaches the firewall-order and PATH cases (red runs).
#
# Cases print `CASE <name> expect=<x> got=<y> ok|BAD`; the last line is
# RESULT=<number of BAD cases>.
set -u
BIN=${BIN:?set BIN to the infraternal binary under test}
HIDDEN=".bootstrap-owner .promotion-transaction .superseded-unit"
[ "${NO_SETUP_FILES:-}" = 1 ] && HIDDEN=
BAD=0
[ "$(id -u)" = 0 ] && grep -Eq '^ +0 +0 +4294967295$' /proc/self/uid_map \
    || { echo "SETUP_FAILED: needs real root under unshare -nm"; exit 2; }
S=$(mktemp -d /root/.j803-XXXXXX)
chmod 700 "$S"
cp "$BIN" "$S/infraternal" && BIN=$S/infraternal

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
mkdir -m 755 "$S/units" "$S/localbin" "$S/evil"
mount --bind "$S/units" /etc/systemd/system
mount --bind "$S/localbin" /usr/local/bin
# Both stubs keep the server's ActiveState in one file, so the move's
# "did it stop?" check sees what a real manager would.
echo active > "$S/active-state"
for stub in systemctl evil/systemctl; do
    tag=; [ $stub = evil/systemctl ] && tag='EVIL '
    cat > "$S/$stub" <<STUB
#!/bin/sh
case "\$*" in
    *ActiveState*) echo "$tag\$*" >> $S/systemctl.log; cat $S/active-state; exit 0;;
    "stop "*) echo inactive > $S/active-state;;
    "start "*|"enable --now "*) echo active > $S/active-state;;
esac
case "\$1" in show) echo "System has not been booted with systemd" >&2; exit 1;; is-enabled) exit 1;; esac
echo "$tag\$*" >> $S/systemctl.log
STUB
done
chmod 755 "$S/systemctl" "$S/evil/systemctl"
mount --bind "$S/systemctl" /usr/bin/systemctl
printf 'Port 22\n' > "$S/cfg"
mount --bind "$S/cfg" /etc/ssh/sshd_config
/usr/sbin/sshd -D -f /etc/ssh/sshd_config -o PidFile=none -E "$S/sshd.log" &
SSHD=$!
sleep 0.5 # sleep: let sshd bind before /proc/net is read
trap 'kill $SSHD 2>/dev/null; wait $SSHD 2>/dev/null; rm -rf "$S"' EXIT

# init ARGS...: the real install with a clean environment, the decoy first in PATH.
init() {
    : > "$S/systemctl.log"
    env -i PATH="$S/evil:/usr/bin:/bin" HOME="$S" "$BIN" server init --system --yes \
        --behind-proxy --trusted-proxy 127.0.0.1 "$@" > "$S/out" 2> "$S/err"
}
D=/var/lib/infraternal
U=/etc/systemd/system/infraternal-server.service
OLD=/var/lib/j803-old
# own: inode, mode and sha256 of every entry other parts keep in $D.
own() {
    (cd $D && find bin agent state sessions $HIDDEN -printf '%i %m %p ' -exec sh -c '[ -f "$1" ] && sha256sum < "$1" | cut -c1-16 || echo dir' _ {} \;) \
        | paste -sd' ' | sha256sum | cut -c1-16
}
# data FOLDER: the server data a move must carry, as one checksum.
data() { (cd "$1" 2>/dev/null && cat infraternal.sqlite mesh/key 2>/dev/null) | sha256sum | cut -c1-16; }
evil() { grep -c '^EVIL' "$S/systemctl.log"; }

echo "### 0. /var/lib/infraternal already holds the root agent's layout (0711, as infraternal up makes it)"
install -d -m 711 $D
install -d -m 755 $D/bin && printf 'agent binary\n' > $D/bin/infraternal && chmod 755 $D/bin/infraternal
install -d -m 700 $D/agent $D/state $D/sessions && printf 'identity\n' > $D/agent/identity
for f in $HIDDEN; do printf '%s\n' "$f" > $D/$f; chmod 600 $D/$f; done
OWN=$(own); echo "    own=$OWN"

echo "### 1. an old-style install whose data folder is $OLD"
init --data $OLD --host-firewall-allow '*,*,tcp,22'
status=$?
echo "    exit=$status stderr: $(tr '\n' ' ' < "$S/err" | head -c 300)"
check OLD_INSTALL_EXIT 0 "$status"
printf 'sqlite bytes\n' > $OLD/infraternal.sqlite; install -d -m 700 $OLD/mesh; printf 'mesh key\n' > $OLD/mesh/key
DATA=$(data $OLD)
check OLD_UNIT_DATA 1 "$(grep -c "\"--data\" \"$OLD\"" $U)"
check OLD_POLICY_MODE 600 "$(stat -c %a $D/host-firewall-server.json 2>/dev/null)"
POLICY=$(sha256sum < $D/host-firewall-server.json | cut -c1-16)

echo "### 2. a re-run the firewall refuses (only tcp/2299 admitted, sshd uses 22) moves nothing"
UNIT_BEFORE=$(sha256sum < $U | cut -c1-16)
# --force: the allow rule changes the unit, and only the firewall's refusal is under test here.
init --force --host-firewall-allow '*,*,tcp,2299'
status=$?
echo "    exit=$status: $(tr '\n' ' ' < "$S/err" | head -c 400)"
check REFUSED_EXIT 1 "$([ $status -ne 0 ] && echo 1 || echo 0)"
check REFUSED_SAYS_SSHD 1 "$(cat "$S/err" "$S/out" | tr '\n' ' ' | grep -c "admits sshd's port 22")"
check REFUSED_UNIT_UNCHANGED "$UNIT_BEFORE" "$(sha256sum < $U | cut -c1-16)"
check REFUSED_OLD_DATA_IN_PLACE "$DATA" "$(data $OLD)"
check REFUSED_NOTHING_IN_TARGET absent "$([ -e $D/infraternal.sqlite ] && echo present || echo absent)"
check REFUSED_NO_STOP 0 "$(grep -c '^stop\|^EVIL stop' "$S/systemctl.log")"
check REFUSED_POLICY_UNCHANGED "$POLICY" "$(sha256sum < $D/host-firewall-server.json | cut -c1-16)"
check REFUSED_OWN_UNTOUCHED "$OWN" "$(own)"

echo "### 2b. a re-run whose unit differs (an extra allow rule) without --force moves nothing"
init --host-firewall-allow '*,*,tcp,22' --host-firewall-allow '*,*,tcp,8022'
status=$?
echo "    exit=$status: $(tr '\n' ' ' < "$S/err" | head -c 300)"
check CHANGED_REFUSED 1 "$([ $status -ne 0 ] && echo 1 || echo 0)"
check CHANGED_SAYS_FORCE 1 "$(cat "$S/err" "$S/out" | tr '\n' ' ' | grep -c 'pass --force')"
check CHANGED_UNIT_UNCHANGED "$UNIT_BEFORE" "$(sha256sum < $U | cut -c1-16)"
check CHANGED_OLD_DATA_IN_PLACE "$DATA" "$(data $OLD)"
check CHANGED_NO_STOP 0 "$(grep -c 'stop' "$S/systemctl.log")"

echo "### 3. the re-run with sshd admitted moves the folder into the shared install base (rename)"
init --host-firewall-allow '*,*,tcp,22'
status=$?
echo "    exit=$status stderr: $(tr '\n' ' ' < "$S/err" | head -c 300)"
echo "    systemctl: $(paste -sd'|' "$S/systemctl.log")"
check MOVE_EXIT 0 "$status"
check MOVE_UNIT_DATA 1 "$(grep -c "\"--data\" \"$D\"" $U)"
check MOVE_DATA_CARRIED "$DATA" "$(data $D)"
check MOVE_OLD_GONE absent "$([ -e $OLD ] && echo present || echo absent)"
check MOVE_OWN_UNTOUCHED "$OWN" "$(own)"
check MOVE_BASE_MODE 711 "$(stat -c %a $D)"
check MOVE_POLICY_KEPT "$POLICY" "$(sha256sum < $D/host-firewall-server.json | cut -c1-16)"
check MOVE_POLICY_MODE 600 "$(stat -c %a $D/host-firewall-server.json)"
check MOVE_NO_LEFTOVERS 0 "$(ls -A $D | grep -c '^\.infraternal-\(incoming\|move\)')"
check MOVE_FIREWALL_UNIT 1 "$(ls /etc/systemd/system | grep -c '^infraternal-firewall\.service$')"
check MOVE_NO_PATH_SYSTEMCTL 0 "$(evil)"
check MOVE_SYSTEMCTL_ORDER \
    "show -p ActiveState --value infraternal-server.service|stop infraternal-server.service|show -p ActiveState --value infraternal-server.service|daemon-reload|start infraternal-server.service|daemon-reload|enable infraternal-firewall.service|restart infraternal-firewall.service|daemon-reload|enable --now infraternal-server.service" \
    "$(paste -sd'|' "$S/systemctl.log")"

echo "### 4. re-running again is a no-op for the folder and the unit"
before=$(stat -c '%i %Y.%y' $U)
sleep 1.1 # sleep: a rewrite within the same second could keep the mtime's seconds
init --host-firewall-allow '*,*,tcp,22'
status=$?
check RERUN_EXIT 0 "$status"
check RERUN_UNIT_UNTOUCHED "$before" "$(stat -c '%i %Y.%y' $U)"
check RERUN_NO_STOP 0 "$(grep -c 'stop' "$S/systemctl.log")"

echo "### 5. cross-filesystem: an install on $S/old2 (root disk) is copied into the shared base"
init --force --data "$S/old2" --host-firewall-allow '*,*,tcp,22'
check OLD2_INSTALL_EXIT 0 "$?"
printf 'sqlite two\n' > "$S/old2/infraternal.sqlite"; install -d -m 700 "$S/old2/mesh"; printf 'key two\n' > "$S/old2/mesh/key"
DATA2=$(data "$S/old2")
init --host-firewall-allow '*,*,tcp,22'
status=$?
echo "    exit=$status (target still holds step 3's server data): $(tr '\n' ' ' < "$S/err" | grep -o 'already holds[^;]*' | head -c 300)"
check NONEMPTY_REFUSED 1 "$([ $status -ne 0 ] && echo 1 || echo 0)"
check NONEMPTY_NAMES_ONLY_FOREIGN 0 "$(grep -o 'already holds[^;]*' "$S/err" | grep -c 'host-firewall\|bootstrap\|promotion\|superseded\|bin\b\|agent\b')"
rm -rf $D/infraternal.sqlite $D/mesh
init --host-firewall-allow '*,*,tcp,22'
status=$?
echo "    exit=$status stdout: $(tr '\n' ' ' < "$S/out" | head -c 300)"
check COPY_EXIT 0 "$status"
check COPY_UNIT_DATA 1 "$(grep -c "\"--data\" \"$D\"" $U)"
check COPY_DATA_CARRIED "$DATA2" "$(data $D)"
L=$(ls -d "$S"/old2.moved-* 2>/dev/null | head -1)
check COPY_LEFTOVER_READ_ONLY 0 "$([ -n "$L" ] && find "$L" -perm /222 -not -type l | wc -l || echo missing)"
check COPY_OWN_UNTOUCHED "$OWN" "$(own)"
check COPY_POLICY_KEPT "$POLICY" "$(sha256sum < $D/host-firewall-server.json | cut -c1-16)"
check COPY_BASE_MODE 711 "$(stat -c %a $D)"
check COPY_NO_PATH_SYSTEMCTL 0 "$(evil)"

echo "RESULT=$BAD"
exit "$BAD"
