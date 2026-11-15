#!/bin/bash
# J671 (#483): real-root proof that no default-drop host table is saved or
# applied unless it admits every port sshd uses now and after a restart.
#
# What it runs, each case with the outcome the invariant requires:
#   netns   (BIN=<infraternal> $0 netns, run as real root under `unshare -nm`)
#           real /usr/sbin/sshd in a private network namespace, systemd hidden
#           (a tmpfs over /run/systemd, as J670's cases.sh did):
#           J658's console split, J670's over-SSH split, the IPv6-only family
#           mismatch, a stopped sshd, and the boot loader re-checking a saved
#           table against the host's current sshd (it must fail open).
#   systemd (BIN=<infraternal> $0 systemd, run as real root on a host whose
#           ssh.service is loaded): runtime drop-ins in /run that set `-p`
#           through SSHD_OPTS, an EnvironmentFile and an ExecStart override
#           using $OPTIONS. Only `server init --dry-run` runs; ssh.service is
#           never restarted, and the drop-ins are removed (trap) with a
#           daemon-reload before the script exits.
#
# Each case prints `CASE <name> expect=<x> got=<y> ok|BAD`; the last line is
# RESULT=<number of BAD cases>. On J662's head every new case is BAD (red);
# on J671's head every case is ok (green).
set -u
BIN=${BIN:?set BIN to the infraternal binary under test}
MODE=${1:?usage: BIN=... $0 netns|systemd}
BAD=0
S=$(mktemp -d /root/.j671-XXXXXX)
chmod 700 "$S"
mkdir -m 700 "$S/d" "$S/u"

# check NAME EXPECT GOT: count a mismatch.
check() {
    local verdict=ok
    [ "$2" = "$3" ] || { verdict=BAD; BAD=$((BAD + 1)); }
    echo "CASE $1 expect=$2 got=$3 $verdict"
}

# plan NAME EXPECT SSH_CONNECTION|- RULE...: server init --dry-run, PLANNED or REFUSED.
plan() {
    local name=$1 expect=$2 conn=$3
    shift 3
    local rules=()
    for rule in "$@"; do rules+=(--host-firewall-allow "$rule"); done
    local run=(env -i PATH=/usr/bin:/bin HOME="$S" INFRATERNAL_TEST_SYSTEMD_SYSTEM_UNIT_DIR="$S/u")
    [ "$conn" != - ] && run+=(SSH_CONNECTION="$conn")
    "${run[@]}" "$BIN" --json server init --system --dry-run --data "$S/d" "${rules[@]}" \
        > "$S/out" 2> "$S/err"
    local status=$? got=REFUSED
    [ $status -eq 0 ] && grep -q host-firewall-server.json "$S/out" && got=PLANNED
    echo "    $name: $(cat "$S/err" "$S/out" | tr '\n' ' ' \
        | grep -oE "(no --host-firewall-allow rule admits[^;]*;[^;]*;|could not be determined[^;]*;|port[^:a-z]{0,3}: [0-9]+)" \
        | head -3 | paste -sd' ')"
    check "$name" "$expect" "$got"
}

netns() {
    [ "$(id -u)" = 0 ] && grep -Eq '^ +0 +0 +4294967295$' /proc/self/uid_map \
        || { echo "SETUP_FAILED: needs real root under unshare -nm"; exit 2; }
    ip link set lo up
    ip link add j671d type dummy && ip addr add 192.0.2.89/24 dev j671d && ip link set j671d up
    mount -t tmpfs none /run/systemd
    [ -d /run/dbus ] && mount -t tmpfs none /run/dbus
    # The boot loader reads /var/lib/infraternal; give this namespace its own.
    mount -t tmpfs -o mode=755 none /var/lib
    mkdir -m 700 /var/lib/infraternal
    printf 'Port 22\n' > "$S/cfg"
    mount --bind "$S/cfg" /etc/ssh/sshd_config
    PIDS=()
    setcfg() { printf '%b' "$1" > "$S/cfg"; }
    sshd_on() {
        /usr/sbin/sshd -D -f /etc/ssh/sshd_config -o PidFile=none -E "$S/sshd-$1.log" "${@:2}" &
        PIDS+=($!)
        sleep 0.5 # sleep: let sshd bind before /proc/net is read
    }
    stopall() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; wait "$p" 2>/dev/null; done; PIDS=(); }
    listening() { echo "    listeners: $(awk 'NR>1 && $4=="0A"{print $2}' /proc/net/tcp /proc/net/tcp6 | paste -sd' ')"; }
    SESSION="192.0.2.6 50000 192.0.2.89 22"

    echo "### J658: console, config Port 22, running sshd -p 2222"
    setcfg 'Port 22\n'; sshd_on j658 -p 2222; listening
    plan J658_CONSOLE_RULE22 REFUSED - '*,*,tcp,22'
    plan J658_CONSOLE_BOTH PLANNED - '*,*,tcp,22' '*,*,tcp,2222'
    stopall

    echo "### J670 P2: over SSH, config edited to Port 2222, sshd still on 22"
    setcfg 'Port 2222\n'; sshd_on a -p 22; listening
    plan A_SSH_RULE22 REFUSED "$SESSION" '*,*,tcp,22'
    plan A_SSH_BOTH PLANNED "$SESSION" '*,*,tcp,22' '*,*,tcp,2222'
    plan A_CONSOLE_RULE22 REFUSED - '*,*,tcp,22'
    stopall

    echo "### J670 P3: IPv6-only sshd on 2201, config Port 22"
    setcfg 'Port 22\n'; sshd_on b -o AddressFamily=inet6 -o 'ListenAddress=[::]:2201'; listening
    plan F_FAMILY_MISMATCH REFUSED - '*,*,tcp,22' '*,10.0.0.0/8,tcp,2201'
    plan F_FAMILY_MISMATCH_SSH REFUSED "$SESSION" '*,*,tcp,22' '*,10.0.0.0/8,tcp,2201'
    plan F_FAMILY_MATCH PLANNED - '*,*,tcp,22' '*,fd00::/8,tcp,2201'
    stopall

    echo "### sshd stopped, config Port 2204"
    setcfg 'Port 2204\n'; listening
    plan D_STOPPED_RULE22 REFUSED - '*,*,tcp,22'
    plan D_STOPPED_RULE22_SSH REFUSED "$SESSION" '*,*,tcp,22'
    plan D_STOPPED_RULE2204 PLANNED - '*,*,tcp,2204'

    echo "### boot loader: saved table admits only tcp/22, sshd now configured and running on 2222"
    printf '{"marker":"infraternal-host-firewall-policy-v1","policy":{"admin_rules":[{"interface":null,"source":null,"protocol":"tcp","port":22}],"accept_interfaces":[],"listeners":[],"mesh_enabled":false}}' \
        > /var/lib/infraternal/host-firewall-server.json
    chmod 600 /var/lib/infraternal/host-firewall-server.json
    setcfg 'Port 2222\n'; sshd_on boot; listening
    env -i PATH=/usr/bin:/bin "$BIN" __host-firewall-apply > "$S/boot.out" 2> "$S/boot.err"
    local status=$?
    echo "    loader exit=$status stderr: $(head -c 400 "$S/boot.err")"
    local chain
    chain=$(nft list chain inet infraternal_host input 2>/dev/null | grep -o 'policy [a-z]*' || echo 'no table')
    echo "    live chain: $chain"
    check BOOT_SSHD_MOVED "policy accept" "$chain"
    check BOOT_SSHD_MOVED_FAILS_LOUDLY 1 "$( [ $status -ne 0 ] && grep -q 'NOT enforced' "$S/boot.err" && echo 1 || echo 0)"
    stopall
    echo "### boot loader control: sshd back on 22, the saved table is enforced"
    setcfg 'Port 22\n'; sshd_on boot2; listening
    env -i PATH=/usr/bin:/bin "$BIN" __host-firewall-apply > "$S/boot.out" 2> "$S/boot.err"
    chain=$(nft list chain inet infraternal_host input 2>/dev/null | grep -o 'policy [a-z]*' || echo 'no table')
    check BOOT_CONTROL "policy drop" "$chain"
    stopall
    echo "    listeners after: $(awk 'NR>1 && $4=="0A"' /proc/net/tcp /proc/net/tcp6 | wc -l)"
}

systemd_cases() {
    [ "$(id -u)" = 0 ] || { echo "SETUP_FAILED: needs real root"; exit 2; }
    systemctl show -p LoadState ssh.service | grep -q loaded \
        || { echo "SETUP_FAILED: no loaded ssh.service"; exit 2; }
    D=/run/systemd/system/ssh.service.d
    mkdir -p "$D"
    F=$D/zz-j671.conf
    E=/run/j671-ssh.env
    cleanup() { rm -f "$F" "$E"; rmdir "$D" 2>/dev/null; systemctl daemon-reload; }
    trap cleanup EXIT
    dropin() { printf '[Service]\n%b' "$1" > "$F"; systemctl daemon-reload; }
    configured=$(/usr/sbin/sshd -G | awk '$1=="port"{print $2}' | head -1)
    echo "    host sshd configured port: $configured"
    echo "### SSHD_OPTS=-p 2299 from Environment=, overridden by the stock EnvironmentFile"
    # Debian/Ubuntu's /etc/default/ssh sets SSHD_OPTS= (empty), and an
    # EnvironmentFile wins over Environment=, so the manager would start
    # sshd on its configured port: the check must agree, not over-refuse.
    # (Where the file does not set it, this case is refused like G_OPTIONS.)
    dropin 'Environment="SSHD_OPTS=-p 2299"\n'
    if grep -qs '^SSHD_OPTS=' /etc/default/ssh; then
        plan G_ENVFILE_OVERRIDES_ENVIRONMENT PLANNED - "*,*,tcp,$configured"
    else
        plan G_SSHD_OPTS_RULE_CONFIGURED REFUSED - "*,*,tcp,$configured"
    fi
    plan G_SSHD_OPTS_BOTH PLANNED - "*,*,tcp,$configured" '*,*,tcp,2299'
    echo "### SSHD_OPTS from an EnvironmentFile"
    printf 'SSHD_OPTS="-p 2298"\n' > "$E"
    dropin "EnvironmentFile=$E\n"
    plan G_ENVFILE_RULE_CONFIGURED REFUSED - "*,*,tcp,$configured"
    plan G_ENVFILE_BOTH PLANNED - "*,*,tcp,$configured" '*,*,tcp,2298'
    echo "### ExecStart drop-in using \$OPTIONS"
    dropin 'Environment="OPTIONS=-p 2296"\nExecStart=\nExecStart=/usr/sbin/sshd -D $OPTIONS\n'
    plan G_OPTIONS_RULE_CONFIGURED REFUSED - "*,*,tcp,$configured"
    plan G_OPTIONS_RULE_2296 PLANNED - "*,*,tcp,$configured" '*,*,tcp,2296'
    echo "### a missing, required EnvironmentFile is an unreadable source"
    rm -f "$E"
    dropin "EnvironmentFile=$E\n"
    plan G_ENVFILE_MISSING REFUSED - "*,*,tcp,$configured"
}

case $MODE in
    netns) netns ;;
    systemd) systemd_cases ;;
    *) echo "unknown mode $MODE"; exit 2 ;;
esac
rm -rf "$S"
echo "RESULT=$BAD"
