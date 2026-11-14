#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Mesh data-plane case (#260, part A): one system between two network
# namespaces on this machine, then the same probes for every system.
#
#   mesh.sh <underlay|infraternal|gotatun|boringtun|tailscale|netbird|netbird-userspace|kernel-plain>
#
# Topology (all inside private namespaces; the root namespace is untouched):
#
#   h2h-a (10.220.0.1, a0) ─┐
#   h2h-b (10.220.0.2, b0) ─┼─ bridge br0 in h2h-u
#   h2h-c (10.220.0.3, c0) ─┘   coordination: Tailscale test control + DERP/STUN,
#                               NetBird combined server; idle for the others
#
# Probes run from h2h-a to the peer's mesh address in h2h-b, where one
# `h2h net-server` answers TCP and UDP. The DE↔IN profile adds 99 ms of netem
# delay on a0 and on b0 (198 ms round trip on the a–b path).
source "$H2H_KIT/lib/common.sh"
SYSTEM=$1
H2H_CASE=mesh-$SYSTEM
trap cleanup EXIT

MATRIX_RPS_ACTIVE=0
MATRIX_RPS_OUTDIR=""
matrix_rps_path() {
    printf '%s/%s/%s\n' "$H2H_RESULTS" "$H2H_CASE" "${H2H_MATRIX_ROW_TAG:-control-$(date +%s%N)}"
}

matrix_restore_rps() {
    [[ ${MATRIX_RPS_ACTIVE:-0} == 1 ]] || return 0
    local current_a current_b
    ip netns exec h2h-a sh -c "printf '%s\\n' '$MATRIX_RPS_A_BEFORE' > '$MATRIX_RPS_A_FILE'" || return 1
    ip netns exec h2h-b sh -c "printf '%s\\n' '$MATRIX_RPS_B_BEFORE' > '$MATRIX_RPS_B_FILE'" || return 1
    current_a=$(ip netns exec h2h-a cat "$MATRIX_RPS_A_FILE") || return 1
    current_b=$(ip netns exec h2h-b cat "$MATRIX_RPS_B_FILE") || return 1
    [[ $current_a == "$MATRIX_RPS_A_BEFORE" && $current_b == "$MATRIX_RPS_B_BEFORE" ]] || return 1
    mkdir -p "$MATRIX_RPS_OUTDIR"
    printf '{"policy":"d348-side-rx","restored":true,"a0_rps_cpus":"%s","b0_rps_cpus":"%s"}\n' "$current_a" "$current_b" > "$MATRIX_RPS_OUTDIR/rps-restore.json"
    MATRIX_RPS_ACTIVE=0
}

matrix_apply_rps_policy() {
    local policy=${H2H_MATRIX_RPS_POLICY:-} before_a before_b flow_a flow_b xps_a xps_b after_a after_b
    [[ -z $policy || $policy == d348-side-rx ]] || die "unknown receiver RPS policy: $policy"
    MATRIX_RPS_A_FILE=/sys/class/net/a0/queues/rx-0/rps_cpus
    MATRIX_RPS_B_FILE=/sys/class/net/b0/queues/rx-0/rps_cpus
    before_a=$(ip netns exec h2h-a cat "$MATRIX_RPS_A_FILE") || die "cannot read h2h-a veth RPS state"
    before_b=$(ip netns exec h2h-b cat "$MATRIX_RPS_B_FILE") || die "cannot read h2h-b veth RPS state"
    flow_a=$(ip netns exec h2h-a cat /sys/class/net/a0/queues/rx-0/rps_flow_cnt) || die "cannot read h2h-a RPS flow count"
    flow_b=$(ip netns exec h2h-b cat /sys/class/net/b0/queues/rx-0/rps_flow_cnt) || die "cannot read h2h-b RPS flow count"
    xps_a=$(ip netns exec h2h-a cat /sys/class/net/a0/queues/tx-0/xps_cpus) || die "cannot read h2h-a XPS state"
    xps_b=$(ip netns exec h2h-b cat /sys/class/net/b0/queues/tx-0/xps_cpus) || die "cannot read h2h-b XPS state"
    MATRIX_RPS_OUTDIR=$(matrix_rps_path)
    mkdir -p "$MATRIX_RPS_OUTDIR"
    if [[ -z $policy ]]; then
        printf '{"policy":"baseline-read-only","a0":{"rps_cpus":"%s","rps_flow_cnt":"%s","xps_cpus":"%s"},"b0":{"rps_cpus":"%s","rps_flow_cnt":"%s","xps_cpus":"%s"}}\n' "$before_a" "$flow_a" "$xps_a" "$before_b" "$flow_b" "$xps_b" > "$MATRIX_RPS_OUTDIR/rps-policy.json"
        return 0
    fi
    MATRIX_RPS_A_BEFORE=$before_a
    MATRIX_RPS_B_BEFORE=$before_b
    MATRIX_RPS_ACTIVE=1
    register_cmd matrix_restore_rps
    ip netns exec h2h-a sh -c "printf '6\\n' > '$MATRIX_RPS_A_FILE'" || die "cannot set h2h-a veth RPS"
    ip netns exec h2h-b sh -c "printf '18\\n' > '$MATRIX_RPS_B_FILE'" || die "cannot set h2h-b veth RPS"
    after_a=$(ip netns exec h2h-a cat "$MATRIX_RPS_A_FILE") || die "cannot read back h2h-a veth RPS"
    after_b=$(ip netns exec h2h-b cat "$MATRIX_RPS_B_FILE") || die "cannot read back h2h-b veth RPS"
    printf '{"policy":"d348-side-rx","a0":{"rps_before":"%s","rps_during":"%s","rps_flow_cnt":"%s","xps_unchanged":"%s","target_mask_hex":"6"},"b0":{"rps_before":"%s","rps_during":"%s","rps_flow_cnt":"%s","xps_unchanged":"%s","target_mask_hex":"18"}}\n' "$before_a" "$after_a" "$flow_a" "$xps_a" "$before_b" "$after_b" "$flow_b" "$xps_b" > "$MATRIX_RPS_OUTDIR/rps-policy.json"
    log "receiver RPS: a0 $before_a -> $after_a (side A 1-2); b0 $before_b -> $after_b (side B 3-4); XPS unchanged"
}

LAT_COUNT=$(h2h_lan_latency_count)
WAN_LAT_COUNT=$(dur 300 60)
# The in-app daemon paces ping slower under load than the CLI (about 110 probes/s
# at 8 flows with pinned cores, J610), so its load is sized from the probe count.
if [[ $SYSTEM == infraternal ]]; then
    TPUT_S=$(h2h_lan_tput_duration 72 4 "$LAT_COUNT" "${H2H_LAN_MIN_PROBE_RATE:-110}")
else
    TPUT_S=$(h2h_lan_tput_duration 72 4)
fi
WAN_TPUT_S=$(dur 20 4)
IDLE_S=$(dur 15 3)
GOTATUN_BIN=${H2H_GOTATUN_BIN:-$H2H_BIN/gotatun}
WG_BIN=${H2H_WG_BIN:-$H2H_BIN/wg}
WIREGUARD_GO_BIN=${H2H_WIREGUARD_GO_BIN:-$H2H_BIN/wireguard-go}

record_memcg() {
    local tag=$1 rel path
    rel=$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)
    path="/sys/fs/cgroup$rel"
    if [[ -r "$path/memory.current" && -r "$path/memory.stat" ]]; then
        {
            printf 'memory.current '
            cat "$path/memory.current"
            cat "$path/memory.stat"
        } > "$D/memcg-$tag.txt"
    else
        printf 'unavailable\n' > "$D/memcg-$tag.txt"
    fi
    cp "$D/memcg-$tag.txt" "$H2H_RESULTS/$H2H_CASE/memcg-$tag.txt"
}

for x in u a b c; do netns_add "h2h-$x"; done
ip -n h2h-u link add br0 type bridge
ip -n h2h-u link set br0 up
n=1
for x in a b c; do
    ip link add "${x}0" netns "h2h-$x" type veth peer name "u$x" netns h2h-u
    ip -n h2h-u link set "u$x" master br0 up
    ip -n "h2h-$x" addr add "10.220.0.$n/24" dev "${x}0"
    ip -n "h2h-$x" link set "${x}0" up
    n=$((n + 1))
done
ns_holder A_PID h2h-a
ns_holder B_PID h2h-b
ns_holder C_PID h2h-c
spawn_in_ns NET_SERVER_PID h2h-b "$H" net-server --bind 0.0.0.0:5201
wait_for 10 in_ns h2h-a "$H" net-wait --to 10.220.0.2:5201 --timeout-s 1 || die "underlay not up"

D=$H2H_RUN/$SYSTEM
mkdir -p "$D"
matrix_apply_rps_policy
MATRIX_DIR="$H2H_RESULTS/$H2H_CASE/matrix"
if [[ -n ${H2H_MATRIX_SCENARIO:-} ]]; then
    mkdir -p "$MATRIX_DIR/raw"
    python3 -I "$H2H_KIT/lib/peer_memory.py" --engine "$SYSTEM" --peers 0 --state baseline \
        --raw-dir "$MATRIX_DIR/raw" --output "$MATRIX_DIR/peer-baseline.json" >/dev/null
fi
WATCH=""      # comma-separated PIDs whose process trees are the system's daemons
PEER=""       # the peer's address on the system's own network
TUN_A=""      # tunnel interface on the first measured endpoint, when present
TUN_B=""      # tunnel interface on the second measured endpoint, when present

# fifo_daemon <name> <cmd...>: a child whose stdin we hold open; it stops when
# we close it. Its PID is left in DAEMON_PID.
fifo_daemon() {
    local name=$1 fd; shift
    mkfifo "$D/$name.in"
    "$@" < "$D/$name.in" > "$D/$name.out" 2> "$D/$name.err" &
    DAEMON_PID=$!
    register_pid "$DAEMON_PID"
    exec {fd}> "$D/$name.in"
    register_cmd "echo quit >&$fd; exec $fd>&-; sleep 1"
}
# first_line <file> <seconds>: the daemon's first output line, or failure as soon as it exits.
first_line() {
    local deadline=$((SECONDS + $2))
    until [[ -s $1 ]]; do
        kill -0 "$DAEMON_PID" 2>/dev/null || return 1
        ((SECONDS < deadline)) || return 1
        sleep 0.1
    done
    head -n1 "$1"
}

start_infraternal() {
    note version "{\"infraternal\":\"$("${H2H_INFRATERNAL_BIN:-$H2H_BIN/infraternal}" --version | head -1)\",\"source\":\"${H2H_INFRATERNAL_SOURCE:-$(cat "$H2H_KIT/SOURCE_COMMIT")}\"}"
    fifo_daemon ix sandboxed "$A_PID" env PYTHONPATH="$H2H_KIT/lib" python3 -I "$H2H_KIT/lib/mesh_ix.py" \
        --binary "${H2H_INFRATERNAL_BIN:-$H2H_BIN/infraternal}" --coordinator "$H2H_BIN/coordinator_fixture" \
        --scratch "$D" --pid-b "$B_PID"
    local ready
    ready=$(first_line "$D/ix.out" 60) || die "infraternal mesh did not come up: $(tail -c 600 "$D/ix.err")"
    START=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["start_ns"])' "$ready")
    PEER=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["peer_ipv4"])' "$ready")
    WATCH=$(python3 -c 'import json,sys; print(",".join(map(str, json.loads(sys.argv[1])["pids"])))' "$ready")
    TUN_A=infraternal0
    TUN_B=infraternal0
    note setup "$ready"
}

start_tailscale() {
    mkdir -p "$D/a" "$D/b"
    fifo_daemon ctl sandboxed "$C_PID" "$H2H_BIN/tscontrol" -addr 10.220.0.3 -control-port 9911
    first_line "$D/ctl.out" 30 > /dev/null || die "local Tailscale control did not start: $(tail -c 600 "$D/ctl.err")"
    START=$("$H" now)
    local x pid pids=() ups=()
    for x in a b; do
        local nspid=$A_PID; [[ $x == b ]] && nspid=$B_PID
        H2H_SCOPE_LOG="$D/$x/daemon.log" spawn_sandboxed pid "$nspid" \
            "$H2H_BIN/tailscaled" --tun=tailscale0 --statedir="$D/$x" \
            --socket="$D/$x/sock" --port=41641 --no-logs-no-support
        pids+=("$pid")
    done
    for x in a b; do
        local nspid=$A_PID; [[ $x == b ]] && nspid=$B_PID
        wait_for 30 test -S "$D/$x/sock" || die "tailscaled $x has no socket"
        H2H_SCOPE_LOG="$D/$x/up.log" spawn_sandboxed pid "$nspid" \
            "$H2H_BIN/tailscale" --socket="$D/$x/sock" up --login-server=http://10.220.0.3:9911 \
            --hostname="h2h-$x" --accept-dns=false --accept-routes=false --timeout=60s
        ups+=("$H2H_SCOPE_CLIENT_PID")
    done
    for pid in "${ups[@]}"; do wait "$pid" || die "tailscale up failed: $(tail -c 600 "$D/a/up.log" "$D/b/up.log")"; done
    PEER=$(sandboxed "$B_PID" "$H2H_BIN/tailscale" --socket="$D/b/sock" ip -4)
    WATCH=$(IFS=,; echo "${pids[*]}")
    TUN_A=tailscale0
    TUN_B=tailscale0
    note version "{\"tailscale\":\"$("$H2H_BIN/tailscale" version | head -1)\"}"
}

start_gotatun() {
    local gotatun_version
    mkdir -p "$D/a" "$D/b" "$D/keys"
    command -v openssl >/dev/null || die "GotaTun key setup requires OpenSSL"
    python3 -I "$H2H_KIT/lib/gotatun_uapi.py" keys "$D/keys"
    START=$("$H" now)
    H2H_SCOPE_LOG="$D/a/daemon.log" spawn_sandboxed GOTA_A_PID "$A_PID" \
        env WG_SUDO=1 WG_LOG_LEVEL=error "$GOTATUN_BIN" --foreground wgA
    H2H_SCOPE_LOG="$D/b/daemon.log" spawn_sandboxed GOTA_B_PID "$B_PID" \
        env WG_SUDO=1 WG_LOG_LEVEL=error "$GOTATUN_BIN" --foreground wgB
    wait_for 20 nsenter -t "$GOTA_A_PID" -m -- test -S /var/run/wireguard/wgA.sock \
        || die "GotaTun a UAPI socket did not appear: $(tail -c 600 "$D/a/daemon.log")"
    wait_for 20 nsenter -t "$GOTA_B_PID" -m -- test -S /var/run/wireguard/wgB.sock \
        || die "GotaTun b UAPI socket did not appear: $(tail -c 600 "$D/b/daemon.log")"
    {
        printf 'binary_sha256 '
        sha256sum "$GOTATUN_BIN" | awk '{print $1}'
        awk -v endpoint=a '$1 == "THP_enabled:" {print endpoint, $2}' "/proc/$GOTA_A_PID/status"
        awk -v endpoint=b '$1 == "THP_enabled:" {print endpoint, $2}' "/proc/$GOTA_B_PID/status"
    } > "$H2H_RESULTS/$H2H_CASE/thp-status.txt"

    ip -n h2h-a addr add 10.66.0.1/24 dev wgA
    ip -n h2h-a link set wgA mtu 1420 up
    ip -n h2h-b addr add 10.66.0.2/24 dev wgB
    ip -n h2h-b link set wgB mtu 1420 up
    nsenter -t "$GOTA_A_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgA --private-key "$D/keys/a.private" --peer-public "$D/keys/b.public" \
        --endpoint 10.220.0.2:51821 --listen-port 51820 --allowed-ip 10.66.0.2/32
    nsenter -t "$GOTA_B_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgB --private-key "$D/keys/b.private" --peer-public "$D/keys/a.public" \
        --endpoint 10.220.0.1:51820 --listen-port 51821 --allowed-ip 10.66.0.1/32
    rm -f "$D/keys/"*.private
    WATCH="$GOTA_A_PID,$GOTA_B_PID"
    PEER=10.66.0.2
    TUN_A=wgA
    TUN_B=wgB
    gotatun_version=$("$GOTATUN_BIN" --version | head -1)
    note version "{\"gotatun\":\"$gotatun_version\",\"source\":\"${H2H_GOTATUN_SOURCE:-unknown}\",\"binary_sha256\":\"$(sha256sum "$GOTATUN_BIN" | awk '{print $1}')\",\"mtu\":1420,\"tun_vnet_hdr\":\"attempted-with-fallback\",\"linux_udp_gso_gro_path\":true}"
}

start_wireguard_go() {
    local version
    mkdir -p "$D/a" "$D/b" "$D/keys"
    command -v openssl >/dev/null || die "WireGuard key setup requires OpenSSL"
    python3 -I "$H2H_KIT/lib/gotatun_uapi.py" keys "$D/keys"
    START=$("$H" now)
    H2H_SCOPE_LOG="$D/a/daemon.log" spawn_sandboxed WG_A_PID "$A_PID" \
        env WG_PROCESS_FOREGROUND=1 LOG_LEVEL=error "$WIREGUARD_GO_BIN" wgA
    H2H_SCOPE_LOG="$D/b/daemon.log" spawn_sandboxed WG_B_PID "$B_PID" \
        env WG_PROCESS_FOREGROUND=1 LOG_LEVEL=error "$WIREGUARD_GO_BIN" wgB
    wait_for 20 nsenter -t "$WG_A_PID" -m -- test -S /var/run/wireguard/wgA.sock \
        || die "wireguard-go a UAPI socket did not appear: $(tail -c 600 "$D/a/daemon.log")"
    wait_for 20 nsenter -t "$WG_B_PID" -m -- test -S /var/run/wireguard/wgB.sock \
        || die "wireguard-go b UAPI socket did not appear: $(tail -c 600 "$D/b/daemon.log")"

    ip -n h2h-a addr add 10.66.0.1/24 dev wgA
    ip -n h2h-a link set wgA mtu 1420 up
    ip -n h2h-b addr add 10.66.0.2/24 dev wgB
    ip -n h2h-b link set wgB mtu 1420 up
    nsenter -t "$WG_A_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgA --private-key "$D/keys/a.private" --peer-public "$D/keys/b.public" \
        --endpoint 10.220.0.2:51821 --listen-port 51820 --allowed-ip 10.66.0.2/32
    nsenter -t "$WG_B_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgB --private-key "$D/keys/b.private" --peer-public "$D/keys/a.public" \
        --endpoint 10.220.0.1:51820 --listen-port 51821 --allowed-ip 10.66.0.1/32
    rm -f "$D/keys/"*.private
    WATCH="$WG_A_PID,$WG_B_PID"
    PEER=10.66.0.2
    TUN_A=wgA
    TUN_B=wgB
    version="upstream commit b3bc704ef0ee21a36298601a9e1e5ff90377ac52"
    note version "{\"wireguard_go\":\"$version\",\"source\":\"b3bc704ef0ee21a36298601a9e1e5ff90377ac52\",\"mtu\":1420,\"udp_gso_gro\":true,\"tun_vnet_hdr\":true}"
}

start_boringtun() {
    local boringtun_version
    mkdir -p "$D/a" "$D/b" "$D/keys"
    command -v openssl >/dev/null || die "BoringTun key setup requires OpenSSL"
    python3 -I "$H2H_KIT/lib/gotatun_uapi.py" keys "$D/keys"
    START=$("$H" now)
    H2H_SCOPE_LOG="$D/a/daemon.log" spawn_sandboxed BORING_A_PID "$A_PID" \
        env WG_SUDO=1 WG_LOG_LEVEL=error "$H2H_BIN/boringtun-cli" --foreground wgA
    H2H_SCOPE_LOG="$D/b/daemon.log" spawn_sandboxed BORING_B_PID "$B_PID" \
        env WG_SUDO=1 WG_LOG_LEVEL=error "$H2H_BIN/boringtun-cli" --foreground wgB
    wait_for 20 nsenter -t "$BORING_A_PID" -m -- test -S /var/run/wireguard/wgA.sock \
        || die "BoringTun a UAPI socket did not appear: $(tail -c 600 "$D/a/daemon.log")"
    wait_for 20 nsenter -t "$BORING_B_PID" -m -- test -S /var/run/wireguard/wgB.sock \
        || die "BoringTun b UAPI socket did not appear: $(tail -c 600 "$D/b/daemon.log")"

    ip -n h2h-a addr add 10.66.0.1/24 dev wgA
    ip -n h2h-a link set wgA mtu 1420 up
    ip -n h2h-b addr add 10.66.0.2/24 dev wgB
    ip -n h2h-b link set wgB mtu 1420 up
    nsenter -t "$BORING_A_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgA --private-key "$D/keys/a.private" --peer-public "$D/keys/b.public" \
        --endpoint 10.220.0.2:51821 --listen-port 51820 --allowed-ip 10.66.0.2/32
    nsenter -t "$BORING_B_PID" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" configure \
        --interface wgB --private-key "$D/keys/b.private" --peer-public "$D/keys/a.public" \
        --endpoint 10.220.0.1:51820 --listen-port 51821 --allowed-ip 10.66.0.1/32
    rm -f "$D/keys/"*.private
    WATCH="$BORING_A_PID,$BORING_B_PID"
    PEER=10.66.0.2
    TUN_A=wgA
    TUN_B=wgB
    boringtun_version=$("$H2H_BIN/boringtun-cli" --version | head -1)
    note version "{\"boringtun\":\"$boringtun_version\",\"source\":\"boringtun-cli-0.5.2\",\"workers\":4,\"multi_queue\":true}"
}

start_netbird() {
    local mode=$1
    mkdir -p "$D/a" "$D/b" "$D/srv"
    python3 -I - "$D/srv/config.yaml" "$D/srv" <<'PY'
import os, secrets, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    f.write(f"""server:
  listenAddress: "10.220.0.3:8080"
  exposedAddress: "http://10.220.0.3:8080"
  stunPorts: [3478]
  healthcheckAddress: "10.220.0.3:9000"
  metricsPort: 9090
  logLevel: "warn"
  logFile: "console"
  authSecret: "{secrets.token_urlsafe(32)}"
  dataDir: "{sys.argv[2]}"
  disableAnonymousMetrics: true
  disableGeoliteUpdate: true
  auth:
    issuer: "http://10.220.0.3:8080/oauth2"
  store:
    engine: "sqlite"
""")
PY
    H2H_SCOPE_LOG="$D/srv/server.log" spawn_sandboxed NETBIRD_SERVER_PID "$C_PID" \
        env NB_SETUP_PAT_ENABLED=true NB_DISABLE_GEOLOCATION=true \
        "$H2H_BIN/netbird-server" --config "$D/srv/config.yaml"
    nsenter -t "$C_PID" -n python3 -I "$H2H_KIT/lib/nb_bootstrap.py" http://10.220.0.3:8080 "$D/setup-key" > /dev/null \
        || die "NetBird bootstrap failed: $(tail -c 600 "$D/srv/server.log")"
    START=$("$H" now)
    local x pid pids=() kernel_env=()
    [[ $mode == userspace ]] && kernel_env=(NB_WG_KERNEL_DISABLED=true)
    for x in a b; do
        local nspid=$A_PID; [[ $x == b ]] && nspid=$B_PID
        H2H_SCOPE_LOG="$D/$x/up.log" spawn_sandboxed pid "$nspid" \
            env NB_STATE_DIR="$D/$x" "${kernel_env[@]}" "$H2H_BIN/netbird" up --foreground-mode \
            --management-url http://10.220.0.3:8080 --setup-key-file "$D/setup-key" --config "$D/$x/config.json" \
            --daemon-addr "unix://$D/$x/sock" --log-file "$D/$x/client.log" --disable-dns --hostname "h2h-$x"
        pids+=("$pid")
    done
    wait_for 60 sh -c "ip -n h2h-b -4 -o addr show dev wt0 | grep -q inet" || die "NetBird gave b no address: $(tail -c 600 "$D/b/client.log")"
    PEER=$(ip -n h2h-b -4 -o addr show dev wt0 | awk '{print $4}' | cut -d/ -f1)
    WATCH=$(IFS=,; echo "${pids[*]}")
    TUN_A=wt0
    TUN_B=wt0
    if [[ $mode == kernel ]]; then
        ip -n h2h-a link set wt0 mtu 1280
        ip -n h2h-b link set wt0 mtu 1280
    fi
    note version "{\"netbird\":\"$("$H2H_BIN/netbird" version | head -1)\",\"wireguard\":\"$(ip -n h2h-a -d link show wt0 | grep -q wireguard && echo kernel || echo userspace)\",\"mtu\":$(ip -n h2h-a -o link show wt0 | sed -n 's/.* mtu \\([0-9][0-9]*\\).*/\\1/p')}"
}

start_kernel_plain() {
    # Build the native WireGuard data path directly, without a coordinating daemon.
    mkdir -p "$D/keys"
    python3 -I "$H2H_KIT/lib/gotatun_uapi.py" keys "$D/keys"
    python3 -I "$H2H_KIT/lib/wg_cli_keys.py" "$D/keys"
    START=$("$H" now)
    ip -n h2h-a link add wgA type wireguard
    ip -n h2h-b link add wgB type wireguard
    ip -n h2h-a addr add 10.66.0.1/24 dev wgA
    ip -n h2h-a link set wgA mtu 1420 up
    ip -n h2h-b addr add 10.66.0.2/24 dev wgB
    ip -n h2h-b link set wgB mtu 1420 up
    ip netns exec h2h-a "$WG_BIN" set wgA \
        private-key "$D/keys/a.wg.private" listen-port 51820 \
        peer "$(cat "$D/keys/b.wg.public")" endpoint 10.220.0.2:51821 \
        allowed-ips 10.66.0.2/32
    ip netns exec h2h-b "$WG_BIN" set wgB \
        private-key "$D/keys/b.wg.private" listen-port 51821 \
        peer "$(cat "$D/keys/a.wg.public")" endpoint 10.220.0.1:51820 \
        allowed-ips 10.66.0.1/32
    ip netns exec h2h-a "$WG_BIN" show wgA
    ip netns exec h2h-b "$WG_BIN" show wgB
    if [[ -n ${H2H_MATRIX_SCENARIO:-} ]]; then
        # Matrix peer-memory samples reapply kernel configs after traffic probes; keep only the protected CLI keys until that sweep ends.
        rm -f "$D/keys/a.private" "$D/keys/b.private"
    else
        rm -f "$D/keys/"*.private "$D/keys/"*.public "$D/keys/"*.wg.private "$D/keys/"*.wg.public
    fi
    TUN_A=wgA
    TUN_B=wgB
    PEER=10.66.0.2
    note version '{"wireguard":"kernel","method":"ip-link-add-and-wg-set","netbird":false,"mtu":1420}'
}

record_link_offloads() {
    local ethtool=${H2H_ETHTOOL_BIN:-}
    local -a arguments
    if [[ -z $ethtool ]]; then
        ethtool=$(command -v ethtool || true)
    fi
    [[ -x $ethtool ]] || die "ethtool is required to record per-row link offloads"
    arguments=(
        --system "$SYSTEM"
        --ethtool "$ethtool"
        --output-dir "$H2H_RESULTS/$H2H_CASE/offloads"
        --interface h2h-a a0 underlay
        --interface h2h-b b0 underlay
    )
    [[ -z $TUN_A ]] || arguments+=(--interface h2h-a "$TUN_A" tunnel)
    [[ -z $TUN_B ]] || arguments+=(--interface h2h-b "$TUN_B" tunnel)
    python3 -I "$H2H_KIT/lib/link_offloads.py" "${arguments[@]}" \
        || die "ethtool offload capture failed for $SYSTEM"
}

matrix_read_scenario() {
    local -a values=()
    [[ -r ${H2H_MATRIX_CONFIG:-} ]] || die "matrix scenario config is missing: ${H2H_MATRIX_CONFIG:-unset}"
    mapfile -t values < <(python3 -I - "$H2H_MATRIX_CONFIG" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
fields = (
    ("inner_mtu_bytes", 1420),
    ("delay_each_direction_ms", ""),
    ("jitter_each_direction_ms", ""),
    ("loss_each_direction_percent", 0),
    ("tcp_flows", []),
    ("latency_payload_bytes", ""),
    ("latency_probes", 0),
    ("loaded_latency_interval_us", 1000),
    ("tput_seconds", 10),
    ("udp_payload_bytes", []),
    ("udp_probe_count", 0),
    ("idle_latency_probes", value.get("latency_probes", 0)),
    ("idle_latency_interval_us", value.get("loaded_latency_interval_us", 1000)),
    ("peer_counts_per_endpoint", [1, 100, 1000]),
    ("forced_rehandshakes", 0),
    ("noise_cpu", ""),
    ("rate_each_direction_mbit", ""),
    ("loss_gemodel", ""),
    ("latency_probe", "net-lat"),
    ("shaping", "legacy"),
)
for key, fallback in fields:
    current = value.get(key, fallback)
    if isinstance(current, list):
        current = ",".join(str(item) for item in current)
    print("" if current is None else current)
PY
)
    [[ ${#values[@]} == 20 ]] || die "could not decode the canonical matrix scenario config"
    M_MTU=${values[0]}
    M_DELAY=${values[1]}
    M_JITTER=${values[2]}
    M_LOSS=${values[3]}
    M_TCP_FLOWS=${values[4]}
    M_LATENCY_SIZE=${values[5]}
    M_LATENCY_COUNT=${values[6]}
    M_LATENCY_INTERVAL=${values[7]}
    M_TPUT_SECONDS=${values[8]}
    M_UDP_SIZES=${values[9]}
    M_UDP_COUNT=${values[10]}
    M_IDLE_COUNT=${values[11]}
    M_IDLE_INTERVAL=${values[12]}
    M_PEER_COUNTS=${values[13]}
    M_HANDSHAKE_COUNT=${values[14]}
    M_NOISE_CPU=${values[15]}
    M_RATE=${values[16]}
    M_GEMODEL=${values[17]}
    M_PROBE=${values[18]}
    M_SHAPING=${values[19]}
    [[ $M_MTU == 1420 ]] || die "D348 matrix MTU must stay at 1420, got $M_MTU"
}

matrix_record_artifacts() {
    local binary="" wg_tool="$WG_BIN"
    case $SYSTEM in
        gotatun) binary=$GOTATUN_BIN ;;
        wireguard-go) binary="$WIREGUARD_GO_BIN" ;;
        kernel-plain) ;;
        *) die "matrix does not compare $SYSTEM" ;;
    esac
    local -a args=(--engine "$SYSTEM" --wg-tool "$wg_tool" --output "$MATRIX_DIR/artifacts.json")
    [[ -z $binary ]] || args+=(--binary "$binary")
    python3 -I "$H2H_KIT/lib/artifact_footprint.py" "${args[@]}" >/dev/null \
        || die "artifact footprint capture failed for $SYSTEM"
}

matrix_start_noise() {
    [[ -n $M_NOISE_CPU ]] || return 0
    taskset -c "$M_NOISE_CPU" bash -c 'while :; do :; done' >/dev/null 2>&1 &
    MATRIX_NOISE_PID=$!
    register_pid "$MATRIX_NOISE_PID"
    wait_for 2 test -r "/proc/$MATRIX_NOISE_PID/status" || die "housekeeping noise process did not start"
    local allowed
    allowed=$(awk '/^Cpus_allowed_list:/ {print $2}' "/proc/$MATRIX_NOISE_PID/status")
    [[ $allowed == "$M_NOISE_CPU" ]] || die "noise process affinity is $allowed, expected housekeeping CPU $M_NOISE_CPU"
    printf '{"pid":%s,"cpus_allowed_list":"%s","role":"housekeeping-only CPU contention"}\n' \
        "$MATRIX_NOISE_PID" "$allowed" > "$MATRIX_DIR/housekeeping-noise.json"
}

matrix_start_syscall_counter() {
    local output=$1 seconds=$2 perf_bin
    MATRIX_PERF_PID=""
    if [[ -x ${H2H_BIN:-}/perf ]]; then
        perf_bin="$H2H_BIN/perf"
    else
        perf_bin=$(command -v perf || true)
    fi
    if [[ -n $perf_bin ]]; then
        taskset -c "${H2H_CPUSET_HOUSEKEEPING:-0,5}" "$perf_bin" stat -a -C 1-4 \
            -e raw_syscalls:sys_enter -o "$output" -- sleep "$seconds" \
            > "$output.stdout" 2> "$output.stderr" &
        MATRIX_PERF_PID=$!
        sleep 0.05
    else
        printf 'perf utility unavailable in kit bin and PATH\n' > "$output"
        printf 'tracepoint counting unavailable; value remains null\n' > "$output.stderr"
    fi
}

matrix_finish_syscall_counter() {
    local prefix=$1 perf_log=$2 throughput_json=$3
    if [[ -n ${MATRIX_PERF_PID:-} ]]; then
        wait "$MATRIX_PERF_PID" || true
        MATRIX_PERF_PID=""
    fi
    local gbit seconds
    read -r gbit seconds < <(python3 -I - "$throughput_json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
print(value.get("gbit_per_s", value.get("payload_gbit_per_s", 0)),
      value.get("seconds", value.get("send_elapsed_s", 0)))
PY
)
    python3 -I "$H2H_KIT/lib/syscall_stats.py" --log "$perf_log" \
        --gbit-per-second "$gbit" --seconds "$seconds" \
        --output "$MATRIX_DIR/$prefix-syscalls.json" >/dev/null
}

matrix_stop_syscall_counter() {
    if [[ -n ${MATRIX_PERF_PID:-} ]]; then
        kill -INT "$MATRIX_PERF_PID" 2>/dev/null || true
        wait "$MATRIX_PERF_PID" || true
        MATRIX_PERF_PID=""
    fi
}

matrix_tcp_retrans_segments() {
    local ns=$1 value
    value=$(in_ns "$ns" awk '
        $1 == "Tcp:" && !header {
            for (i = 1; i <= NF; i++) if ($i == "RetransSegs") column = i
            header = 1
            next
        }
        $1 == "Tcp:" && header { print $column; found = 1; exit }
        END { if (!found || !column) exit 1 }
    ' /proc/net/snmp) || return 1
    [[ $value =~ ^[0-9]+$ ]] || return 1
    printf '%s\n' "$value"
}

# Where each direction's netem queue lives, as "<namespace> <device>" pairs. Legacy shaping puts
# netem on the sender's egress; per-packet shaping puts it on an ifb at the receiver's ingress.
SHAPE_DEV_AB="h2h-a a0"
SHAPE_DEV_BA="h2h-b b0"

# Turn the segmentation and coalescing offloads off on one veth end and prove they are off.
# Features are switched one by one because an unknown name must not undo the others.
matrix_veth_offloads_off() { # matrix_veth_offloads_off <ns> <dev>
    local ns=$1 dev=$2 feature state
    local ethtool=${H2H_ETHTOOL_BIN:-$(command -v ethtool || echo /usr/sbin/ethtool)}
    [[ -x $ethtool ]] || die "ethtool is required for per-packet shaping"
    for feature in gso tso gro tx-udp-segmentation tx-udp_tnl-segmentation tx-udp_tnl-csum-segmentation \
        tx-gso-list rx-gro-list rx-udp-gro-forwarding tx-gso-partial; do
        ip netns exec "$ns" "$ethtool" -K "$dev" "$feature" off >/dev/null 2>&1 || true
    done
    ip netns exec "$ns" "$ethtool" -k "$dev" > "$MATRIX_DIR/shaping-offloads-$ns-$dev.txt" 2>&1 || true
    for feature in generic-segmentation-offload tcp-segmentation-offload tx-udp-segmentation generic-receive-offload; do
        state=$(awk -v name="$feature:" '$1 == name { print $2 }' "$MATRIX_DIR/shaping-offloads-$ns-$dev.txt")
        [[ -z $state || $state == off ]] || die "$ns/$dev still has $feature $state after switching offloads off"
    done
}

# Apply the scenario's netem to the A<->B underlay.
#   legacy     : netem on each side's egress with offloads as found. netem decides per skb, and a
#                GSO skb (up to 64 KB of WireGuard packets) is dropped or spared as one unit, and
#                software segmentation happens after the qdisc, so loss comes in batches.
#   per-packet : offloads off on both veth ends, so the sender's veth segments every skb into
#                MTU-sized packets before they reach the peer, and netem on an ifb fed from the
#                receiver's ingress, so every wire packet gets its own loss decision.
# Either way each direction gets the same delay, jitter, loss and rate as before.
matrix_apply_shaping() { # matrix_apply_shaping <netem args...>
    local shaping=${M_SHAPING:-legacy}
    case $shaping in
        legacy)
            netem_set h2h-a a0 "$@"
            netem_set h2h-b b0 "$@"
            SHAPE_DEV_AB="h2h-a a0"
            SHAPE_DEV_BA="h2h-b b0"
            ;;
        per-packet)
            matrix_veth_offloads_off h2h-a a0
            matrix_veth_offloads_off h2h-b b0
            local -a netem_args=("$@")
            local pair ns dev ifb
            for pair in "h2h-b b0 ifb-hb" "h2h-a a0 ifb-ha"; do
                read -r ns dev ifb <<< "$pair"
                ip -n "$ns" link add "$ifb" type ifb || die "cannot create $ifb in $ns (ifb module missing?)"
                ip -n "$ns" link set dev "$ifb" txqueuelen 10000 up
                tc -n "$ns" qdisc add dev "$dev" handle ffff: ingress
                tc -n "$ns" filter add dev "$dev" parent ffff: protocol all u32 match u32 0 0 \
                    action mirred egress redirect dev "$ifb"
                tc -n "$ns" qdisc replace dev "$ifb" root netem limit 200000 "${netem_args[@]}"
            done
            SHAPE_DEV_AB="h2h-b ifb-hb"
            SHAPE_DEV_BA="h2h-a ifb-ha"
            ;;
        *) die "unknown shaping $shaping" ;;
    esac
    echo "$shaping" > "$MATRIX_DIR/shaping.txt"
    tc -n "${SHAPE_DEV_AB% *}" -s qdisc show dev "${SHAPE_DEV_AB#* }" > "$MATRIX_DIR/netem-ab.txt"
    tc -n "${SHAPE_DEV_BA% *}" -s qdisc show dev "${SHAPE_DEV_BA#* }" > "$MATRIX_DIR/netem-ba.txt"
}

# Save both directions' netem counters as JSON (`tc -s -j`), for wire_loss.py.
matrix_wire_snapshot() { # matrix_wire_snapshot <stem>
    tc -n "${SHAPE_DEV_AB% *}" -s -j qdisc show dev "${SHAPE_DEV_AB#* }" > "$1-ab.json" 2>/dev/null || true
    tc -n "${SHAPE_DEV_BA% *}" -s -j qdisc show dev "${SHAPE_DEV_BA#* }" > "$1-ba.json" 2>/dev/null || true
}

# Once a second, write `<epoch seconds> <bytes>` where bytes is the total the receiving
# namespace has taken in over every TCP connection to the benchmark port. progress.py turns
# the file into silent-second and longest-stall counts, so a flow that stays up but delivers
# nothing is visible even when the average goodput looks fine. Runs until it is stopped.
matrix_progress_sampler() { # matrix_progress_sampler <tsv> <seconds>
    local out=$1 seconds=$2 tick total
    : > "$out"
    for ((tick = 0; tick <= seconds + 3; tick++)); do
        # A sample with no connection yet (or no bytes_received field) must count as zero, not
        # end the loop: this runs under `set -eo pipefail`, where grep's "no match" would kill it.
        total=$({ ip netns exec h2h-b ss -H -tin state established '( sport = :5201 )' 2>/dev/null || true; } \
            | { grep -o 'bytes_received:[0-9]*' || true; } | awk -F: '{ sum += $2 } END { print sum + 0 }') || total=0
        printf '%s %s\n' "$(date +%s.%N)" "$total" >> "$out"
        sleep 1 # sleep: the stall sampler takes one receiver byte count per second
    done
}

matrix_tcp_sample() { # matrix_tcp_sample <prefix> <flows> <seconds> <probes> <interval-us> <udp-payload> [loaded-memory-peer-count]
    local prefix=$1 flows=$2 seconds=$3 probes=$4 interval=$5 size=$6
    local memory_peers=${7:-}
    local latency_pid tput_pid latency_client tput_client latency_tmp tput_tmp latency_err tput_err
    local retrans_before_a retrans_before_b retrans_after_a retrans_after_b retrans_a retrans_b
    local latency_json="$MATRIX_DIR/$prefix-latency.json"
    local tput_json="$MATRIX_DIR/$prefix-throughput.json"
    local perf_log="$MATRIX_DIR/$prefix-syscalls.perf.txt"
    latency_tmp="$latency_json.tmp"
    tput_tmp="$tput_json.tmp"
    latency_err="$latency_json.err"
    tput_err="$tput_json.err"
    local -a latency_command=("$H" net-lat --to "$PEER:5201" --size "$size" --count "$probes" \
        --interval-us "$interval" --raw-path "$MATRIX_DIR/$prefix-latency.jsonl")
    local latency_stdout=$latency_tmp latency_stderr=$latency_err latency_raw=""
    if [[ ${M_PROBE:-net-lat} == icmp ]]; then
        # ICMP probes under the load, `ping -D -O -n`, summarized by pingstat's loss-aware rule
        # (each lost reply ranks as an infinite RTT). The raw log is kept beside the JSON.
        latency_raw="$MATRIX_DIR/$prefix-latency.raw"
        latency_stdout=$latency_raw
        latency_stderr=$latency_raw
        latency_command=(ping -D -O -n -i "$(awk -v us="$interval" 'BEGIN { printf "%.6f", us / 1000000 }')" \
            -c "$probes" "$PEER")
    fi
    H2H_SCOPE_PAUSE=1 H2H_SCOPE_LOG="$D/$prefix-latency-scope.log" \
        H2H_SCOPE_STDOUT="$latency_stdout" H2H_SCOPE_STDERR="$latency_stderr" \
        spawn_in_ns latency_pid h2h-a "${latency_command[@]}"
    latency_client=$H2H_SCOPE_CLIENT_PID
    H2H_SCOPE_PAUSE=1 H2H_SCOPE_LOG="$D/$prefix-tput-scope.log" \
        H2H_SCOPE_STDOUT="$tput_tmp" H2H_SCOPE_STDERR="$tput_err" \
        spawn_in_ns tput_pid h2h-a "$H" net-tput --to "$PEER:5201" \
            --flows "$flows" --seconds "$seconds" --pids "$WATCH"
    tput_client=$H2H_SCOPE_CLIENT_PID
    h2h_cpu_audit_start "$prefix"
    matrix_start_syscall_counter "$perf_log" "$seconds"
    retrans_before_a=$(matrix_tcp_retrans_segments h2h-a) || die "cannot read h2h-a Tcp.RetransSegs before $prefix"
    retrans_before_b=$(matrix_tcp_retrans_segments h2h-b) || die "cannot read h2h-b Tcp.RetransSegs before $prefix"
    [[ -z ${M_DELAY:-} ]] || matrix_wire_snapshot "$MATRIX_DIR/$prefix-wire-before"
    kill -CONT "$latency_pid" "$tput_pid"
    local progress_pid=""
    if [[ ${M_PROBE:-net-lat} == icmp ]]; then
        matrix_progress_sampler "$MATRIX_DIR/$prefix-progress.tsv" "$seconds" &
        progress_pid=$!
    fi
    if [[ -n $memory_peers ]]; then
        # Capture while the common TCP load is active; WATCH contains only the
        # engine process trees, so the probe and harness do not enter RSS.
        sleep 1
        matrix_peer_memory "$memory_peers" loaded 0
    fi

    local tput_status=0 latency_status=0 audit_status=0
    if wait "$tput_client"; then
        mv "$tput_tmp" "$tput_json"
        rm -f "$tput_err"
        log "$prefix throughput: $(head -c 400 "$tput_json")"
    else
        tput_status=$?
        mv "$tput_tmp" "$tput_json.failed" 2>/dev/null || true
        log "$prefix throughput failed: $(tail -c 400 "$tput_err")"
    fi
    if wait "$latency_client"; then
        if [[ -n $latency_raw ]]; then
            python3 -I "$H2H_KIT/lib/pingstat.py" --matrix-json --interval-us "$interval" \
                --expected-sent "$probes" "$latency_raw" > "$latency_json" || latency_status=$?
        else
            mv "$latency_tmp" "$latency_json"
            rm -f "$latency_err"
        fi
        log "$prefix loaded latency: $(head -c 400 "$latency_json")"
    else
        latency_status=$?
        mv "$latency_tmp" "$latency_json.failed" 2>/dev/null || true
        log "$prefix loaded latency failed: $(tail -c 400 "$latency_err")"
    fi
    if [[ -n ${M_DELAY:-} ]]; then
        matrix_wire_snapshot "$MATRIX_DIR/$prefix-wire-after"
        python3 -I "$H2H_KIT/lib/wire_loss.py" --stem "$MATRIX_DIR/$prefix-wire" \
            --shaping "${M_SHAPING:-legacy}" --loss "${M_LOSS:-0}" --gemodel "${M_GEMODEL:-}" \
            --output "$MATRIX_DIR/$prefix-wire.json" >/dev/null || log "$prefix wire-loss summary failed"
    fi
    if [[ -n $progress_pid ]]; then
        stop_pid "$progress_pid"
        wait "$progress_pid" 2>/dev/null || true
        python3 -I "$H2H_KIT/lib/progress.py" --tsv "$MATRIX_DIR/$prefix-progress.tsv" \
            --output "$MATRIX_DIR/$prefix-progress.json" >/dev/null \
            || log "$prefix progress summary failed"
    fi
    retrans_after_a=$(matrix_tcp_retrans_segments h2h-a) || die "cannot read h2h-a Tcp.RetransSegs after $prefix"
    retrans_after_b=$(matrix_tcp_retrans_segments h2h-b) || die "cannot read h2h-b Tcp.RetransSegs after $prefix"
    retrans_a=$((retrans_after_a - retrans_before_a))
    retrans_b=$((retrans_after_b - retrans_before_b))
    printf '{"counter":"Tcp.RetransSegs","source":"per-netns /proc/net/snmp","a_before":%s,"a_after":%s,"a_delta":%s,"b_before":%s,"b_after":%s,"b_delta":%s,"total_retransmits":%s}
' "$retrans_before_a" "$retrans_after_a" "$retrans_a" "$retrans_before_b" "$retrans_after_b" "$retrans_b" "$((retrans_a + retrans_b))" > "$MATRIX_DIR/$prefix-retransmits.json"
    if h2h_cpu_audit_stop; then :; else audit_status=$?; fi
    if ((tput_status == 0)); then
        matrix_finish_syscall_counter "$prefix" "$perf_log" "$tput_json"
    elif [[ -n ${MATRIX_PERF_PID:-} ]]; then
        wait "$MATRIX_PERF_PID" || true
        MATRIX_PERF_PID=""
    fi
    ((tput_status == 0 && latency_status == 0 && audit_status == 0)) \
        || die "D348 matrix workload/audit failed for $prefix ($tput_status/$latency_status/$audit_status)"
}

matrix_idle_latency() { # matrix_idle_latency <tag> <payload-bytes> <count> <interval-us>
    local tag=$1 size=$2 count=$3 interval=$4
    measure "matrix/$tag" in_ns h2h-a "$H" net-lat --to "$PEER:5201" --size "$size" \
        --count "$count" --interval-us "$interval" --raw-path "$MATRIX_DIR/$tag.jsonl"
}

matrix_idle_cpu() {
    local seconds=${H2H_MATRIX_IDLE_CPU_SECONDS:-10}
    local status=0 sample_status
    python3 -I "$H2H_KIT/lib/kernel_idle_cpu.py" --engine "$SYSTEM" --pids "$WATCH" \
        --seconds "$seconds" --output "$MATRIX_DIR/idle-cpu.json" \
        > "$MATRIX_DIR/idle-cpu.stdout" 2> "$MATRIX_DIR/idle-cpu.stderr" || status=$?
    [[ -s $MATRIX_DIR/idle-cpu.json ]] || die "idle CPU accounting produced no JSON"
    sample_status=$(python3 -I - "$MATRIX_DIR/idle-cpu.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("status", "unavailable"))
PY
)
    ((status == 0)) && [[ $sample_status == measured ]] \
        || die "idle CPU accounting failed for $SYSTEM: $(head -c 400 "$MATRIX_DIR/idle-cpu.json")"
    log "idle CPU accounting for $SYSTEM: $(head -c 400 "$MATRIX_DIR/idle-cpu.json")"
}

matrix_warmup() {
    local tmp="$MATRIX_DIR/warmup.json.tmp" error="$MATRIX_DIR/warmup.json.err"
    in_ns h2h-a "$H" net-wait --to "$PEER:5201" --timeout-s 10 \
        > "$tmp" 2> "$error" \
        || die "the common first-packet warmup failed for $SYSTEM: $(tail -c 400 "$error")"
    mv "$tmp" "$MATRIX_DIR/warmup.json"
    rm -f "$error"
}

matrix_peer_memory() { # matrix_peer_memory <peer-count> [idle|loaded] [settle-seconds]
    local peers=$1 state=${2:-idle} settle=${3:-$IDLE_S}
    local process_json="$MATRIX_DIR/peer-$peers-$state-processes.json"
    log "capturing $state RSS and kernel memory at $peers peers after ${settle}s"
    if ((settle > 0)); then sleep "$settle"; fi
    "$H" proc-mem --pids "$WATCH" > "$process_json"
    python3 -I "$H2H_KIT/lib/peer_memory.py" --engine "$SYSTEM" --peers "$peers" --state "$state" \
        --baseline "$MATRIX_DIR/peer-baseline.json" --process-memory "$process_json" \
        --raw-dir "$MATRIX_DIR/raw" --output "$MATRIX_DIR/peer-$peers-$state-memory.json" >/dev/null \
        || die "peer memory capture failed at $peers peers"
}

matrix_set_peer_count() { # matrix_set_peer_count <total-count>
    local peers=$1 current=${MATRIX_PEER_CURRENT:-1} start owner_a owner_b
    ((peers == 100 || peers == 1000)) || die "unsupported matrix peer count $peers"
    ((peers > current)) || die "matrix peer counts must increase monotonically: $current to $peers"
    start=$current
    case $SYSTEM in
        gotatun) owner_a=$GOTA_A_PID; owner_b=$GOTA_B_PID ;;
        wireguard-go) owner_a=$WG_A_PID; owner_b=$WG_B_PID ;;
        kernel-plain)
            local inert=$((peers - 1)) cfg_a="$D/peers-a-$peers.conf" cfg_b="$D/peers-b-$peers.conf"
            # Keep each interface's active peer bound to the opposite endpoint key.
            python3 -I "$H2H_KIT/lib/peer_scale.py" kernel-config --count "$inert" --start 1 \
                --interface-private-key-file "$D/keys/a.wg.private" --listen-port 51820 \
                --active-public "$(cat "$D/keys/b.public")" --active-ip 10.66.0.2/32 \
                --active-endpoint 10.220.0.2:51821 --output "$cfg_a" > "$D/peers-a-$peers.json"
            python3 -I "$H2H_KIT/lib/peer_scale.py" kernel-config --count "$inert" --start 1 \
                --interface-private-key-file "$D/keys/b.wg.private" --listen-port 51821 \
                --active-public "$(cat "$D/keys/a.public")" --active-ip 10.66.0.1/32 \
                --active-endpoint 10.220.0.1:51820 --output "$cfg_b" > "$D/peers-b-$peers.json"
            ip netns exec h2h-a "$WG_BIN" setconf wgA "$cfg_a"
            ip netns exec h2h-b "$WG_BIN" setconf wgB "$cfg_b"
            # The generated setconf files hold private keys and are mode 0600.
            rm -f "$cfg_a" "$cfg_b"
            ;;
        *) die "matrix peer scaling does not support $SYSTEM" ;;
    esac
    if [[ $SYSTEM != kernel-plain ]]; then
        nsenter -t "$owner_a" -n -m -- python3 -I "$H2H_KIT/lib/peer_scale.py" add-uapi \
            --interface wgA --count "$((peers - start))" --start "$start" > "$D/peers-a-$peers.json"
        nsenter -t "$owner_b" -n -m -- python3 -I "$H2H_KIT/lib/peer_scale.py" add-uapi \
            --interface wgB --count "$((peers - current))" --start "$current" > "$D/peers-b-$peers.json"
    fi
    local count_a count_b
    if [[ $SYSTEM == kernel-plain ]]; then
        count_a=$(ip netns exec h2h-a "$WG_BIN" show wgA peers | wc -l)
        count_b=$(ip netns exec h2h-b "$WG_BIN" show wgB peers | wc -l)
    else
        count_a=$(nsenter -t "$owner_a" -n -m -- "$WG_BIN" show wgA peers | wc -l)
        count_b=$(nsenter -t "$owner_b" -n -m -- "$WG_BIN" show wgB peers | wc -l)
    fi
    [[ $count_a -eq $peers && $count_b -eq $peers ]] \
        || die "peer count mismatch at $peers: endpoint A=$count_a endpoint B=$count_b"
    MATRIX_PEER_CURRENT=$peers
}

matrix_peer_memory_sweep() {
    local count
    for count in ${M_PEER_COUNTS//,/ }; do
        if ((count > 1)); then matrix_set_peer_count "$count"; fi
        matrix_peer_memory "$count" idle
    done
}

matrix_peer_reset() {
    local peer_a peer_b owner_a owner_b
    case $SYSTEM in
        kernel-plain)
            peer_a=$(cat "$D/keys/a.wg.public"); peer_b=$(cat "$D/keys/b.wg.public")
            ip netns exec h2h-a "$WG_BIN" set wgA peer "$peer_b" remove
            ip netns exec h2h-b "$WG_BIN" set wgB peer "$peer_a" remove
            ip netns exec h2h-a "$WG_BIN" set wgA peer "$peer_b" endpoint 10.220.0.2:51821 allowed-ips 10.66.0.2/32
            ip netns exec h2h-b "$WG_BIN" set wgB peer "$peer_a" endpoint 10.220.0.1:51820 allowed-ips 10.66.0.1/32
            ;;
        gotatun)
            owner_a=$GOTA_A_PID; owner_b=$GOTA_B_PID
            peer_a="$D/keys/a.public"; peer_b="$D/keys/b.public"
            ;;
        wireguard-go)
            owner_a=$WG_A_PID; owner_b=$WG_B_PID
            peer_a="$D/keys/a.public"; peer_b="$D/keys/b.public"
            ;;
        *) die "matrix handshake reset does not support $SYSTEM" ;;
    esac
    if [[ $SYSTEM != kernel-plain ]]; then
        nsenter -t "$owner_a" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" peer-update \
            --interface wgA --peer-public "$peer_b" --endpoint 10.220.0.2:51821 --allowed-ip 10.66.0.2/32
        nsenter -t "$owner_b" -n -m -- python3 -I "$H2H_KIT/lib/gotatun_uapi.py" peer-update \
            --interface wgB --peer-public "$peer_a" --endpoint 10.220.0.1:51820 --allowed-ip 10.66.0.1/32
    fi
}

matrix_handshake_storm() {
    local cycle started_ns cycle_json cycle_tmp
    local raw="$MATRIX_DIR/handshake-storm.jsonl"
    : > "$raw"
    h2h_cpu_audit_start handshake-storm
    for cycle in $(seq 1 "$M_HANDSHAKE_COUNT"); do
        started_ns=$("$H" now)
        matrix_peer_reset
        cycle_json="$MATRIX_DIR/handshake-$cycle.json"
        cycle_tmp="$cycle_json.tmp"
        in_ns h2h-a "$H" net-wait --to "$PEER:5201" --since-ns "$started_ns" --timeout-s 10 \
            > "$cycle_tmp" 2> "$cycle_json.err" \
            || { mv "$cycle_tmp" "$cycle_json.failed" 2>/dev/null || true; die "first packet failed after handshake reset $cycle"; }
        mv "$cycle_tmp" "$cycle_json"
        python3 -I - "$cycle" "$cycle_json" >> "$raw" <<'PY'
import json, sys
value = json.load(open(sys.argv[2], encoding="utf-8"))
value["cycle"] = int(sys.argv[1])
print(json.dumps(value, sort_keys=True))
PY
    done
    h2h_cpu_audit_stop || die "D348 audit failed during the reconnect/handshake storm"
    printf '{"forced_rehandshakes":%s,"successful_first_packets":%s,"semantics":"serial peer reset followed by one first-packet handshake probe"}\n' \
        "$M_HANDSHAKE_COUNT" "$M_HANDSHAKE_COUNT" > "$MATRIX_DIR/handshake-storm-summary.json"
}

matrix_udp_pps() { # matrix_udp_pps <payload-bytes>
    local size=$1 output="$MATRIX_DIR/udp-$1-pps.json" tmp="$MATRIX_DIR/udp-$1-pps.json.tmp"
    local error="$MATRIX_DIR/udp-$1-pps.json.err" perf_log="$MATRIX_DIR/udp-$1-syscalls.perf.txt"
    local cpu_before="$MATRIX_DIR/udp-$1-cpu-before.json" cpu_after="$MATRIX_DIR/udp-$1-cpu-after.json"
    local status=0
    h2h_cpu_audit_start "udp-pps-$size"
    matrix_start_syscall_counter "$perf_log" 300
    python3 -I "$H2H_KIT/lib/matrix.py" cpu-snapshot --output "$cpu_before" >/dev/null
    in_ns h2h-a "$H" net-pps --to "$PEER:5201" --size "$size" --count "$M_UDP_COUNT" \
        --raw-path "$MATRIX_DIR/udp-$size-pps.jsonl" > "$tmp" 2> "$error" || status=$?
    python3 -I "$H2H_KIT/lib/matrix.py" cpu-snapshot --output "$cpu_after" >/dev/null || status=$?
    matrix_stop_syscall_counter
    if ((status == 0)); then mv "$tmp" "$output"; rm -f "$error"; else mv "$tmp" "$output.failed" 2>/dev/null || true; fi
    h2h_cpu_audit_stop || status=$?
    ((status == 0)) || die "UDP packet-rate probe or audit failed at $size bytes"
    python3 -I "$H2H_KIT/lib/matrix.py" cpu-window-summary --before "$cpu_before" \
        --after "$cpu_after" --measurement "$output" --output "$MATRIX_DIR/udp-$size-cpu.json" >/dev/null \
        || die "UDP CPU accounting failed at $size bytes"
    matrix_finish_syscall_counter "udp-$size" "$perf_log" "$output"
    log "udp-$size packet rate: $(head -c 500 "$output")"
}

run_matrix_scenario() {
    matrix_read_scenario
    matrix_record_artifacts
    matrix_start_noise
    if [[ -n $M_DELAY ]]; then
        local -a netem_args=(delay "${M_DELAY}ms")
        [[ -z $M_JITTER || $M_JITTER == 0 ]] || netem_args+=("${M_JITTER}ms")
        if [[ -n $M_GEMODEL ]]; then
            # Gilbert-Elliott bursts: "p r 1-h 1-k" as netem takes them; the words are split on purpose.
            # shellcheck disable=SC2206
            netem_args+=(loss gemodel $M_GEMODEL)
        elif [[ $M_LOSS != 0 ]]; then
            netem_args+=(loss "${M_LOSS}%")
        fi
        [[ -z $M_RATE ]] || netem_args+=(rate "${M_RATE}mbit")
        matrix_apply_shaping "${netem_args[@]}"
    fi
    matrix_warmup
    matrix_idle_cpu

    case $H2H_MATRIX_SCENARIO in
        best-lan|best-lan-15k|mobile-*|wan-50ms|wan-150ms-loss-0.5|wan-150ms-loss-2|wan-20ms-loss-1|wan-40ms-loss-1-jitter-10|wan-50mbit-loss-0.5|cpu-contended)
            # idle_latency_probes defaults to latency_probes, so LAN scenarios are unchanged.
            matrix_idle_latency idle-latency-mtu "$M_LATENCY_SIZE" "$M_IDLE_COUNT" "$M_IDLE_INTERVAL"
            for flows in ${M_TCP_FLOWS//,/ }; do
                matrix_tcp_sample "tcp-$flows" "$flows" "$M_TPUT_SECONDS" "$M_LATENCY_COUNT" \
                    "$M_LATENCY_INTERVAL" "$M_LATENCY_SIZE"
            done
            ;;
        small-udp)
            for size in ${M_UDP_SIZES//,/ }; do
                matrix_idle_latency "idle-latency-$size" "$size" "$M_IDLE_COUNT" "$M_IDLE_INTERVAL"
                matrix_udp_pps "$size"
            done
            ;;
        idle)
            matrix_idle_latency idle-latency-mtu "$M_LATENCY_SIZE" "$M_IDLE_COUNT" "$M_IDLE_INTERVAL"
            matrix_idle_latency idle-latency-64 64 "$M_IDLE_COUNT" "$M_IDLE_INTERVAL"
            matrix_idle_latency idle-latency-256 256 "$M_IDLE_COUNT" "$M_IDLE_INTERVAL"
            ;;
        peer-scale)
            matrix_idle_latency idle-latency-mtu "$M_LATENCY_SIZE" "$M_LATENCY_COUNT" "$M_IDLE_INTERVAL"
            local peers
            for peers in ${M_PEER_COUNTS//,/ }; do
                if ((peers > 1)); then matrix_set_peer_count "$peers"; fi
                matrix_peer_memory "$peers" idle
                matrix_tcp_sample "peer-$peers-tcp-1" 1 "$M_TPUT_SECONDS" "$M_LATENCY_COUNT" \
                    "$M_LATENCY_INTERVAL" "$M_LATENCY_SIZE" "$peers"
                cp "$MATRIX_DIR/peer-$peers-tcp-1-throughput.json" "$MATRIX_DIR/peer-$peers-throughput.json"
            done
            rm -f "$D/keys/a.wg.private" "$D/keys/b.wg.private"
            cp "$MATRIX_DIR/peer-1000-tcp-1-throughput.json" "$MATRIX_DIR/tcp-1-throughput.json"
            cp "$MATRIX_DIR/peer-1000-tcp-1-latency.json" "$MATRIX_DIR/tcp-1-latency.json"
            cp "$MATRIX_DIR/peer-1000-tcp-1-syscalls.json" "$MATRIX_DIR/tcp-1-syscalls.json"
            ;;
        handshake-storm)
            matrix_idle_latency idle-latency-mtu "$M_LATENCY_SIZE" "$M_LATENCY_COUNT" "$M_IDLE_INTERVAL"
            for flows in ${M_TCP_FLOWS//,/ }; do
                matrix_tcp_sample "tcp-$flows" "$flows" "$M_TPUT_SECONDS" "$M_LATENCY_COUNT" \
                    "$M_LATENCY_INTERVAL" "$M_LATENCY_SIZE"
            done
            matrix_handshake_storm
            ;;
        *) die "unknown matrix scenario $H2H_MATRIX_SCENARIO" ;;
    esac

    if [[ $H2H_MATRIX_SCENARIO != peer-scale ]]; then
        matrix_peer_memory_sweep
        if [[ $SYSTEM == kernel-plain ]]; then
            # The shared peer-memory sweep is the last step that needs these interface keys.
            rm -f "$D/keys/a.wg.private" "$D/keys/b.wg.private"
        fi
    fi
    python3 -I "$H2H_KIT/lib/matrix.py" collect-row \
        --case-dir "$H2H_RESULTS/$H2H_CASE" --engine "$SYSTEM" \
        --tag "$H2H_MATRIX_ROW_TAG" --scenario "$H2H_MATRIX_SCENARIO" \
        --calibration "${H2H_MATRIX_CALIBRATION_STATUS:-uncalibrated}" >/dev/null \
        || die "matrix row collection failed for $H2H_MATRIX_ROW_TAG"
    netem_clear h2h-a a0
    netem_clear h2h-b b0
}

case $SYSTEM in
    underlay) START=$("$H" now); PEER=10.220.0.2 ;;
    infraternal) start_infraternal ;;
    gotatun) start_gotatun ;;
    boringtun) start_boringtun ;;
    wireguard-go) start_wireguard_go ;;
    tailscale) start_tailscale ;;
    netbird) start_netbird kernel ;;
    netbird-userspace) start_netbird userspace ;;
    kernel-plain) start_kernel_plain ;;
    *) die "unknown system $SYSTEM" ;;
esac

record_link_offloads

if [[ -n ${H2H_MATRIX_SCENARIO:-} ]]; then
    run_matrix_scenario
    log "matrix row complete: scenario=$H2H_MATRIX_SCENARIO engine=$SYSTEM tag=$H2H_MATRIX_ROW_TAG"
    exit 0
fi

measure first-packet in_ns h2h-a "$H" net-wait --to "$PEER:5201" --since-ns "$START" --timeout-s 120
in_ns h2h-a ip -o link show > "$H2H_RESULTS/$H2H_CASE/links-a.txt" 2>&1 || true
measure idle "$H" proc-idle --pids "$WATCH" --seconds "$IDLE_S"
record_memcg one

profile() { # profile <tag> <lat-count> <lat-interval-us> <tput-seconds>
    local tag=$1 count=$2 interval=$3 secs=$4 size flows ping_pid tput_pid
    local ping_client tput_client ping_raw ping_status_file tput_file tput_tmp tput_err
    local ping_status tput_status audit_status probes_outlived
    # D345 invariant (#260, J562): every loaded probe must be sent while the load
    # runs. A probe stream that outlives the load mixes idle round trips into the
    # loaded p99 and biases it low (J525 calibration: 85-90% of 12,000 probes were
    # idle; the old 2,000 probes at 5.5-8.1 ms also overran a 10 s load). So the
    # window FAILS, rather than reporting a quietly wrong number. Fix it by raising
    # H2H_LAN_TPUT_SECONDS or lowering H2H_LAN_PING_COUNT. The check is a liveness
    # probe at the moment the load ends; the audit is stopped first so the failure
    # leaves a clean window directory.
    # It is deliberately conservative: a ping that sent its last probe inside the
    # load but still waits on a lost reply also fails the window (J581 F3). Rerun
    # such a window; never weaken the check.
    for size in 64 512 1400; do
        measure "lat-$tag-$size" in_ns h2h-a "$H" net-lat --to "$PEER:5201" --size "$size" --count "$count" --interval-us "$interval"
    done
    for flows in 1 8; do
        ping_raw="$H2H_RESULTS/$H2H_CASE/icmp-$tag-$flows.raw"
        ping_status_file="$H2H_RESULTS/$H2H_CASE/icmp-$tag-$flows.exit"
        tput_file="$H2H_RESULTS/$H2H_CASE/tput-$tag-$flows.json"
        tput_tmp="$tput_file.tmp"
        tput_err="$tput_file.err"
        # `ping -w` can send beyond -c while waiting for that many replies.
        # Keep this sample's -c value as the exact transmitted-probe count.
        H2H_SCOPE_PAUSE=1 \
            H2H_SCOPE_LOG="$D/icmp-scope-$tag-$flows.log" \
            H2H_SCOPE_STDOUT="$ping_raw" H2H_SCOPE_STDERR="$ping_raw" \
            spawn_in_ns ping_pid h2h-a ping -D -O -n -i 0.005 -c "$count" "$PEER"
        ping_client=$H2H_SCOPE_CLIENT_PID
        H2H_SCOPE_PAUSE=1 \
            H2H_SCOPE_LOG="$D/tput-scope-$tag-$flows.log" \
            H2H_SCOPE_STDOUT="$tput_tmp" H2H_SCOPE_STDERR="$tput_err" \
            spawn_in_ns tput_pid h2h-a "$H" net-tput --to "$PEER:5201" \
                --flows "$flows" --seconds "$secs" --pids "$WATCH"
        tput_client=$H2H_SCOPE_CLIENT_PID
        h2h_cpu_audit_start "$tag-$flows"
        kill -CONT "$ping_pid" "$tput_pid"

        tput_status=0
        probes_outlived=0
        if wait "$tput_client"; then
            mv "$tput_tmp" "$tput_file"
            rm -f "$tput_err"
            log "tput-$tag-$flows: $(head -c 400 "$tput_file")"
            if kill -0 "$ping_client" 2>/dev/null; then
                probes_outlived=1
            fi
        else
            tput_status=$?
            log "tput-$tag-$flows failed: $(tail -c 400 "$tput_err")"
            mv "$tput_tmp" "$tput_file.failed" 2>/dev/null || true
        fi
        ping_status=0
        if wait "$ping_client"; then :; else ping_status=$?; fi
        printf '%s\n' "$ping_status" > "$ping_status_file"
        audit_status=0
        if h2h_cpu_audit_stop; then :; else audit_status=$?; fi
        ((tput_status == 0)) || die "throughput probe failed for $tag/$flows flows"
        ((probes_outlived == 0)) || die "loaded probe stream outlived the $secs s load for $tag/$flows flows; raise H2H_LAN_TPUT_SECONDS or lower H2H_LAN_PING_COUNT"
        ((audit_status == 0)) || die "D348 audit failed for $tag/$flows flows"
        summarize_icmp "$tag" "$flows" "$count"
    done
}

# Preserve raw ping output so the keep p99 comes from ICMP replies and cannot
# hide loss behind the harness's RTT estimator.
raw_icmp() { # raw_icmp <profile> <flows> <count> <interval-seconds>
    local tag=$1 flows=$2 count=$3 interval=$4
    local directory="$H2H_RESULTS/$H2H_CASE" raw summary status_file ping_status=0
    local deadline
    if [[ $interval == 1.0 ]]; then
        deadline=$((count + 10))
    else
        deadline=$((count / 100 + 5))
    fi
    ((deadline < 5)) && deadline=5
    mkdir -p "$directory"
    raw="$directory/icmp-$tag-$flows.raw"
    summary="$directory/icmp-$tag-$flows.summary.txt"
    status_file="$directory/icmp-$tag-$flows.exit"
    in_ns h2h-a ping -D -O -n -i "$interval" -c "$count" -w "$deadline" "$PEER" \
        > "$raw" 2>&1 || ping_status=$?
    printf '%s\n' "$ping_status" > "$status_file"
}

summarize_icmp() { # summarize_icmp <profile> <flows> <expected-count>
    local tag=$1 flows=$2 count=$3
    local directory="$H2H_RESULTS/$H2H_CASE" raw summary ping_status
    raw="$directory/icmp-$tag-$flows.raw"
    summary="$directory/icmp-$tag-$flows.summary.txt"
    ping_status=$(cat "$directory/icmp-$tag-$flows.exit")
    python3 -I "$H2H_KIT/lib/pingstat.py" --expected-sent "$count" "$raw" > "$summary"
    log "icmp-$tag-$flows: $(cat "$summary") (ping exit $ping_status)"
}
capture_soak_counters() { # capture_soak_counters <before|after>
    local phase=$1 ns
    for ns in h2h-a h2h-b h2h-u; do
        {
            printf 'namespace=%s phase=%s\n' "$ns" "$phase"
            printf '\n--- links ---\n'
            ip -n "$ns" -s link show
            printf '\n--- snmp ---\n'
            ip netns exec "$ns" cat /proc/net/snmp
            printf '\n--- netstat ---\n'
            ip netns exec "$ns" cat /proc/net/netstat
            printf '\n--- udp sockets and drops ---\n'
            ip netns exec "$ns" cat /proc/net/udp
        } > "$H2H_RESULTS/$H2H_CASE/soak-counters-$phase-$ns.txt"
    done
}

run_soak() {
    local seconds=${H2H_SOAK_SECONDS:-0} ping_pid tput_pid ping_client tput_client
    local ping_status_file ping_raw tput_file tput_tmp tput_err rc=0 ping_rc=0 audit_rc=0
    [[ $seconds == 3600 ]] || die "kept-cut soak must be exactly 3,600 seconds"
    capture_soak_counters before
    ping_raw="$H2H_RESULTS/$H2H_CASE/icmp-soak-8.raw"
    ping_status_file="$H2H_RESULTS/$H2H_CASE/icmp-soak-8.exit"
    tput_file="$H2H_RESULTS/$H2H_CASE/tput-soak-8.json"
    tput_tmp="$tput_file.tmp"
    tput_err="$tput_file.err"
    H2H_SCOPE_PAUSE=1 \
        H2H_SCOPE_LOG="$D/icmp-scope-soak-8.log" \
        H2H_SCOPE_STDOUT="$ping_raw" H2H_SCOPE_STDERR="$ping_raw" \
        spawn_in_ns ping_pid h2h-a ping -D -O -n -i 1.0 -c "$seconds" \
            -w "$((seconds + 10))" "$PEER"
    ping_client=$H2H_SCOPE_CLIENT_PID
    H2H_SCOPE_PAUSE=1 \
        H2H_SCOPE_LOG="$D/tput-scope-soak-8.log" \
        H2H_SCOPE_STDOUT="$tput_tmp" H2H_SCOPE_STDERR="$tput_err" \
        spawn_in_ns tput_pid h2h-a "$H" net-tput --to "$PEER:5201" \
            --flows 8 --seconds "$seconds" --pids "$WATCH"
    tput_client=$H2H_SCOPE_CLIENT_PID
    h2h_cpu_audit_start soak
    kill -CONT "$ping_pid" "$tput_pid"
    if wait "$tput_client"; then
        mv "$tput_tmp" "$tput_file"
        rm -f "$tput_err"
        log "tput-soak-8: $(head -c 400 "$tput_file")"
    else
        rc=$?
        log "tput-soak-8 failed: $(tail -c 400 "$tput_err")"
        mv "$tput_tmp" "$tput_file.failed" 2>/dev/null || true
    fi
    if wait "$ping_client"; then :; else ping_rc=$?; ((rc != 0)) || rc=$ping_rc; fi
    printf '%s\n' "$ping_rc" > "$ping_status_file"
    if h2h_cpu_audit_stop; then :; else audit_rc=$?; ((rc != 0)) || rc=$audit_rc; fi
    ((rc == 0 && audit_rc == 0)) \
        || die "one-hour soak workload or D348 audit failed with status $rc/$audit_rc"
    summarize_icmp soak 8 "$seconds"
    sleep 2
    capture_soak_counters after
    measure mem-after-soak "$H" proc-mem --pids "$WATCH"
}

if [[ ${H2H_SOAK_SECONDS:-0} == 3600 ]]; then
    run_soak
else
    profile lan "$LAT_COUNT" 1000 "$TPUT_S"
    if [[ ${H2H_CALIBRATION_ONLY:-0} == 1 ]]; then
        log "D348 calibration-only control complete; WAN and peer-scale cases are outside the calibration window"
        exit 0
    fi
    measure mem-after-load "$H" proc-mem --pids "$WATCH"

    netem_set h2h-a a0 delay 99ms
    netem_set h2h-b b0 delay 99ms
    sleep 2
    profile de-in "$WAN_LAT_COUNT" 10000 "$WAN_TPUT_S"
    # Loss is at the packet layer on both egress interfaces. Two independent 2%
    # drops imply 3.96% round-trip exposure, not a single 2% end-to-end profile.
    netem_set h2h-a a0 delay 99ms loss 2%
    netem_set h2h-b b0 delay 99ms loss 2%
    sleep 2
    profile de-in-loss "$WAN_LAT_COUNT" 10000 "$WAN_TPUT_S"
    netem_clear h2h-a a0
    netem_clear h2h-b b0

    if [[ ${H2H_REORDER_CHECK:-0} == 1 ]]; then
        netem_set h2h-a a0 delay 99ms reorder 25% 50%
        netem_set h2h-b b0 delay 99ms reorder 25% 50%
        sleep 2
        profile de-in-reorder "$WAN_LAT_COUNT" 10000 "$WAN_TPUT_S"
        netem_clear h2h-a a0
        netem_clear h2h-b b0
    fi
fi

if [[ $SYSTEM == tailscale ]]; then
    note peer-scale '{"configured_peers_per_endpoint":1,"at_1000":"not supported by the two-node testcontrol fixture"}'
elif [[ $SYSTEM == infraternal ]]; then
    for x in a b; do
        nspid=$A_PID
        [[ $x == b ]] && nspid=$B_PID
        python3 -I "$H2H_KIT/lib/peer_scale.py" kernel-config --count 1000 --start 0 --output "$D/peers-$x.conf"
        nsenter -t "$nspid" -n -- "$WG_BIN" setconf infraternal0 "$D/peers-$x.conf"
        test "$(nsenter -t "$nspid" -n -- "$WG_BIN" show infraternal0 peers | wc -l)" -eq 1000 \
            || die "kernel WireGuard peer count is not 1,000 on $x"
    done
    sleep 2
    measure idle-1000 "$H" proc-idle --pids "$WATCH" --seconds "$IDLE_S"
    measure mem-1000 "$H" proc-mem --pids "$WATCH"
    record_memcg 1000
    note peer-scale '{"configured_peers_per_endpoint":1000,"method":"wg setconf"}'
elif [[ $SYSTEM == gotatun || $SYSTEM == boringtun || $SYSTEM == wireguard-go ]]; then
    case $SYSTEM in
        gotatun) peer_a=$GOTA_A_PID; peer_b=$GOTA_B_PID; iface_a=wgA; iface_b=wgB ;;
        boringtun) peer_a=$BORING_A_PID; peer_b=$BORING_B_PID; iface_a=wgA; iface_b=wgB ;;
        wireguard-go) peer_a=$WG_A_PID; peer_b=$WG_B_PID; iface_a=wgA; iface_b=wgB ;;
    esac
    nsenter -t "$peer_a" -n -m -- python3 -I "$H2H_KIT/lib/peer_scale.py" add-uapi --interface "$iface_a" --count 999 --start 1 > "$D/peers-a.json"
    nsenter -t "$peer_b" -n -m -- python3 -I "$H2H_KIT/lib/peer_scale.py" add-uapi --interface "$iface_b" --count 999 --start 1 > "$D/peers-b.json"
    sleep 2
    measure idle-1000 "$H" proc-idle --pids "$WATCH" --seconds "$IDLE_S"
    measure mem-1000 "$H" proc-mem --pids "$WATCH"
    record_memcg 1000
    note peer-scale '{"configured_peers_per_endpoint":1000,"method":"WireGuard UAPI, 999 additional non-traffic peers per endpoint"}'
fi

if [[ $SYSTEM == tailscale ]]; then
    sandboxed "$A_PID" "$H2H_BIN/tailscale" --socket="$D/a/sock" status --json \
        | python3 -c 'import json,sys; s=json.load(sys.stdin); print(json.dumps([{"cur_addr":p.get("CurAddr"),"relay":p.get("Relay")} for p in (s.get("Peer") or {}).values()]))' \
        > "$H2H_RESULTS/$H2H_CASE/path.json" || true
fi
if [[ $SYSTEM == netbird* ]]; then
    # NetBird logs whether each peer connection is peer-to-peer or relayed.
    grep -ihE 'p2p|relay' "$D/a/client.log" | tail -n 20 > "$H2H_RESULTS/$H2H_CASE/path.txt" || true
fi
log done
