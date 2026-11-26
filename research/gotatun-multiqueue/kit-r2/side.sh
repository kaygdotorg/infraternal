#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1230 (#260, #580; from J1137/J1160) cross-VM fair-comparison fixture: one VM's side.
#
# Every engine, product, probe and control plane runs inside ONE netns `j30` whose only link is an
# ipvlan (L2) child of eth0 with its own 10.70.3.19x address. The netns has no default route, and
# an nft table inside it drops (and counts) anything leaving j39v for an address outside
# 10.70.3.0/24 and all IPv6 (ipvlan traffic skips the host's postrouting hook, so the host
# egress-guard cannot see it; this table is the guard, and its counters are the proof).
# Tunnel addresses (10.66.0.0/24 for the engine rows; Tailscale/NetBird/infraternal mesh ranges)
# exist only inside the netns. `nsdown` kills every process in the netns and deletes it, which
# also removes the ipvlan, so nothing outlives the fixture.
#
#   side.sh nsup <ip> [iperf]      create the netns (iperf: also start the iperf3 server)
#   side.sh nsdown                 tear everything down
#   side.sh wgkey                  new WireGuard key pair, prints the public key
#   side.sh up kernel|wggo|gotatun <self-tun-ip> <peer-pub> <peer-underlay-ip>
#   side.sh guard                  load the captured infraternal_mesh guard table onto j39w
#   side.sh up ix-serve | ix-drive <B-ip> | ix-watch    infraternal mesh nodes (B, A)
#   side.sh up hsctl | ts          headscale on C / tailscaled on A, B
#   side.sh up nbsrv | nb          NetBird combined server on C / NetBird client on A, B
#   side.sh reach <peer>           first packet through the tunnel; prints its epoch time
#   side.sh paths                  record how the peers are connected (direct or relayed)
#   side.sh down                   stop the current engine, keep the netns
set -euo pipefail
R=/root/j1239
BIN=$R/bin
NS=j39
RUN=$R/run
C_IP=10.70.3.198
nsx() { ip netns exec "$NS" "$@"; }
wait_for() { local t=$1; shift; local end=$((SECONDS + t)); until "$@" >/dev/null 2>&1; do ((SECONDS < end)) || return 1; sleep 0.1; done; }
bg() { # bg <name> <cmd...>: detached in the netns, pid in $RUN/<name>.pid
    local name=$1; shift
    setsid nohup ip netns exec "$NS" "$@" > "$RUN/$name.out" 2> "$RUN/$name.err" < /dev/null &
    echo $! > "$RUN/$name.pid"
}
# Engines record what the observer should watch: process ids and the tunnel device.
watch() { printf '%s\n' "$*" > "$RUN/watch"; }
# Each `up` records when it started (this VM's clock, NTP-synced like the others), so the
# driver can compute connection setup time on the VMs' own clocks, not hd01's ssh latency.
stamp() { mkdir -p "$RUN"; date +%s.%N > "$RUN/started.$1"; }

cmd_nsup() {
    local ip=$1
    [[ ! -e /run/netns/$NS ]] || { echo "netns $NS already exists" >&2; exit 1; }
    mkdir -p "$RUN"; chmod 700 "$R" "$RUN"
    ip netns add "$NS"
    nsx nft -f - <<NFT
table inet j39guard {
  chain post {
    type filter hook postrouting priority 0; policy accept;
    oifname "j39v" ip daddr != 10.70.3.0/24 counter drop comment "J1230: only the VM LAN"
    oifname "j39v" meta nfproto ipv6 counter drop
  }
}
NFT
    # A just-deleted netns releases its ipvlan asynchronously (kernel cleanup work), so the
    # address stays taken until its last sockets (TCP TIME_WAIT, ~60 s) are gone: retry for 90 s.
    local i
    for i in $(seq 1 180); do
        ip link add j39v link eth0 type ipvlan mode l2 2>/dev/null && break
        sleep 0.5
    done
    ip link set j39v netns "$NS"
    nsx sysctl -qw net.ipv6.conf.j39v.disable_ipv6=1
    for i in $(seq 1 180); do nsx ip addr add "$ip/24" dev j39v 2>/dev/null && break; sleep 0.5; done
    nsx ip -4 -o addr show dev j39v | grep -q "$ip/" || { echo "cannot assign $ip" >&2; exit 1; }
    nsx ip link set lo up
    nsx ip link set j39v up
    nsx sysctl -qw net.ipv4.tcp_ecn=1
    # The receiving node (B) also keeps the round-trip echo server for every row of the hold.
    if [[ ${2:-} == iperf ]]; then
        bg iperf3s "$BIN/iperf3" -s -p 5201
        # J1230: a second server for the two-tunnel ceiling row (its second tunnel's flows).
        bg iperf3s.2 "$BIN/iperf3" -s -p 5202
        bg rrs python3 -I "$R/rr.py" serve 0.0.0.0 7801
        wait_for 10 nsx sh -c "ss -ltn | grep -q ':7801 '" || { cat "$RUN/rrs.err" >&2; exit 1; }
    fi
    nsx ip -br a; nsx ip r
}

cmd_nsdown() {
    local pids
    [[ -s $RUN/reachbg.pid ]] && kill "$(cat "$RUN/reachbg.pid")" 2>/dev/null || true
    pids=$(ip netns pids "$NS" 2>/dev/null || true)
    [[ -z $pids ]] || kill $pids 2>/dev/null || true
    sleep 2
    pids=$(ip netns pids "$NS" 2>/dev/null || true)
    [[ -z $pids ]] || kill -9 $pids 2>/dev/null || true
    sleep 1
    [[ ! -e /run/netns/$NS ]] || ip netns del "$NS"
    rm -f /var/run/wireguard/j39w.sock /var/run/wireguard/j39x.sock
    rm -rf "$RUN"
    if ip -br link | grep -q j39; then echo "j39 links remain" >&2; exit 1; fi
    echo "nsdown ok"
}

cmd_wgkey() {
    mkdir -p "$RUN"
    (umask 077; "$BIN/wg" genkey > "$RUN/wg.key")
    "$BIN/wg" pubkey < "$RUN/wg.key"
}

# J1230: the second tunnel's key pair (two-tunnel ceiling row only).
cmd_wgkey2() {
    mkdir -p "$RUN"
    (umask 077; "$BIN/wg" genkey > "$RUN/wg2.key")
    "$BIN/wg" pubkey < "$RUN/wg2.key"
}

wg_config() { # wg_config <self-tun-ip> <peer-pub> <peer-ul-ip>
    nsx "$BIN/wg" set j39w private-key "$RUN/wg.key" listen-port 51820 \
        peer "$2" endpoint "$3:51820" allowed-ips 10.66.0.0/24
    nsx ip addr add "$1/24" dev j39w
    # The VMs' eth0 MTU is 1450 (not 1500), so the largest WireGuard MTU without outer
    # fragmentation is 1450 - 20 (IPv4) - 8 (UDP) - 32 (WireGuard) = 1390. Every engine row uses it.
    nsx ip link set j39w mtu 1390 up
}

up_kernel() {
    stamp node
    nsx ip link add j39w type wireguard
    wg_config "$@"
    watch "tun=j39w pids="
}

# J1230 ceiling row: two whole GotaTun devices (two processes, two UDP ports, two tunnel subnets)
# between the same two VMs. Two independent pipelines are an upper bound for what "one pipeline
# per core" inside one device could reach on these VMs.
#   up gotatun2 <self1> <peer-pub1> <peer-ul> <self2> <peer-pub2>
up_gotatun2() {
    stamp node
    bg gotatun env WG_SUDO=1 WG_LOG_LEVEL=error WG_LOG_FILE="$RUN/gotatun.log" "${XENV_WORDS[@]}" \
        "${GTBIN:-$BIN/gotatun-j59}" -f j39w
    bg gotatun2 env WG_SUDO=1 WG_LOG_LEVEL=error WG_LOG_FILE="$RUN/gotatun2.log" "${XENV_WORDS[@]}" \
        "${GTBIN:-$BIN/gotatun-j59}" -f j39x
    wait_for 20 test -S /var/run/wireguard/j39w.sock || { cat "$RUN/gotatun.err" >&2; exit 1; }
    wait_for 20 test -S /var/run/wireguard/j39x.sock || { cat "$RUN/gotatun2.err" >&2; exit 1; }
    wg_config "$1" "$2" "$3"
    nsx "$BIN/wg" set j39x private-key "$RUN/wg2.key" listen-port 51821 \
        peer "$5" endpoint "$3:51821" allowed-ips 10.67.0.0/24
    nsx ip addr add "$4/24" dev j39x
    nsx ip link set j39x mtu 1390 up
    watch "tun=j39w,j39x pids=$(cat "$RUN/gotatun.pid") $(cat "$RUN/gotatun2.pid")"
}

up_wggo() {
    stamp node
    bg wggo env WG_PROCESS_FOREGROUND=1 LOG_LEVEL=error "$BIN/wireguard-go" j39w
    wait_for 20 test -S /var/run/wireguard/j39w.sock || { cat "$RUN/wggo.err" >&2; exit 1; }
    wg_config "$@"
    watch "tun=j39w pids=$(cat "$RUN/wggo.pid")"
}

# J1230: the bare GotaTun CLI, configured over the same UAPI with `wg set` as wireguard-go.
# GTBIN picks the build (dev pin or a candidate); XENV carries a row's switches
# (e.g. GOTATUN_SIDE_SOCKET=1), space-separated NAME=value words.
read -r -a XENV_WORDS <<< "${XENV:-J1230_XENV=none}"
up_gotatun() {
    stamp node
    bg gotatun env WG_SUDO=1 WG_LOG_LEVEL=error WG_LOG_FILE="$RUN/gotatun.log" "${XENV_WORDS[@]}" \
        "${GTBIN:-$BIN/gotatun-j59}" -f j39w
    wait_for 20 test -S /var/run/wireguard/j39w.sock || { cat "$RUN/gotatun.err" >&2; exit 1; }
    wg_config "$@"
    watch "tun=j39w pids=$(cat "$RUN/gotatun.pid")"
}

# J1230: every engine row runs behind the same nft guard table the infraternal mesh installs
# (J1160: the table alone costs kernel WG ~20% and GotaTun ~11% of reverse throughput here).
# The product row captured it into guard.nft on this VM; only the interface name changes.
cmd_guard() {
    test -s $R/guard.nft || { echo "no captured guard table" >&2; exit 1; }
    if nsx ip link show j39x > /dev/null 2>&1; then
        # J1230 two-tunnel row: one table whose interface tests name both tunnels, so every
        # packet still crosses the guard chains once, as on a one-tunnel row.
        sed 's/{ "lo", "infraternal0" }/{ "lo", "j39w", "j39x" }/g; s/"infraternal0"/{ "j39w", "j39x" }/g' $R/guard.nft | nsx nft -f -
    else
        sed 's/"infraternal0"/"j39w"/g' $R/guard.nft | nsx nft -f -
    fi
    nsx nft list table inet infraternal_mesh | grep -c .
}

up_ix_serve() {
    stamp node
    bg ix env "${XENV_WORDS[@]}" PYTHONPATH="$R/lib" python3 -I "$R/xix.py" serve --listen 10.70.3.197:7701 \
        --binary "$BIN/infraternal" --scratch "$RUN" --pidfile "$RUN/ix-agent.pid"
    wait_for 20 nsx sh -c "ss -ltn | grep -q 10.70.3.197:7701" || { cat "$RUN/ix.err" >&2; exit 1; }
    echo listening
}

up_ix_drive() {
    stamp node
    mkfifo "$RUN/ix.in"
    setsid nohup ip netns exec "$NS" env "${XENV_WORDS[@]}" PYTHONPATH="$R/lib" python3 -I "$R/xix.py" drive \
        --remote "$1:7701" --binary "$BIN/infraternal" --coordinator "$BIN/coordinator_fixture" \
        --scratch "$RUN" --endpoints "10.70.3.196,$1" < "$RUN/ix.in" > "$RUN/ix.out" 2> "$RUN/ix.err" &
    echo $! > "$RUN/ix.pid"
    # Hold the fifo open in a sleeper so the driver keeps waiting for "quit".
    setsid nohup sleep 86400 > "$RUN/ix.in" 2> /dev/null < /dev/null &
    echo $! > "$RUN/ix-holder.pid"
    wait_for 90 test -s "$RUN/ix.out" || { cat "$RUN/ix.err" >&2; exit 1; }
    local ready; ready=$(head -1 "$RUN/ix.out")
    python3 -c 'import json,sys; d=json.loads(sys.argv[1]); print(d["peer_ipv4"])' "$ready" > "$RUN/peer"
    watch "tun=infraternal0 pids=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["pids"][0])' "$ready")"
    cat "$RUN/peer"
}

ix_serve_watch() { # after node A connected, B's agent pid is known
    wait_for 30 test -s "$RUN/ix-agent.pid"
    watch "tun=infraternal0 pids=$(cat "$RUN/ix-agent.pid")"
}

# J1230: headscale (self-hosted Tailscale control) on C, inside the netns. Headscale refuses to run
# without a DERP map, so its embedded DERP and STUN server run on C (inside the LAN); no public
# DERP map URL, no MagicDNS, sqlite state in the run dir.
up_hsctl() {
    stamp ctl
    mkdir -p "$RUN/hs"; chmod 700 "$RUN/hs"
    cat > "$RUN/hs/config.yaml" <<YAML
server_url: http://$C_IP:8080
listen_addr: $C_IP:8080
metrics_listen_addr: 127.0.0.1:9099
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
noise:
  private_key_path: $RUN/hs/noise_private.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: "j30"
    region_name: "J1230 embedded DERP on C"
    verify_clients: true
    stun_listen_addr: "$C_IP:3478"
    private_key_path: $RUN/hs/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: $C_IP
  urls: []
  paths: []
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: $RUN/hs/db.sqlite
    write_ahead_log: true
log:
  level: warn
dns:
  magic_dns: false
  override_local_dns: false
  nameservers:
    global: []
unix_socket: $RUN/hs/headscale.sock
unix_socket_permission: "0700"
logtail:
  enabled: false
YAML
    bg hs "$BIN/headscale" -c "$RUN/hs/config.yaml" serve
    wait_for 30 nsx sh -c "ss -ltn | grep -q $C_IP:8080" || { tail -c 1500 "$RUN/hs.err" "$RUN/hs.out" >&2; exit 1; }
    wait_for 10 test -S "$RUN/hs/headscale.sock" || { tail -c 800 "$RUN/hs.err" >&2; exit 1; }
    local hsc=("$BIN/headscale" -c "$RUN/hs/config.yaml")
    nsx "${hsc[@]}" users create j30 > "$RUN/hs/user.log" 2>&1 || { cat "$RUN/hs/user.log" >&2; exit 1; }
    local uid
    uid=$(nsx "${hsc[@]}" users list -o json 2>/dev/null | python3 -c 'import json,sys; print([u for u in json.load(sys.stdin) if u["name"]=="j30"][0]["id"])')
    # The key stays in a 0600 file and is never printed; it expires with the run.
    (umask 077; nsx "${hsc[@]}" preauthkeys create --user "$uid" --reusable --expiration 2h -o json 2>/dev/null \
        | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["key"])' > "$RUN/setup-key")
    test -s "$RUN/setup-key" || { echo "no preauth key" >&2; exit 1; }
    date +%s.%N > "$RUN/ready.ctl"
    watch "tun= pids=$(cat "$RUN/hs.pid")"
    echo headscale ready
}

up_ts() {
    stamp node
    mkdir -p "$RUN/ts"
    test -s "$RUN/setup-key" || { echo "no auth key" >&2; exit 1; }
    bg tsd unshare -m --propagation private sh -c 'mount -t tmpfs j30-nodbus /run/dbus && exec "$@"' isolated "$BIN/tailscaled" --tun=tailscale0 --statedir="$RUN/ts" --socket="$RUN/ts/sock" \
        --port=41641 --no-logs-no-support
    wait_for 30 test -S "$RUN/ts/sock" || { tail -c 800 "$RUN/tsd.err" >&2; exit 1; }
    nsx "$BIN/tailscale" --socket="$RUN/ts/sock" up --login-server="http://$C_IP:8080" --auth-key="file:$RUN/setup-key" \
        --hostname="j30-$(hostname -s)" --accept-dns=false --accept-routes=false --timeout=60s > "$RUN/tsup.log" 2>&1 \
        || { tail -c 800 "$RUN/tsup.log" >&2; exit 1; }
    rm -f "$RUN/setup-key"
    nsx "$BIN/tailscale" --socket="$RUN/ts/sock" ip -4 | tee "$RUN/peer"
    watch "tun=tailscale0 pids=$(cat "$RUN/tsd.pid")"
}

up_nbsrv() {
    stamp ctl
    mkdir -p "$RUN/srv"
    python3 -I - "$RUN/srv/config.yaml" "$RUN/srv" "$C_IP" <<'PY'
import os, secrets, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
ip = sys.argv[3]
with os.fdopen(fd, "w") as f:
    f.write(f"""server:
  listenAddress: "{ip}:8080"
  exposedAddress: "http://{ip}:8080"
  stunPorts: [3478]
  healthcheckAddress: "{ip}:9000"
  metricsPort: 9090
  logLevel: "warn"
  logFile: "console"
  authSecret: "{secrets.token_urlsafe(32)}"
  dataDir: "{sys.argv[2]}"
  disableAnonymousMetrics: true
  disableGeoliteUpdate: true
  auth:
    issuer: "http://{ip}:8080/oauth2"
  store:
    engine: "sqlite"
""")
PY
    bg nbsrv env NB_SETUP_PAT_ENABLED=true NB_DISABLE_GEOLOCATION=true "$BIN/netbird-server" --config "$RUN/srv/config.yaml"
    nsx python3 -I "$R/lib/nb_bootstrap.py" "http://$C_IP:8080" "$RUN/setup-key" > /dev/null \
        || { tail -c 800 "$RUN/nbsrv.err" "$RUN/nbsrv.out" >&2; exit 1; }
    date +%s.%N > "$RUN/ready.ctl"
    watch "tun= pids=$(cat "$RUN/nbsrv.pid")"
    echo bootstrapped
}

up_nb() {
    stamp node
    mkdir -p "$RUN/nb"
    test -s "$RUN/setup-key" || { echo "no setup key" >&2; exit 1; }
    # NetBird's default on Linux with the wireguard module present: kernel WireGuard (wt0).
    bg nb unshare -m --propagation private sh -c 'mount -t tmpfs j30-nodbus /run/dbus && exec "$@"' isolated env NB_STATE_DIR="$RUN/nb" "$BIN/netbird" up --foreground-mode \
        --management-url "http://$C_IP:8080" --setup-key-file "$RUN/setup-key" --config "$RUN/nb/config.json" \
        --daemon-addr "unix://$RUN/nb/sock" --log-file "$RUN/nb/client.log" --disable-dns --hostname "j30-$(hostname -s)"
    wait_for 90 sh -c "ip -n $NS -4 -o addr show dev wt0 | grep -q inet" || { tail -c 800 "$RUN/nb/client.log" >&2; exit 1; }
    rm -f "$RUN/setup-key"
    ip -n "$NS" -4 -o addr show dev wt0 | awk '{print $4}' | cut -d/ -f1 | tee "$RUN/peer"
    watch "tun=wt0 pids=$(cat "$RUN/nb.pid")"
}

# J1230: the first packet through the tunnel, polled every ~0.2 s; prints this VM's epoch time.
cmd_reach() {
    local i
    for i in $(seq 1 600); do
        if nsx ping -c1 -W0.2 -q "$1" > /dev/null 2>&1; then date +%s.%N; return 0; fi
    done
    return 1
}

# J1230: the same poll started in the background before node A comes up (the peer's tunnel
# address is known once node B is up), so the ssh round trips of the driver are not counted.
# `waitreach` returns the recorded time once the first reply came back.
cmd_reachbg() {
    mkdir -p "$RUN"; rm -f "$RUN/reach"
    setsid nohup bash -c 'for i in $(seq 1 3000); do if ip netns exec '"$NS"' ping -c1 -W0.2 -q '"$1"' > /dev/null 2>&1; then date +%s.%N > '"$RUN"'/reach.tmp; mv '"$RUN"'/reach.tmp '"$RUN"'/reach; exit 0; fi; sleep 0.02; done' > /dev/null 2>&1 < /dev/null &
    echo $! > "$RUN/reachbg.pid"
}
cmd_waitreach() { wait_for 120 test -s "$RUN/reach" || return 1; cat "$RUN/reach"; }

# J1230: how the two peers are connected right now (direct UDP between the LAN addresses, or a relay).
cmd_paths() {
    nsx ip -d -o link show 2>&1
    nsx ss -uanp 2>&1 | head -40
    [[ -S $RUN/ts/sock ]] && nsx "$BIN/tailscale" --socket="$RUN/ts/sock" status 2>&1 | head -10
    [[ -S $RUN/nb/sock ]] && nsx "$BIN/netbird" status -d --daemon-addr "unix://$RUN/nb/sock" 2>&1 | head -40
    [[ -e /sys/module/wireguard ]] && nsx "$BIN/wg" show all 2>&1 | head -30
    nsx nft list table inet j39guard 2>&1
    return 0
}

cmd_up() {
    local e=$1; shift
    case $e in
        kernel) up_kernel "$@" ;;
        wggo) up_wggo "$@" ;;
        gotatun) up_gotatun "$@" ;;
        gotatun2) up_gotatun2 "$@" ;;
        ix-serve) up_ix_serve "$@" ;;
        ix-watch) ix_serve_watch ;;
        ix-drive) up_ix_drive "$@" ;;
        hsctl) up_hsctl ;;
        ts) up_ts ;;
        nbsrv) up_nbsrv ;;
        nb) up_nb "$@" ;;
        *) echo "unknown engine $e" >&2; exit 2 ;;
    esac
}

cmd_down() {
    # The in-app driver turns both nodes off ("quit") before anything is killed.
    if [[ -e $RUN/ix-holder.pid ]]; then
        timeout 5 sh -c "echo quit > '$RUN/ix.in'" < /dev/null > /dev/null 2>&1 || true
        kill "$(cat "$RUN/ix-holder.pid")" 2>/dev/null || true
        wait_for 20 sh -c "! kill -0 $(cat "$RUN/ix.pid") 2>/dev/null" || true
    fi
    local keep pids p
    # The background reachability poller lives in the host namespace: stop it by its pid.
    [[ -s $RUN/reachbg.pid ]] && kill "$(cat "$RUN/reachbg.pid")" 2>/dev/null || true
    # The hold-long servers (iperf3, rr.py echo) stay; everything else in the netns goes.
    keep=" $(cat "$RUN/iperf3s.pid" "$RUN/iperf3s.2.pid" "$RUN/rrs.pid" 2>/dev/null | tr '\n' ' ' || true) "
    for p in $(ip netns pids "$NS"); do
        [[ $keep == *" $p "* ]] && continue
        kill "$p" 2>/dev/null || true
    done
    sleep 2
    for p in $(ip netns pids "$NS"); do
        [[ $keep == *" $p "* ]] && continue
        kill -9 "$p" 2>/dev/null || true
    done
    sleep 1
    for l in $(nsx ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
        [[ $l == lo || $l == j39v ]] || nsx ip link del "$l" 2>/dev/null || true
    done
    # Tables an engine installed (the mesh guard, a product's own) go with it; the fixture's stays.
    for t in $(nsx nft list tables 2>/dev/null | awk '{print $2" "$3}' | tr ' ' ':'); do
        [[ $t == inet:j39guard ]] || nsx nft delete table ${t%%:*} ${t#*:} 2>/dev/null || true
    done
    rm -f /var/run/wireguard/j39w.sock /var/run/wireguard/j39x.sock
    find "$RUN" -mindepth 1 -maxdepth 1 ! -name 'iperf3s.*' ! -name 'rrs.*' -exec rm -rf {} +
    nsx ip -br link
}

c=$1; shift
"cmd_$c" "$@"
