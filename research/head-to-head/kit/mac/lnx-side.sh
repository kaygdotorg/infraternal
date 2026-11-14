#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Linux-peer helper for the Mac<->Linux head-to-head (#260, J674). Runs as root on the arm64 Linux
# VM that shares the Mac VM's bridge (no NAT, no NetBird in between). Measurement only.
# This is the versioned copy of the file deployed as /opt/j461c/lnx-side.sh: after a change,
# `scp` it there (see mac/README.md). The state paths keep the original j461c names so the
# peer needs no re-provisioning.
#
#   lnx-side.sh coord-up <my-ip>          start throwaway Headscale + NetBird combined server
#   lnx-side.sh secret hs|nb              print the Headscale pre-auth key / NetBird setup key
#                                         (stdout only, consumed by the Mac driver over ssh; never logged)
#   lnx-side.sh start <engine> <mac-ip>   start this side of an engine; prints "PEER_IP <tunnel ip>"
#                                         (gotatun reads "private_key peer_public_key" on stdin)
#   lnx-side.sh path <engine>             the client's own view of its path to the Mac
#   lnx-side.sh serve <ip>                j421net sink :5201 + echo :5202 on <ip> (prints pids)
#   lnx-side.sh load <to-ip> <flows> <secs> <out-prefix>   source + loaded probe toward the Mac
#   lnx-side.sh stats                     "proc_cpu_ticks sys_busy_ticks pss_kib alive"
#   lnx-side.sh stop                      stop the engine and the serve processes
#   lnx-side.sh coord-down | cleanup      stop servers / remove everything this kit created
# Engines: gotatun (bin/gotatun), tailscale, netbird. State: /run/j461c (tmpfs, root only).
set -uo pipefail
D=/opt/j461c; BIN=$D/bin; S=/run/j461c
mkdir -p $S $D/log $D/out; chmod 700 $S
cmd=$1; shift

pids() { cat $S/engine.pids 2>/dev/null; }

case $cmd in
coord-up)
  IP=$1; mkdir -p $S/hs $S/nbs/data $D/log $D/out; echo $IP > $S/ip
  printf 'regions:\n  900:\n    regionid: 900\n    regioncode: none\n    regionname: unreachable\n    nodes:\n      - name: 900a\n        regionid: 900\n        hostname: %s\n        ipv4: %s\n        derpport: 9\n        stunport: -1\n        stunonly: false\n' "$IP" "$IP" > $S/hs/derp.yaml
  cat > $S/hs/config.yaml <<EOF
server_url: http://$IP:8080
listen_addr: $IP:8080
metrics_listen_addr: 127.0.0.1:9091
grpc_listen_addr: 127.0.0.1:50443
noise: { private_key_path: $S/hs/noise.key }
prefixes: { v4: 100.80.0.0/16, allocation: sequential }
derp: { server: { enabled: false }, urls: [], paths: [$S/hs/derp.yaml], auto_update_enabled: false }
database: { type: sqlite, sqlite: { path: $S/hs/db.sqlite } }
dns: { magic_dns: false, override_local_dns: false, base_domain: j461c.invalid }
unix_socket: $S/hs/hs.sock
unix_socket_permission: "0700"
log: { level: warn }
policy: { mode: file, path: "" }
logtail: { enabled: false }
EOF
  setsid $BIN/headscale -c $S/hs/config.yaml serve > $D/log/headscale.log 2>&1 < /dev/null & echo $! > $S/hs/pid
  cat > $S/nbs/config.yaml <<EOF
server:
  listenAddress: "$IP:8081"
  exposedAddress: "http://$IP:8081"
  metricsPort: 9092
  healthcheckAddress: "127.0.0.1:9002"
  logLevel: "warn"
  logFile: "console"
  authSecret: "$(head -c 24 /dev/urandom | base64)"
  dataDir: "$S/nbs/data"
  disableAnonymousMetrics: true
  disableGeoliteUpdate: true
  auth:
    issuer: "http://$IP:8081/oauth2"
    localAuthDisabled: false
    dashboardRedirectURIs: ["http://$IP:8081/nb-auth"]
    cliRedirectURIs: ["http://localhost:53000/"]
  store: { engine: "sqlite", dsn: "", encryptionKey: "$(head -c 32 /dev/urandom | base64)" }
EOF
  chmod 600 $S/nbs/config.yaml
  NB_DISABLE_GEOLOCATION=true NB_SETUP_PAT_ENABLED=true setsid $BIN/netbird-server --config $S/nbs/config.yaml > $D/log/netbird-server.log 2>&1 < /dev/null & echo $! > $S/nbs/pid
  for _ in $(seq 1 60); do curl -sf http://$IP:8080/health >/dev/null && curl -s -o /dev/null http://$IP:8081/api/instance && break; sleep 0.5; done
  $BIN/headscale -c $S/hs/config.yaml users create j461c >/dev/null 2>&1
  uid=$($BIN/headscale -c $S/hs/config.yaml users list -o json | python3 -c 'import json,sys; print([u["id"] for u in json.load(sys.stdin) if u["name"]=="j461c"][0])')
  $BIN/headscale -c $S/hs/config.yaml preauthkeys create --user "$uid" --reusable --expiration 4h -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])' > $S/hs/authkey
  pw="J461-$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"
  python3 -c 'import json,sys; print(json.dumps({"email":"j461c@j461c.invalid","password":sys.argv[1],"name":"j461c","create_pat":True,"pat_expire_in":1}))' "$pw" > $S/nbs/setup.json
  curl -s -X POST -H 'Content-Type: application/json' --data @$S/nbs/setup.json http://$IP:8081/api/setup | python3 -c 'import json,sys; print(json.load(sys.stdin)["personal_access_token"])' > $S/nbs/pat
  printf '{"name":"j461c","type":"reusable","expires_in":86400,"auto_groups":[],"usage_limit":0}' > $S/nbs/sk.json
  curl -s -X POST -H "Authorization: Token $(cat $S/nbs/pat)" -H 'Content-Type: application/json' --data @$S/nbs/sk.json http://$IP:8081/api/setup-keys | python3 -c 'import json,sys; print(json.load(sys.stdin)["key"])' > $S/nbs/setupkey
  [ -s $S/hs/authkey ] && [ -s $S/nbs/setupkey ] && echo COORD_OK || echo COORD_FAIL
  ;;
secret) case $1 in hs) cat $S/hs/authkey ;; nb) cat $S/nbs/setupkey ;; esac ;;
start)
  E=$1; MAC=$2; mkdir -p $S/e; : > $S/engine.pids
  case $E in
  gotatun)
    read -r priv peerpub
    # A socket left by an earlier run would accept nothing; remove it so the wait below sees ours.
    rm -f /var/run/wireguard/j461cg.sock
    setsid env WG_LOG_LEVEL=error $(cat $D/genv 2>/dev/null) $BIN/gotatun -f --disable-drop-privileges j461cg > $D/log/gotatun.log 2>&1 < /dev/null & echo $! >> $S/engine.pids
    for i in $(seq 1 50); do
      [ -S /var/run/wireguard/j461cg.sock ] && printf 'set=1\nprivate_key=%s\nlisten_port=61820\nreplace_peers=true\npublic_key=%s\nendpoint=%s:61820\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=172.30.42.1/32\n\n' "$priv" "$peerpub" "$MAC" | $BIN/j421net uapi /var/run/wireguard/j461cg.sock >/dev/null 2>&1
      printf 'get=1\n\n' | $BIN/j421net uapi /var/run/wireguard/j461cg.sock 2>/dev/null | grep -q '^listen_port=61820' && break; sleep 0.1
    done
    printf 'get=1\n\n' | $BIN/j421net uapi /var/run/wireguard/j461cg.sock 2>/dev/null | grep -q '^listen_port=61820' && echo CONFIG_OK || echo CONFIG_FAIL
    ip addr add 172.30.42.2/32 peer 172.30.42.1 dev j461cg; ip link set j461cg mtu 1280 up
    echo "PEER_IP 172.30.42.2" ;;
  tailscale)
    mkdir -p $S/ts
    setsid env TS_LOGS_DIR=$S/ts $BIN/tailscaled --statedir=$S/ts --socket=$S/ts/ts.sock --tun=ts-j461c --port=41642 > $D/log/tailscaled.log 2>&1 < /dev/null & echo $! >> $S/engine.pids
    for _ in $(seq 1 50); do [ -S $S/ts/ts.sock ] && break; sleep 0.1; done
    $BIN/tailscale --socket=$S/ts/ts.sock up --login-server=http://$(cat $S/ip):8080 --auth-key=file:$S/hs/authkey --hostname=j461c-linux --accept-dns=false --timeout=60s >> $D/log/ts-up.log 2>&1
    echo "PEER_IP $($BIN/tailscale --socket=$S/ts/ts.sock ip -4)" ;;
  netbird)
    mkdir -p $S/nb/state $S/nb/home
    MGMT=$(awk -F'"' '/exposedAddress/{print $2}' $S/nbs/config.yaml)
    # Own mount namespace with tmpfs over NetBird's fixed dirs, so no host NetBird state is touched.
    setsid unshare -m --propagation private sh -c "
      for d in /var/lib/netbird /etc/netbird /var/log/netbird; do [ -d \$d ] && mount -t tmpfs -o mode=0700 none \$d; done
      export NB_STATE_DIR=$S/nb/state HOME=$S/nb/home
      $BIN/netbird service run --daemon-addr unix://$S/nb/nb.sock --log-file $D/log/netbird-client.log &
      echo \$! > $S/nb/pid
      for i in \$(seq 1 50); do [ -S $S/nb/nb.sock ] && break; sleep 0.1; done
      $BIN/netbird up --daemon-addr unix://$S/nb/nb.sock --log-file console --management-url $MGMT --setup-key-file $S/nbs/setupkey \
        --hostname j461c-linux --interface-name wt-j461c --wireguard-port 61830 --disable-dns --disable-server-routes --disable-client-routes
      wait" > $D/log/nb-up.log 2>&1 < /dev/null &
    echo $! > $S/nb/wrapper
    for _ in $(seq 1 50); do [ -s $S/nb/pid ] && break; sleep 0.1; done
    cat $S/nb/pid >> $S/engine.pids
    for _ in $(seq 1 120); do ip=$($BIN/netbird status --daemon-addr unix://$S/nb/nb.sock --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["netbirdIp"].split("/")[0])' 2>/dev/null); [ -n "$ip" ] && break; sleep 0.5; done
    echo "PEER_IP $ip" ;;
  esac ;;
path)
  case $1 in
  gotatun) printf 'get=1\n\n' | $BIN/j421net uapi /var/run/wireguard/j461cg.sock | grep -E 'endpoint|last_handshake|rx_bytes|tx_bytes'; ip link show j461cg | head -1 ;;
  tailscale) $BIN/tailscale --socket=$S/ts/ts.sock status; ip link show ts-j461c | head -1 ;;
  netbird) $BIN/netbird status --daemon-addr unix://$S/nb/nb.sock -d; ip -d link show wt-j461c | head -3 ;;
  esac ;;
serve)
  setsid $BIN/j421net sink -bind $1:5201 > $D/log/sink.log 2>&1 < /dev/null & echo $! > $S/serve.pids
  setsid $BIN/j421net echo -bind $1:5202 > $D/log/echo.log 2>&1 < /dev/null & echo $! >> $S/serve.pids
  sleep 0.3; echo SERVE_OK ;;
load)
  TO=$1; F=$2; SECS=$3; O=$D/out/$4; mkdir -p "$(dirname "$O")"
  n=$((SECS * 1000 / 5))
  $BIN/j421net probe -to $TO:5202 -count $n -interval-ms 5 -raw $O.rtt > $O.probe.json 2>&1 & PR=$!
  $BIN/j421net source -to $TO:5201 -flows $F -secs $SECS > $O.source.json 2>&1
  wait $PR; echo LOAD_DONE ;;
stats)
  t=0; m=0; a=1
  for p in $(pids); do
    if [ -r /proc/$p/stat ]; then t=$((t + $(awk '{print $14+$15}' /proc/$p/stat))); v=$(awk '/^Pss:/{print $2}' /proc/$p/smaps_rollup); m=$((m + ${v:-0})); else a=0; fi
  done
  echo "$t $(awk '/^cpu /{print $2+$3+$4+$7+$8}' /proc/stat) $m $a $(getconf CLK_TCK)" ;;
stop)
  [ -S $S/ts/ts.sock ] && $BIN/tailscale --socket=$S/ts/ts.sock logout >/dev/null 2>&1
  [ -S $S/nb/nb.sock ] && $BIN/netbird down --daemon-addr unix://$S/nb/nb.sock >/dev/null 2>&1
  for p in $(cat $S/serve.pids 2>/dev/null) $(pids) $(cat $S/nb/wrapper 2>/dev/null); do kill $p 2>/dev/null; done
  sleep 2
  for p in $(cat $S/serve.pids 2>/dev/null) $(pids) $(cat $S/nb/wrapper 2>/dev/null); do kill -9 $p 2>/dev/null; done
  rm -rf $S/ts $S/nb $S/e $S/engine.pids $S/serve.pids
  for i in j461cg ts-j461c wt-j461c; do ip link del $i 2>/dev/null; done
  rm -f /var/run/wireguard/j461cg.sock
  echo STOPPED ;;
coord-down)
  for p in $S/hs/pid $S/nbs/pid; do [ -f $p ] && kill "$(cat $p)" 2>/dev/null; done; sleep 1; echo COORD_DOWN ;;
cleanup)
  bash $0 stop >/dev/null; bash $0 coord-down >/dev/null
  n=0; for p in /proc/[0-9]*; do e=$(readlink $p/exe 2>/dev/null) || continue; case $e in $BIN/*) kill -9 ${p#/proc/} && n=$((n+1));; esac; done
  rm -rf $S
  echo "CLEAN swept=$n procs_left=$(for p in /proc/[0-9]*; do readlink $p/exe; done 2>/dev/null | grep -c "^$BIN/") links=$(ip -br link | grep -cE 'j461c|wt-j461c|ts-j461c')" ;;
esac
