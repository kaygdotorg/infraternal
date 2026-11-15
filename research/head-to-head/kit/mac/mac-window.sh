#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# One Mac<->Linux measurement window of the head-to-head kit (#260, J674). Run as `lume` on the
# Mac VM under the Mac lock (see mac/README.md; mac/mac-run.sh does that for you):
#
#   lockf -k /tmp/mac-bench.lock bash mac-window.sh <window-id> <engine>...
#
# Engines: `pin` (GotaTun as pinned on dev), `cand` (the candidate), `tailscale`, `netbird`
# (open-source userspace clients). Each has its macOS side on this Mac and its Linux side on the
# arm64 Linux VM on the same bridge (no NAT, no NetBird in between). `pin` and `cand` run the
# product's own Mac data path (MacUtun + GotaTun) through the ignored `mac_bench_device` test
# harness, built by mac/build-harness.sh; the Linux GotaTun CLI is the peer's.
# Directions: mac-tx (Mac sends, the probe runs on the Mac) and mac-rx (Linux sends, the probe
# runs on Linux). Flows: 1 and 8. Receipts per case: <case>.{source,probe,meta}.json plus the
# raw RTTs, the engine logs and the path files. mac/mac_pool.py pools windows into the report.
#
# Local Network privacy: macOS refuses LAN traffic from a non-root, ssh-launched process (it
# fails silently or with EHOSTUNREACH), so every ping, probe, sink and source runs under `sudo`.
# That is deliberate, not a leftover: do not "simplify" it away.
#
# Env: PEER (Linux IP) and PSSH (ssh target of the Linux VM) are required. Optional: KIT_HOME
# (default /Users/Shared/h2h-mac: bin/ holds the executables, ev/ the evidence, run/ engine state),
# ME (this Mac's LAN IP; default: en0), LAN_SECS (default 15), DIRS (default "mac-tx mac-rx"),
# PIN_BIN / CAND_BIN (harness names in bin/; defaults mesh-bench-pin / mesh-bench-cand),
# PIN_ENV / CAND_ENV (extra environment for that harness, e.g. "J614_CREDITS=32").
# No `set -e`: a failed case is recorded and the window goes on.
set -uo pipefail
W=$1; shift
J=${KIT_HOME:-/Users/Shared/h2h-mac}
BIN=$J/bin
EV=$J/ev/$W
R=$J/run   # per-window engine state on the Mac (root-owned files where engines write)
mkdir -p "$EV"
# Refuse before any side effect when a third-party client is not the pinned version (pins.txt).
here=$(cd "$(dirname "$0")" && pwd)
if ! pin_out=$(bash "$here/check-pins.sh" "$here/../../pins.txt" "$BIN" "$@"); then
  echo "$pin_out" | tee -a "$EV/window.log"
  echo "REFUSED: a client version differs from pins.txt (see $EV/window.log)" >&2; exit 4
fi
echo "$pin_out" >> "$EV/window.log"
ME=${ME:-$(ipconfig getifaddr en0)}
PEER=${PEER:?}; PSSH=${PSSH:?}
LAN_SECS=${LAN_SECS:-15}; DIRS=${DIRS:-mac-tx mac-rx}
SSHO=(-o BatchMode=yes)
# The Linux VM is reached with the existing `claude` key and known_hosts, so ssh runs as claude.
ssh() { sudo -n -u claude -i /usr/bin/ssh -o BatchMode=yes "$@"; }
L() { ssh "${SSHO[@]}" "$PSSH" sudo -n bash /opt/j461c/lnx-side.sh "$@"; }

log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$EV/window.log"; }

# Summed CPU seconds of the given pids (ps TIME is [[hh:]mm:]ss.cc).
cpu_s() { [ -z "$*" ] && { echo 0; return; }; ps -o time= -p "$(IFS=,; echo "$*")" | python3 -c '
import sys
t=0.0
for l in sys.stdin:
    l=l.strip()
    if not l: continue
    s=0.0
    for p in l.split(":"): s=s*60+float(p)
    t+=s
print(round(t,3))'; }
# Summed physical footprint (bytes) of the given pids.
foot() { local t=0 p v; for p in "$@"; do v=$(sudo footprint -f bytes -p "$p" 2>/dev/null | sed -nE 's/.*Footprint: ([0-9]+) B.*/\1/p' | head -1); t=$((t + ${v:-0})); done; echo $t; }
alive() { local p; for p in "$@"; do sudo kill -0 "$p" 2>/dev/null || { echo 0; return; }; done; echo 1; }
# Does this engine run the GotaTun product harness on the Mac?
is_gotatun() { case $1 in pin|cand) return 0;; *) return 1;; esac; }

# ---------- Mac side of each engine: sets MPIDS (engine pids on the Mac), MY_IP, PEER_IP, GIF ----------
# Product Mac data path: macos_node's own MacUtun + GotaTun, as an ignored test binary. Keys go
# through a root-only env file, never argv. $1 = harness binary in $BIN, $2 = extra environment.
start_product() {
  local d=$R/p; sudo mkdir -p $d; sudo chmod 700 $d
  local K ka kb pa pb; K=$($BIN/j421net keys)
  ka=$(echo "$K" | python3 -c 'import json,sys; print(json.load(sys.stdin)["a_private"])'); kb=$(echo "$K" | python3 -c 'import json,sys; print(json.load(sys.stdin)["b_private"])')
  pa=$(echo "$K" | python3 -c 'import json,sys; print(json.load(sys.stdin)["a_public"])'); pb=$(echo "$K" | python3 -c 'import json,sys; print(json.load(sys.stdin)["b_public"])')
  printf 'J461_PRIVATE_HEX=%s\nJ461_PEER_PUBLIC_HEX=%s\nJ461_ENDPOINT=%s:61820\nJ461_PORT=61820\nJ461_ADDR=172.30.42.1\nJ461_PEER_ADDR=172.30.42.2\nJ461_IFNAME_FILE=%s/tun\nJ461_STOP=%s/stop\n' "$ka" "$pb" "$PEER" "$d" "$d" | sudo tee $d/env >/dev/null
  # PIN_ENV / CAND_ENV go into the same root-only file, quoted by extra-env.sh, never into the
  # command line of the root shell below; a malformed entry fails the engine instead of running.
  # (pipefail makes a failing extra-env.sh fail the whole pipe)
  if ! bash "$here/extra-env.sh" "$2" | sudo tee -a $d/env >/dev/null; then log "FAIL $E: bad extra environment [$2]"; return; fi
  sudo chmod 600 $d/env
  # Paths arrive as positional arguments ($1..$3), so nothing is re-parsed by the root shell.
  sudo bash -c 'echo $$ > "$1/pid"; set -a; . "$1/env"; set +a; exec "$2" --ignored --exact macos_node::tests::bench_device::mac_bench_device --test-threads=1 --nocapture >> "$3" 2>&1' _ "$d" "$BIN/$1" "$EV/$E/engine-mac.log" &
  for _ in $(seq 1 100); do sudo test -s $d/tun && break; sleep 0.1; done
  MPIDS=$(sudo cat $d/pid); GIF=$(sudo cat $d/tun 2>/dev/null)
  local out; out=$(echo "$kb $pa" | L start gotatun $ME); echo "$out" > $EV/$E/linux-start.txt
  grep -q CONFIG_OK <<<"$out" || log "FAIL $E: linux side not configured"
  PEER_IP=172.30.42.2; MY_IP=172.30.42.1
  { echo "mac: product harness $1 env [$2], utun $GIF, MTU 1280"; shasum -a 256 $BIN/$1; } > $EV/$E/path-mac.txt
}
start_pin() { start_product "${PIN_BIN:-mesh-bench-pin}" "${PIN_ENV:-}"; }
start_cand() { start_product "${CAND_BIN:-mesh-bench-cand}" "${CAND_ENV:-}"; }
start_tailscale() {
  local d=$R/ts; sudo mkdir -p $d; sudo chmod 700 $d
  L secret hs | sudo tee $d/authkey >/dev/null
  sudo bash -c "echo \$\$ > $d/pid; TS_LOGS_DIR=$d exec $BIN/tailscaled --statedir=$d --socket=$d/ts.sock --tun=utun --port=41642 > $EV/$E/engine-mac.log 2>&1" &
  for _ in $(seq 1 50); do sudo test -S $d/ts.sock && break; sleep 0.1; done
  MPIDS=$(sudo cat $d/pid)
  PEER_IP=$(L start tailscale $ME | awk '/^PEER_IP/{print $2}')
  sudo $BIN/tailscale --socket=$d/ts.sock up --login-server=http://$PEER:8080 --auth-key=file:$d/authkey --hostname=j461c-mac --accept-dns=false --accept-routes=false --timeout=60s >> $EV/$E/up.log 2>&1
  sudo rm -f $d/authkey
  MY_IP=$(sudo $BIN/tailscale --socket=$d/ts.sock ip -4)
}
start_netbird() {
  local d=$R/nb; sudo mkdir -p $d/state $d/home; sudo chmod 700 $d
  L secret nb | sudo tee $d/setupkey >/dev/null
  # env -i: no SUDO_* variables, so the CLI never resolves lume's ~/Library config dir; NB_STATE_DIR
  # keeps daemon state out of the host install's dirs; our own socket, utun, port and no DNS changes.
  sudo env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=$d/home NB_STATE_DIR=$d/state bash -c "echo \$\$ > $d/pid; exec $BIN/netbird service run --daemon-addr unix://$d/nb.sock --log-file $EV/$E/engine-mac.log" > /dev/null 2>&1 &
  for _ in $(seq 1 50); do sudo test -S $d/nb.sock && break; sleep 0.1; done
  MPIDS=$(sudo cat $d/pid)
  sudo env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin HOME=$d/home NB_STATE_DIR=$d/state $BIN/netbird up --daemon-addr unix://$d/nb.sock --log-file console \
    --management-url http://$PEER:8081 --setup-key-file $d/setupkey --hostname j461c-mac --interface-name utun143 --wireguard-port 61830 \
    --disable-dns --disable-server-routes --disable-client-routes --extra-iface-blacklist utun100 >> $EV/$E/up.log 2>&1
  sudo rm -f $d/setupkey
  PEER_IP=$(L start netbird $ME | awk '/^PEER_IP/{print $2}')
  for _ in $(seq 1 120); do MY_IP=$(sudo env -i HOME=$d/home NB_STATE_DIR=$d/state $BIN/netbird status --daemon-addr unix://$d/nb.sock --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["netbirdIp"].split("/")[0])' 2>/dev/null); [ -n "$MY_IP" ] && break; sleep 0.5; done
}
# Record each engine's own view of its path, on both sides.
path_mac() {
  case $E in
    tailscale) { $BIN/tailscale version | head -1; echo "mac: open-source tailscaled, utun, userspace WireGuard"; sudo $BIN/tailscale --socket=$R/ts/ts.sock ping -c 5 "$PEER_IP"; sudo $BIN/tailscale --socket=$R/ts/ts.sock status; } >> $EV/$E/path-mac.txt 2>&1 ;;
    netbird) { $BIN/netbird version; echo "mac: netbird daemon, utun143, userspace WireGuard"; sudo env -i HOME=$R/nb/home NB_STATE_DIR=$R/nb/state $BIN/netbird status --daemon-addr unix://$R/nb/nb.sock -d; } >> $EV/$E/path-mac.txt 2>&1 ;;
    pin|cand) printf 'mac: product harness uses MacUtun (utun %s); no UAPI control socket\n' "$GIF" >> "$EV/$E/path-mac.txt" ;;
  esac
  local LE=$E; is_gotatun $E && LE=gotatun
  L path $LE > $EV/$E/path-linux.txt 2>&1
}
stop_mac() {
  case $E in
    tailscale) sudo $BIN/tailscale --socket=$R/ts/ts.sock logout >/dev/null 2>&1 ;;
    netbird) sudo env -i HOME=$R/nb/home NB_STATE_DIR=$R/nb/state $BIN/netbird down --daemon-addr unix://$R/nb/nb.sock >/dev/null 2>&1 ;;
  esac
  # The harness exits by itself once its stop file appears; give it a moment before the kill.
  is_gotatun $E && { sudo touch $R/p/stop; for _ in $(seq 1 30); do sudo kill -0 $MPIDS 2>/dev/null || break; sleep 0.2; done; }
  for p in $MPIDS; do sudo kill $p 2>/dev/null; done; sleep 2; for p in $MPIDS; do sudo kill -9 $p 2>/dev/null; done
  sudo rm -rf $R
}

run_engine() {
  E=$1; mkdir -p "$EV/$E"; MPIDS=""; PEER_IP=""; MY_IP=""; GIF=""
  case $E in pin|cand|tailscale|netbird) ;; *) log "SKIP unknown engine $E"; return;; esac
  log "== engine $E load $(sysctl -n vm.loadavg) linux-load $(ssh -n "${SSHO[@]}" "$PSSH" cat /proc/loadavg)"
  if ! sudo ping -c 2 -t 3 -q $PEER >/dev/null; then log "ABORT: lost ping to $PEER"; exit 3; fi
  ps -Ao %cpu,comm -r | head -6 > "$EV/$E/top-before.txt"
  start_$E
  log "$E mac pids [$MPIDS] mac ip $MY_IP linux ip $PEER_IP"
  if [ -z "$PEER_IP" ] || [ -z "$MY_IP" ] || [ "$(alive $MPIDS)" != 1 ]; then log "FAIL $E: not up"; L stop >/dev/null; stop_mac; return; fi
  L serve "$PEER_IP" >/dev/null
  # Warm-up: measure only once 20 UDP probes in a row come back through the tunnel (up to ~60 s).
  local i lost=x; for i in $(seq 1 30); do lost=$(sudo $BIN/j421net probe -to $PEER_IP:5202 -count 20 -interval-ms 50 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["lost"])' 2>/dev/null); [ "$lost" = 0 ] && break; done
  log "$E warm-up: last batch lost=$lost after $i batches"
  path_mac
  sudo $BIN/j421net sink -bind $MY_IP:5201 > "$EV/$E/sink.log" 2>&1 & local SINK=$!
  sudo $BIN/j421net echo -bind $MY_IP:5202 > "$EV/$E/echo.log" 2>&1 & local ECHO=$!
  sleep 0.5   # sleep: let the sink and echo servers bind before the first probe
  sudo $BIN/j421net probe -to $PEER_IP:5202 -count 200 -interval-ms 5 > "$EV/$E/idle-probe.json" 2>&1
  echo "{\"idle_footprint_mac\": $(foot $MPIDS), \"linux_stats\": \"$(L stats)\"}" > "$EV/$E/idle.json"
  local dir flows secs=$LAN_SECS
  for dir in $DIRS; do for flows in 1 8; do
    local c="$EV/$E/lan-$dir-${flows}f" tag="$W/$E/lan-$dir-${flows}f"
    is_gotatun $E && echo "=== CASE lan-$dir-${flows}f START $(date +%s)" | sudo tee -a $EV/$E/engine-mac.log >/dev/null
    local c0 l0; c0=$(cpu_s $MPIDS); l0=$(L stats)
    if [ $dir = mac-tx ]; then
      sudo $BIN/j421net probe -to $PEER_IP:5202 -count $((secs*200)) -interval-ms 5 -raw "$c.rtt" > "$c.probe.json" 2>&1 & local PR=$!
      sudo $BIN/j421net source -to $PEER_IP:5201 -flows $flows -secs $secs > "$c.source.json" 2>&1
      wait $PR
    else
      L load $MY_IP $flows $secs "$tag" >/dev/null
      ssh "${SSHO[@]}" "$PSSH" cat /opt/j461c/out/$tag.source.json > "$c.source.json"
      ssh "${SSHO[@]}" "$PSSH" cat /opt/j461c/out/$tag.probe.json > "$c.probe.json"
    fi
    is_gotatun $E && echo "=== CASE lan-$dir-${flows}f END $(date +%s)" | sudo tee -a $EV/$E/engine-mac.log >/dev/null
    local c1 l1; c1=$(cpu_s $MPIDS); l1=$(L stats)
    echo "{\"mac_cpu_s\": $(python3 -c "print(round($c1-$c0,3))"), \"linux_before\": \"$l0\", \"linux_after\": \"$l1\", \"footprint_mac\": $(foot $MPIDS), \"alive\": $(alive $MPIDS), \"load\": \"$(sysctl -n vm.loadavg)\"}" > "$c.meta.json"
    log "$E $dir ${flows}f: $(python3 -c "import json; s=json.load(open('$c.source.json')); p=json.load(open('$c.probe.json')); m=json.load(open('$c.meta.json')); print(s['gbit_per_s'], 'Gbit/s stalls', s['stall_seconds'], 'p99', p.get('p99_ms'), 'la-p99', p.get('loss_aware_p99_ms'), 'lost', p['lost'], 'macCPU', m['mac_cpu_s'])" 2>&1)"
  done; done
  ps -Ao %cpu,comm -r | head -6 > "$EV/$E/top-after.txt"
  kill $SINK $ECHO 2>/dev/null
  L stop >/dev/null; stop_mac
  sleep 1   # sleep: let the utun and sockets of this engine go before the next one starts
}

trap '[ -n "${E:-}" ] && stop_mac; L cleanup > "$EV/linux-cleanup.txt" 2>&1' EXIT
log "window $W order: $* (LAN ${LAN_SECS}s; dirs $DIRS) mac $ME <-> linux $PEER"
log "underlay: $(sudo ping -c 20 -i 0.2 -q $PEER | tail -1)"
if ! sudo ping -c 3 -t 3 -q $PEER >/dev/null; then log "ABORT: no ping to $PEER (bridge isolation back?)"; exit 3; fi
log "coordination: $(L coord-up $PEER)"
L serve $PEER >/dev/null
for f in 1 8; do sudo $BIN/j421net source -to $PEER:5201 -flows $f -secs 5 > "$EV/underlay-${f}f.json"; done
L stop >/dev/null
log "underlay ceiling mac->linux 1f/8f (no tunnel): $(python3 -c "import json; print(json.load(open('$EV/underlay-1f.json'))['gbit_per_s'], json.load(open('$EV/underlay-8f.json'))['gbit_per_s'])")"
# rows.tsv: tag<TAB>engine in run order, the same shape the Linux holds write.
: > "$EV/rows.tsv"; for e in "$@"; do printf '%s\t%s\n' "$e" "$e" >> "$EV/rows.tsv"; done
for e in "$@"; do run_engine "$e"; done
E=""
log "WINDOW_DONE $W"
