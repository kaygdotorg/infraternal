#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# gotatun-netns-bench: compare WireGuard engines on one machine.
#
# Two network namespaces are joined by one veth pair. Each namespace holds one
# WireGuard interface of the engine under test. iperf3 and a TCP round-trip
# probe (rr.py) run through the tunnel; /proc gives CPU, memory and idle wakeups. Nothing is routed to
# an uplink and nothing leaves the host: the namespaces only have loopback,
# the veth end and the tunnel interface.
#
# Method: an A/A series first (the first arm against itself, to measure the
# noise floor), then A B B A holds. `summarize.py` turns the output into a
# table. See README.md. Needs root, bash, iproute2, wireguard-tools, iperf3,
# ping (handshake check only), taskset and python3.
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: run.sh --arm NAME=BIN [--arm NAME=BIN ...] [options]
  --arm NAME=BIN   an engine: a program taking `-f IFACE` (gotatun, wireguard-go),
                   or the word "kernel" as BIN for kernel WireGuard. The first arm is A.
  --holds N        paired holds per series (default 3)
  --secs N         iperf3 seconds per run (default 20)
  --idle N         seconds of idle wakeup sampling after load (default 5)
  --flows "1 8"    parallel TCP flow counts (default "1 8")
  --cc "cubic bbr" congestion controls (default "cubic bbr")
  --delay MS       one-way netem delay on both veth ends (default 0; 99 = 198 ms RTT)
  --loss PCT       netem loss on both veth ends (default 0)
  --cpus "A B S C P"  CPU sets for engine A, engine B, iperf3 server, client, round-trip probe
  --rr-reply N     bytes of each round-trip reply (default 64: a keystroke echo)
  --rr-interval MS milliseconds between round-trip requests (default 20)
  --out DIR        output directory (default ./out-DATE)
USAGE
}
die() { echo "run.sh: $*" >&2; exit 1; }

HOLDS=3 SECS=20 IDLE=5 FLOWS="1 8" CCS="cubic bbr" DELAY=0 LOSS=0 CPUSPEC="" OUT="" RR_REPLY=64 RR_INTERVAL=20
ARM_NAMES=() ARM_BINS=()
while (($#)); do
  case $1 in
    --arm) [[ ${2:-} == *=* ]] || die "--arm wants NAME=BIN"
           ARM_NAMES+=("${2%%=*}"); ARM_BINS+=("${2#*=}"); shift 2 ;;
    --holds) HOLDS=$2; shift 2 ;;
    --secs) SECS=$2; shift 2 ;;
    --idle) IDLE=$2; shift 2 ;;
    --flows) FLOWS=$2; shift 2 ;;
    --cc) CCS=$2; shift 2 ;;
    --delay) DELAY=$2; shift 2 ;;
    --loss) LOSS=$2; shift 2 ;;
    --cpus) CPUSPEC=$2; shift 2 ;;
    --rr-reply) RR_REPLY=$2; shift 2 ;;
    --rr-interval) RR_INTERVAL=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown option $1" ;;
  esac
done
((${#ARM_NAMES[@]} >= 1)) || { usage >&2; die "give at least one --arm"; }
((EUID == 0)) || die "needs root (network namespaces)"
for t in ip tc wg iperf3 ping taskset python3 lscpu; do
  command -v "$t" >/dev/null || die "missing tool: $t"
done
for i in "${!ARM_BINS[@]}"; do
  [[ ${ARM_BINS[i]} == kernel || -x ${ARM_BINS[i]} ]] || die "not executable: ${ARM_BINS[i]}"
done
OUT=${OUT:-./out-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT/raw"

# CPU layout: engines, iperf3 and the probe get separate CPUs so they do not steal from each other.
if [[ -n $CPUSPEC ]]; then
  read -r CPU_A CPU_B CPU_S CPU_C CPU_P <<<"$CPUSPEC"
else
  mapfile -t C < <(lscpu -p=CPU --online | grep -v '^#')
  ((${#C[@]} >= 4)) || die "needs at least 4 online CPUs"
  if ((${#C[@]} >= 8)); then
    CPU_A=${C[0]},${C[1]} CPU_B=${C[2]},${C[3]} CPU_S=${C[4]} CPU_C=${C[5]} CPU_P=${C[6]}
  else
    CPU_A=${C[0]} CPU_B=${C[1]} CPU_S=${C[2]} CPU_C=${C[3]} CPU_P=${C[3]}
  fi
fi

NS_A=gtb-a NS_B=gtb-b IF_A=gtba0 IF_B=gtbb0 VETH_A=gtbv-a VETH_B=gtbv-b
TUN_A=10.77.0.1 TUN_B=10.77.0.2 UL_A=10.78.0.1 UL_B=10.78.0.2 PORT=51820 RR_PORT=5300 MTU=1420
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CLK_TCK=$(getconf CLK_TCK)
CREATED=() PIDS=()
export WG_LOG_LEVEL=error LOG_LEVEL=error # keep logging out of the measurement
export WG_SUDO=1 # gotatun-cli: skip the sudo-user lookup (it fails without a login session)
umask 077

cleanup() {
  local p ns
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  for ns in "${CREATED[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
  rm -f "/var/run/wireguard/$IF_A.sock" "/var/run/wireguard/$IF_B.sock"
}
trap cleanup EXIT

in_ns() { local ns=$1; shift; ip netns exec "$ns" "$@"; }

# Make both namespaces and the veth pair. Refuses to touch existing ones, and
# checks that no veth end leaked into the root namespace.
setup_net() {
  local ns
  for ns in $NS_A $NS_B; do
    ip netns list | grep -qw "$ns" && die "namespace $ns exists; remove it first"
  done
  ip netns add $NS_A; CREATED+=("$NS_A")
  ip netns add $NS_B; CREATED+=("$NS_B")
  ip link add $VETH_A netns $NS_A type veth peer name $VETH_B netns $NS_B
  if ip link show $VETH_A >/dev/null 2>&1 || ip link show $VETH_B >/dev/null 2>&1; then
    die "a veth end is in the root namespace"
  fi
  ip -n $NS_A addr add $UL_A/24 dev $VETH_A
  ip -n $NS_B addr add $UL_B/24 dev $VETH_B
  for ns in $NS_A:$VETH_A $NS_B:$VETH_B; do
    ip -n "${ns%%:*}" link set lo up
    ip -n "${ns%%:*}" link set "${ns##*:}" up
    if [[ $DELAY != 0 || $LOSS != 0 ]]; then
      in_ns "${ns%%:*}" tc qdisc add dev "${ns##*:}" root netem delay "${DELAY}ms" loss "${LOSS}%"
    fi
  done
}

# Everything a reader needs to judge whether two runs are comparable.
machine_header() {
  {
    echo "date: $(date -u +%FT%TZ)  host: $(hostname)  kernel: $(uname -r)"
    echo "cpu: $(lscpu | sed -n 's/^Model name: *//p')  online: $(nproc --all)"
    echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
    echo "rmem_max: $(sysctl -n net.core.rmem_max)  wmem_max: $(sysctl -n net.core.wmem_max)  netdev_max_backlog: $(sysctl -n net.core.netdev_max_backlog)"
    echo "loadavg at start: $(cat /proc/loadavg)"
    echo "cpus: A=$CPU_A B=$CPU_B iperf-server=$CPU_S iperf-client=$CPU_C rr-probe=$CPU_P"
    echo "run: holds=$HOLDS secs=$SECS idle=$IDLE flows=[$FLOWS] cc=[$CCS] delay=${DELAY}ms loss=${LOSS}% mtu=$MTU rr=${RR_REPLY}B/${RR_INTERVAL}ms"
    echo "tools: $(iperf3 --version | head -1); $(wg --version | cut -d' ' -f1-2)"
    echo "veth offloads: $(in_ns $NS_A ethtool -k $VETH_A 2>/dev/null | grep -E '^(tcp-segmentation|generic-(segmentation|receive)-offload|generic-receive-offload|rx-gro)' | tr -s ' \n' ' ' || echo n/a)"
    local i
    for i in "${!ARM_NAMES[@]}"; do
      if [[ ${ARM_BINS[i]} == kernel ]]; then
        echo "arm ${ARM_NAMES[i]}: kernel wireguard"
      else
        echo "arm ${ARM_NAMES[i]}: ${ARM_BINS[i]} sha256=$(sha256sum "${ARM_BINS[i]}" | cut -c1-16) $("${ARM_BINS[i]}" --version 2>&1 | head -1)"
      fi
    done
  } >"$OUT/machine.txt"
}

# start_engine NS IFACE BIN CPUS -> sets ENGINE_PID (empty for the kernel arm).
start_engine() {
  local ns=$1 ifc=$2 bin=$3 cpus=$4 n=0
  ENGINE_PID=
  if [[ $bin == kernel ]]; then ip -n "$ns" link add "$ifc" type wireguard; return; fi
  # No shell function in front of the `&`: $! must be the engine itself (ip netns exec execs).
  ip netns exec "$ns" taskset -c "$cpus" "$bin" -f "$ifc" >"$OUT/raw/engine-$ifc.log" 2>&1 &
  ENGINE_PID=$!; PIDS+=("$ENGINE_PID")
  until [[ -S /var/run/wireguard/$ifc.sock ]]; do
    sleep 0.1; ((++n < 50)) || die "$bin did not create its control socket"
  done
}

# configure NS IFACE OWN_TUN_IP PEER_TUN_IP PEER_UNDERLAY_IP PRIVFILE PEERPUBKEY
configure() {
  local ns=$1 ifc=$2 own=$3 peer=$4 ul=$5 priv=$6 pub=$7
  in_ns "$ns" wg set "$ifc" private-key "$priv" listen-port $PORT \
    peer "$pub" allowed-ips "$peer/32" endpoint "$ul:$PORT"
  ip -n "$ns" addr add "$own/24" dev "$ifc"
  ip -n "$ns" link set "$ifc" mtu $MTU up
}

ticks() { # utime+stime of a whole process, in clock ticks
  local s f; s=$(<"/proc/$1/stat"); read -ra f <<<"${s##*) }"; echo $((f[11] + f[12]))
}
ctxsw() { cat /proc/"$1"/task/*/status | awk '/^voluntary_ctxt_switches/ {s += $2} END {print s + 0}'; }
vm() { awk -v k="$2:" '$1 == k {print $2}' "/proc/$1/status"; }

# run_one PHASE HOLD POS ARM BIN CC FLOWS: one fresh pair of engines, one load, one CSV row.
run_one() {
  local phase=$1 hold=$2 pos=$3 arm=$4 bin=$5 cc=$6 flows=$7
  local id="$phase-h$hold-p$pos-$arm-$cc-P$flows" k="$OUT/keys"
  local load0 hs=NA ca=NA cb=NA hwm=NA rl=NA ri=NA wk=NA t0 w0 w1 sp pp ip_ rs
  echo "== $id" >&2
  mkdir -p "$k"; load0=$(cut -d' ' -f1 /proc/loadavg)
  wg genkey >"$k/a.key"; wg genkey >"$k/b.key"
  start_engine $NS_A $IF_A "$bin" "$CPU_A"; PID_A=$ENGINE_PID
  start_engine $NS_B $IF_B "$bin" "$CPU_B"; PID_B=$ENGINE_PID
  configure $NS_A $IF_A $TUN_A $TUN_B $UL_B "$k/a.key" "$(wg pubkey <"$k/b.key")"
  configure $NS_B $IF_B $TUN_B $TUN_A $UL_A "$k/b.key" "$(wg pubkey <"$k/a.key")"
  t0=$(date +%s%N); local n=0
  until in_ns $NS_A ping -c1 -W1 -q $TUN_B >/dev/null 2>&1; do
    ((++n < 15)) || die "no handshake in $id"
  done
  hs=$((($(date +%s%N) - t0) / 1000000))

  ip netns exec $NS_B taskset -c "$CPU_S" iperf3 -s -1 -B $TUN_B >/dev/null 2>&1 & sp=$!; PIDS+=("$sp")
  n=0; until in_ns $NS_B ss -ltn | grep -q ':5201 '; do sleep 0.1; ((++n < 50)) || die "iperf3 server"; done
  ip netns exec $NS_B taskset -c "$CPU_S" python3 -I "$HERE/rr.py" serve $TUN_B $RR_PORT >"$OUT/raw/$id.rrs.log" 2>&1 & rs=$!; PIDS+=("$rs")
  n=0; until in_ns $NS_B ss -ltn | grep -q ":$RR_PORT "; do sleep 0.1; ((++n < 50)) || die "rr server"; done
  [[ -n $PID_A ]] && { ca=$(ticks "$PID_A"); cb=$(ticks "$PID_B"); }
  ip netns exec $NS_A taskset -c "$CPU_C" iperf3 -c $TUN_B -B $TUN_A -t "$SECS" -P "$flows" -C "$cc" -J \
    >"$OUT/raw/$id.iperf.json" 2>"$OUT/raw/$id.iperf.err" & ip_=$!
  sleep 1 # let the flows ramp before probing latency under load
  # A TCP request/reply probe, not ping: ping busy-waits and costs the engines 1 to 9% throughput.
  ip netns exec $NS_A taskset -c "$CPU_P" python3 -I "$HERE/rr.py" client $TUN_B $RR_PORT "$RR_REPLY" "$RR_INTERVAL" \
    $((SECS - 2)) "$OUT/raw/$id.rr.json" >"$OUT/raw/$id.rr.log" 2>&1 & pp=$!
  wait "$ip_" || echo "iperf3 failed in $id (see raw/$id.iperf.err)" >&2
  wait "$pp" || true; wait "$sp" 2>/dev/null || true
  kill "$rs" 2>/dev/null || true; wait "$rs" 2>/dev/null || true
  if [[ -n $PID_A ]]; then
    ca=$((($(ticks "$PID_A") - ca) * 1000 / CLK_TCK)); cb=$((($(ticks "$PID_B") - cb) * 1000 / CLK_TCK))
    hwm=$(($(vm "$PID_A" VmHWM) + $(vm "$PID_B" VmHWM)))
    sleep 1; rl=$(($(vm "$PID_A" VmRSS) + $(vm "$PID_B" VmRSS)))
    w0=$(($(ctxsw "$PID_A") + $(ctxsw "$PID_B"))); sleep "$IDLE"
    w1=$(($(ctxsw "$PID_A") + $(ctxsw "$PID_B")))
    ri=$(($(vm "$PID_A" VmRSS) + $(vm "$PID_B" VmRSS))); wk=$(((w1 - w0) / IDLE))
  fi
  echo "$id,$phase,$hold,$pos,$arm,$cc,$flows,$hs,$ca,$cb,$hwm,$rl,$ri,$wk,$load0,$(cut -d' ' -f1 /proc/loadavg)" >>"$OUT/runs.csv"
  stop_engines
}

stop_engines() {
  local p
  for p in ${PID_A:-} ${PID_B:-}; do kill "$p" 2>/dev/null || true; done
  for p in ${PID_A:-} ${PID_B:-}; do wait "$p" 2>/dev/null || true; done
  ip -n $NS_A link del $IF_A 2>/dev/null || true; ip -n $NS_B link del $IF_B 2>/dev/null || true
  rm -f "/var/run/wireguard/$IF_A.sock" "/var/run/wireguard/$IF_B.sock"
  PID_A='' PID_B=''; sleep 1
}

PID_A='' PID_B=''
setup_net
machine_header
echo "id,phase,hold,pos,arm,cc,flows,handshake_ms,cpu_ms_a,cpu_ms_b,hwm_kb,rss_load_kb,rss_idle_kb,wakeups_per_s,load_start,load_end" >"$OUT/runs.csv"

# A/A first: the first arm twice per hold shows how far two identical runs drift apart.
for ((h = 1; h <= HOLDS; h++)); do
  for cc in $CCS; do for f in $FLOWS; do
    for pos in 1 2; do run_one aa "$h" $pos "${ARM_NAMES[0]}" "${ARM_BINS[0]}" "$cc" "$f"; done
  done; done
done
# Then A B B A (generalised: every arm in order, then every arm in reverse) per hold and cell.
if ((${#ARM_NAMES[@]} > 1)); then
  for ((h = 1; h <= HOLDS; h++)); do
    for cc in $CCS; do for f in $FLOWS; do
      order=(); pos=0
      for ((i = 0; i < ${#ARM_NAMES[@]}; i++)); do order+=("$i"); done
      for ((i = ${#ARM_NAMES[@]} - 1; i >= 0; i--)); do order+=("$i"); done
      for i in "${order[@]}"; do
        run_one abba "$h" $((++pos)) "${ARM_NAMES[i]}" "${ARM_BINS[i]}" "$cc" "$f"
      done
    done; done
  done
fi
rm -rf "$OUT/keys"
echo "done: python3 $(dirname "$0")/summarize.py $OUT" >&2
