#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# J1230 smoke test of the lanes + multi-queue build, as root in a throwaway dir: two netns joined
# by a veth (10.99.0.1/.2, no other links, no default route), gotatun-mq2 in each, 3 s iperf3 each
# direction, lane socket counters. Everything is removed on exit (trap).
set -uo pipefail
D=$(cd "$(dirname "$0")" && pwd)
N1=j30s1 N2=j30s2
cleanup() {
  for n in $N1 $N2; do
    for p in $(ip netns pids $n 2>/dev/null); do kill $p 2>/dev/null; done
  done
  sleep 1
  for n in $N1 $N2; do
    for p in $(ip netns pids $n 2>/dev/null); do kill -9 $p 2>/dev/null; done
    ip netns del $n 2>/dev/null
  done
  rm -f /var/run/wireguard/j30sx.sock /var/run/wireguard/j30sy.sock
  echo cleaned
}
trap cleanup EXIT
ip netns add $N1; ip netns add $N2
ip link add j30sa netns $N1 type veth peer name j30sb netns $N2
ip -n $N1 addr add 10.99.0.1/24 dev j30sa; ip -n $N2 addr add 10.99.0.2/24 dev j30sb
for n in $N1 $N2; do ip -n $n link set lo up; done
ip -n $N1 link set j30sa up; ip -n $N2 link set j30sb up
(umask 077; $D/wg genkey > $D/k1; $D/wg genkey > $D/k2)
P1=$($D/wg pubkey < $D/k1) P2=$($D/wg pubkey < $D/k2)
# Distinct interface names, so the two UAPI sockets (/var/run/wireguard/<name>.sock) differ.
up() { # up <netns> <ifname> <key> <peer-pub> <peer-ip> <self-tun-ip> <i>
  ip netns exec $1 env WG_SUDO=1 WG_LOG_LEVEL=info GOTATUN_LANES=${LANES:-2} GOTATUN_TUN_QUEUES=${QUEUES:-2} \
    setsid $D/gotatun-mq2 -f $2 > $D/gt$7.out 2> $D/gt$7.err < /dev/null &
  for t in $(seq 1 50); do [ -S /var/run/wireguard/$2.sock ] && break; sleep 0.1; done
  ip netns exec $1 $D/wg set $2 private-key $3 listen-port 51820 peer $4 endpoint $5:51820 allowed-ips 10.66.0.0/24
  ip -n $1 addr add $6/24 dev $2; ip -n $1 link set $2 mtu 1390 up
}
up $N1 j30sx $D/k1 $P2 10.99.0.2 10.66.0.1 1
up $N2 j30sy $D/k2 $P1 10.99.0.1 10.66.0.2 2
sleep 3
# Per-lane receive counters on the receiving side.
ip netns exec $N2 nft -f - <<NFT
table inet j30c { chain inp { type filter hook input priority 0; policy accept; udp dport 51820 counter; udp dport 51821 counter; udp dport 51822 counter; udp dport 51823 counter; }; }
NFT
ip netns exec $N1 ping -c3 -W1 10.66.0.2 | tail -2
ip netns exec $N2 $D/iperf3 -s -D -p 5202
sleep 0.5
ip netns exec $N1 $D/iperf3 -c 10.66.0.2 -p 5202 -P 8 -t 4 2>&1 | grep -E 'SUM.*(sender|receiver)'
ip netns exec $N1 $D/iperf3 -c 10.66.0.2 -p 5202 -P 8 -t 4 -R 2>&1 | grep -E 'SUM.*(sender|receiver)'
echo "== lane sockets ($N1)"; ip netns exec $N1 ss -uanp | grep -E '5182[0-9]'
echo "== lane counters ($N2 input)"; ip netns exec $N2 nft list table inet j30c | grep counter
echo "== tun queues"; ip netns exec $N1 ls /sys/class/net/j30sx/queues/
ip -n $N1 -s link show j30sx | tail -4
echo "== nstat $N2"; ip netns exec $N2 cat /proc/net/netstat | awk 'NR==1{for(i=1;i<=NF;i++)k[i]=$i} NR==2{for(i=1;i<=NF;i++) if(k[i]~/OFOQueue|SACKReorder|TSReorder/) print k[i],$i}'
cat $D/gt1.err $D/gt2.err | head -20
