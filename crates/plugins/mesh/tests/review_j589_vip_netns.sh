#!/bin/bash
# Run under `unshare -Urnm`. RULE=pinned exits 1 (red), RULE=any exits 0 (control).
# J589: SSH admin rule pinned to the interface owning the dialled address.
# Outer netns = server (VIP 192.0.2.89 on lo, NIC v0 10.0.0.1). Child = admin client 10.0.0.2.
# RULE=pinned installs what server init saves for SSH_CONNECTION "10.0.0.2 P 192.0.2.89 22":
#   iifname "lo" ip saddr 10.0.0.2 tcp dport 22 accept
# RULE=any installs: tcp dport 22 accept (control).
set -u
NFT=${NFT:-/usr/sbin/nft}
ip link set lo up
ip addr add 192.0.2.89/32 dev lo
unshare -n sleep 30 & CHILD=$!
# sleep: give the child a moment to enter its namespace before moving the veth.
sleep 0.3
in_child() { nsenter --net=/proc/$CHILD/ns/net "$@"; }
ip link add v0 type veth peer name v1
ip link set v1 netns /proc/$CHILD/ns/net
ip addr add 10.0.0.1/24 dev v0; ip link set v0 up
in_child ip link set lo up; in_child ip addr add 10.0.0.2/24 dev v1; in_child ip link set v1 up
in_child ip route add 192.0.2.89/32 via 10.0.0.1
if [ "$RULE" = pinned ]; then SSH='iifname "lo" ip saddr 10.0.0.2 tcp dport 22 accept'; else SSH='tcp dport 22 accept'; fi
"$NFT" -f - <<NFT
table inet infraternal_host {
    chain input {
        type filter hook input priority filter - 10; policy drop;
        iifname "lo" accept
        ct state invalid drop
        ct state established,related accept
        ip protocol icmp accept
        meta l4proto ipv6-icmp accept
        $SSH
    }
}
NFT
python3 -I -c '
import socket
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0",22)); s.listen(4); s.settimeout(8)
try: s.accept()
except Exception: pass' & SRV=$!
# sleep: let the listener bind before the client connects.
sleep 0.5
in_child python3 -I -c '
import socket, sys
try:
    socket.create_connection(("192.0.2.89",22), timeout=3).close(); print("SSH_TO_VIP=connected")
except Exception as e:
    print("SSH_TO_VIP=DROPPED", type(e).__name__); sys.exit(1)'
ST=$?
echo "IIF_SEEN_BY_TABLE=v0 (getifaddrs owner of 192.0.2.89: $(ip -o -4 addr show to 192.0.2.89/32 | awk '{print $2}'))"
kill $SRV $CHILD 2>/dev/null; echo "RULE=$RULE EXIT=$ST"; exit $ST
