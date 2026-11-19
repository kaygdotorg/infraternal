#!/usr/bin/env bash
# J555 review (#483, D386): kernel proof for the rendered host input table's IPv6 behaviour.
#
# Build the renderer first, then run it under a user namespace (no real root needed):
#   cargo build -p infraternal-plugin-mesh --example render_host_table
#   RENDER=<target>/debug/examples/render_host_table unshare -Urnm bash review_j555_ipv6_netns.sh
# It loads the exact table `host_firewall::render` prints for an admin-only
# policy (no hand-written copy, so it cannot drift from the renderer) into an
# outer namespace, links it by veth to a child namespace, then:
#   1. ND control: the child pings the outer link-local address. Neighbour
#      discovery must pass (expected to pass: ND is untracked, not invalid).
#   2. DHCPv6: the outer host sends a client message from [fe80::a]:546 to
#      ff02::1:2:547; the child "server" answers unicast from [fe80::b]:547.
#      The reply must reach the outer client. Exit 1 when it is dropped.
# NO_TABLE=1 runs the same probes without the table, as the harness control.
# LEGACY_TABLE=1 strips the renderer's DHCPv6 reply rule (J573), reproducing
# J555's red; the run fails if there was no such rule to strip.
set -u
NFT=${NFT:-$(command -v nft || echo /usr/sbin/nft)}
: "${RENDER:?set RENDER to the built render_host_table example}"
POLICY='{"admin_rules":[{"interface":null,"source":null,"protocol":"tcp","port":22}],"accept_interfaces":[],"listeners":[],"mesh_enabled":false}'
TABLE=$("$RENDER" "$POLICY") || { echo "RENDER_FAILED"; exit 2; }
if [ -n "${LEGACY_TABLE:-}" ]; then
  LEGACY=$(printf '%s\n' "$TABLE" | grep -v 'udp dport 546')
  [ "$LEGACY" != "$TABLE" ] || { echo "RENDER_HAS_NO_DHCPV6_RULE"; exit 2; }
  TABLE=$LEGACY
fi
ip link set lo up
unshare -n sleep 30 & CHILD=$!
# sleep: give the child a moment to enter its namespace before moving the veth.
sleep 0.3
in_child() { nsenter --net=/proc/$CHILD/ns/net "$@"; }
ip link add v0 type veth peer name v1
ip link set v1 netns /proc/$CHILD/ns/net
ip addr add fe80::a/64 dev v0 nodad
ip link set v0 up
in_child ip link set lo up
in_child ip addr add fe80::b/64 dev v1 nodad
in_child ip link set v1 up
if [ -z "${NO_TABLE:-}" ]; then
printf '%s\n' "$TABLE" | "$NFT" -f - || { echo "TABLE_LOAD_FAILED"; exit 2; }
"$NFT" list table inet infraternal_host
else
  echo "control run: no host table loaded"
fi
# sleep: let the links reach UP before the first probe.
sleep 1
if in_child ping -6 -c 2 -W 2 fe80::a%v1 >/dev/null 2>&1; then
  echo "ND_CONTROL=pass"
else
  echo "ND_CONTROL=FAIL (neighbour discovery dropped)"
fi
in_child python3 -I -c '
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", 547))
mreq = socket.inet_pton(socket.AF_INET6, "ff02::1:2") + socket.if_nametoindex("v1").to_bytes(4, "little")
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
s.settimeout(8)
data, peer = s.recvfrom(1500)
s.sendto(b"reply", peer)  # unicast from fe80::b:547, the link-local server address
' & SERVER=$!
# sleep: let the child server join ff02::1:2 before the client solicits.
sleep 1
python3 -I -c '
import socket, sys
c = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
idx = socket.if_nametoindex("v0")
c.bind(("fe80::a", 546, 0, idx))
c.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
c.settimeout(4)
c.sendto(b"solicit", ("ff02::1:2", 547, 0, idx))
try:
    c.recvfrom(1500)
    print("DHCPV6_REPLY=received")
except socket.timeout:
    print("DHCPV6_REPLY=DROPPED")
    sys.exit(1)
'
STATUS=$?
wait $SERVER 2>/dev/null
kill $CHILD 2>/dev/null
echo "EXIT=$STATUS"
exit $STATUS
