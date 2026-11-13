#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Moves the device-QA server (QA1 only) to another release bundle: copies the bundle beside the others under
# /opt/qa/releases/<rev>, points /opt/qa/current at it and restarts `infraternal-qa-server`. The previous release stays
# on disk for rollback. Run as root on mesh-staging only inside a window granted for it. It rewrites no unit file,
# no nginx config, no firewall rule, TLS key or CA, and touches nothing outside /opt/qa and the one QA1 server unit.
#
# Usage: qa1-upgrade.sh <bundle-dir-with-infraternal-web-SOURCE> <expected-rev-prefix>
set -euo pipefail
test "$(hostname -s)" = mesh-staging
src=${1:?bundle dir}; want=${2:?expected revision prefix}
rev=$(cat "$src/SOURCE")
[[ "$rev" == "$want"* ]] || { echo "bundle is $rev, expected $want*: aborting"; exit 3; }
dest=/opt/qa/releases/${rev:0:9}
echo "start $(date -u +%T); current was $(readlink /opt/qa/current)"
if [ -d "$dest" ]; then
  # A directory with this name may hold other bytes than the bundle (an older build with the same prefix): refuse
  # unless its binary and web tree are byte-identical to the bundle, and print both so the receipt shows it.
  echo "existing release dir: $(sha256sum "$dest/infraternal" | cut -c1-64) SOURCE=$(cat "$dest/SOURCE")"
  echo "bundle:               $(sha256sum "$src/infraternal" | cut -c1-64) SOURCE=$rev"
  cmp -s "$dest/infraternal" "$src/infraternal" && diff -rq "$src/web" "$dest/web" >/dev/null && [ "$(cat "$dest/SOURCE")" = "$rev" ] \
    || { echo "existing $dest differs from the bundle: aborting before any change"; exit 5; }
else
  # The bundle must be the WHOLE release (`share/infraternal`: server, web/, SOURCE and the four static
  # `infraternal-*-musl` host binaries), or Add host fails on the phone ("matching static binary is unavailable").
  for f in infraternal web SOURCE infraternal-x86_64-musl infraternal-x86_64-session-musl infraternal-aarch64-musl infraternal-aarch64-session-musl; do
    [ -e "$src/$f" ] || { echo "bundle is incomplete: $src/$f missing, aborting before any change"; exit 6; }
  done
  cp -a "$src" "$dest"
  # `cp -a` keeps the SELinux type of the staging directory (tmp_t when it came from /tmp), and systemd then refuses
  # to exec the server (203/EXEC, "Permission denied"). Give the copy the labels the policy wants for /opt.
  restorecon -RF "$dest"
fi
ln -sfn "$dest" /opt/qa/current
systemctl restart infraternal-qa-server
for i in $(seq 1 60); do curl -fs -m 2 http://127.0.0.1:7021/healthz >/dev/null && break; sleep 1; done
echo "current=$(readlink /opt/qa/current) SOURCE=$(cat /opt/qa/current/SOURCE)"
echo "QA1: server=$(systemctl is-active infraternal-qa-server) proxy=$(systemctl is-active infraternal-qa-proxy) pid=$(systemctl show infraternal-qa-server -p MainPID --value) exe=$(sha256sum "$(readlink -f /proc/$(systemctl show infraternal-qa-server -p MainPID --value)/exe)" | cut -c1-16)"
echo "health: 7021=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7021/healthz || true) 8443=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/healthz || true)"
echo "end $(date -u +%T)"
