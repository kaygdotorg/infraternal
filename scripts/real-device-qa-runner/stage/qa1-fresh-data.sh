#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
#
# Gives the device-QA server (QA1 only) a fresh, empty data directory, keeping the old one beside it. Run as root on
# mesh-staging only inside a window granted for it. A fresh data dir is what a first-run account test needs; the old
# one is kept so nothing is lost. It never touches J479's server, nginx on 443, /opt/j479, /run/infraternal or any
# unit that is not `infraternal-qa-server` / `infraternal-qa-proxy`, and it changes no TLS key, CA or network setting.
#
# Usage: qa1-fresh-data.sh <label>      (label: letters, digits, dashes; names the kept directory)
set -euo pipefail
test "$(hostname -s)" = mesh-staging
label=${1:?label}
[[ "$label" =~ ^[A-Za-z0-9-]+$ ]] || { echo "bad label" >&2; exit 2; }
data=/var/lib/infraternal-qa
kept="$data.$label-$(date -u +%Y%m%dT%H%M%SZ)"
echo "start $(date -u +%T)"
systemctl stop infraternal-qa-proxy infraternal-qa-server
sleep 1
[[ "$(systemctl is-active infraternal-qa-server || true)" == inactive && "$(systemctl show infraternal-qa-server -p MainPID --value)" == 0 ]] \
  || { echo "QA1 server did not stop: aborting before any move"; exit 4; }
mv "$data" "$kept"
install -d -m700 -o infraternal-qa -g infraternal-qa "$data"
# The restorecon keeps SELinux labels sane for the new directory; it is a no-op when none are needed.
restorecon -R "$data" 2>/dev/null || true
systemctl start infraternal-qa-server infraternal-qa-proxy
sleep 3
echo "kept: $kept"
echo "QA1: server=$(systemctl is-active infraternal-qa-server) proxy=$(systemctl is-active infraternal-qa-proxy) pid=$(systemctl show infraternal-qa-server -p MainPID --value)"
echo "health: 7021=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7021/healthz || true) 8443=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/healthz || true)"
echo "end $(date -u +%T)"
