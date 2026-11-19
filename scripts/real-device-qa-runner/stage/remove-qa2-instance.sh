#!/usr/bin/env bash
# Removes the SECOND device-QA server that install-qa2-instance.sh created on mesh-staging, and nothing else: the first QA
# instance (:8443, /opt/qa, /var/lib/infraternal-qa), J479's server and the main service are never touched.
# Prints before/after hashes and listeners so the handback can show them unchanged.
# Usage (root on mesh-staging): remove-qa2-instance.sh
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
test "$(hostname -s)" = mesh-staging
echo "== before: main unit $(sha256sum /etc/systemd/system/infraternal-server.service | cut -c1-16) QA1 units $(sha256sum /etc/systemd/system/infraternal-qa-server.service /etc/systemd/system/infraternal-qa-proxy.service | cut -c1-16 | tr '\n' ' ') main pid $(systemctl show infraternal-server -p MainPID --value) QA1 pid $(systemctl show infraternal-qa-server -p MainPID --value)"
systemctl disable --now infraternal-qa2-proxy infraternal-qa2-server 2>&1 | tail -2 || true
rm -f /etc/systemd/system/infraternal-qa2-server.service /etc/systemd/system/infraternal-qa2-proxy.service
systemctl daemon-reload
systemctl reset-failed infraternal-qa2-server infraternal-qa2-proxy 2>/dev/null || true
# Only the paths this fixture created: its nginx config directory, its data directory and its user.
rm -f /opt/qa2/nginx.conf
rmdir /opt/qa2
rm -rf --one-file-system /var/lib/infraternal-qa2
id infraternal-qa2 >/dev/null 2>&1 && userdel infraternal-qa2
echo "== after: main unit $(sha256sum /etc/systemd/system/infraternal-server.service | cut -c1-16) QA1 units $(sha256sum /etc/systemd/system/infraternal-qa-server.service /etc/systemd/system/infraternal-qa-proxy.service | cut -c1-16 | tr '\n' ' ') main pid $(systemctl show infraternal-server -p MainPID --value) QA1 pid $(systemctl show infraternal-qa-server -p MainPID --value)"
echo "qa2 units: $(systemctl list-unit-files | grep -c qa2) (want 0); user: $(id infraternal-qa2 2>&1 | head -c 30); dirs: $(ls -d /opt/qa2 /var/lib/infraternal-qa2 2>&1 | tr '\n' ' ' | head -c 120)"
echo "listeners (want 8443, 7543, 7011 and 443 only): $(ss -ltn | grep -E ':(7021|7031|7543|7643|8443|9000|7011|443) ' | awk '{print $4}' | tr '\n' ' ')"
echo "health: QA1 8443=$(curl -sk -m 5 -o /dev/null -w %{http_code} https://127.0.0.1:8443/healthz) main 7011=$(curl -s -m 5 -o /dev/null -w %{http_code} http://127.0.0.1:7011/healthz) qa2 9000=$(curl -sk -m 5 -o /dev/null -w %{http_code} https://127.0.0.1:9000/healthz) (want 200 200 000)"
