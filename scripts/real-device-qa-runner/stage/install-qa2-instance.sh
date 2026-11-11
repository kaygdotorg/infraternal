#!/usr/bin/env bash
# Installs a SECOND device-QA infraternal server on mesh-staging for the desktop-Safari run, beside the first QA
# instance and J479's server (never touches either). Fresh data dir, so a fresh first-run owner can be created from
# Mac Safari. Same release and the same certificate/CA as the first instance (the Mac trusts that CA for
# mesh-staging.vpn.kayg.org; the port does not matter), own user, ports and nginx.
#   server 127.0.0.1:7031, hosts 10.69.69.53:7643, TLS :8444, data /var/lib/infraternal-qa2
# Usage (root on mesh-staging): install-qa2-instance.sh            # needs /opt/qa/current and /opt/qa/tls
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
test "$(hostname -s)" = mesh-staging
test -x /opt/qa/current/infraternal && test -f /opt/qa/tls/cert.pem
name=mesh-staging.vpn.kayg.org
id infraternal-qa2 >/dev/null 2>&1 || useradd --system --home-dir /var/lib/infraternal-qa2 --shell /usr/sbin/nologin infraternal-qa2
install -d -m700 -o infraternal-qa2 -g infraternal-qa2 /var/lib/infraternal-qa2
install -d -m755 /opt/qa2
# The nginx worker (user nginx) reads the same key the first proxy uses; nothing new is exposed.
cat > /opt/qa2/nginx.conf <<NG
user nginx;
worker_processes 1;
pid /run/qa2-nginx.pid;
error_log /var/log/nginx/qa2-error.log;
events { worker_connections 1024; }
http {
  access_log off;
  map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }
  server {
    listen 8444 ssl;
    server_name $name;
    ssl_certificate /opt/qa/tls/cert.pem;
    ssl_certificate_key /opt/qa/tls/key.pem;
    location / {
      proxy_pass http://127.0.0.1:7031;
      proxy_http_version 1.1;
      proxy_set_header Host \$host:8444;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-For \$remote_addr;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection \$connection_upgrade;
      proxy_read_timeout 3600s;
    }
  }
}
NG
cat > /etc/systemd/system/infraternal-qa2-server.service <<UNIT
[Unit]
Description=device-QA infraternal server 2 (J509, desktop Safari), beside the first QA server
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=infraternal-qa2
RuntimeDirectory=infraternal-qa2
RuntimeDirectoryMode=0700
Environment=XDG_RUNTIME_DIR=/run/infraternal-qa2
Environment=HOME=/var/lib/infraternal-qa2
WorkingDirectory=/var/lib/infraternal-qa2
ExecStart=/opt/qa/current/infraternal server --data /var/lib/infraternal-qa2 --listen 127.0.0.1:7031 --public-origin https://$name:8444 --web-root /opt/qa/current/web --remote-listen 10.69.69.53:7643 --remote-ca-dir /var/lib/infraternal-qa2/remote-ca --behind-proxy --trusted-proxy 127.0.0.1
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/infraternal-qa2-proxy.service <<UNIT
[Unit]
Description=device-QA TLS proxy 2 (J509)
After=network-online.target
[Service]
ExecStart=/usr/sbin/nginx -c /opt/qa2/nginx.conf -g "daemon off;"
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now infraternal-qa2-server infraternal-qa2-proxy
for i in $(seq 1 60); do curl -fs -m 2 http://127.0.0.1:7031/healthz >/dev/null && break; sleep 1; done
curl -fsk -m 5 -o /dev/null -w 'proxy2_health=%{http_code}\n' https://127.0.0.1:8444/healthz
