#!/usr/bin/env bash
# Installs the device-QA infraternal server BESIDE J479's staging server on mesh-staging (never touches it).
# Own data dir, own ports (server 127.0.0.1:7021, hosts 10.69.69.53:7543, TLS 8443), own CA and own nginx.
# Usage (as root on mesh-staging): install-qa-instance.sh <bundle-dir-with-infraternal-and-web>
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
test "$(hostname -s)" = mesh-staging
src=${1:?bundle dir}
rev=$(cat "$src/SOURCE")
dest=/opt/qa/releases/$rev
install -d -m755 /opt/qa/releases /opt/qa/tls
[ -d "$dest" ] || { cp -a "$src" "$dest"; }
ln -sfn "$dest" /opt/qa/current
name=mesh-staging.vpn.kayg.org
if [ ! -f /opt/qa/tls/ca.pem ]; then
  umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1095 -subj "/CN=infraternal device-QA CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -keyout /opt/qa/tls/ca.key -out /opt/qa/tls/ca.pem
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$name" -keyout /opt/qa/tls/key.pem -out /opt/qa/tls/leaf.csr
  printf 'subjectAltName=DNS:%s,IP:10.69.69.53\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\nbasicConstraints=CA:FALSE\n' "$name" > /opt/qa/tls/leaf.ext
  openssl x509 -req -in /opt/qa/tls/leaf.csr -CA /opt/qa/tls/ca.pem -CAkey /opt/qa/tls/ca.key -CAcreateserial -days 365 -extfile /opt/qa/tls/leaf.ext -out /opt/qa/tls/cert.pem
  chmod 644 /opt/qa/tls/ca.pem /opt/qa/tls/cert.pem; chgrp nginx /opt/qa/tls/key.pem; chmod 640 /opt/qa/tls/key.pem
fi
# A second ROOT server would share root's fixed /run/infraternal with J479's embedded agent ("address in use"),
# so the QA server runs as its own user with a private runtime dir.
id infraternal-qa >/dev/null 2>&1 || useradd --system --home-dir /var/lib/infraternal-qa --shell /usr/sbin/nologin infraternal-qa
install -d -m700 -o infraternal-qa -g infraternal-qa /var/lib/infraternal-qa
cat > /opt/qa/nginx.conf <<NG
user nginx;
worker_processes 1;
pid /run/qa-nginx.pid;
error_log /var/log/nginx/qa-error.log;
events { worker_connections 1024; }
http {
  access_log off;
  map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }
  server {
    listen 8443 ssl;
    server_name $name;
    ssl_certificate /opt/qa/tls/cert.pem;
    ssl_certificate_key /opt/qa/tls/key.pem;
    location / {
      proxy_pass http://127.0.0.1:7021;
      proxy_http_version 1.1;
      proxy_set_header Host \$host:8443;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-For \$remote_addr;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection \$connection_upgrade;
      proxy_read_timeout 3600s;
    }
  }
}
NG
cat > /etc/systemd/system/infraternal-qa-server.service <<UNIT
[Unit]
Description=device-QA infraternal server (J509), beside the J479 staging server
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=infraternal-qa
RuntimeDirectory=infraternal-qa
RuntimeDirectoryMode=0700
Environment=XDG_RUNTIME_DIR=/run/infraternal-qa
Environment=HOME=/var/lib/infraternal-qa
WorkingDirectory=/var/lib/infraternal-qa
ExecStart=/opt/qa/current/infraternal server --data /var/lib/infraternal-qa --listen 127.0.0.1:7021 --public-origin https://$name:8443 --web-root /opt/qa/current/web --remote-listen 10.69.69.53:7543 --remote-ca-dir /var/lib/infraternal-qa/remote-ca --behind-proxy --trusted-proxy 127.0.0.1
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/infraternal-qa-proxy.service <<UNIT
[Unit]
Description=device-QA TLS proxy (J509)
After=network-online.target
[Service]
ExecStart=/usr/sbin/nginx -c /opt/qa/nginx.conf -g "daemon off;"
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
firewall-cmd --state >/dev/null 2>&1 && { firewall-cmd --add-port=8443/tcp >/dev/null; firewall-cmd --add-port=7543/tcp >/dev/null; } || true
systemctl enable --now infraternal-qa-server infraternal-qa-proxy
for i in $(seq 1 60); do curl -fs -m 2 http://127.0.0.1:7021/healthz >/dev/null && break; sleep 1; done
curl -fsk -m 5 -o /dev/null -w 'proxy_health=%{http_code}\n' https://127.0.0.1:8443/healthz
echo "qa instance: rev=$rev"
