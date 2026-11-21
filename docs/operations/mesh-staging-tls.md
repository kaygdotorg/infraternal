# Public TLS for the mesh-staging test server

`infraternal up` trusts only public certificate authorities, so a test server
that enrols machines needs a real certificate. The mesh-staging server
(`infraternal-server`, NetBird address 10.69.69.53) serves one under
`https://mesh-staging.infraternal.com` (#565).

## What exists

| Piece | Where |
|---|---|
| DNS | `mesh-staging.infraternal.com` A record to 10.69.69.53 (a private NetBird address, DNS-only, no proxy) in the `infraternal.com` Cloudflare zone |
| Issuer | Let's Encrypt, DNS-01 through the Cloudflare API (the host name is private, so HTTP-01 cannot work), ACME client `lego`, ECDSA P-256, no account email |
| Client state | on hd01 under `~/orch/secrets/acme/` (mode 0700): `run-lego.sh`, `install-cert.sh`, `renew.sh`, the ACME account and the certificate files. The Cloudflare token stays in `~/orch/secrets/cloudflare.env` and is loaded only into lego's environment. |
| Terminator | `j479-proxy.service` (nginx, :443) on mesh-staging, files `/var/lib/j479/tls/cert.pem` (0644) and `key.pem` (0600), both root-owned |
| Not changed | the device-QA proxy on :8443 keeps its own QA-CA certificate, and the `mesh-staging.vpn.kayg.org` name is untouched |

## Renewal

`mesh-staging-cert-renew.timer` (systemd user unit on hd01, lingering enabled)
runs `renew.sh` daily at about 04:17 local time. lego renews only when fewer than
30 days remain. After a renewal it runs `install-cert.sh`, which copies the new
files to mesh-staging, checks the nginx config and sends the proxy a graceful
`SIGHUP` (the unit has no `reload` action, and a restart would drop connections).
Other ways to renew: `systemctl --user start mesh-staging-cert-renew.service`
(does nothing until the window opens).

## Roll back or remove

- Back to the self-signed pair: on mesh-staging, as root, copy
  `cert.pem.selfsigned` and `key.pem.selfsigned` over `cert.pem` and `key.pem`
  in `/var/lib/j479/tls`, then `systemctl kill -s HUP --kill-whom=main j479-proxy`.
  (The self-signed certificate expired on 2026-11-17.)
- Stop renewing: `systemctl --user disable --now mesh-staging-cert-renew.timer`
  and delete the two unit files in `~/.config/systemd/user`.
- Drop the name: delete the A record in the Cloudflare zone.

## Check

```sh
curl -sv https://mesh-staging.infraternal.com/healthz   # ssl_verify_result 0, {"status":"ok"}
```
