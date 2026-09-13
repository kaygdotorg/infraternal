# Container deployment

This package contains one application image and one unprivileged NGINX
reverse proxy. The Python server is intentionally a small standard-library
HTTP server, so the proxy is part of the production boundary. NGINX applies
request body and header limits, connection and request rate limits, bounded
upstream timeouts, and response buffering before forwarding the small
same-origin surface to the application.

The default Compose port is bound to `127.0.0.1`. The application has no host
port and is reachable only from the proxy network. A deployment that needs to
serve the page publicly must put a trusted TLS terminator in front of this
loopback listener, or extend the proxy configuration with its own certificate
and TLS policy. Do not publish the application container directly.

## Runtime boundary

The browser can use these same-origin routes:

- `/` and `/services/<slug>` for the static page and client-side routes;
- `/config.json` for the validated public display configuration;
- `/api/v1/config` is an equivalent API-shaped configuration route;
- `/healthz` for liveness and `/readyz` for sanitized readiness;
- `/api/v1/status?range=<fixed-range>` for the sanitized status projection.

The proxy returns `404` for `/api`, `/config`, `/metrics`, `/probe`, and
`/grafana` paths unless they match the exact public routes above. The backend
also rejects unknown API paths. Prometheus is queried only by the application;
its URL, selectors, metric names, matcher values, and bearer token never enter
the browser response. The application joins a separate egress network so it
can reach the configured Prometheus-compatible endpoint, while the proxy
network is marked internal.

The backend's CSP, `Referrer-Policy`, `Permissions-Policy`, frame, content
type, and cross-origin headers pass through NGINX unchanged. The proxy does
not add CORS or expose a generic upstream proxy. NGINX access logs record only
the request path (not the query string); do not enable a custom log format
that records authorization or upstream request bodies.

## Threat boundaries

The public client and any internet-facing TLS ingress are untrusted. NGINX
limits their request size, header size, idle time, connection count, and
per-address rate before the bounded Python worker and upstream-query pools are
used. A malformed or unexpectedly large Prometheus response is rejected by
the application, and public errors contain only a generic status. The
read-only root filesystem, dropped capabilities, no-new-privileges setting,
rootless engine, and resource caps limit the impact of an application or proxy
fault inside its container namespace.

These controls do not replace host patching, TLS configuration, file ownership
review, or upstream access control. A user who can change the operator config,
read the rootless engine's files, or control the configured Prometheus endpoint
already crosses the package trust boundary. Do not treat this Compose example
as protection from a compromised host, a malicious image registry, or a
misconfigured public TLS terminator.

## Prerequisites

Use a Linux host with either a rootless Docker daemon and the Docker Compose
plugin, or rootless Podman with a Compose provider. Do not run these commands
with `sudo`, mount a container-engine socket, use host networking, or grant a
privileged port.

Rootless Docker needs `newuidmap`/`newgidmap` and at least 65,536 subordinate
UIDs and GIDs for the user running the daemon. Check the daemon before using
it:

```sh
docker info --format '{{json .SecurityOptions}}'
```

The output should identify rootless mode. If the Docker client reports that it
cannot access its socket, start or repair the user's rootless daemon according
to the Docker rootless documentation; do not switch to a system daemon just
to run this package.

Rootless Podman should report `true` here and have a subordinate UID/GID range:

```sh
podman info --format '{{.Host.Security.Rootless}}'
grep "^$(id -un):" /etc/subuid /etc/subgid
```

The Podman override uses `keep-id` so a non-root image user can read private
host files without making them world-readable. It is intentionally a separate
override because Docker does not understand Podman's `keep-id:uid=...` syntax.

## Prepare operator files

The checked-in example is synthetic. Make a private working copy and set its
public display fields and one fixed Prometheus-compatible URL. A URL such as
`https://prometheus.example.com` is a documentation example; a Prometheus
service DNS name such as `http://prometheus:9090` is appropriate only when the
operator has attached the application to that service's network.

```sh
export STATUS_RUNTIME_DIR=/path/to/status-page-runtime
mkdir -p "$STATUS_RUNTIME_DIR"
cp config/status.example.json "$STATUS_RUNTIME_DIR/status.json"
chmod 0640 "$STATUS_RUNTIME_DIR/status.json"
export STATUS_CONFIG_FILE="$STATUS_RUNTIME_DIR/status.json"
```

Edit `$STATUS_CONFIG_FILE` and keep `bearer_token_file` as `null` when the
Prometheus endpoint does not require authentication. For a hosted or private
endpoint, create a separate host file using the credential system appropriate
for the host. The file must be owned by the user running the rootless engine,
readable by that user, and inaccessible to other users:

```sh
umask 077
# Populate this path from a secret manager or a protected transfer.
install -m 0640 /dev/null /path/to/status-page-prometheus-token
```

Do not put the token in `compose.yaml`, `.env`, a command line, a Dockerfile,
an image build argument, or an environment variable. Set the JSON field to the
in-container path `/run/secrets/metrics-token`, and provide only the host
path to Compose:

```sh
export PROMETHEUS_TOKEN_FILE=/path/to/status-page-prometheus-token
```

`PROMETHEUS_TOKEN_FILE` is a pathname, not a token value. Compose mounts the
file read-only at `/run/secrets/metrics-token`. Use that same in-container path
for either `bearer_token_file` or `basic_auth.password_file`; configure exactly
one authentication method. The checked-in placeholder is deliberately
non-secret and is used only so a clean checkout can validate the Compose model;
replace it before enabling either authentication method.

For a config file or secret under a directory with mode `0700`, the directory
must be traversable by the rootless engine user. Do not solve a permission
error by changing the credential to `0644` or `0666`. Use a private host group
for the `0640` files. With rootless Podman, use the
`keep-id` override shown below; with rootless Docker, the rootless daemon user
must own the source file and its private group must have read access. The
Compose service adds container group `0` as a supplementary group; in a
rootless Docker user namespace this is the daemon user's host group, while the
application itself remains UID `65532`. The host secret is never world-readable.

## Build and run with rootless Docker

The Python image is built from a digest-pinned `python:3.13-slim-bookworm`
base. The proxy uses the digest-pinned official NGINX unprivileged image and
listens on port 8080 inside the container. Build and start the complete
two-container service:

```sh
docker compose -f compose.yaml config
docker compose -f compose.yaml build --pull app
docker compose -f compose.yaml up -d
```

The Compose service applies a read-only root filesystem, a small writable
`/tmp` tmpfs, dropped capabilities, `no-new-privileges`, PID limits, and
memory/CPU caps to both containers. Check the local proxy and the two public
application routes:

```sh
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --fail --silent --show-error http://127.0.0.1:8080/config.json
curl --fail --silent --show-error \
  'http://127.0.0.1:8080/api/v1/status?range=15m'
```

The status request returns a generic `503` until the configured endpoint is
reachable and has the expected metrics. That response must not contain the
upstream URL, token, selectors, or an exception. `/healthz` and `/config.json`
are useful for checking the image and public projection without making an
upstream query.

View bounded logs and stop the service with:

```sh
docker compose -f compose.yaml logs --tail=100 app proxy
docker compose -f compose.yaml down
```

## Build and run with rootless Podman

Use the Podman Compose provider with the small override that maps the host
user to the numeric non-root UIDs declared by the images:

```sh
podman compose -f compose.yaml -f deploy/compose.podman.yaml config
BUILDAH_FORMAT=docker podman compose -f compose.yaml -f deploy/compose.podman.yaml build app
podman compose -f compose.yaml -f deploy/compose.podman.yaml up -d
```

Check the same loopback routes with `curl` and stop the service as follows:

```sh
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
podman compose -f compose.yaml -f deploy/compose.podman.yaml down
```

## Put an existing trusted ingress in front

The Compose file accepts a private bind address and port when an existing TLS
terminator or reverse proxy must remain the public edge. Set those values to
an address reachable by that ingress and an unused private port, then use the
same documented Podman commands:

```sh
export STATUS_BIND_ADDRESS="${STATUS_INGRESS_ADDRESS}"
export STATUS_HTTP_PORT="${STATUS_INGRESS_PORT}"
BUILDAH_FORMAT=docker podman compose -f compose.yaml -f deploy/compose.podman.yaml build app
podman compose -f compose.yaml -f deploy/compose.podman.yaml up -d
```

Only the NGINX proxy is published on that private bind; the application keeps
no host port. Configure the existing ingress to proxy the public root and the
candidate's client-side service routes to this NGINX listener. If the public
site has a prefix such as `/preview`, strip that prefix once at the existing
ingress before proxying. Keep the exact legacy API route on its existing
service while cached frontend assets transition to the package's
`/api/v1/status` path. Remove any older ingress CSP/header override so the
backend headers remain authoritative. The upstream TLS policy and public HSTS
belong at the trusted ingress.

Do not attach the application container directly to an internet-facing
network, publish its port, or use a custom wrapper that bypasses the Compose
resource, secret, and read-only settings. Future source updates should rebuild
the image from this canonical package; production configuration, credentials,
and private static assets remain external read-only mounts.

The equivalent isolated application smoke test, useful when inspecting an
image without starting the reverse proxy, is:

```sh
podman build --format docker -f Containerfile -t status-page:local .
podman run --rm --read-only \
  --user 65532:65532 \
  --userns keep-id:uid=65532,gid=65532 \
  --cap-drop=all --security-opt=no-new-privileges \
  --pids-limit 128 --memory 256m --cpus 1 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --publish 127.0.0.1:18080:8080 \
  --volume "$STATUS_CONFIG_FILE:/etc/status-page/config.json:ro" \
  status-page:local
```

This direct command is for local inspection only; use the NGINX service for a
production deployment. If SELinux labels prevent a bind mount on a host that
uses SELinux, apply the host's documented private read-only label procedure
to the config path. Do not disable SELinux or make a token world-readable.

## Inspect hardening

Both services should show a read-only root filesystem, no added capabilities,
the `no-new-privileges` security option, bounded PIDs and resources, and no
published application port. The app's image user is numeric UID/GID `65532`;
the unprivileged NGINX image uses UID/GID `101`. The only writable paths are
the explicitly mounted `/tmp` tmpfs instances. The config and secret mounts
are read-only, and the secret is not present in the image layer or environment.

For an engine-specific inspection, use the corresponding read-only commands:

```sh
docker compose -f compose.yaml ps
docker inspect status-page-app --format '{{json .Config}}'

podman compose -f compose.yaml -f deploy/compose.podman.yaml ps
podman inspect status-page-app --format '{{json .Config}}'
```

Compose-generated names can include the project directory, so use `docker ps`
or `podman ps` to obtain the actual container name when the literal example
does not match. Never print the contents of `/run/secrets/metrics-token` in
logs or diagnostics.

## Updates and exposure

Rebuild the app image after source changes and review the exact image digest
and package file manifest before exposing a listener. Update the pinned NGINX
digest deliberately after reviewing the official unprivileged-image release
and its security notes. Keep the host binding on loopback unless a separately
reviewed TLS ingress is enforcing authentication, request limits, and an
internet-facing policy.

The status page is intentionally anonymous and read-only. It does not provide
Grafana, Prometheus, exporter, arbitrary query, datasource proxy, or container
socket access. The only network egress required by the app is the configured
Prometheus-compatible API.

References: [Docker rootless mode](https://docs.docker.com/engine/security/rootless/),
[Compose secrets](https://docs.docker.com/compose/how-tos/use-secrets/),
[Compose service hardening](https://docs.docker.com/reference/compose-file/services/),
[Podman rootless mode](https://docs.podman.io/en/latest/markdown/podman-run.1.html),
and the [NGINX unprivileged image](https://github.com/nginx/docker-nginx-unprivileged).

### Rate limits behind another proxy

The bundled application sees NGINX as its client; its 6,000-request/minute
budget is aggregate admission control, not an end-user limit. If a TLS ingress
sits before NGINX, NGINX likewise sees that ingress address. Apply true per-client
limits at the trusted outermost ingress. NGINX permits 100 requests/second,
a 200-request burst and 48 active requests per source address, accommodating
concurrent page loads through that shared hop while keeping admission bounded.
Do not trust arbitrary forwarded IP
headers. Internal concurrency, memory, connection and upstream-query caps
remain enforced independently of those edge limits.
