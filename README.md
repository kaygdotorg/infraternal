# Infraternal

This package is a configurable, read-only status page for a small allowlist of
public services. A server-side adapter queries one fixed Prometheus-compatible
endpoint and publishes a sanitized projection containing display metadata,
availability, response-time aggregates, and bounded timestamps. The browser
never receives the datasource URL, authentication material, PromQL, metric
names, private selectors, or raw upstream labels.

The example configuration is intentionally synthetic. Replace its example
values before using it for a real service, and keep the operator configuration
outside `web/` and outside the public container image layer.

## Quick start

The default server binds to `127.0.0.1:8080`, which is suitable for local
testing or a trusted reverse proxy on the same host.

```sh
cp config/status.example.json /tmp/status-page.json
STATUS_CONFIG=/tmp/status-page.json python3 status_api.py
```

Check the liveness and public configuration routes:

```sh
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/readyz
curl -i http://127.0.0.1:8080/config.json
```

The example datasource is `prometheus.example.com`, so the status route will
remain unavailable until the operator supplies a reachable Prometheus-compatible
endpoint and matching private selectors. The server rejects plain HTTP unless
`allow_insecure_http` is explicitly enabled for a private development network.

## Configuration boundary

`config/status.example.json` is a private operator input. It has four logical
parts:

- `site` contains public brand, title, description, and canonical URL text.
  An optional `source_url` must be an HTTPS GitHub owner/repository URL; when
  set, the page shows an accessible source link in the navigation. An optional
  `social_image` is an absolute path to a local SVG, PNG, JPEG, or WebP asset;
  the default is the bundled generic favicon. The server renders these values
  into HTML metadata for link previews and escapes them at the boundary.
- `prometheus` contains one fixed datasource URL and optional server-only
  credentials. The URL cannot contain userinfo, query parameters, or fragments.
- `probe` contains server-owned metric names, label names, a fixed job value,
  and optional exact label matchers.
- `services` contains public `slug`, `name`, and `group` values plus the private
  `selector` and optional exact matchers used for upstream selection.

The public slug is deliberately independent from the private selector. A slug
is a stable URL identity; it is never inserted into PromQL. Startup validation
rejects duplicate identities, unknown fields, unsafe metric or label names,
oversized strings, duplicate selectors, and configurations that exceed the
bounded service/group limits. The largest accepted configuration has 80
services so the largest fixed history range remains within the response byte
limit.

The server also accepts these environment overrides:

```text
STATUS_CONFIG                       Configuration path (default /etc/status-page/config.json)
PROMETHEUS_URL                      Fixed Prometheus-compatible base URL
PROMETHEUS_BEARER_TOKEN_FILE        Read-only file containing a bearer token
PROMETHEUS_BASIC_USERNAME           Basic-auth username
PROMETHEUS_BASIC_PASSWORD_FILE      Read-only file containing the basic-auth password
ALLOW_INSECURE_PROMETHEUS_HTTP      1/true/yes enables plain HTTP for private development
STATUS_BRAND / STATUS_TITLE         Runtime site text overrides
STATUS_DESCRIPTION / STATUS_PUBLIC_URL
STATUS_SOURCE_URL                   Optional HTTPS GitHub owner/repository link
STATUS_SOCIAL_IMAGE                  Optional local absolute social-image path
LISTEN_HOST / PORT                  Bind address and port (defaults 127.0.0.1:8080)
```

Bearer authentication and basic authentication are mutually exclusive. A
hosted Prometheus service such as Grafana Cloud can be used through its
Prometheus-compatible HTTP query endpoint with the credentials required by
that endpoint, normally server-side basic authentication with a read-only
access policy. This package does not implement or expose a Grafana datasource
proxy, dashboard API, or arbitrary Prometheus query proxy.

Credentials must be mounted as read-only files. They are not included in
`config.json` examples, generated browser configuration, status responses,
URLs, logs, or error messages. Do not put a token in an environment value when
the deployment platform can provide a mounted secret file instead.

## Public routes

Only these application routes are intended to be public:

```text
GET or HEAD /healthz
GET or HEAD /readyz
GET or HEAD /config.json
GET or HEAD /api/v1/config
GET or HEAD /api/v1/status?range=<one fixed enum>
GET or HEAD / and /services/<public-slug>/  (static app routes)
```

`range` must be exactly one of `15m`, `1h`, `6h`, `24h`, `7d`, `30d`, `3mo`,
`6mo`, or `1y`; extra query parameters are rejected. No request chooses a
datasource, metric, label, selector, PromQL expression, time bounds, step, or
proxy path. The API returns only the configured public service fields and
sanitized observations. Hostnames, IP addresses, upstream labels, private
selectors, and raw upstream error text are excluded.

Responses are bounded by byte, series, sample, row, and service limits. Exact
range responses are coalesced and cached briefly, with one serialized
stale-if-error layer; the shorter metric caches fail through so stale age is
not renewed by a second cache. `HEAD` reuses an existing response and does not start an upstream refresh. A
small process-local rate limiter and concurrency bounds provide a second line
of defense. When a reverse proxy fronts the application, the application sees
the proxy as its peer; size its limiter as an aggregate safeguard and enforce
the real per-client policy at the trusted TLS edge. Do not make the app trust
arbitrary `X-Forwarded-For` headers.

## Frontend and assets

The page uses only same-origin scripts, styles, fonts, favicon, and API
requests. Decorative backgrounds are local CSS gradients. The response CSP
allows same-origin resources plus one fixed SHA-256 hash for the vendored
Torph stylesheet, disallows objects, frames, forms, and plugins, and is paired
with `Referrer-Policy: no-referrer`, `nosniff`, same-origin resource policy,
and frame protections. It does not use `unsafe-inline`. The frontend fetches the validated public
configuration first, checks every status row against that allowlist, escapes
display strings, rejects future/oversized/malformed observations, and caps
rendered rows before building chart or table DOM.

The chart adapter is authored in `charts/src/` and generated into `web/`.
`charts/package-lock.json` is checked in; `node_modules/` is deliberately not
part of the package.

## Build and tests

The Python service has no runtime package dependency. Run its tests from the
repository root:

```sh
python3 -m unittest discover -s status-page/tests -p 'test_*.py' -v
python3 -m py_compile status-page/status_api.py
node --check status-page/web/app.js
```

To rebuild the chart bundle, use the pinned lockfile and remove the install
directory before creating a release archive:

```sh
cd status-page/charts
npm ci
npm run typecheck
npm run build
cd ../..
```

The build writes `web/bklit-charts.js`, `web/bklit-charts.css`, and the copied
MIT notice. Run `npm audit --omit=dev` and the full `npm audit` against the
current registry as part of release review; registry results are time-bound.

## Deployment

`Containerfile`, `compose.yaml`, and the rootless deployment examples are
provided beside this README. They bind the application to loopback by default
and mount configuration and credentials read-only. The intended public path is:

```text
client -> TLS reverse proxy -> loopback status-page server -> fixed metrics endpoint
```

Use a maintained production HTTP server or a production reverse proxy in front
of the Python stdlib handler. The direct `python3 status_api.py` listener is a
local/private or development endpoint; it is not a claim that the stdlib
listener is a complete internet-facing edge server.

At the public edge, terminate TLS, allow only `GET` and `HEAD`, cap request
line/header/body sizes, enforce connection/read/write/idle timeouts, apply
per-client and global rate limits, and sanitize forwarded headers. Cache the
anonymous status response for a short period and allow stale data only under a
documented outage policy. Keep the application bound to loopback, disable
CORS, do not expose a Docker/Podman socket, and do not publish a metrics,
Grafana, probe, or arbitrary query path.

Rootless Docker or Podman should run the image as a numeric non-root user with
a read-only filesystem, no added capabilities, `no-new-privileges`, bounded
resources, and read-only config/secret mounts. Pin the base image by an
immutable tag or digest in a release build and record the image digest/SBOM.

## License and provenance

The project `LICENSE` is a provisional MIT choice for the original package
code. Confirm the release license before publishing an archive. Third-party
components retain their own terms; see `THIRD_PARTY_NOTICES.md` and the notice
files beside the assets. The Bklit source snapshot and generated chart bundle,
the minified Torph bundle, and the two shipped fonts each have recorded
checksums there. Do not remove those notices when regenerating or redistributing
the package.

## Updating an instance

Keep this checkout generic. Store site configuration, secrets and optional brand
assets outside it, mounted read-only into the container. Make changes here, run
`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests`, rebuild the
image, then recreate the services with the same external configuration. Test
`/healthz`, `/config.json` and every configured range before changing the public
reverse proxy. Retain the previous image tag and proxy configuration for rollback.
Never copy operator configuration into a commit or image layer.

The decorative background scrolls in document space instead of attaching to
the viewport. This avoids the fixed-edge solid-color extension described in
[WebKit issue 301756](https://bugs.webkit.org/show_bug.cgi?id=301756#c2).
Actual toolbar appearance still depends on Safari version and device settings.
