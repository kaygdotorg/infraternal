# Configuration

`config/status.example.json` is a synthetic template for private operator input. It has four logical
parts:

- `site` contains public brand, title, description, and canonical URL text.
  An optional `source_url` must be an HTTPS GitHub owner/repository URL; when
  set, the page shows an accessible source link in the navigation. An optional
  `social_image` is a root-relative URL path to a local SVG, PNG, JPEG, or WebP asset;
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

The server accepts these configuration and bind-address overrides:

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
STATUS_SOCIAL_IMAGE                  Optional root-relative social-image URL path
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


## Connecting Blackbox Exporter

Infraternal reads metrics from Prometheus; it does not run probes or connect to
Blackbox Exporter directly. Your Prometheus scrape configuration must collect
`probe_success` (0 or 1) and `probe_duration_seconds`, or equivalent configured
metrics. The example expects `job="blackbox"`, `environment="public"`, and a
`service` label matching each private selector, such as `probe_website`.
Change those exact matchers to match your own series. Select exactly one series
per service; ambiguous matches are rejected instead of silently combined.

Grafana is optional. For Grafana Cloud, supply its Prometheus metrics query
endpoint, not a dashboard URL. The adapter uses `/api/v1/query_range` appended
to the configured base URL, so retain any path prefix required by the provider.

The default freshness threshold is 90 seconds. Set `probe.freshness_seconds`
to fit your scrape interval; stale observations appear as missing rather than
as healthy services. Historical coverage depends on your metrics retention.

## Branding and local assets

`site.social_image` is a URL such as `/social-preview.png`, resolved below
`web/`, not a host filesystem path. Mount your private artwork at the matching
container path, for example `/app/web/social-preview.png`, read-only. A missing
asset fails startup. Mount a custom favicon at `/app/web/favicon.svg` if desired.
Keep these files and production configuration outside the source checkout.
Artwork is publicly served: inspect it and its metadata for private information
before mounting it. A private host directory does not make a served asset private.
Only public display values belong in `site`, service names, groups and slugs:
those fields are intentionally visible to every visitor.

## Health endpoints

`/healthz` and `/readyz` confirm the process is serving after configuration
validation. Neither queries Prometheus or proves upstream availability. Verify
`/api/v1/status?range=24h` and observation timestamps to test metrics connectivity
and freshness. Empty history can mean that your selectors have no samples.

## Operational limits

Defaults below apply to direct Python startup. Compose sets the application
rate budget to 6,000 requests per minute because NGINX is its shared peer.
Non-integer limit values are rejected; integer limits and timeouts are clamped
to the bounds below. A nonnumeric `UPSTREAM_TIMEOUT` is rejected, while a
nonnumeric `REQUEST_TIMEOUT` falls back to 20 seconds.

| Environment variable | Default | Bounds / purpose |
| --- | --- | --- |
| `MAX_REQUESTS` | 32 | 1–128 concurrent request workers |
| `MAX_UPSTREAM_QUERIES` | 4 | 1–16 concurrent metrics queries |
| `UPSTREAM_TIMEOUT` | 15 | 1–60 seconds per upstream request |
| `REQUEST_TIMEOUT` | 20 | 1–120 seconds per client socket |
| `RATE_LIMIT_REQUESTS` | 120 | 1–10,000 requests per peer per window |
| `RATE_LIMIT_WINDOW` | 60 | 1–3,600 seconds |
| `ENABLE_HSTS` | 0 | `1`, `true` or `yes` enables application HSTS; normally own this at the TLS ingress |

These limits do not replace the proxy's connection, body and header limits.
See [container deployment](containers.md) for aggregate limits behind ingress.
