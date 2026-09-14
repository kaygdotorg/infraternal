# Architecture and data semantics

Infraternal has two runtime components: a Python HTTP service and an
unprivileged NGINX proxy. A separate TLS ingress terminates public HTTPS.
Prometheus-compatible storage is an existing external dependency. There is no
application database; history is queried from the metrics store and cached in
memory. Restarting the process discards caches, not monitoring history.

## Source map

| Path | Responsibility |
| --- | --- |
| `status_api.py` | Configuration validation, fixed queries, projection, caches, bounded HTTP server and HTML metadata |
| `web/app.js` | Public config validation, routing, service views, shared surface helpers, chart lifecycle and refresh |
| `web/style.css` | Shared card/pill surfaces, typography, layout and responsive styles |
| `web/theme.js` | Theme and color-mode selection |
| `charts/src/bklit-charts.tsx` | React adapter for compact/detail latency and availability charts |
| `charts/src/vendor/` | Vendored Bklit source and license |
| `web/bklit-charts.*` | Generated chart runtime and stylesheet |
| `tests/` | Backend and package regression checks |
| `compose.yaml`, `deploy/` | Rootless runtime, NGINX and engine-specific configuration |

## Request flow and privacy

Startup validates the operator configuration and local social asset. The
browser loads public display configuration from `/config.json`, then requests
`/api/v1/status?range=<enum>`. The service constructs exact, server-owned
selectors and rebuilds public results from the configured service allowlist.
It never relays an upstream response directly. Private selectors and public
slugs are separate identities.

Only configuration fields intended for display are public. A name or slug can
still reveal sensitive information if an operator puts it there; choose them
accordingly. Credentials are read from mounted files. Upstream redirects,
ambiguous series and oversized responses are rejected. The proxy and server
both restrict request paths and resource use. See [SECURITY.md](../SECURITY.md)
and [container deployment](containers.md) for deployment boundaries.

## What the numbers mean

Current state uses the newest success sample and its source timestamp, not the
query evaluation time. Samples older than the configured freshness threshold
become unknown. Latency is attached only when its source timestamp matches the
success sample within one second, preventing a previous scrape's response time
from appearing beside a new state.

History uses raw Prometheus range functions for each interval. `count_over_time`
counts observed success samples; `sum_over_time` counts passes for a binary
0/1 success metric; `min_over_time` marks intervals containing failures. Duration
is `avg_over_time` of the configured duration metric. Missing intervals are
omitted, not fabricated as passed or failed checks.

| Selected range | Aggregation interval |
| --- | --- |
| 15m, 1h, 6h | 1 minute |
| 24h | 5 minutes |
| 7d | 30 minutes |
| 30d | 2 hours |
| 3mo | 6 hours |
| 6mo, 1y | 12 hours |

Observed uptime is passed observations divided by recorded observations.
Check counts represent samples, while table rows represent intervals. The
median is the median of interval mean durations, not the exact median of all
raw checks; larger intervals are labelled accordingly. The displayed average
weights interval means by success-sample counts, so it is an estimate if the
success and duration metrics have different sample coverage. Durations arrive
in seconds, are projected in nanoseconds, and displayed in milliseconds.
All displayed dates use the visitor's local time zone.

## Caching and resource bounds

The serialized status response has a 15-second cache lifetime and up to
300 seconds of stale fallback after expiry on refresh failure. Its identity
and gzip representations are cached together, and concurrent refreshes for
the same key are coalesced. Inner metric caches do not add another stale
window. The fallback preserves the prior current observation and timestamp;
freshness is not re-evaluated inside that already serialized response. A cached
state can therefore remain visible for the fallback window during an upstream
outage. Account for that delay when interpreting the page as a live signal.
A cold status `HEAD` returns unavailable instead of starting metrics queries;
a cached `HEAD` returns headers without a body.

The server caps services, upstream bytes, series, samples, public response
bytes and concurrent work. Limits are safeguards, not throughput promises.
Proxy limits apply to source addresses, which become aggregate limits behind
another proxy. True visitor limits belong at the trusted outer ingress.

## Frontend lifecycle and shared UI

`surfaceCard` and `surfacePill` generate consistent surface classes. CSS owns
their shared appearance; variants control spacing and context. The outer app
updates DOM while retaining compatible chart containers. React chart roots
mount near the viewport; offscreen roots are released after a delay, retaining
layout space and preserving keyboard focus. This bounds active chart work
without changing the service list's scroll height.

The summary and metadata rotate independently, and clicking either stops only
that control's automatic rotation. Rotation pauses when hidden or offscreen.
Local gradients scroll with the document rather than forming a fixed layer at
the viewport edge. Physical Safari controls still require device testing.

See [verification scope](verification.md) for measured bounds and limitations.

Shared pill activation pulses the outer surface as well as selected segmented
items. The same container feedback applies to pill padding and single-value
statistics; it adds no action or keyboard focus to informational text. Motion
is transform-only, is not triggered by refresh, and is cancelled or skipped
when reduced motion is requested.
