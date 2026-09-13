# Verification scope

The initial release was reviewed for public data projection, fixed-query
construction, configuration validation, authentication forwarding, resource
bounds, stale data, client rendering, and rootless container behavior.

Regression tests cover raw-sample counting, source-timestamp freshness,
cross-scrape latency rejection, matcher conflicts, duplicate series, unsafe
Unicode, escaped HTML metadata, credential separation, redirect rejection,
response bounds, cache coalescing, and gzip negotiation.

A synthetic rootless Podman run exercised the app behind unprivileged NGINX:
public routes, compressed API and JavaScript responses, denied query/metrics
paths, read-only configuration, non-root process IDs, no effective capabilities,
no-new-privileges, loopback publication and resource limits.

The maximum tested history response (80 services × 731 observations) was
8,232,961 bytes, below the enforced 8 MiB identity limit. Browser lifecycle
checks retain only nearby graphs and preserve layout when offscreen roots are
released. These are bounded tests, not a guarantee against all vulnerabilities
or a physical mobile frame-rate benchmark. Re-run checks for each release.

Safari toolbar rendering must also be checked on actual devices. Desktop
viewport tests cannot reproduce its native floating controls.
