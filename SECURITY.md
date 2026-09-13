# Security notes

This package is designed for a public, anonymous projection of private
monitoring data. The deployment boundary is:

```text
browser -> TLS/reverse proxy -> static files and narrow status API
                               -> one fixed, authenticated metrics endpoint
```

Treat the operator configuration, the metrics endpoint, and mounted secret
files as private. Treat every browser request and every upstream response as
untrusted input.

## Release and deployment requirements

- Start only after configuration validation succeeds. Keep the datasource URL,
  auth headers, metric names, matchers, selectors, and upstream errors on the
  server side.
- Use the public route allowlist in [container deployment](docs/containers.md). Never add a
  request-selected host, datasource identifier, path, PromQL expression, label,
  arbitrary time range, step, or raw proxy endpoint. Only the fixed history
  range enum is request-selectable.
- Mount credentials read-only and do not place them in source, browser config,
  query strings, container build arguments, logs, health output, or error
  responses.
- Terminate TLS at a maintained reverse proxy, publish the bundled NGINX proxy
  on loopback and keep the application on internal networks without a host
  port. Enforce request/header/body limits, read/write/idle timeouts,
  connection limits, per-IP rate limits, and compression/cache policy there.
- Run rootless with a numeric non-root user, read-only root filesystem,
  `no-new-privileges`, no added capabilities, bounded resources, and no
  container runtime socket.
- Keep all assets same-origin by default. Review the exact release archive,
  binary strings, image metadata, generated chart output, and configuration
  before publishing.

The API applies fixed query templates, PromQL identifier validation, exact
string-literal escaping, redirect rejection, upstream byte/series/sample caps,
public response caps, cache coalescing, and a process-local request limiter.
Those controls complement, rather than replace, an edge proxy and host-level
resource limits.

## Reporting

Do not open a public issue with a credential, private datasource URL, private
service inventory, or other operational detail. Email [security@kayg.org](mailto:security@kayg.org) privately. Include a minimal
reproduction, affected revision, impact, and suggested mitigation. Redact
credentials and private infrastructure details; do not send production secrets. Revoke any
credential that may have been exposed before preparing a report.

This document describes the intended controls; it is not a penetration test,
security warranty, or deployment-specific configuration review.
