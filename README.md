# Infraternal

A self-hosted status page for services you already monitor with Prometheus and
Blackbox Exporter. Give visitors a clear view of availability and response
times without exposing your monitoring system.

Infraternal reads your existing probe metrics and turns them into a public
service overview, interactive charts, and per-service check history. You choose
which services appear and how they are named. It works with a self-hosted
Prometheus-compatible endpoint or a hosted metrics service such as Grafana
Cloud; Grafana itself is not required.

## What you get

- A service overview and detail pages with observed uptime and response times.
- Interactive Bklit charts, availability segments, and keyboard-accessible
  tooltips, with history ranges from 15 minutes to one year.
- Light and dark themes, local gradient backgrounds, and shared translucent
  cards and pills. Fonts and scripts are served locally.
- Configurable branding, favicon, social preview, and an optional GitHub source
  link. Your instance configuration stays separate from the product code.
- Rootless Docker and Podman deployment with an unprivileged NGINX proxy.
- A narrow, read-only API: visitors cannot submit PromQL, select upstream hosts,
  or access your credentials, metric labels, or private selectors.

It is a presentation layer, not a monitoring or alerting engine. Prometheus and
Blackbox Exporter must already collect the data. Infraternal has no database,
probe scheduler, incident editor, or notification service. Historical charts
use interval aggregates; missing observations are not counted as uptime.

## How it works

```text
Blackbox Exporter → Prometheus-compatible metrics store
                                  ↑ fixed server-side queries
Visitor → TLS ingress → NGINX → Infraternal
                                  ↓ sanitized public data
                           status page and charts
```

The Python service has no third-party runtime dependencies. The browser uses a
small JavaScript application with React islands for charts. All browser assets
and API requests are same-origin; there are no required CDN or analytics calls.
The product accepts up to 80 configured services and bounds query results,
response sizes, concurrency and rendering work. See [architecture and data
semantics](docs/architecture.md) for the details and tradeoffs.

## Try it locally

Run these commands from the repository root with Python 3.10 or newer:

```sh
cp config/status.example.json /tmp/infraternal.json
# Edit /tmp/infraternal.json with your metrics endpoint and service selectors.
STATUS_CONFIG=/tmp/infraternal.json python3 status_api.py
```

Open <http://127.0.0.1:8080>. The example contains synthetic values; it will not
show live status until you configure a reachable datasource and matching probe
labels. The local server binds to loopback. Use the production proxy setup
below before making an instance public.

Read the [configuration guide](docs/configuration.md) for Blackbox labels,
Grafana Cloud authentication, branding, freshness and health checks.

## Deploy

Follow the [Docker and rootless Podman guide](docs/containers.md). It includes
secret-file permissions, private networking, TLS ingress, resource limits,
updates and reboot behavior. The provided Compose stack publishes only NGINX
on loopback; the application container has no host port.

Keep production configuration, credentials and private artwork **outside the
repository**, mounted read-only. Update the same generic source for every
instance, then rebuild and recreate the containers with your external config.
Retain the previous image and ingress configuration for rollback.

## Develop and contribute

See [CONTRIBUTING.md](CONTRIBUTING.md) for runnable checks, chart builds,
repository structure and contribution expectations. The generated chart bundle
is committed, so running the Python service does not require Node.js.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
node --input-type=module --check < web/app.js
```

## Security and verification

The browser receives only configured public names, groups, slugs and sanitized
observations. Do not put private information in those public display fields.
Upstream addresses, credentials and query selectors remain server-side.

Read [SECURITY.md](SECURITY.md) for the security boundary and reporting guidance,
and [verification scope](docs/verification.md) for the checks performed and their
limits. A security review is not a guarantee against every vulnerability.
Safari's native toolbar and safe areas still require physical-device testing.

## License

Original project code is distributed under the [MIT license](LICENSE).
Bundled dependencies and fonts retain their own licenses; see
[third-party notices](THIRD_PARTY_NOTICES.md) and [licenses/](licenses/).
