#!/usr/bin/env python3
"""A small, read-only public projection for a Prometheus-backed status page.

The Prometheus API is a private server-side dependency.  The browser can only
request one of the fixed public history ranges and receives the validated
display metadata plus aggregate availability/latency observations.  This
module deliberately has no arbitrary query or upstream proxy endpoint.
"""

from __future__ import annotations

import calendar
import base64
import gzip
import html
import json
import math
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any, Callable, Iterable


BASE_DIR = Path(__file__).resolve().parent
WEB_ROOT = BASE_DIR / "web"
CONFIG_ENV = "STATUS_CONFIG"
DEFAULT_CONFIG_PATH = Path("/etc/status-page/config.json")

MAX_CONFIG_BYTES = 512 * 1024
MAX_UPSTREAM_BYTES = 4 * 1024 * 1024
MAX_PUBLIC_BYTES = 8 * 1024 * 1024
MAX_UPSTREAM_SAMPLES_PER_SERIES = 10_000
MAX_UPSTREAM_SERIES = 512
MAX_UPSTREAM_SAMPLES_TOTAL = 100_000
# 80 services × 731 points is kept below MAX_PUBLIC_BYTES even when the
# operator uses the maximum validated display-string lengths.  This keeps the
# largest accepted range a usable response rather than a guaranteed 503.
MAX_SERVICES = 80
MAX_GROUPS = 100
MAX_STRING_LENGTH = 240
MAX_KEY_LENGTH = 64
MAX_MATCHERS = 16
MAX_RATE_CLIENTS = 4096
MAX_CLOCK_SKEW_SECONDS = 300
MAX_HISTORY_POINTS = 1024

RANGES: OrderedDict[str, tuple[int, int, str]] = OrderedDict(
    (
        ("15m", (900, 60, "15 minutes")),
        ("1h", (3600, 60, "1 hour")),
        ("6h", (21600, 60, "6 hours")),
        ("24h", (86400, 300, "24 hours")),
        ("7d", (604800, 1800, "7 days")),
        ("30d", (2592000, 7200, "30 days")),
        ("3mo", (7776000, 21600, "3 months")),
        ("6mo", (15552000, 43200, "6 months")),
        ("1y", (31536000, 43200, "1 year")),
    )
)

_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_LABEL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_METRIC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_:]{0,127}$")
_GITHUB_URL_RE = re.compile(r"^https://github\.com/[A-Za-z0-9][A-Za-z0-9._-]{0,63}/[A-Za-z0-9][A-Za-z0-9._-]{0,99}/?$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ASSET_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SOCIAL_IMAGE_EXTENSIONS = {".svg", ".png", ".jpg", ".jpeg", ".webp"}
SOURCE_TIMESTAMP_TOLERANCE_SECONDS = 1


class ConfigError(ValueError):
    """Raised when the server configuration is unsafe or incomplete."""


class UpstreamError(RuntimeError):
    """Raised when the private metrics source cannot provide a safe result."""


class Busy(RuntimeError):
    """Raised when a request cannot obtain an upstream/cache slot."""


def _bounded_string(value: Any, field: str, *, maximum: int = MAX_STRING_LENGTH) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ConfigError(f"{field} must be a non-empty string of at most {maximum} characters")
    if _CONTROL_RE.search(value):
        raise ConfigError(f"{field} contains a control character")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ConfigError(f"{field} is not valid UTF-8") from exc
    return value


def _optional_string(value: Any, field: str, *, maximum: int = MAX_STRING_LENGTH) -> str | None:
    if value is None:
        return None
    return _bounded_string(value, field, maximum=maximum)


def _optional_path(value: Any, field: str) -> Path | None:
    if value is None:
        return None
    return Path(_bounded_string(value, field, maximum=2048))


def _safe_key(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _KEY_RE.fullmatch(value):
        raise ConfigError(f"{field} must match {_KEY_RE.pattern}")
    return value


def _safe_label(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _LABEL_RE.fullmatch(value):
        raise ConfigError(f"{field} must be a Prometheus label identifier")
    return value


def _safe_metric(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _METRIC_RE.fullmatch(value):
        raise ConfigError(f"{field} must be a Prometheus metric identifier")
    return value


def _url(value: Any, field: str) -> str:
    value = _bounded_string(value, field, maximum=2048)
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ConfigError(f"{field} must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError(f"{field} cannot contain credentials, query parameters, or fragments")
    return value.rstrip("/")


def _github_url(value: Any, field: str) -> str | None:
    if value is None:
        return None
    value = _bounded_string(value, field, maximum=2048)
    if not _GITHUB_URL_RE.fullmatch(value):
        raise ConfigError(f"{field} must be an HTTPS GitHub owner/repository URL")
    return value.rstrip("/")


def _public_asset(value: Any, field: str) -> str:
    """Validate an absolute URL path for a checked-in public asset.

    The path is resolved below the configured web root when the server starts;
    this syntax check keeps traversal, URL authorities, and active URL parts
    out of the browser metadata before that filesystem check.
    """
    value = _bounded_string(value, field, maximum=240)
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or not value.startswith("/")
        or value.startswith("//")
    ):
        raise ConfigError(f"{field} must be an absolute local asset path")
    parts = value[1:].split("/")
    if not parts or any(not part or part in {".", ".."} or not _ASSET_SEGMENT_RE.fullmatch(part) for part in parts):
        raise ConfigError(f"{field} contains an unsafe asset path")
    if Path(parts[-1]).suffix.lower() not in _SOCIAL_IMAGE_EXTENSIONS:
        raise ConfigError(f"{field} must reference an SVG, PNG, JPEG, or WebP asset")
    return value


def _prom_string(value: str) -> str:
    """Quote a validated value for a Prometheus string literal."""
    # Configuration values are bounded and control-free before this function is
    # called.  Escaping is kept explicit so a quote cannot become PromQL.
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _read_json(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ConfigError("configuration file is unavailable") from exc
    if size <= 0 or size > MAX_CONFIG_BYTES:
        raise ConfigError("configuration file is empty or too large")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConfigError("configuration file is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ConfigError("configuration root must be an object")
    return value


def _parse_matchers(value: Any, field: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > MAX_MATCHERS:
        raise ConfigError(f"{field} must contain at most {MAX_MATCHERS} label matchers")
    result: dict[str, str] = {}
    for raw_label, raw_value in value.items():
        label = _safe_label(raw_label, f"{field} label")
        result[label] = _bounded_string(raw_value, f"{field}.{label}", maximum=128)
    return result


def _load_secret(path: Path | None, label: str) -> str | None:
    if path is None:
        return None
    try:
        stat = path.stat()
        if not path.is_file() or stat.st_size > 8192:
            raise ConfigError(f"{label} file is missing or too large")
        token = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f"{label} file cannot be read") from exc
    if not token or _CONTROL_RE.search(token):
        raise ConfigError(f"{label} file is empty or contains control characters")
    return token


def _public_ranges() -> list[dict[str, Any]]:
    return [
        {"key": key, "hours": seconds / 3600, "label": key, "description": label}
        for key, (seconds, _step, label) in RANGES.items()
    ]


def _env_override(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    return value if value else None


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    """Read a bounded integer setting without allowing resource inflation."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    return max(minimum, min(value, maximum))


def load_config(path: str | Path, environ: dict[str, str] | None = None) -> dict[str, Any]:
    """Load and validate server configuration, returning private runtime data.

    The returned object is intentionally separate from ``browser_config``;
    private upstream URL, token, metric names, and matchers never cross that
    boundary.
    """
    env = os.environ if environ is None else environ
    raw = _read_json(Path(path))
    allowed = {"site", "prometheus", "probe", "services"}
    unknown = set(raw) - allowed
    if unknown:
        raise ConfigError("unknown configuration field")

    site = raw.get("site")
    if not isinstance(site, dict):
        raise ConfigError("site must be an object")
    if set(site) - {"brand", "title", "description", "public_url", "source_url", "social_image"}:
        raise ConfigError("unknown site configuration field")
    brand = _env_override(env.get("STATUS_BRAND"), "STATUS_BRAND") or site.get("brand")
    title = _env_override(env.get("STATUS_TITLE"), "STATUS_TITLE") or site.get("title")
    description = _env_override(env.get("STATUS_DESCRIPTION"), "STATUS_DESCRIPTION") or site.get(
        "description"
    )
    public_url = _env_override(env.get("STATUS_PUBLIC_URL"), "STATUS_PUBLIC_URL") or site.get(
        "public_url"
    )
    source_url = _env_override(env.get("STATUS_SOURCE_URL"), "STATUS_SOURCE_URL")
    if source_url is None:
        source_url = site.get("source_url")
    social_image = _env_override(env.get("STATUS_SOCIAL_IMAGE"), "STATUS_SOCIAL_IMAGE")
    if social_image is None:
        social_image = site.get("social_image")
    brand = _bounded_string(brand, "site.brand")
    title = _bounded_string(title, "site.title")
    description = _bounded_string(description, "site.description")
    public_url = _url(public_url, "site.public_url")
    source_url = _github_url(source_url, "site.source_url")
    social_image = _public_asset(social_image, "site.social_image") if social_image is not None else "/favicon.svg"

    prometheus = raw.get("prometheus")
    if not isinstance(prometheus, dict):
        raise ConfigError("prometheus must be an object")
    if set(prometheus) - {"url", "bearer_token_file", "basic_auth", "allow_insecure_http"}:
        raise ConfigError("unknown prometheus configuration field")
    prometheus_url = _env_override(env.get("PROMETHEUS_URL"), "PROMETHEUS_URL") or prometheus.get("url")
    prometheus_url = _url(prometheus_url, "prometheus.url")
    allow_insecure = prometheus.get("allow_insecure_http", False)
    if not isinstance(allow_insecure, bool):
        raise ConfigError("prometheus.allow_insecure_http must be a boolean")
    if env.get("ALLOW_INSECURE_PROMETHEUS_HTTP", "").lower() in {"1", "true", "yes"}:
        allow_insecure = True
    if urllib.parse.urlsplit(prometheus_url).scheme == "http" and not allow_insecure:
        raise ConfigError("plain HTTP Prometheus URLs require explicit allow_insecure_http")
    token_raw = _env_override(env.get("PROMETHEUS_BEARER_TOKEN_FILE"), "PROMETHEUS_BEARER_TOKEN_FILE")
    if token_raw is None:
        token_raw = prometheus.get("bearer_token_file")
    token_path = _optional_path(token_raw, "prometheus.bearer_token_file")
    token = _load_secret(token_path, "bearer token")

    basic_raw = prometheus.get("basic_auth")
    if basic_raw is not None and not isinstance(basic_raw, dict):
        raise ConfigError("prometheus.basic_auth must be an object or null")
    if isinstance(basic_raw, dict) and set(basic_raw) - {"username", "password_file"}:
        raise ConfigError("unknown prometheus.basic_auth field")
    basic_username = _env_override(env.get("PROMETHEUS_BASIC_USERNAME"), "PROMETHEUS_BASIC_USERNAME")
    basic_password_raw = _env_override(
        env.get("PROMETHEUS_BASIC_PASSWORD_FILE"), "PROMETHEUS_BASIC_PASSWORD_FILE"
    )
    if isinstance(basic_raw, dict):
        if basic_username is None:
            basic_username = basic_raw.get("username")
        if basic_password_raw is None:
            basic_password_raw = basic_raw.get("password_file")
    basic_password_path = _optional_path(basic_password_raw, "prometheus.basic_auth.password_file")
    basic_password = _load_secret(basic_password_path, "basic-auth password")
    if basic_username is None and basic_password is None:
        basic_auth = None
    else:
        basic_username = _bounded_string(basic_username, "prometheus.basic_auth.username", maximum=128)
        if ":" in basic_username:
            raise ConfigError("prometheus.basic_auth.username cannot contain a colon")
        if basic_password is None:
            raise ConfigError("prometheus.basic_auth.password_file is required")
        basic_auth = {"username": basic_username, "password": basic_password}
    if token is not None and basic_auth is not None:
        raise ConfigError("configure bearer token or basic auth, not both")

    probe = raw.get("probe")
    if probe is None:
        probe = {}
    if not isinstance(probe, dict):
        raise ConfigError("probe must be an object")
    if set(probe) - {
        "job_label",
        "service_label",
        "job",
        "success_metric",
        "duration_metric",
        "freshness_seconds",
        "matchers",
    }:
        raise ConfigError("unknown probe configuration field")
    job_label = _safe_label(probe.get("job_label", "job"), "probe.job_label")
    service_label = _safe_label(probe.get("service_label", "service"), "probe.service_label")
    if job_label == service_label:
        raise ConfigError("probe.job_label and probe.service_label must differ")
    job = _bounded_string(probe.get("job", "blackbox"), "probe.job", maximum=128)
    success_metric = _safe_metric(probe.get("success_metric", "probe_success"), "probe.success_metric")
    duration_metric = _safe_metric(
        probe.get("duration_metric", "probe_duration_seconds"), "probe.duration_metric"
    )
    freshness = probe.get("freshness_seconds", 90)
    if not isinstance(freshness, int) or not 30 <= freshness <= 3600:
        raise ConfigError("probe.freshness_seconds must be an integer from 30 through 3600")
    global_matchers = _parse_matchers(probe.get("matchers"), "probe.matchers")
    if job_label in global_matchers or service_label in global_matchers:
        raise ConfigError("probe.matchers cannot override job or service identity")

    services_raw = raw.get("services")
    if not isinstance(services_raw, list) or not 1 <= len(services_raw) <= MAX_SERVICES:
        raise ConfigError(f"services must contain 1 through {MAX_SERVICES} entries")
    services: list[dict[str, Any]] = []
    keys: set[str] = set()
    names: set[str] = set()
    groups: set[str] = set()
    for index, item in enumerate(services_raw):
        if not isinstance(item, dict):
            raise ConfigError(f"services[{index}] must be an object")
        if set(item) - {"slug", "name", "group", "selector", "matchers"}:
            raise ConfigError(f"unknown services[{index}] configuration field")
        # ``slug`` is public URL identity.  It is deliberately independent of
        # the private ``selector`` value sent to Prometheus below.
        slug = _safe_key(item.get("slug"), f"services[{index}].slug")
        name = _bounded_string(item.get("name"), f"services[{index}].name")
        group = _bounded_string(item.get("group"), f"services[{index}].group", maximum=120)
        selector = _bounded_string(item.get("selector"), f"services[{index}].selector", maximum=128)
        if slug in keys or name in names:
            raise ConfigError("service slugs and names must be unique")
        if selector in keys:
            raise ConfigError("service selectors must be unique")
        keys.add(slug)
        keys.add(selector)
        names.add(name)
        groups.add(group)
        if len(groups) > MAX_GROUPS:
            raise ConfigError(f"services may use at most {MAX_GROUPS} groups")
        matchers = _parse_matchers(item.get("matchers"), f"services[{index}].matchers")
        if job_label in matchers or service_label in matchers:
            raise ConfigError("service matchers cannot override job or service identity")
        overlapping = set(global_matchers) & set(matchers)
        if any(global_matchers[label] != matchers[label] for label in overlapping):
            raise ConfigError("service matchers cannot conflict with probe.matchers")
        services.append(
            {
                "slug": slug,
                "name": name,
                "group": group,
                "selector": selector,
                "matchers": matchers,
            }
        )

    return {
        "site": {
            "brand": brand,
            "title": title,
            "description": description,
            "public_url": public_url,
            "source_url": source_url,
            "social_image": social_image,
        },
        "prometheus_url": prometheus_url,
        "bearer_token": token,
        "basic_auth": basic_auth,
        "probe": {
            "job_label": job_label,
            "service_label": service_label,
            "job": job,
            "success_metric": success_metric,
            "duration_metric": duration_metric,
            "freshness_seconds": freshness,
            "matchers": global_matchers,
        },
        "services": services,
    }


def browser_config(config: dict[str, Any]) -> dict[str, Any]:
    """Return only the display fields safe for an anonymous browser."""
    site = config["site"]
    grouped: OrderedDict[str, list[dict[str, str]]] = OrderedDict()
    services = []
    for service in config["services"]:
        display = {"slug": service["slug"], "name": service["name"], "group": service["group"]}
        services.append(display)
        grouped.setdefault(service["group"], []).append({"slug": service["slug"], "name": service["name"]})
    groups = [{"name": name, "services": entries} for name, entries in grouped.items()]
    public_site = {
        "brand": site["brand"],
        "title": site["title"],
        "description": site["description"],
        "publicUrl": site["public_url"],
    }
    if site.get("source_url"):
        public_site["sourceUrl"] = site["source_url"]
    return {
        "site": public_site,
        "services": services,
        "groups": groups,
        "ranges": _public_ranges(),
        "api": {"path": "/api/v1/status"},
    }


def _metric_selector(config: dict[str, Any], service: dict[str, Any]) -> str:
    probe = config["probe"]
    matchers: dict[str, str] = {
        probe["job_label"]: probe["job"],
        probe["service_label"]: service["selector"],
        **probe["matchers"],
        **service["matchers"],
    }
    # The identity labels are inserted last so malformed duplicate input can
    # never replace the server-owned job or private selector.
    matchers[probe["job_label"]] = probe["job"]
    matchers[probe["service_label"]] = service["selector"]
    return ",".join(f"{label}={_prom_string(matchers[label])}" for label in sorted(matchers))


def _combined_expression(config: dict[str, Any], metric: str) -> str:
    """Build one fixed OR expression from the validated private selectors."""
    expression = " or ".join(
        f"{metric}{{{_metric_selector(config, service)}}}" for service in config["services"]
    )
    if len(expression) > 512 * 1024:
        raise ConfigError("compiled metric selector is too large")
    return expression


def _timestamp_expression(config: dict[str, Any], metric: str) -> str:
    """Build a fixed expression that exposes each raw sample timestamp."""
    metric = _safe_metric(metric, "metric")
    expression = " or ".join(
        f"timestamp({metric}{{{_metric_selector(config, service)}}})" for service in config["services"]
    )
    if len(expression) > 512 * 1024:
        raise ConfigError("compiled timestamp selector is too large")
    return expression


def _range_expression(config: dict[str, Any], metric: str, function: str, window: str) -> str:
    """Build a fixed per-service range expression.

    Each range function receives the raw metric samples for one configured
    selector.  Keeping the range selector inside every function avoids a
    PromQL subquery, whose default evaluation interval could count resampled
    points instead of recorded scrapes on long public ranges.
    """
    if function not in {"min_over_time", "count_over_time", "sum_over_time", "avg_over_time"}:
        raise ConfigError("unsupported range function")
    metric = _safe_metric(metric, "metric")
    if not re.fullmatch(r"[0-9]+s", window):
        raise ConfigError("invalid range window")
    expression = " or ".join(
        f"{function}({metric}{{{_metric_selector(config, service)}}}[{window}])"
        for service in config["services"]
    )
    if len(expression) > 512 * 1024:
        raise ConfigError("compiled range selector is too large")
    return expression


def _service_candidates(config: dict[str, Any], metric: dict[str, Any]) -> list[dict[str, Any]]:
    probe = config["probe"]
    candidates = []
    if metric.get(probe["job_label"]) != probe["job"]:
        return candidates
    if any(metric.get(label) != value for label, value in probe["matchers"].items()):
        return candidates
    for service in config["services"]:
        if metric.get(probe["service_label"]) != service["selector"]:
            continue
        if any(metric.get(label) != value for label, value in service["matchers"].items()):
            continue
        candidates.append(service)
    return candidates


class PrometheusClient:
    """Fixed-query Prometheus client with byte/sample and redirect limits."""

    def __init__(self, config: dict[str, Any], *, opener: Any | None = None):
        self.config = config
        self.base_url = config["prometheus_url"]
        self.token = config["bearer_token"]
        self.basic_auth = config.get("basic_auth")
        self.opener = opener or urllib.request.build_opener(_NoRedirect())
        self.slots = threading.BoundedSemaphore(_env_int("MAX_UPSTREAM_QUERIES", 4, 1, 16))
        try:
            upstream_timeout = float(os.environ.get("UPSTREAM_TIMEOUT", "15"))
        except ValueError as exc:
            raise ConfigError("UPSTREAM_TIMEOUT must be a number") from exc
        self.timeout = max(1.0, min(upstream_timeout, 60.0))

    def _read_limited(self, response: Any) -> bytes:
        length = response.headers.get("Content-Length")
        if length:
            try:
                if int(length) > MAX_UPSTREAM_BYTES:
                    raise UpstreamError("upstream response too large")
            except ValueError as exc:
                raise UpstreamError("invalid upstream content length") from exc
        data = response.read(MAX_UPSTREAM_BYTES + 1)
        if len(data) > MAX_UPSTREAM_BYTES:
            raise UpstreamError("upstream response too large")
        return data

    def query(self, expression: str, start: int, end: int, step: int) -> dict[str, dict[float, float]]:
        params = urllib.parse.urlencode(
            {
                "query": expression,
                "start": start,
                "end": end,
                "step": step,
                "timeout": f"{self.timeout:g}s",
                "limit": MAX_UPSTREAM_SERIES,
            }
        ).encode("ascii")
        if not self.slots.acquire(blocking=False):
            raise Busy("upstream query limit reached")
        try:
            auth_header: dict[str, str] = {}
            if self.token:
                auth_header["Authorization"] = f"Bearer {self.token}"
            elif self.basic_auth:
                credentials = f"{self.basic_auth['username']}:{self.basic_auth['password']}".encode("utf-8")
                auth_header["Authorization"] = "Basic " + base64.b64encode(credentials).decode("ascii")
            request = urllib.request.Request(
                f"{self.base_url}/api/v1/query_range",
                data=params,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    **auth_header,
                },
                method="POST",
            )
            try:
                with self.opener.open(request, timeout=self.timeout) as response:
                    if getattr(response, "status", 200) != 200:
                        raise UpstreamError("upstream request failed")
                    raw = self._read_limited(response)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                raise UpstreamError("upstream request failed") from exc
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise UpstreamError("upstream response is invalid") from exc
            if not isinstance(payload, dict) or payload.get("status") != "success":
                raise UpstreamError("upstream response is unsuccessful")
            data = payload.get("data")
            if not isinstance(data, dict) or data.get("resultType") != "matrix":
                raise UpstreamError("upstream result is not a matrix")
            result = data.get("result", [])
            if not isinstance(result, list) or len(result) > MAX_UPSTREAM_SERIES:
                raise UpstreamError("upstream returned too many series")
            output: dict[str, dict[float, float]] = {}
            sample_total = 0
            for series in result:
                if not isinstance(series, dict) or not isinstance(series.get("metric"), dict):
                    continue
                candidates = _service_candidates(self.config, series["metric"])
                if len(candidates) != 1:
                    continue
                slug = candidates[0]["slug"]
                values = series.get("values")
                if not isinstance(values, list) or len(values) > MAX_UPSTREAM_SAMPLES_PER_SERIES:
                    raise UpstreamError("upstream returned too many samples")
                sample_total += len(values)
                if sample_total > MAX_UPSTREAM_SAMPLES_TOTAL:
                    raise UpstreamError("upstream returned too many samples")
                parsed: dict[float, float] = {}
                for point in values:
                    if not isinstance(point, (list, tuple)) or len(point) != 2:
                        continue
                    try:
                        timestamp = float(point[0])
                        value = float(point[1])
                    except (TypeError, ValueError, OverflowError):
                        continue
                    if math.isfinite(timestamp) and math.isfinite(value):
                        parsed[timestamp] = value
                if slug in output:
                    raise UpstreamError("upstream returned multiple series for a service")
                else:
                    output[slug] = parsed
            return output
        finally:
            self.slots.release()

    def _expression(self, metric: str) -> str:
        return _combined_expression(self.config, metric)

    def latest(self, now: int) -> dict[str, dict[str, Any]]:
        probe = self.config["probe"]
        success: dict[str, dict[float, float]] = {}
        duration: dict[str, dict[float, float]] = {}
        success_source: dict[str, dict[float, float]] = {}
        duration_source: dict[str, dict[float, float]] = {}
        # One fixed expression per metric keeps selectors server-owned while
        # avoiding one upstream request per public service.
        freshness = self.config["probe"]["freshness_seconds"]
        lookback = max(180, freshness + 60)
        for metric_name, target in (
            (probe["success_metric"], success),
            (probe["duration_metric"], duration),
        ):
            target.update(self.query(self._expression(metric_name), now - lookback, now, 60))
        for metric_name, target in (
            (probe["success_metric"], success_source),
            (probe["duration_metric"], duration_source),
        ):
            target.update(self.query(_timestamp_expression(self.config, metric_name), now - lookback, now, 60))
        result: dict[str, dict[str, Any]] = {}
        for key, values in success.items():
            if not values:
                continue
            evaluation_timestamp = max(values)
            raw_success = values[evaluation_timestamp]
            source_timestamp = success_source.get(key, {}).get(evaluation_timestamp)
            if source_timestamp is None or not math.isfinite(source_timestamp):
                continue
            if source_timestamp > now + MAX_CLOCK_SKEW_SECONDS or now - source_timestamp > freshness:
                continue
            raw_duration = duration.get(key, {}).get(evaluation_timestamp)
            duration_timestamp = duration_source.get(key, {}).get(evaluation_timestamp)
            if (
                duration_timestamp is None
                or not math.isfinite(duration_timestamp)
                or duration_timestamp > now + MAX_CLOCK_SKEW_SECONDS
                or now - duration_timestamp > freshness
                # Success and duration are emitted by the same blackbox
                # scrape.  Do not attach a previous scrape's latency to a
                # current success observation when Prometheus has repeated
                # one metric through its lookback window.
                or abs(duration_timestamp - source_timestamp) > SOURCE_TIMESTAMP_TOLERANCE_SECONDS
            ):
                raw_duration = None
            result[key] = {
                "timestamp": stamp(source_timestamp),
                "success": raw_success == 1,
                "duration": raw_duration * 1e9 if raw_duration is not None and raw_duration >= 0 else None,
            }
        return result

    def history(self, period: str, now: int) -> list[dict[str, Any]]:
        seconds, step, _label = RANGES[period]
        start = now - seconds + step
        window = f"{step}s"
        probe = self.config["probe"]
        selectors = probe["success_metric"]
        duration_selectors = probe["duration_metric"]
        # Range functions operate directly on raw samples for each configured
        # selector. A subquery around an instant-vector OR would count its
        # evaluation ticks, which can differ from the observed scrape count.
        minimum = self.query(_range_expression(self.config, selectors, "min_over_time", window), start, now, step)
        counts = self.query(_range_expression(self.config, selectors, "count_over_time", window), start, now, step)
        totals = self.query(_range_expression(self.config, selectors, "sum_over_time", window), start, now, step)
        durations = self.query(
            _range_expression(self.config, duration_selectors, "avg_over_time", window), start, now, step
        )

        result: list[dict[str, Any]] = []
        for index, service in enumerate(self.config["services"]):
            key = service["slug"]
            # The query results are keyed by service label. Every public row
            # below is rebuilt from the corresponding configured service.
            service_minimum = minimum.get(key, {})
            service_counts = counts.get(key, {})
            service_totals = totals.get(key, {})
            service_durations = durations.get(key, {})
            if len(service_minimum) > MAX_HISTORY_POINTS:
                raise UpstreamError("upstream returned too many history points")
            rows = []
            for timestamp, value in sorted(service_minimum.items()):
                count = _safe_count(service_counts.get(timestamp, 0))
                if not count:
                    continue
                duration = service_durations.get(timestamp)
                rows.append(
                    {
                        "timestamp": stamp(timestamp),
                        "success": value == 1,
                        "duration": duration * 1e9 if duration is not None and duration >= 0 else None,
                        "count": count,
                        "passed": max(0, min(count, _safe_count(service_totals.get(timestamp, 0)))),
                        "interval": step,
                    }
                )
            result.append(
                {
                    "name": service["name"],
                    "slug": key,
                    "group": service["group"],
                    "results": rows,
                    "interval": step,
                }
            )
        return result


def _safe_count(value: Any) -> int:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return 0
    if not math.isfinite(number) or number <= 0:
        return 0
    return min(int(number), 10_000_000)


def stamp(timestamp: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))


def _fresh_current(value: dict[str, Any] | None, now: int, freshness: int) -> dict[str, Any] | None:
    if not value:
        return None
    try:
        timestamp = calendar.timegm(time.strptime(value["timestamp"], "%Y-%m-%dT%H:%M:%SZ"))
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    if timestamp > now + MAX_CLOCK_SKEW_SECONDS:
        return None
    return value if now - timestamp <= freshness else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise UpstreamError("upstream redirects are not followed")


class ExpiringCache:
    """Coalesce refreshes and retain a short stale value during upstream errors."""

    def __init__(self, stale_seconds: int = 300):
        self.values: dict[str, tuple[float, Any]] = {}
        self.in_flight: set[str] = set()
        self.lock = threading.Lock()
        self.stale_seconds = stale_seconds

    def get(self, key: str, ttl: int, loader: Callable[[], Any], now: float | None = None) -> Any:
        now = time.time() if now is None else now
        with self.lock:
            cached = self.values.get(key)
            if cached and now - cached[0] < ttl:
                return cached[1]
            if key in self.in_flight:
                if cached and now - cached[0] <= ttl + self.stale_seconds:
                    return cached[1]
                raise Busy("cache refresh in progress")
            self.in_flight.add(key)
        try:
            value = loader()
        except Exception:
            with self.lock:
                cached = self.values.get(key)
                self.in_flight.discard(key)
                if cached and now - cached[0] <= ttl + self.stale_seconds:
                    return cached[1]
            raise
        with self.lock:
            self.values[key] = (now, value)
            self.in_flight.discard(key)
        return value

    def peek(self, key: str, max_age: int, now: float | None = None) -> Any | None:
        """Return a cached value without starting a refresh.

        ``HEAD`` status requests use this path so they never trigger an
        upstream query.  The caller supplies the complete stale window it is
        willing to describe in response headers.
        """
        now = time.time() if now is None else now
        with self.lock:
            cached = self.values.get(key)
            if cached and now - cached[0] <= max_age:
                return cached[1]
        return None


class RateLimiter:
    """Small process-local request limiter; put a stronger limit at the edge."""

    def __init__(self, limit: int = 120, window: int = 60):
        self.limit = max(1, limit)
        self.window = max(1, window)
        self.clients: OrderedDict[str, deque[float]] = OrderedDict()
        self.lock = threading.Lock()

    def allow(self, client: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        with self.lock:
            stamps = self.clients.setdefault(client, deque())
            self.clients.move_to_end(client)
            cutoff = now - self.window
            while stamps and stamps[0] <= cutoff:
                stamps.popleft()
            if len(stamps) >= self.limit:
                return False
            stamps.append(now)
            while len(self.clients) > MAX_RATE_CLIENTS:
                self.clients.popitem(last=False)
            return True


def _json_bytes(value: Any) -> bytes:
    data = json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(data) > MAX_PUBLIC_BYTES:
        raise UpstreamError("public response too large")
    return data


def _accepts_gzip(header: str) -> bool:
    """Return true only when gzip is explicitly acceptable (q > 0)."""
    for item in header.split(","):
        parts = [part.strip() for part in item.split(";")]
        if not parts or parts[0].lower() != "gzip":
            continue
        quality = 1.0
        for parameter in parts[1:]:
            name, separator, value = parameter.partition("=")
            if name.strip().lower() == "q" and separator:
                try:
                    quality = float(value.strip())
                except ValueError:
                    return False
        return math.isfinite(quality) and quality > 0
    return False


STATUS_CACHE_CONTROL = "public, max-age=15, s-maxage=30, stale-while-revalidate=60, stale-if-error=300"


def _render_index(web_root: Path, config: dict[str, Any]) -> bytes:
    """Render only the public site metadata into the static app shell.

    The browser config remains a JSON projection, while this small server-side
    substitution makes title/description/URL metadata useful to crawlers and
    link previews.  All values have already passed startup validation and are
    HTML-escaped again at the rendering boundary.
    """
    root = web_root.resolve()
    template_path = root / "index.html"
    try:
        if not template_path.is_file() or template_path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError("web index is missing or too large")
        template = template_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ConfigError("web index cannot be read as UTF-8") from exc

    social_image = config["site"].get("social_image", "/favicon.svg")
    asset_path = root / social_image.lstrip("/")
    try:
        resolved_asset = asset_path.resolve()
        if root not in resolved_asset.parents or not resolved_asset.is_file():
            raise ConfigError("site.social_image must reference an asset below the web root")
    except OSError as exc:
        raise ConfigError("site.social_image cannot be resolved") from exc

    values = {
        "__STATUS_TITLE__": html.escape(config["site"]["title"], quote=True),
        "__STATUS_DESCRIPTION__": html.escape(config["site"]["description"], quote=True),
        "__STATUS_BRAND__": html.escape(config["site"]["brand"], quote=False),
        "__STATUS_PUBLIC_URL__": html.escape(config["site"]["public_url"].rstrip("/") + "/", quote=True),
        "__STATUS_SOCIAL_IMAGE__": html.escape(
            f"{urllib.parse.urlsplit(config['site']['public_url']).scheme}://"
            f"{urllib.parse.urlsplit(config['site']['public_url']).netloc}{social_image}",
            quote=True,
        ),
    }

    marker_re = re.compile("|".join(re.escape(marker) for marker in values))
    rendered = marker_re.sub(lambda match: values[match.group(0)], template)
    if re.search(r"__STATUS_[A-Z_]+__", rendered):
        raise ConfigError("web index is missing a required metadata marker")
    return rendered.encode("utf-8")


class StatusHandler(SimpleHTTPRequestHandler):
    server_version = "status-page"
    sys_version = ""

    def __init__(self, *args: Any, directory: str | None = None, **kwargs: Any):
        super().__init__(*args, directory=directory or str(WEB_ROOT), **kwargs)

    @property
    def status_server(self) -> "StatusServer":
        return self.server  # type: ignore[return-value]

    def _client_id(self) -> str:
        return self.client_address[0] if self.client_address else "unknown"

    def _send_bytes(
        self,
        status: int,
        data: bytes,
        *,
        cache_control: str,
        send_body: bool = True,
        gzip_data: bytes | None = None,
        retry_after: int | None = None,
        allow: str | None = None,
    ) -> None:
        wants_gzip = _accepts_gzip(self.headers.get("Accept-Encoding", ""))
        if wants_gzip:
            data = gzip_data if gzip_data is not None else gzip.compress(data, compresslevel=6, mtime=0)
            encoding = "gzip"
        else:
            encoding = None
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache_control)
        self.send_header("Vary", "Accept-Encoding")
        if retry_after is not None:
            self.send_header("Retry-After", str(retry_after))
        if allow is not None:
            self.send_header("Allow", allow)
        if encoding:
            self.send_header("Content-Encoding", encoding)
        self.end_headers()
        if send_body:
            self.wfile.write(data)

    def _send_json(
        self,
        status: int,
        value: Any,
        *,
        cache_control: str,
        send_body: bool = True,
        retry_after: int | None = None,
        allow: str | None = None,
    ) -> None:
        try:
            data = _json_bytes(value)
        except UpstreamError:
            status, data = 503, b'{"error":"response unavailable"}'
            cache_control = "no-store"
        self._send_bytes(
            status,
            data,
            cache_control=cache_control,
            send_body=send_body,
            retry_after=retry_after,
            allow=allow,
        )

    def _send_error_json(self, status: int, message: str, *, retry_after: int | None = None) -> None:
        self._send_json(status, {"error": message}, cache_control="no-store", retry_after=retry_after)

    def _send_index(self, *, send_body: bool) -> None:
        data = self.status_server.index_html
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=60, stale-while-revalidate=60")
        self.end_headers()
        if send_body:
            self.wfile.write(data)

    def _status_payload(self, period: str) -> list[dict[str, Any]]:
        now = int(time.time())
        seconds, _step, _label = RANGES[period]
        history = self.status_server.cache.get(
            f"history:{period}",
            60 if seconds <= 86400 else 300,
            lambda: self.status_server.client.history(period, now),
            now,
        )
        latest = self.status_server.cache.get(
            "latest",
            30,
            lambda: self.status_server.client.latest(now),
            now,
        )
        freshness = self.status_server.config["probe"]["freshness_seconds"]
        return [dict(row, current=_fresh_current(latest.get(row["slug"]), now, freshness)) for row in history]

    def _status_response(self, period: str, *, send_body: bool) -> None:
        cache_key = f"response:{period}"
        if send_body:
            cached = self.status_server.response_cache.get(
                cache_key,
                15,
                lambda: self._build_status_response(period),
            )
        else:
            # A HEAD request reports metadata for a representation already in
            # cache.  It never starts a Prometheus refresh by itself.
            cached = self.status_server.response_cache.peek(cache_key, 15 + 300)
            if cached is None:
                raise Busy("status representation is not cached")
        plain, compressed = cached
        self._send_bytes(
            200,
            plain,
            gzip_data=compressed,
            cache_control=STATUS_CACHE_CONTROL,
            send_body=send_body,
        )

    def _build_status_response(self, period: str) -> tuple[bytes, bytes]:
        plain = _json_bytes(self._status_payload(period))
        return plain, gzip.compress(plain, compresslevel=6, mtime=0)

    def handle_request(self, send_body: bool) -> None:
        if not self.status_server.rate_limiter.allow(self._client_id()):
            self._send_json(429, {"error": "rate limit exceeded"}, cache_control="no-store", send_body=send_body)
            return
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        if path == "/healthz" and not parsed.query:
            self._send_json(200, {"status": "ok"}, cache_control="no-store", send_body=send_body)
            return
        if path == "/readyz" and not parsed.query:
            self._send_json(200, {"status": "ready"}, cache_control="no-store", send_body=send_body)
            return
        if path in {"/config.json", "/api/v1/config"} and not parsed.query:
            self._send_json(
                200,
                browser_config(self.status_server.config),
                cache_control="public, max-age=60, stale-while-revalidate=60",
                send_body=send_body,
            )
            return
        if path == "/api/v1/status":
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            period_values = params.get("range", [])
            period = period_values[0] if len(period_values) == 1 else ""
            if set(params) != {"range"} or period not in RANGES:
                self._send_json(400, {"error": "unsupported range"}, cache_control="no-store", send_body=send_body)
                return
            try:
                self._status_response(period, send_body=send_body)
            except Exception:
                self._send_json(
                    503,
                    {"error": "monitoring data temporarily unavailable"},
                    cache_control="no-store",
                    send_body=send_body,
                    retry_after=5,
                )
            return

        # Service routes are client-side routes. The app shell is rendered from
        # validated server configuration so crawlers receive the same public
        # title/description/URL as the browser application.
        if path in {"/", "/index.html"} or re.fullmatch(r"/services/[A-Za-z0-9._%~-]+/?", path):
            self._send_index(send_body=send_body)
            return
        self.path = path
        super().do_GET() if send_body else super().do_HEAD()

    def do_GET(self) -> None:
        self.handle_request(send_body=True)

    def do_HEAD(self) -> None:
        self.handle_request(send_body=False)

    def _method_not_allowed(self) -> None:
        self._send_json(
            405,
            {"error": "method not allowed"},
            cache_control="no-store",
            allow="GET, HEAD",
        )

    def do_POST(self) -> None:
        self._method_not_allowed()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def do_OPTIONS(self) -> None:
        self._method_not_allowed()

    def do_TRACE(self) -> None:
        self._method_not_allowed()

    def end_headers(self) -> None:
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'sha256-9FSs7KcrLRUSOwDMKKsTkMyDhNfMELkrw2Pw7LJTjZA='; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'self'",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=(), usb=()")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if self.status_server.enable_hsts:
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        super().end_headers()

    def log_message(self, *_args: Any) -> None:
        # Request paths can contain user-controlled data; the public service
        # does not log them by default.
        return


class StatusServer(HTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], config: dict[str, Any], *, web_root: Path = WEB_ROOT):
        self.config = config
        self.web_root = web_root.resolve()
        self.index_html = _render_index(self.web_root, config)
        self.workers: ThreadPoolExecutor | None = None
        # Compile the complete fixed selector set before accepting requests.
        # This keeps malformed operator configuration out of the request path.
        _combined_expression(config, config["probe"]["success_metric"])
        _combined_expression(config, config["probe"]["duration_metric"])
        _timestamp_expression(config, config["probe"]["success_metric"])
        _timestamp_expression(config, config["probe"]["duration_metric"])
        for _seconds, step, _label in RANGES.values():
            window = f"{step}s"
            for metric, function in (
                (config["probe"]["success_metric"], "min_over_time"),
                (config["probe"]["success_metric"], "count_over_time"),
                (config["probe"]["success_metric"], "sum_over_time"),
                (config["probe"]["duration_metric"], "avg_over_time"),
            ):
                _range_expression(config, metric, function, window)
        self.client = PrometheusClient(config)
        # Keep one stale layer at the serialized public response boundary. The
        # metric caches must fail through after their short TTL; otherwise a
        # stale inner value would be wrapped as a fresh outer response and the
        # stale window would silently stack.
        self.cache = ExpiringCache(stale_seconds=0)
        self.response_cache = ExpiringCache(stale_seconds=300)
        self.rate_limiter = RateLimiter(
            _env_int("RATE_LIMIT_REQUESTS", 120, 1, 10_000),
            _env_int("RATE_LIMIT_WINDOW", 60, 1, 3600),
        )
        self.enable_hsts = os.environ.get("ENABLE_HSTS", "0").lower() in {"1", "true", "yes"}
        handler = lambda *args, **kwargs: StatusHandler(*args, directory=str(self.web_root), **kwargs)
        super().__init__(address, handler)
        request_workers = _env_int("MAX_REQUESTS", 32, 1, 128)
        self.request_slots = threading.BoundedSemaphore(request_workers)
        self.workers = ThreadPoolExecutor(max_workers=request_workers, thread_name_prefix="status-page")

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            request_timeout = float(os.environ.get("REQUEST_TIMEOUT", "20"))
        except ValueError:
            request_timeout = 20.0
        request.settimeout(max(1.0, min(request_timeout, 120.0)))
        self.workers.submit(self._process_request_thread, request, client_address)

    def _process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            self.finish_request(request, client_address)
            self.shutdown_request(request)
        except Exception:
            self.handle_error(request, client_address)
            self.shutdown_request(request)
        finally:
            self.request_slots.release()

    def server_close(self) -> None:
        workers = self.workers
        if workers is not None:
            workers.shutdown(wait=True, cancel_futures=True)
            self.workers = None
        super().server_close()


def main() -> None:
    config_path = Path(os.environ.get(CONFIG_ENV, DEFAULT_CONFIG_PATH))
    config = load_config(config_path)
    host = os.environ.get("LISTEN_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    if not 1 <= port <= 65535:
        raise SystemExit("PORT must be between 1 and 65535")
    server = StatusServer((host, port), config)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
