#!/usr/bin/env python3
import json
import base64
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import status_api


ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    status = 200

    def __init__(self, payload: dict):
        self.headers = {"Content-Length": str(len(json.dumps(payload).encode()))}
        self._body = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit=-1):
        return self._body


class FakeOpener:
    def __init__(self, payload):
        self.payload = payload
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        return FakeResponse(self.payload)


class StatusApiTests(unittest.TestCase):
    def make_config(self, **overrides):
        value = json.loads((ROOT / "config/status.example.json").read_text())
        value["prometheus"]["url"] = "http://127.0.0.1:19090"
        value["prometheus"]["allow_insecure_http"] = True
        for key, item in overrides.items():
            value[key] = item
        return value

    def write_config(self, value, token=None):
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "config.json"
        if token is not None:
            token_path = Path(directory.name) / "token"
            token_path.write_text(token)
            value["prometheus"]["bearer_token_file"] = str(token_path)
        path.write_text(json.dumps(value))
        return directory, path

    def test_public_config_excludes_private_selector_and_credentials(self):
        directory, path = self.write_config(self.make_config(), token="secret-value")
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)
        public = status_api.browser_config(config)
        encoded = json.dumps(public)
        self.assertNotIn("prometheus.example.com", encoded)
        self.assertNotIn("secret-value", encoded)
        self.assertNotIn("probe_website", encoded)
        self.assertIn('"slug": "website"', encoded)
        self.assertNotIn('"selector"', encoded)
        self.assertNotIn('"service_label"', encoded)

    def test_selector_is_private_and_public_slug_is_not_promql(self):
        directory, path = self.write_config(self.make_config(), token=None)
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)
        expression = status_api._combined_expression(config, "probe_success")
        self.assertIn('service="probe_website"', expression)
        self.assertNotIn('service="website"', expression)
        self.assertNotIn("|", expression)

    def test_history_counts_raw_samples_without_a_subquery_resample(self):
        directory, path = self.write_config(self.make_config())
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)
        client = status_api.PrometheusClient(config, opener=FakeOpener({}))
        expressions = []

        def capture(expression, start, end, step):
            expressions.append(expression)
            return {}

        client.query = capture
        client.history("1h", 1_000)
        self.assertEqual(len(expressions), 4)
        self.assertTrue(all("[60s]" in expression for expression in expressions))
        self.assertTrue(all("[60s:]" not in expression for expression in expressions))
        self.assertIn("min_over_time(probe_success{", expressions[0])
        self.assertIn("count_over_time(probe_success{", expressions[1])

    def test_promql_values_are_escaped_and_query_is_posted(self):
        value = self.make_config()
        value["probe"]["matchers"]["tenant"] = 'safe\\"value'
        directory, path = self.write_config(value)
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)
        payload = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [
                    {
                        "metric": {
                            "job": "blackbox",
                            "service": "probe_website",
                            "environment": "public",
                            "tenant": 'safe\\"value',
                        },
                        "values": [[1000, "1"]],
                    }
                ],
            },
        }
        opener = FakeOpener(payload)
        client = status_api.PrometheusClient(config, opener=opener)
        result = client.query(status_api._combined_expression(config, "probe_success"), 900, 1000, 60)
        self.assertEqual(result["website"][1000.0], 1.0)
        request = opener.requests[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, "http://127.0.0.1:19090/api/v1/query_range")
        self.assertIn(b"limit=", request.data)
        self.assertIn(b"safe%5C%5C%5C%22value", request.data)

    def test_source_timestamp_prevents_repeated_old_sample_being_current(self):
        directory, path = self.write_config(self.make_config())
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)
        client = status_api.PrometheusClient(config, opener=FakeOpener({}))
        now = 10_000
        calls = [
            {"website": {float(now): 1.0}},
            {"website": {float(now): 0.25}},
            {"website": {float(now): float(now - 3600)}},
            {"website": {float(now): float(now - 3600)}},
        ]

        def repeated_old_sample(_expression, _start, _end, _step):
            return calls.pop(0)

        client.query = repeated_old_sample
        self.assertEqual(client.latest(now), {})

    def test_duration_from_different_scrape_is_not_paired_with_success(self):
        directory, path = self.write_config(self.make_config())
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)
        client = status_api.PrometheusClient(config, opener=FakeOpener({}))
        now = 10_000
        calls = [
            {"website": {float(now): 1.0}},
            {"website": {float(now): 0.25}},
            {"website": {float(now): float(now - 20)}},
            {"website": {float(now): float(now - 20 - status_api.SOURCE_TIMESTAMP_TOLERANCE_SECONDS - 1)}},
        ]

        def different_scrapes(_expression, _start, _end, _step):
            return calls.pop(0)

        client.query = different_scrapes
        result = client.latest(now)
        self.assertEqual(result["website"]["timestamp"], status_api.stamp(now - 20))
        self.assertIsNone(result["website"]["duration"])

    def test_upstream_wrong_job_or_global_matcher_is_rejected(self):
        value = self.make_config()
        directory, path = self.write_config(value)
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)
        payload = {
            "status": "success",
            "data": {
                "resultType": "matrix",
                "result": [
                    {
                        "metric": {"job": "other-job", "service": "probe_website", "environment": "public"},
                        "values": [[1000, "1"]],
                    },
                    {
                        "metric": {"job": "blackbox", "service": "probe_website", "environment": "private"},
                        "values": [[1000, "1"]],
                    },
                ],
            },
        }
        result = status_api.PrometheusClient(config, opener=FakeOpener(payload)).query("fixed", 900, 1000, 60)
        self.assertEqual(result, {})

    def test_global_and_service_matchers_cannot_conflict(self):
        value = self.make_config()
        value["services"][0]["matchers"] = {"environment": "private"}
        directory, path = self.write_config(value)
        self.addCleanup(directory.cleanup)
        with self.assertRaises(status_api.ConfigError):
            status_api.load_config(path)

    def test_source_url_is_validated_and_publicly_projected(self):
        value = self.make_config()
        value["site"]["source_url"] = "https://github.com/example/status-page/"
        directory, path = self.write_config(value)
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)
        self.assertEqual(status_api.browser_config(config)["site"]["sourceUrl"], "https://github.com/example/status-page")

        value["site"]["source_url"] = "https://github.com/example/status-page?token=secret"
        path.write_text(json.dumps(value))
        with self.assertRaises(status_api.ConfigError):
            status_api.load_config(path)

    def test_public_strings_must_be_utf8_encodable(self):
        value = self.make_config()
        value["site"]["brand"] = "bad\ud800"
        directory, path = self.write_config(value)
        self.addCleanup(directory.cleanup)
        with self.assertRaises(status_api.ConfigError):
            status_api.load_config(path)

    def test_index_metadata_is_server_rendered_and_escaped(self):
        value = self.make_config()
        value["site"]["title"] = 'Example <script>alert("x")</script>'
        value["site"]["brand"] = "Example & Status"
        directory, path = self.write_config(value)
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)
        rendered = status_api._render_index(ROOT / "web", config).decode()
        self.assertIn("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;", rendered)
        self.assertNotIn("<script>alert(\"x\")</script>", rendered)
        self.assertIn("Example &amp; Status", rendered)
        self.assertIn("https://status.example.com/favicon.svg", rendered)
        self.assertNotIn("__STATUS_", rendered)

    def test_bind_collision_preserves_original_oserror(self):
        directory, path = self.write_config(self.make_config())
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)
        first = status_api.StatusServer(("127.0.0.1", 0), config, web_root=ROOT / "web")
        self.addCleanup(first.server_close)
        with self.assertRaises(OSError):
            status_api.StatusServer(("127.0.0.1", first.server_address[1]), config, web_root=ROOT / "web")

    def test_gzip_quality_zero_is_respected(self):
        self.assertFalse(status_api._accepts_gzip("gzip;q=0"))
        self.assertTrue(status_api._accepts_gzip("br, gzip;q=0.5"))

    def test_basic_auth_is_server_only_and_encoded_for_upstream(self):
        value = self.make_config()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        password_path = Path(directory.name) / "password"
        password_path.write_text("read-only-secret")
        value["prometheus"]["basic_auth"] = {
            "username": "123456",
            "password_file": str(password_path),
        }
        config_path = Path(directory.name) / "config.json"
        config_path.write_text(json.dumps(value))
        config = status_api.load_config(config_path)
        payload = {
            "status": "success",
            "data": {"resultType": "matrix", "result": []},
        }
        opener = FakeOpener(payload)
        status_api.PrometheusClient(config, opener=opener).query("fixed", 900, 1000, 60)
        request = opener.requests[0]
        expected = base64.b64encode(b"123456:read-only-secret").decode()
        self.assertEqual(request.get_header("Authorization"), f"Basic {expected}")
        public = json.dumps(status_api.browser_config(config))
        self.assertNotIn("read-only-secret", public)
        self.assertNotIn("123456", public)

    def test_bearer_and_basic_auth_cannot_be_combined(self):
        value = self.make_config()
        directory, path = self.write_config(value, token="secret-value")
        self.addCleanup(directory.cleanup)
        value["prometheus"]["basic_auth"] = {"username": "user", "password_file": str(path)}
        path.write_text(json.dumps(value))
        with self.assertRaises(status_api.ConfigError):
            status_api.load_config(path)

    def test_future_current_is_not_fresh(self):
        now = 1_000
        current = {"timestamp": status_api.stamp(now + status_api.MAX_CLOCK_SKEW_SECONDS + 1), "success": True}
        self.assertIsNone(status_api._fresh_current(current, now, 90))
        current["timestamp"] = status_api.stamp(now + status_api.MAX_CLOCK_SKEW_SECONDS)
        self.assertIsNotNone(status_api._fresh_current(current, now, 90))

    def test_redirect_handler_fails_closed(self):
        with self.assertRaises(status_api.UpstreamError):
            status_api._NoRedirect().redirect_request(None, None, "https://other.example/redirect")

    def test_duplicate_upstream_series_fail_closed(self):
        directory, path = self.write_config(self.make_config())
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)
        series = {
            "metric": {"job": "blackbox", "service": "probe_website", "environment": "public"},
            "values": [[1000, "1"]],
        }
        opener = FakeOpener({"status": "success", "data": {"resultType": "matrix", "result": [series, series]}})
        client = status_api.PrometheusClient(config, opener=opener)
        with self.assertRaises(status_api.UpstreamError):
            client.query("fixed", 900, 1000, 60)

    def test_oversized_upstream_body_is_rejected(self):
        directory, path = self.write_config(self.make_config())
        self.addCleanup(directory.cleanup)
        config = status_api.load_config(path)

        class LargeResponse(FakeResponse):
            def __init__(self):
                self.headers = {"Content-Length": str(status_api.MAX_UPSTREAM_BYTES + 1)}

        class LargeOpener:
            def open(self, request, timeout):
                return LargeResponse()

        client = status_api.PrometheusClient(config, opener=LargeOpener())
        with self.assertRaises(status_api.UpstreamError):
            client.query("fixed", 900, 1000, 60)

    def test_expiring_cache_serves_bounded_stale_value(self):
        cache = status_api.ExpiringCache(stale_seconds=10)
        self.assertEqual(cache.get("x", 1, lambda: {"ok": True}, now=0), {"ok": True})
        self.assertEqual(cache.get("x", 1, lambda: (_ for _ in ()).throw(RuntimeError()), now=5), {"ok": True})
        with self.assertRaises(RuntimeError):
            cache.get("x", 1, lambda: (_ for _ in ()).throw(RuntimeError()), now=20)

    def test_public_cache_uses_one_stale_layer_without_restamping_inner_data(self):
        inner = status_api.ExpiringCache(stale_seconds=0)
        outer = status_api.ExpiringCache(stale_seconds=300)
        self.assertEqual(inner.get("metrics", 1, lambda: {"at": 0}, now=0), {"at": 0})
        self.assertEqual(
            outer.get("response", 1, lambda: inner.get("metrics", 1, lambda: {"at": 0}, now=0), now=0),
            {"at": 0},
        )
        self.assertEqual(
            outer.get("response", 1, lambda: inner.get("metrics", 1, lambda: (_ for _ in ()).throw(RuntimeError()), now=2), now=2),
            {"at": 0},
        )
        with self.assertRaises(RuntimeError):
            outer.get("response", 1, lambda: inner.get("metrics", 1, lambda: (_ for _ in ()).throw(RuntimeError()), now=302), now=302)


if __name__ == "__main__":
    unittest.main()
