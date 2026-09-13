#!/usr/bin/env python3
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import status_api


ROOT = Path(__file__).resolve().parents[1]


class PackageContractTests(unittest.TestCase):
    def test_release_tree_has_no_runtime_cache_or_dependency_install(self):
        self.assertFalse(any(path.name == "node_modules" for path in ROOT.rglob("*")))
        self.assertFalse(any(path.name == "__pycache__" for path in ROOT.rglob("*")))
        self.assertFalse(any(path.name in {".openai", "hosting.json"} for path in ROOT.rglob("*")))

    def test_example_config_is_synthetic_and_valid(self):
        config = status_api.load_config(ROOT / "config/status.example.json")
        self.assertEqual(len(config["services"]), 3)
        public = status_api.browser_config(config)
        self.assertEqual({entry["slug"] for entry in public["services"]}, {"website", "api", "dns"})

    def test_browser_assets_have_no_private_identity_or_remote_images(self):
        text = "\n".join(
            path.read_text(errors="ignore")
            for path in (ROOT / "web").rglob("*")
            if path.is_file() and path.suffix.lower() in {".html", ".js", ".css", ".svg", ".txt"}
        )
        for forbidden in ("images.unsplash.com", "qa-private-sentinel.invalid"):
            self.assertNotIn(forbidden, text)
        self.assertNotRegex(text, re.compile(r"/Users/|/home/[^/]+/|https?://(?:10\.|192\.168\.)"))

    def test_public_config_shape_is_display_only(self):
        raw = json.loads((ROOT / "config/status.example.json").read_text())
        config = status_api.load_config(ROOT / "config/status.example.json")
        public = status_api.browser_config(config)
        self.assertNotIn("prometheus", public)
        self.assertNotIn("probe", public)
        self.assertNotIn("selector", json.dumps(public))
        self.assertEqual(public["api"]["path"], "/api/v1/status")

    def test_security_headers_are_self_contained(self):
        source = (ROOT / "status_api.py").read_text()
        self.assertIn("default-src 'self'", source)
        self.assertIn("object-src 'none'", source)
        self.assertIn("form-action 'none'", source)
        self.assertIn("frame-ancestors 'none'", source)
        self.assertIn("sha256-9FSs7KcrLRUSOwDMKKsTkMyDhNfMELkrw2Pw7LJTjZA=", source)
        self.assertNotIn("unsafe-inline", source)
        self.assertNotIn("Access-Control-Allow-Origin", source)

    def test_browser_has_no_remote_fetch_or_datasource_proxy(self):
        text = "\n".join(
            path.read_text(errors="ignore")
            for path in (ROOT / "web").rglob("*")
            if path.is_file() and path.suffix.lower() in {".html", ".js", ".css", ".svg"}
        )
        self.assertNotRegex(text, re.compile(r"fetch\(\s*[\"']https?://", re.IGNORECASE))
        self.assertNotIn("query_range", text)
        self.assertNotIn("Authorization", text)


if __name__ == "__main__":
    unittest.main()
