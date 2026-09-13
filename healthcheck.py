"""Dependency-free container liveness probe; no shell quoting is required."""
import urllib.request

with urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=2) as response:
    raise SystemExit(0 if response.status == 200 else 1)
