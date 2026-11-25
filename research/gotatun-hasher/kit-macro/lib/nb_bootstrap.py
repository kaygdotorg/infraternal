#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bootstrap a local NetBird combined server for the head-to-head kit (#260).

Uses NetBird's own first-run path, the same one its end-to-end tests use:
with NB_SETUP_PAT_ENABLED=true the unauthenticated /api/setup creates the
owner and returns a personal access token; the REST API then issues one
reusable setup key. Nothing leaves the benchmark namespaces.

The owner password, the token and the setup key are random, single-run
values. They are kept in memory or in the 0600 output file and never printed.

    nb_bootstrap.py <base-url> <setup-key-out-file>
"""
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request


def call(base, path, body=None, token=None):
    request = urllib.request.Request(base + path, method="POST" if body is not None else "GET")
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", "Token " + token)
    data = json.dumps(body).encode() if body is not None else None
    with urllib.request.urlopen(request, data=data, timeout=30) as response:
        return json.load(response)


def main():
    base, out = sys.argv[1], sys.argv[2]
    deadline = time.monotonic() + 120
    while True:
        try:
            call(base, "/api/instance")
            break
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            if time.monotonic() > deadline:
                sys.exit("management API did not come up")
            time.sleep(0.2)
    setup = call(base, "/api/setup", {
        "email": "h2h@example.test",
        "name": "h2h",
        "password": secrets.token_urlsafe(24) + "aA1!",
        "create_pat": True,
        "pat_expire_in": 1,
    })
    token = setup.get("personal_access_token")
    if not token:
        sys.exit("setup returned no access token (NB_SETUP_PAT_ENABLED unset?)")
    key = call(base, "/api/setup-keys", {
        "name": "h2h", "type": "reusable", "expires_in": 86400, "auto_groups": [], "usage_limit": 0,
    }, token)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(key["key"])
    print(json.dumps({"bootstrapped": True}))


if __name__ == "__main__":
    main()
