#!/usr/bin/env python3
# Role: open the tile-lane replay page in Safari through safaridriver and wait for its reports [#146 proposal C].
"""Usage: wd.py <driver-url> <page-url> <done-file> <seconds>

Creates one Safari WebDriver session, opens the page, waits until <done-file> exists (serve.py writes it when the page
posts its last report) or <seconds> pass, and always deletes the session. Standard library only.
"""
import json, os, sys, time, urllib.request

def call(method, url, body=None):
    """One WebDriver request; returns the decoded JSON value."""
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.loads(response.read() or b"{}")

driver, page, done, seconds = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
session = call("POST", f"{driver}/session", {"capabilities": {"alwaysMatch": {"browserName": "safari"}}})["value"]["sessionId"]
try:
    call("POST", f"{driver}/session/{session}/url", {"url": page})
    deadline = time.time() + seconds
    while time.time() < deadline and not os.path.exists(done):
        time.sleep(2)
    print("done" if os.path.exists(done) else "timeout")
finally:
    call("DELETE", f"{driver}/session/{session}")
