# SPDX-License-Identifier: AGPL-3.0-only
"""Minimal Safari WebDriver client (standard library only) for the desktop-Safari run. Ships to the Mac VM as `wd.py`.

Safari allows ONE automation session at a time and drives the real, visible Safari, so every use must hold
/tmp/mac-bench.lock and delete its session at the end (`Session.close`). The driver itself is started and stopped by PID
by `scripts/real-device-qa mac`.
"""
import base64
import json
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:4444"


def call(method, path, body=None, timeout=180):
    """One WebDriver HTTP call; returns the decoded JSON or {'http_error': code, 'body': text}."""
    req = urllib.request.Request(BASE + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return {"http_error": e.code, "body": e.read().decode()[:300]}


class Session:
    """One Safari window. All methods are synchronous and tolerant: a failed step returns None/False, never raises."""

    def __init__(self, width=1440, height=900):
        r = call("POST", "/session", {"capabilities": {"alwaysMatch": {"browserName": "safari"}}})
        if "value" not in r or "sessionId" not in r["value"]:
            raise SystemExit("no WebDriver session: %r" % r)
        self.id = r["value"]["sessionId"]
        self.c("POST", "/window/rect", {"width": width, "height": height})
        self.c("POST", "/timeouts", {"script": 60000, "pageLoad": 60000})

    def c(self, method, path, body=None):
        return call(method, "/session/%s%s" % (self.id, path), body)

    def get(self, url):
        return self.c("POST", "/url", {"url": url})

    def js(self, script, args=None):
        """Runs a synchronous script body (use `return`)."""
        return self.c("POST", "/execute/sync", {"script": script, "args": args or []}).get("value")

    def shot(self, path):
        v = self.c("GET", "/screenshot").get("value")
        if v:
            open(path, "wb").write(base64.b64decode(v))
        return bool(v)

    def wait(self, cond_js, timeout=30, every=0.5):
        """Polls a JS expression (a `return`-less boolean expression) until it is truthy."""
        end = time.time() + timeout
        while time.time() < end:
            if self.js("return !!(%s)" % cond_js):
                return True
            time.sleep(every)
        return False

    def element(self, css):
        el = self.c("POST", "/element", {"using": "css selector", "value": css}).get("value")
        return list(el.values())[0] if isinstance(el, dict) and el else None

    def click(self, css):
        """Native click (a real user gesture) on the first element matching a CSS selector."""
        e = self.element(css)
        return bool(e) and "http_error" not in self.c("POST", "/element/%s/click" % e, {})

    def click_text(self, text, tag="button", timeout=15):
        """Native click on the first VISIBLE element of `tag` whose text contains `text` (marked with a data attribute first)."""
        end = time.time() + timeout
        while time.time() < end:
            hit = self.js("""const t = arguments[0], tag = arguments[1];
              for (const e of document.querySelectorAll(tag)) { const r = e.getBoundingClientRect();
                if (r.width > 0 && r.height > 0 && getComputedStyle(e).visibility !== 'hidden' && (e.textContent + ' ' + (e.getAttribute('aria-label') || '')).toLowerCase().includes(t.toLowerCase())) { e.setAttribute('data-qa-hit', '1'); return true; } }
              return false;""", [text, tag])
            if hit:
                ok = self.click('[data-qa-hit="1"]')
                self.js("document.querySelectorAll('[data-qa-hit]').forEach(e => e.removeAttribute('data-qa-hit'))")
                return ok
            time.sleep(0.5)
        return False

    def type_into(self, css, text):
        e = self.element(css)
        if not e:
            return False
        self.c("POST", "/element/%s/click" % e, {})
        return "http_error" not in self.c("POST", "/element/%s/value" % e, {"text": text})

    def keys(self, *chords):
        """Presses key chords, each a list of keys held together, e.g. keys(['\\ue03d', 'k']) is Cmd+K (\\ue03d = Meta)."""
        actions = []
        for chord in chords:
            seq = [{"type": "keyDown", "value": k} for k in chord] + [{"type": "keyUp", "value": k} for k in reversed(chord)]
            actions += seq
        return self.c("POST", "/actions", {"actions": [{"type": "key", "id": "kb", "actions": actions}]})

    def close(self):
        call("DELETE", "/session/%s" % self.id)
