#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Desktop Safari (1440 x 900) checks, run ON the Mac VM against a safaridriver that `scripts/real-device-qa mac` started.

Usage: real-device-qa-mac.py OUT_DIR URL THEME [signed-out]

Real Safari gives what the simulator cannot: the page's own DOM. For each page it saves a screenshot and prints one
`MAC_METRIC` JSON line: viewport, horizontal overflow of the document, the number of elements that stick out of the
viewport, and the computed font sizes of the main text. A page passes the overflow rule when `scrollWidth <= innerWidth`.
THEME is `latte` (light) or `mocha` (dark): the app's own theme, forced with `?theme=`.
"""
import json, sys, time
sys.path.insert(0, __import__("os").path.dirname(__file__))
from wd import Session

METRICS = """
const out = {url: location.href, innerWidth, innerHeight, scrollWidth: document.documentElement.scrollWidth,
  scrollHeight: document.documentElement.scrollHeight, dpr: devicePixelRatio};
const wide = [];
for (const e of document.querySelectorAll('body *')) {
  const r = e.getBoundingClientRect();
  if (r.width > 0 && r.right > innerWidth + 1 && getComputedStyle(e).position !== 'fixed') wide.push(e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + ' right=' + Math.round(r.right));
}
out.overflowing = wide.length; out.overflowSample = wide.slice(0, 5);
const sizes = {};
for (const sel of ['h1','h2','p','button','input','label','.auth-hint','code']) {
  const e = document.querySelector(sel);
  if (e) sizes[sel] = getComputedStyle(e).fontSize + ' ' + getComputedStyle(e).fontFamily.split(',')[0];
}
out.fontSizes = sizes;
out.scheme = document.documentElement.getAttribute('data-auth-scheme') || document.documentElement.getAttribute('data-theme') || '';
return out;
"""

def main():
    out_dir, url, theme = sys.argv[1], sys.argv[2], sys.argv[3]
    s = Session()
    try:
        s.c("POST", "/window/rect", {"width": 1440, "height": 900})
        s.get("%s/?r=%d&theme=%s" % (url, int(time.time()), theme))
        time.sleep(8)
        name = "%s-%s" % (url.split("//")[1].split("/")[0].replace(":", "_"), theme)
        s.shot("%s/%s-load.png" % (out_dir, name))
        print("MAC_METRIC " + json.dumps(s.js(METRICS)))
    finally:
        s.close()

main()
