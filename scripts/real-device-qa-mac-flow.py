#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Desktop-Safari flows for the real-device check, run ON the Mac VM (as lume) against safaridriver on :4444.

Usage: real-device-qa-mac-flow.py ORIGIN OUT_DIR COMMAND [ARGS...]
Commands: owner-setup | signin | probe  (more are appended as the checklist grows)

The origin is a throwaway device-QA server. Safari cannot make a platform passkey under WebDriver, so a test-only
in-page software authenticator (real-device-qa-sw-authenticator.js) is injected. Its state (one throwaway credential) is
kept in /tmp/j509/sw-state.json (0600) so a later session can sign in. Secrets (setup token, host password) are read from
0600 files in /tmp/j509 and typed into the page; nothing secret is printed or screenshotted by a step that shows it.
Every step prints `MAC_RESULT <PASS|FAIL> <name> <detail>`.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wd import Session  # noqa: E402  (shipped next to this file as wd.py)

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = "/tmp/j509/sw-state.json"


def result(ok, name, detail=""):
    print("MAC_RESULT %s %s %s" % ("PASS" if ok else "FAIL", name, detail), flush=True)
    return ok


def inject_sw(s, origin):
    """(Re)installs the in-page software authenticator when the page does not have it; state lives in localStorage.

    WebDriver scripts run in an isolated JavaScript world: a property set on `navigator.credentials` there is invisible to
    the app. The authenticator is therefore added as an inline <script> element (the app's CSP only restricts framing),
    which runs in the page's own world. The DOM attribute `data-qa-sw` tells whether it is already installed."""
    if s.js("return document.documentElement.getAttribute('data-qa-sw') === '1'"):
        return True
    code = open(os.path.join(HERE, "sw-authenticator.js")).read().replace("__SW_ORIGIN__", origin)
    # WebKit may garbage-collect the JS wrapper that carries properties set on `navigator.credentials`, which silently
    # restores the native methods (seen: a patched `create` was native again seconds later). The prototype persists.
    code = code.replace('Object.defineProperty(navigator.credentials, "create"', 'Object.defineProperty(CredentialsContainer.prototype, "create"')
    code = code.replace('Object.defineProperty(navigator.credentials, "get"', 'Object.defineProperty(CredentialsContainer.prototype, "get"')
    # Import the saved credential only when the page has none: re-importing an older file over a live state would move
    # the signature counter backwards, and the server then refuses every later sign-in.
    if os.path.exists(STATE) and not s.js("return localStorage.getItem('__sw')"):
        s.js("localStorage.setItem('__sw', arguments[0])", [open(STATE).read()])
    prelude = ("window.__swLoad = async () => JSON.parse(localStorage.getItem('__sw') || 'null');"
               "window.__swSave = async (st) => { localStorage.setItem('__sw', JSON.stringify(st)); };")
    s.js("""const el = document.createElement('script'); el.textContent = arguments[0]; document.documentElement.appendChild(el); el.remove();
            document.documentElement.setAttribute('data-qa-sw', '1');""", [prelude + code])
    return s.js("return document.documentElement.getAttribute('data-qa-sw') === '1'") is True


def save_sw(s):
    """Keeps the throwaway credential so the next session can sign in (0600 file on the Mac)."""
    v = s.js("return localStorage.getItem('__sw')")
    if v:
        os.makedirs("/tmp/j509", exist_ok=True)
        fd = os.open(STATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(v)
    return bool(v)


def fill(s, css, text):
    """Sets a text field's value the way typing does (native setter + input event) for fields that refuse keystrokes."""
    return bool(s.js("""const e = document.querySelector(arguments[0]); if (!e) return false; e.focus();
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(e, arguments[1]);
      e.dispatchEvent(new Event('input', {bubbles: true})); e.dispatchEvent(new Event('change', {bubbles: true})); return e.value.length === arguments[1].length;""", [css, text]))


def secret(name):
    """The last word of a 0600 file in /tmp/j509 (the setup token prints a sentence before the token)."""
    words = open("/tmp/j509/" + name).read().split()
    return words[-1] if words else ""


def shot(s, out, name):
    s.shot(os.path.join(out, name + ".png"))


def labels(s):
    """Visible labelled controls and headings, to see what a screen offers."""
    return s.js("""const out = [];
      for (const e of document.querySelectorAll('button, [role=button], input, a, h1, h2, h3, [role=tab], [role=menuitem], [role=switch], [aria-label]')) {
        const r = e.getBoundingClientRect(); if (r.width < 1 || r.height < 1 || r.bottom < 0 || r.right < 0 || r.top > innerHeight || r.left > innerWidth) continue;
        out.push(e.tagName.toLowerCase() + '|' + (e.id || '') + '|' + (e.getAttribute('aria-label') || e.textContent || e.placeholder || '').trim().replace(/\\s+/g, ' ').slice(0, 60) + '|' + Math.round(r.left) + ',' + Math.round(r.top) + ',' + Math.round(r.width) + 'x' + Math.round(r.height));
      }
      return out.slice(0, 80);""") or []


def owner_setup(s, origin, out):
    s.get("%s/?r=%d&theme=latte" % (origin, time.time()))
    time.sleep(6)
    result(inject_sw(s, origin), "inject-software-authenticator")
    result(s.type_into("#setup-token", secret("setup-token.txt")), "token-typed")
    result(s.click_text("Continue"), "token-continue")
    time.sleep(3)
    shot(s, out, "owner-identity")
    result(s.type_into("#setup-username", "mac-owner"), "username")
    result(s.click_text("Continue"), "identity-continue")
    time.sleep(2)
    result(s.click_text("Create passkey"), "create-passkey")
    result(s.wait(".auth-check", 20), "recovery-step")
    result(save_sw(s), "credential-saved")
    s.click(".auth-check")
    result(s.click_text("Open infraternal"), "open-app")
    time.sleep(8)
    shot(s, out, "owner-signed-in")
    print("MAC_LABELS " + json.dumps(labels(s)))


def signin(s, origin, out, unlock=True):
    """Signs in with the saved throwaway credential (a fresh session has no cookie)."""
    s.get("%s/?r=%d&theme=latte" % (origin, time.time()))
    time.sleep(6)
    result(inject_sw(s, origin), "inject-software-authenticator")
    if s.wait("document.querySelector('#login-passkey')", 5):
        result(s.click("#login-passkey"), "continue-with-passkey")
        result(s.wait("!document.querySelector('.auth-screen')", 40), "signed-in")
    else:
        result(True, "already-signed-in")
    time.sleep(4)
    if unlock:
        result(unlock_hosts(s), "host-connections-unlocked")
        time.sleep(5)


def unlock_hosts(s, out=None):
    """Palette > "Unlock host connections": one passkey tap that lets the server's host CA sign host logins again. Without
    it (after a server restart or a new browser session) hosts stay offline and are not listed."""
    s.keys(["\ue03d", "k"])
    time.sleep(1.5)
    type_text(s, "Unlock host connections")
    time.sleep(1.5)
    has_row = "unlock host connections" in (s.js("const r = document.querySelector('#palette-results'); return r ? r.innerText.toLowerCase() : ''") or "")
    if has_row:
        s.keys(["\ue007"])
        ok = s.wait("document.body.innerText.includes('Host connections unlocked')", 25)
        time.sleep(4)
        return ok
    s.keys(["\ue00c"])  # Escape: nothing to unlock
    return True


def add_host(s, origin, out):
    """Add host through the desktop UI to the throwaway dev-02 account, down to a live shell."""
    # The empty state offers "Open shell" now (J528); Add host is a palette action.
    if not s.click_text("Add host", timeout=3):
        s.keys(["\ue03d", "k"]); time.sleep(1.5); type_text(s, "Add hosts"); time.sleep(1.5)
        s.keys(["\ue007"])
    result(bool(s.wait("document.querySelector(\"input[aria-label='Hosts to add']\")", 10)), "add-host-open")
    time.sleep(2)
    result(s.type_into("input[aria-label='Hosts to add']", "qa-device2@10.69.69.117:2222"), "host-typed")
    s.keys(["\ue007"])  # Enter adds the typed host to the list
    time.sleep(1)
    result(s.click_text("Continue"), "continue")
    time.sleep(6)
    shot(s, out, "add-host-after-continue")
    if "already added" in (s.js("return document.body.innerText") or ""):
        # The server still has the host: the wizard offers to open a terminal instead of signing in again.
        result(s.click_text("Open a terminal", timeout=10), "already-added-open-terminal")
        result(s.wait("document.querySelector(\"button[aria-label*='Show details']\")", 60), "shell-opened")
        time.sleep(3)
        shot(s, out, "host-added")
        return
    # First host on a fresh server: the certificate authority for host logins is created with one passkey tap.
    if s.click_text("Confirm with passkey", timeout=8):
        result(True, "ca-confirm")
        time.sleep(8)
    if s.click_text("Trust and continue", timeout=15):
        result(True, "host-key-trusted")
        time.sleep(6)
    shot(s, out, "add-host-signin-choices")
    # The radios are 12 px custom controls under a label; a script click still fires the same change event.
    s.js("const r = document.querySelectorAll('input[type=radio]')[1]; if (r) { r.click(); }")
    result(bool(s.js("const r = document.querySelectorAll('input[type=radio]')[1]; return r && r.checked")), "password-option")
    time.sleep(1)
    result(fill(s, "input[aria-label^='Password for']", open("/tmp/j509/host-password.txt").read().strip()), "password-typed")
    result(s.click_text("Sign in", timeout=10), "sign-in")
    s.wait("document.body.innerText.includes('already added') || document.querySelector(\"button[aria-label*='Show details']\")", 60)
    if "already added" in (s.js("return document.body.innerText") or ""):
        result(s.click_text("Open a terminal", timeout=10), "already-added-open-terminal")
    result(s.wait("document.querySelector('.xterm, [aria-label^=\"Terminal input\"]') && document.body.innerText.includes('qa-device2@')", 90), "shell-opened")
    time.sleep(3)
    shot(s, out, "host-added")
    print("MAC_LABELS " + json.dumps(labels(s)))


def type_text(s, text):
    """Types text into whatever has focus, one real key press per character (Enter is \\n)."""
    chords = [["\ue007"] if ch == "\n" else [ch] for ch in text]
    return s.keys(*chords)


def focus_terminal(s):
    s.js("const t = document.querySelector(\"textarea[aria-label='Terminal input']\"); if (t) t.focus();")


WINDOWS_JS = """const out = [];
for (const e of document.querySelectorAll('section[aria-label]')) {
  const r = e.getBoundingClientRect(); if (r.width < 50) continue;
  out.push({label: (e.getAttribute('aria-label') || '').slice(0, 40), left: Math.round(r.left), right: Math.round(r.right), width: Math.round(r.width), top: Math.round(r.top), bottom: Math.round(r.bottom)});
}
return {innerWidth, scrollWidth: document.documentElement.scrollWidth, windows: out};"""


def ensure_window(s, out, tag, origin=None):
    """Makes sure the QA host has an open shell window. After a page load the host is listed in the sidebar only while its
    agent is connected, so when it is not, the Add host wizard is the way back in: it says "already added" and offers
    "Open a terminal" (or, for a host the server no longer has, walks through signing in and installing)."""
    has = "return !!document.querySelector(\"button[aria-label*='Show details']\")"
    if s.js(has):
        return True
    end = time.time() + 8
    while time.time() < end:
        for text in ("10.69.69.117", "qa-device2"):
            if s.click_text(text, tag="button", timeout=1):
                time.sleep(5)
                if s.js(has):
                    return True
        time.sleep(1)
    if origin:
        add_host(s, origin, out)
        if s.js(has):
            return True
    shot(s, out, tag + "-no-window")
    return False


def phase_shell(s, origin, out, tag):
    signin(s, origin, out)
    phase_shell_inner(s, out, tag)


def phase_shell_inner(s, out, tag):
    result("connected" in " ".join(labels(s)), "host-shell-live")
    focus_terminal(s)
    type_text(s, "echo qa-ok\n")
    time.sleep(2)
    shot(s, out, tag + "-shell-typed")
    result("qa-ok" in (s.js("return document.body.innerText") or ""), "typed-output-visible")
    print("MAC_METRIC " + json.dumps({"name": "windows-before-exit", **(s.js(WINDOWS_JS) or {})}))
    type_text(s, "exit\n")
    t0 = time.time()
    gone = s.wait("!document.body.innerText.includes('Session ended') && !document.querySelector('[aria-label*=\"shell ended\"]')", 10)
    time.sleep(3)
    ended = s.js("return document.body.innerText.includes('Session ended') || !!document.querySelector('[aria-label*=\"shell ended\"]')")
    shot(s, out, tag + "-after-exit")
    result(not ended, "exit-closes-window", "ended-text-visible=%s after %.1fs" % (ended, time.time() - t0))
    print("MAC_METRIC " + json.dumps({"name": "windows-after-exit", **(s.js(WINDOWS_JS) or {})}))
    print("MAC_LABELS " + json.dumps(labels(s)))


def phase_fit(s, origin, out, tag):
    signin(s, origin, out)
    result(ensure_window(s, out, tag, origin), "shell-window-open")
    phase_fit_inner(s, out, tag)


def phase_fit_inner(s, out, tag):
    """The window column at desktop width and at a phone-narrow window (402 css px): nothing wider than the viewport.
    Only the host's own windows count: the other views' windows sit off to the right of the canvas by design."""
    for width, height in ((1440, 900), (402, 840)):
        s.c("POST", "/window/rect", {"width": width, "height": height})
        time.sleep(3)
        m = s.js(WINDOWS_JS) or {}
        m["name"] = "fit-%d" % width
        print("MAC_METRIC " + json.dumps(m))
        shot(s, out, "%s-fit-%d" % (tag, width))
        wide = [w for w in m.get("windows", []) if ("shell" in w["label"].lower()) and w["left"] < m.get("innerWidth", 0) and w["right"] > m.get("innerWidth", 0) + 1]
        result(not wide and m.get("scrollWidth", 0) <= m.get("innerWidth", 0) + 1, "fits-%d" % width, "windows-over=%s scrollW=%s innerW=%s" % ([w["label"] for w in wide], m.get("scrollWidth"), m.get("innerWidth")))
    s.c("POST", "/window/rect", {"width": 1440, "height": 900})


SCROLL_JS = """const panel = document.querySelector('section.canvas-popover[role=dialog] .canvas-popover-scroll');
if (!panel) return null;
panel.setAttribute('data-qa-scroll', '1'); return {sh: panel.scrollHeight, ch: panel.clientHeight, label: 'canvas-popover-scroll'};"""


def phase_pill(s, origin, out, tag):
    signin(s, origin, out)
    result(ensure_window(s, out, tag, origin), "shell-window-open")
    phase_pill_inner(s, out, tag)


def phase_pill_inner(s, out, tag):
    result(s.click_text("Show details", timeout=10), "open-machine-pill")
    time.sleep(3)
    shot(s, out, tag + "-pill-machine")
    # Read the panel's own text (the page also carries theme-preview sample text that mentions kernels).
    text = s.js("const d = document.querySelector('section.canvas-popover[role=dialog]'); return d ? d.innerText : ''") or ""
    flat = text.replace("\n", " | ")
    print("MAC_METRIC " + json.dumps({"name": "pill-text", "has_kernel": "Kernel" in text, "has_arch": "Architecture" in text, "text": flat[:700]}))
    facts = {}
    try:
        facts = json.load(open("/tmp/j509/host-facts.json"))
    except Exception:
        pass
    if facts:
        result(facts.get("kernel", "?") in text and facts.get("arch", "?") in text, "pill-facts-match-host", "host=%s" % facts)
    info = s.js(SCROLL_JS)
    print("MAC_METRIC " + json.dumps({"name": "scroll-container", "info": info}))
    if not info:
        result(False, "scroll-hold", "no scrollable panel found")
    else:
        s.js("const p = document.querySelector('[data-qa-scroll]'); p.scrollTop = Math.floor((p.scrollHeight - p.clientHeight) / 2);")
        time.sleep(1)
        start = s.js("return document.querySelector('[data-qa-scroll]').scrollTop")
        samples = [(0, start)]
        for i in range(1, 8):
            time.sleep(5)
            samples.append((i * 5, s.js("const p = document.querySelector('[data-qa-scroll]'); return p ? p.scrollTop : null")))
        shot(s, out, tag + "-pill-scrolled-35s")
        print("MAC_METRIC " + json.dumps({"name": "scroll-samples", "samples": samples}))
        held = start and start > 0 and all(v is not None and abs(v - start) <= 2 for _, v in samples)
        result(bool(held), "scroll-hold", "scrollTop samples every 5 s: %s" % [v for _, v in samples])
    s.click_text("Connection", tag="button", timeout=5)
    time.sleep(2)
    shot(s, out, tag + "-pill-connection")
    print("MAC_LABELS " + json.dumps(labels(s)))


def page_text(s):
    return s.js("return document.body.innerText") or ""


def removal_outcome(s, out, tag, how):
    """After a Remove host confirmation: wait for the end state and record what the page says. A passkey confirmation is
    answered with the software authenticator. `sign in again` anywhere is the owner's reported failure."""
    if s.click_text("Confirm with passkey", timeout=8):
        result(True, how + ": passkey-confirm-tapped")
    end = time.time() + 60
    text = ""
    while time.time() < end:
        time.sleep(2)
        text = page_text(s)
        low = text.lower()
        if "sign in again" in low or "could not be removed" in low or "removed" in low or "access revoked" in low or "is not added" in low:
            break
    shot(s, out, "%s-%s-outcome" % (tag, how))
    low = text.lower()
    failed = "sign in again" in low or "could not be removed" in low
    result(not failed and ("removed" in low or "revoked" in low), how + ": host-removed", "sign-in-again=%s" % ("sign in again" in low))
    return not failed


def remove_via_pill(s, out, tag):
    if not s.click_text("Show details", timeout=10):
        return result(False, "pill-remove: open-pill")
    time.sleep(2)
    s.click_text("Connection", tag="button", timeout=6)
    time.sleep(2)
    shot(s, out, tag + "-pill-remove-connection-tab")
    if not s.click_text("Remove host", tag="button", timeout=10):
        print("MAC_LABELS " + json.dumps(labels(s)))
        return result(False, "pill-remove: remove-row")
    time.sleep(2)
    shot(s, out, tag + "-pill-remove-question")
    # the in-panel question has Keep and Remove; Remove starts it
    s.click_text("Remove", tag="button", timeout=8, exact=True)
    return removal_outcome(s, out, tag, "pill-remove")


def remove_via_palette(s, out, tag):
    s.keys(["\ue03d", "k"])
    time.sleep(1.5)
    type_text(s, "Remove host")
    time.sleep(2)
    shot(s, out, tag + "-palette-remove-results")
    rows = s.js("const r = document.querySelector('#palette-results'); return r ? r.innerText.slice(0, 300) : ''") or ""
    print("MAC_METRIC " + json.dumps({"name": "palette-remove-rows", "text": rows.replace("\n", " | ")}))
    if "remove host" not in rows.lower():
        s.keys(["\ue00c"])
        return result(False, "palette-remove: row-present")
    s.keys(["\ue007"])
    time.sleep(2)
    shot(s, out, tag + "-palette-remove-question")
    s.click_text("Remove", tag="button", timeout=8, exact=True)
    return removal_outcome(s, out, tag, "palette-remove")


def remove_via_swipe(s, out, tag):
    """Left swipe on the host's row in the sidebar reveals Remove (a glass confirmation card follows)."""
    s.js("""const row = [...document.querySelectorAll('#tree button')].find(b => /qa-device2|10\\.69\\.69\\.117|infraternal-dev-02/.test(b.getAttribute('aria-label') || b.textContent));
           if (row) { const r = row.getBoundingClientRect(); document.documentElement.setAttribute('data-qa-row', [r.left, r.top, r.width, r.height].join(',')); }""")
    rect = s.js("return document.documentElement.getAttribute('data-qa-row')")
    if not rect:
        print("MAC_LABELS " + json.dumps(labels(s)[:50]))
        return result(False, "swipe-remove: host-row-present")
    x, y, w, h = [float(v) for v in rect.split(",")]
    s.drag(x + w - 20, y + h / 2, x + 20, y + h / 2)
    time.sleep(1.5)
    shot(s, out, tag + "-swipe-remove-revealed")
    if not s.click_text("Remove", tag="button", timeout=6, exact=True):
        return result(False, "swipe-remove: remove-revealed")
    time.sleep(2)
    shot(s, out, tag + "-swipe-remove-question")
    s.click_text("Remove", tag="button", timeout=8, exact=True)
    return removal_outcome(s, out, tag, "swipe-remove")


def readd(s, origin, out, tag, how):
    """Puts the host back after a removal (the wizard's password route installs a fresh agent)."""
    ok = ensure_window(s, out, tag, origin)
    result(ok, how + ": re-added")
    time.sleep(10)  # the fresh agent needs a moment to connect before its row shows in the sidebar
    return ok


TEXT_JS = """const pick = (sel) => { const e = document.querySelector(sel); if (!e) return null; const cs = getComputedStyle(e); return {size: cs.fontSize, family: cs.fontFamily.split(',')[0], lh: cs.lineHeight, text: (e.textContent || '').trim().slice(0, 24)}; };
return {innerWidth, rootFont: getComputedStyle(document.documentElement).fontSize,
  capsule: pick('#capsule'), sidebarItem: pick('#tree .bm-leaf .bm-label'), host_pill: pick("button[aria-label*='Show details']"),
  terminal: pick('#terminal-host'), paletteInput: pick('#palette-input'), panelRow: pick('[aria-label*="details"] button, [aria-label^="Details for"] button'),
  uiSizeVar: getComputedStyle(document.documentElement).getPropertyValue('--ui-size') || getComputedStyle(document.documentElement).getPropertyValue('--ui-scale')};"""


MOTION_JS = """const done = arguments[arguments.length - 1];
const btn = document.querySelector("button[aria-label*='Show details']"); if (!btn) { done({error: 'no pill'}); return; }
const t0 = performance.now(); const frames = []; let target = null;
const r0 = btn.getBoundingClientRect(); const opts = {bubbles: true, cancelable: true, composed: true, clientX: r0.left + r0.width / 2, clientY: r0.top + r0.height / 2, pointerId: 1, pointerType: 'mouse', isPrimary: true, button: 0, buttons: 1};
btn.dispatchEvent(new PointerEvent('pointerdown', opts)); btn.dispatchEvent(new MouseEvent('mousedown', opts));
btn.dispatchEvent(new PointerEvent('pointerup', {...opts, buttons: 0})); btn.dispatchEvent(new MouseEvent('mouseup', {...opts, buttons: 0})); btn.dispatchEvent(new MouseEvent('click', {...opts, buttons: 0}));
const sample = () => {
  const d = document.querySelector('[aria-label^="Details for"], [role=dialog][aria-label*="Details" i]');
  const now = performance.now() - t0;
  if (d) { const r = d.getBoundingClientRect(); const cs = getComputedStyle(d); frames.push([Math.round(now), +cs.opacity, Math.round(r.height), cs.transform === 'none' ? 0 : cs.transform.slice(0, 40)]); }
  if (now < 900) requestAnimationFrame(sample); else done({frames, transition: (d && getComputedStyle(d).transitionDuration + ' ' + getComputedStyle(d).transitionTimingFunction) || null, animation: (d && getComputedStyle(d).animationName + ' ' + getComputedStyle(d).animationDuration + ' ' + getComputedStyle(d).animationTimingFunction) || null});
};
requestAnimationFrame(sample);"""


def phase_extras(s, origin, out, tag):
    signin(s, origin, out)
    result(ensure_window(s, out, tag, origin), "shell-window-open")
    for width, height in ((1440, 900), (402, 840)):
        s.c("POST", "/window/rect", {"width": width, "height": height})
        time.sleep(3)
        print("MAC_METRIC " + json.dumps({"name": "text-%d" % width, **(s.js(TEXT_JS) or {})}))
    s.c("POST", "/window/rect", {"width": 1440, "height": 900})
    time.sleep(2)
    # palette and settings
    s.keys(["\ue03d", "k"]); time.sleep(2); shot(s, out, tag + "-palette"); s.keys(["\ue00c"]); time.sleep(1)
    s.click_text("Settings, 21 windows", timeout=5); time.sleep(3); shot(s, out, tag + "-settings")
    s.click_text("Console,", timeout=5); time.sleep(2)
    # motion: the machine panel opening, frame by frame. A page-side sampler runs first (it records time, opacity, height
    # and transform of the popover on every animation frame); then a native click opens the panel.
    s.js("""window.__m = []; window.__t0 = performance.now(); const end = performance.now() + 3500;
      (function f() { const d = document.querySelector('section.canvas-popover[role=dialog]'); const now = performance.now();
        if (d) { const r = d.getBoundingClientRect(); const cs = getComputedStyle(d); window.__m.push([Math.round(now), +cs.opacity, Math.round(r.height), cs.transform === 'none' ? 'none' : cs.transform.slice(0, 36)]); }
        if (now < end) requestAnimationFrame(f); })();""")
    time.sleep(0.5)
    t_click = s.js("return performance.now()")
    s.click_text("Show details", timeout=5)
    time.sleep(3.5)
    frames = s.js("return window.__m") or []
    t_click = t_click or 0
    frames = [[f[0] - int(t_click)] + f[1:] for f in frames if f[0] >= t_click - 20]
    print("MAC_METRIC " + json.dumps({"name": "motion-pill-open", "n": len(frames), "frames": frames[:45]}))
    if frames:
        first = frames[0][0]
        faded = next((f[0] for f in frames if f[1] >= 0.99), frames[-1][0])
        grow = [f for f in frames if abs(f[2] - frames[0][2]) > 20]
        jump = (grow[0][0] - faded, frames[0][2], frames[-1][2]) if grow else None
        # The click reaches the page a few hundred ms after the timestamp (WebDriver round trips); the animation itself is
        # the span from the first visible frame to opacity 0.99.
        result(faded - first <= 300, "motion-pill-open-duration", "fade/scale-in took %d ms (first frame to opacity 0.99; rule <= 300 ms, ease-out: opacity %s)" % (faded - first, [f[1] for f in frames[:6]]))
        print("MAC_METRIC " + json.dumps({"name": "motion-pill-height-jump", "after_fade_ms": jump[0] if jump else None, "from_px": jump[1] if jump else None, "to_px": jump[2] if jump else None}))
    else:
        result(False, "motion-pill-open-duration", "no frames sampled")


def tree_text(s):
    """The sidebar's host tree as text (empty when the sidebar is closed)."""
    # textContent plus every aria-label: the tree's rows are buttons whose text can be hidden from innerText.
    return s.js("""const t = document.querySelector('#tree'); if (!t) return '';
      return (t.textContent.replace(/\\s+/g, ' ') + ' || ' + [...t.querySelectorAll('[aria-label]')].map(e => e.getAttribute('aria-label')).join(' | '));""") or ""


def rect_of(s, finder_js):
    """Bounding rect of the element a JS expression returns, or None."""
    return s.js("const e = (() => { %s })(); if (!e) return null; const r = e.getBoundingClientRect(); return {l: r.left, t: r.top, r: r.right, b: r.bottom, w: r.width, h: r.height, iw: innerWidth, ih: innerHeight};" % finder_js)


def phase_c392(s, origin, out, tag):
    """Checks added for dev c392b16ea: host tree and locked host, Remove question on a phone, panel height, empty state."""
    signin(s, origin, out, unlock=False)
    time.sleep(8)
    # 1. every host is listed, a locked host says "Unlock to connect"
    if not s.js("return !!document.querySelector('#tree')"):
        s.click("#sidebar-toggle"); time.sleep(2)
    locked = tree_text(s)
    print("MAC_METRIC " + json.dumps({"name": "tree-while-locked", "text": locked.replace("\n", " | ")[:300]}))
    shot(s, out, tag + "-tree-locked")
    result(any(k in locked for k in ("10.69.69.117", "qa-device2", "infraternal-dev-02")), "tree-lists-host-while-locked", locked.replace("\n", " | ")[:120])
    result("unlock to connect" in locked.lower(), "locked-host-shows-unlock-to-connect")
    unlock_hosts(s); time.sleep(10)
    unlocked = tree_text(s)
    print("MAC_METRIC " + json.dumps({"name": "tree-after-unlock", "text": unlocked.replace("\n", " | ")[:300]}))
    shot(s, out, tag + "-tree-unlocked")
    result("unlock to connect" not in unlocked.lower() and any(k in unlocked for k in ("10.69.69.117", "qa-device2", "infraternal-dev-02")), "host-connects-after-unlock", unlocked.replace("\n", " | ")[:120])
    result(ensure_window(s, out, tag, origin), "shell-window-open")
    time.sleep(6)
    with_window = tree_text(s)
    print("MAC_METRIC " + json.dumps({"name": "tree-with-window-open", "text": with_window.replace("\n", " | ")[:300]}))
    result(any(k in with_window for k in ("10.69.69.117", "qa-device2", "infraternal-dev-02")), "tree-lists-host-with-window-open", with_window[:120])
    # 2. the machine panel opens at its final height (no jump)
    s.js("""window.__m = []; const end = performance.now() + 3000;
      (function f() { const d = document.querySelector('section.canvas-popover[role=dialog]'); const now = performance.now();
        if (d) { const r = d.getBoundingClientRect(); window.__m.push([Math.round(now), Math.round(d.offsetHeight)]); }
        if (now < end) requestAnimationFrame(f); })();""")
    time.sleep(0.4)
    s.click_text("Show details", timeout=5)
    time.sleep(3.3)
    hs = [f[1] for f in (s.js("return window.__m") or [])]
    print("MAC_METRIC " + json.dumps({"name": "panel-heights", "n": len(hs), "first": hs[:3], "last": hs[-3:], "distinct": sorted(set(hs))[:8]}))
    if hs:
        jump = max(hs) - min(h for h in hs if h > 50) if any(h > 50 for h in hs) else 0
        result(jump <= 24, "panel-opens-at-final-height", "heights seen %s (rule: no growth of more than 24 px after it appears)" % sorted(set(hs))[:6])
    else:
        result(False, "panel-opens-at-final-height", "no frames")
    s.keys(["\ue00c"]); time.sleep(1)
    # 3. Remove question: Keep and Remove inside the panel and the viewport at phone width
    s.c("POST", "/window/rect", {"width": 402, "height": 840}); time.sleep(3)
    s.click_text("Show details", timeout=5); time.sleep(2)
    s.click_text("Connection", tag="button", timeout=5); time.sleep(2)
    s.js("const r = [...document.querySelectorAll('section.canvas-popover button')].find(b => /remove host/i.test(b.textContent)); if (r) r.scrollIntoView({block: 'nearest'});")
    time.sleep(1)
    result(s.click_text("Remove host", tag="button", timeout=6), "remove-row-pressed")
    time.sleep(2)
    shot(s, out, tag + "-remove-question-402")
    pop = rect_of(s, "return document.querySelector('section.canvas-popover[role=dialog]');")
    keep = rect_of(s, "return [...document.querySelectorAll('section.canvas-popover button')].find(b => b.textContent.trim() === 'Keep');")
    rem = rect_of(s, "return [...document.querySelectorAll('section.canvas-popover button')].find(b => b.textContent.trim() === 'Remove');")
    print("MAC_METRIC " + json.dumps({"name": "remove-question-rects-402", "panel": pop, "keep": keep, "remove": rem}))
    def inside(r, box):
        return bool(r and box and r["l"] >= box["l"] - 1 and r["r"] <= box["r"] + 1 and r["t"] >= box["t"] - 1 and r["b"] <= box["b"] + 1 and r["b"] <= r["ih"] and r["r"] <= r["iw"])
    result(inside(keep, pop) and inside(rem, pop), "remove-question-buttons-in-view", "keep=%s remove=%s panel=%s" % (keep and (round(keep["t"]), round(keep["b"])), rem and (round(rem["t"]), round(rem["b"])), pop and (round(pop["t"]), round(pop["b"]))))
    s.click_text("Keep", tag="button", timeout=4, exact=True); time.sleep(1)
    s.keys(["\ue00c"]); s.c("POST", "/window/rect", {"width": 1440, "height": 900}); time.sleep(2)
    # 4. Add host sign-in footer: Back and Sign in on one row, at 1440 and at 402
    for width in (1440, 402):
        s.c("POST", "/window/rect", {"width": width, "height": 840 if width == 402 else 900}); time.sleep(2)
        s.keys(["\ue03d", "k"]); time.sleep(1.5); type_text(s, "Add hosts"); time.sleep(1.5); s.keys(["\ue007"]); time.sleep(2)
        s.type_into("input[aria-label='Hosts to add']", "qa-device2@infraternal-dev-02-std.vpn.kayg.org:2222"); s.keys(["\ue007"]); time.sleep(1)
        s.click_text("Continue", timeout=6); time.sleep(8)
        s.click_text("Trust and continue", timeout=4); time.sleep(4)
        back = rect_of(s, "return [...document.querySelectorAll('section[aria-label=\"Add hosts\"] button')].find(b => b.textContent.trim() === 'Back');")
        signin_b = rect_of(s, "return [...document.querySelectorAll('section[aria-label=\"Add hosts\"] button')].find(b => b.textContent.trim() === 'Sign in');")
        shot(s, out, "%s-addhost-signin-%d" % (tag, width))
        one_row = bool(back and signin_b and abs(back["t"] - signin_b["t"]) <= 3 and abs(back["b"] - signin_b["b"]) <= 3)
        print("MAC_METRIC " + json.dumps({"name": "signin-footer-%d" % width, "back": back, "signin": signin_b}))
        result(one_row, "signin-footer-one-row-%d" % width, "back top=%s sign-in top=%s" % (back and round(back["t"]), signin_b and round(signin_b["t"])))
        s.click_text("Close", tag="button", timeout=3)
        s.keys(["\ue00c"]); time.sleep(1)
    s.c("POST", "/window/rect", {"width": 1440, "height": 900}); time.sleep(2)
    # 5. empty state after the last window closes: "No windows open" and an Open shell button
    focus_terminal(s)
    type_text(s, "exit\n")
    time.sleep(5)
    body = page_text(s)
    shot(s, out, tag + "-no-windows")
    result("no windows open" in body.lower(), "empty-state-says-no-windows-open", "text has 'No windows open': %s; 'No hosts yet': %s" % ("no windows open" in body.lower(), "no hosts yet" in body.lower()))
    result(bool(s.js("return [...document.querySelectorAll('button')].some(b => /open shell/i.test(b.textContent + ' ' + (b.getAttribute('aria-label') || '')))")), "empty-state-has-open-shell")
    print("MAC_LABELS " + json.dumps([l for l in labels(s) if 'Settings' not in l and 'Themes' not in l][:14]))


def main():
    origin, out, cmd = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]
    os.makedirs(out, exist_ok=True)
    s = Session()
    try:
        if cmd == "owner-setup":
            owner_setup(s, origin, out)
        elif cmd == "signin":
            signin(s, origin, out)
            shot(s, out, "signed-in")
            print("MAC_LABELS " + json.dumps(labels(s)))
        elif cmd == "add-host":
            signin(s, origin, out)
            add_host(s, origin, out)
        elif cmd in ("shell", "fit", "pill"):
            tag = sys.argv[4] if len(sys.argv) > 4 else "latte"
            {"shell": phase_shell, "fit": phase_fit, "pill": phase_pill}[cmd](s, origin, out, tag)
        elif cmd == "sidebar":
            signin(s, origin, out)
            print("SIDEBAR", json.dumps(s.js("return [...document.querySelectorAll('#sidebar button, #sidebar [role=treeitem], #tree *')].filter(e => e.getBoundingClientRect().width > 0).map(e => e.tagName + ':' + (e.getAttribute('aria-label') || e.textContent).trim().replace(/\\s+/g, ' ').slice(0, 70)).slice(0, 40)")))
            s.keys(["\ue03d", "k"]); time.sleep(2); type_text(s, "10.69"); time.sleep(2)
            shot(s, out, "palette-host-search")
            print("PALETTE", json.dumps(labels(s)[:30]))
            print("HOSTS-API", json.dumps(s.js("return [...document.querySelectorAll('[aria-label]')].map(e => e.getAttribute('aria-label')).filter(l => /10\\.69|qa-device|host/i.test(l)).slice(0, 20)")))
        elif cmd == "hostcheck":
            signin(s, origin, out)
            time.sleep(20)
            print("sidebar:", json.dumps(s.js("return [...document.querySelectorAll('#tree button')].map(e => (e.getAttribute('aria-label') || e.textContent).trim().slice(0, 60))")))
            s.click_text("Add host"); time.sleep(3)
            s.type_into("input[aria-label='Hosts to add']", "qa-device2@10.69.69.117:2222"); s.keys(["\ue007"]); time.sleep(2)
            shot(s, out, "hostcheck-add")
            print("add-labels:", json.dumps(labels(s)[:40]))
            print("add-text:", (s.js("""const d = document.querySelector('section[aria-label="Add hosts"]'); return d ? d.innerText.slice(0, 500) : null""") or "").replace("\n", " | "))
        elif cmd == "newwindow":
            signin(s, origin, out)
            time.sleep(15)
            result(s.click("button[aria-label='New window']"), "new-window-button")
            time.sleep(3)
            shot(s, out, "new-window-menu")
            print("menu:", json.dumps([l for l in labels(s) if 'section||' not in l][:45]))
        elif cmd == "all":
            tag = sys.argv[4] if len(sys.argv) > 4 else "latte"
            signin(s, origin, out)
            if not s.js("return !!document.querySelector(\"button[aria-label*='Show details']\")"):
                add_host(s, origin, out)
            result(ensure_window(s, out, tag, origin), "shell-window-open")
            phase_fit_inner(s, out, tag)
            phase_pill_inner(s, out, tag)
            phase_shell_inner(s, out, tag)
        elif cmd == "remove-pill":
            tag = sys.argv[4] if len(sys.argv) > 4 else "latte"
            signin(s, origin, out)
            result(ensure_window(s, out, tag, origin), "shell-window-open")
            remove_via_pill(s, out, tag)
            print("MAC_LABELS " + json.dumps(labels(s)[:40]))
        elif cmd == "remove-all":
            tag = sys.argv[4] if len(sys.argv) > 4 else "latte"
            signin(s, origin, out)
            result(ensure_window(s, out, tag, origin), "shell-window-open")
            remove_via_pill(s, out, tag)
            readd(s, origin, out, tag, "after-pill")
            remove_via_palette(s, out, tag)
            readd(s, origin, out, tag, "after-palette")
            remove_via_swipe(s, out, tag)
            readd(s, origin, out, tag, "after-swipe")
        elif cmd == "sidebar-watch":
            signin(s, origin, out)
            ensure_window(s, out, "x", origin)
            for t in (0, 10, 20, 40, 60):
                time.sleep(10 if t else 1)
                print("t+%ds sidebar=%s pill=%s" % (t, json.dumps(s.js("return [...document.querySelectorAll('#tree button')].map(e => (e.getAttribute('aria-label') || e.textContent).trim().slice(0, 40))")),
                      json.dumps(s.js("const b = document.querySelector(\"button[aria-label*='Show details']\"); return b && b.getAttribute('aria-label')"))))
        elif cmd == "tree":
            signin(s, origin, out)
            ensure_window(s, out, "x", origin)
            time.sleep(8)
            print("TREE-TEXT", json.dumps(s.js("const t = document.querySelector('#tree'); return t ? t.innerText : null")))
            print("TREE-HTML", json.dumps(s.js("const t = document.querySelector('#tree'); return t ? t.innerHTML.replace(/<svg.*?<\\/svg>/g, '').slice(0, 1800) : null")))
            print("SIDEBAR-TEXT", json.dumps((s.js("const t = document.querySelector('#sidebar'); return t ? t.innerText : null") or "")[:600]))
            shot(s, out, "tree")
        elif cmd == "extras":
            phase_extras(s, origin, out, sys.argv[4] if len(sys.argv) > 4 else "latte")
        elif cmd == "dialogs":
            signin(s, origin, out)
            ensure_window(s, out, "x", origin)
            s.click_text("Show details", timeout=10); time.sleep(2)
            print("DIALOGS", json.dumps(s.js("return [...document.querySelectorAll('[role=dialog], dialog, [class*=details], [class*=pop]')].slice(0, 12).map(e => e.tagName + '|' + (e.getAttribute('role') || '') + '|' + (e.getAttribute('aria-label') || '') + '|' + (e.className || '').toString().slice(0, 50) + '|' + Math.round(e.getBoundingClientRect().height))")))
        elif cmd == "set-dark":
            signin(s, origin, out)
            print("before:", s.js("return document.documentElement.dataset.theme"))
            result(s.click_text("Settings, 21 windows", timeout=8), "open-settings"); time.sleep(3)
            names = s.js("return [...document.querySelectorAll('button')].map(b => b.textContent.trim().replace(/\\s+/g, ' ').slice(0, 40)).filter(t => /mocha|dark|catppuccin|tokyo|night|nord|dracula|ink|paper/i.test(t))")
            print("theme buttons:", json.dumps(names))
            for name in ("Tokyo Night", "Dracula", "Nord"):
                s.js("""const b = [...document.querySelectorAll('button')].find(b => b.textContent.trim().replace(/\\s+/g, ' ') === arguments[0]); if (b) { b.scrollIntoView({block: 'center'}); b.setAttribute('data-qa-theme', '1'); }""", [name])
                if s.click("[data-qa-theme='1']"):
                    s.js("document.querySelectorAll('[data-qa-theme]').forEach(e => e.removeAttribute('data-qa-theme'))")
                    time.sleep(2)
                    t = s.js("return document.documentElement.dataset.theme")
                    print("clicked", name, "-> data-theme =", t)
                    if t and t not in ("latte",):
                        break
            shot(s, out, "set-dark")
            print("after:", s.js("return document.documentElement.dataset.theme"), "| reload:")
            s.get("%s/?r=%d" % (origin, time.time())); time.sleep(8); inject_sw(s, origin)
            print("after reload data-theme:", s.js("return document.documentElement.dataset.theme"))
        elif cmd == "c392":
            phase_c392(s, origin, out, sys.argv[4] if len(sys.argv) > 4 else "latte")
        elif cmd == "probe":
            s.get("%s/?r=%d&theme=latte" % (origin, time.time()))
            time.sleep(8)
            inject_sw(s, origin)
            print("MAC_LABELS " + json.dumps(labels(s)))
            shot(s, out, "probe")
        else:
            raise SystemExit("unknown command " + cmd)
    finally:
        # The authenticator's signature counter advances on every sign-in and the server rejects a counter that goes back,
        # so the state is saved at the end of every session, whatever happened.
        try:
            save_sw(s)
        except Exception:
            pass
        s.close()


main()
