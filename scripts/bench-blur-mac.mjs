// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Frame cost of a theme's look on a real GPU (#323, D322): Safari or Chrome on the Mac VM against a production build of the tracer served by its test double.
 *
 * Usage (from the Mac's GUI session, with the test double reachable on `localhost:5400`):
 *
 *     node bench-blur-mac.mjs safari|chrome <out.jsonl> [repeats]
 *
 * For each look (Solid; Tinted, the default; and "tint only", Tinted with its blur at 0) and each window count (4 and 12) it loads the page fresh, brings the
 * canvas to that many terminal windows, then records every animation frame twice: while the page is idle for 5 s, and while a window is dragged by its pill for 5 s
 * with a real pointer (not synthetic events: the window drag needs pointer capture). It prints p50, p95 and the worst interval between frames, the frames per second,
 * and the dropped frames (an interval over 25 ms, i.e. a frame later than one and a half 60 Hz frames), one JSON line per run.
 *
 * It also records which graphics renderer the page got, so a run that fell back to software drawing is visible as such. Nothing is saved to the person's look: each run
 * seeds the page's own saved themes and the test double's account copy, which the double forgets per browser context. Needs Node 22 or newer (global fetch and WebSocket)
 * and no packages: Safari is driven by its WebDriver (`safaridriver`), Chrome through the DevTools protocol.
 */
import { spawn } from "node:child_process";
import { writeFileSync, appendFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const BASE = process.env.BENCH_BASE ?? "http://localhost:5400";
const [browser, out, repeatsArg] = process.argv.slice(2);
if (!["safari", "chrome"].includes(browser ?? "") || !out) { console.error("usage: node bench-blur-mac.mjs safari|chrome <out.jsonl> [repeats]"); process.exit(2); }
const REPEATS = Number(repeatsArg ?? 1);
const SPAN_MS = 5000;
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

/** The three looks, as the saved themes the page starts from (null: nothing saved, so a new person's default, Tinted). */
const BASICS = { colors: "mocha", font: "maple-mono-nf", uiSize: 100 };
const LOOKS = {
  solid: { v: 1, selected: "solid", basics: BASICS, themes: [] },
  tinted: null,
  "tint only": { v: 1, selected: "tinted", basics: BASICS, themes: [{ id: "tinted", tint: 75, blur: 0, grain: 0, background: "aurora" }] },
};

/** A driver gives the benchmark four things: go to a page, run a script in it, press and move a real pointer, and quit. */
async function safariDriver() {
  const port = 4455;
  const child = spawn("safaridriver", ["-p", String(port)], { stdio: "ignore" });
  // The driver takes a moment to listen (longer right after another session ended): wait for its status instead of guessing.
  for (let i = 0; i < 40; i++) {
    await sleep(500);
    try { if ((await fetch(`http://127.0.0.1:${port}/status`)).ok) break; } catch { /* not listening yet */ }
  }
  const call = async (method, path, body) => {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { "content-type": "application/json" }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const json = await response.json();
    if (json.value?.error) throw new Error(`${json.value.error}: ${json.value.message}`);
    return json.value;
  };
  const created = await call("POST", "/session", { capabilities: { alwaysMatch: { browserName: "safari" } } });
  const session = created.sessionId;
  await call("POST", `/session/${session}/window/rect`, { x: 0, y: 0, width: 1440, height: 900 });
  const s = (path) => `/session/${session}${path}`;
  return {
    name: "Safari " + (created.capabilities?.browserVersion ?? ""),
    goto: (url) => call("POST", s("/url"), { url }),
    run: (script, ...args) => call("POST", s("/execute/sync"), { script, args }),
    /** Presses at (x, y), follows `points` ([x, y] each, one every `step` ms) and releases. One request, so the pace is the driver's. */
    async drag(x, y, points, step) {
      const actions = [{ type: "pointerMove", duration: 0, x, y, origin: "viewport" }, { type: "pointerDown", button: 0 }, ...points.map(([px, py]) => ({ type: "pointerMove", duration: step, x: px, y: py, origin: "viewport" })), { type: "pointerUp", button: 0 }];
      await call("POST", s("/actions"), { actions: [{ type: "pointer", id: "mouse", parameters: { pointerType: "mouse" }, actions }] });
      await call("DELETE", s("/actions"));
    },
    async quit() { try { await call("DELETE", s("")); } catch { /* the session may be gone */ } child.kill(); },
  };
}

async function chromeDriver() {
  const dir = mkdtempSync(join(tmpdir(), "j206-chrome-"));
  const port = 9333;
  const child = spawn("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", [`--remote-debugging-port=${port}`, `--user-data-dir=${dir}`, "--no-first-run", "--no-default-browser-check", "--window-size=1440,900", "--window-position=0,0", "--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows", "--disable-background-timer-throttling", "about:blank"], { stdio: "ignore" });
  let target;
  for (let i = 0; i < 40 && !target; i++) {
    await sleep(500);
    try { target = (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find((t) => t.type === "page"); } catch { /* not up yet */ }
  }
  if (!target) throw new Error("Chrome did not start");
  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((ok, fail) => { ws.onopen = ok; ws.onerror = fail; });
  let id = 0;
  const pending = new Map();
  ws.onmessage = (event) => { const m = JSON.parse(event.data); if (m.id && pending.has(m.id)) { const [ok, fail] = pending.get(m.id); pending.delete(m.id); m.error ? fail(new Error(m.error.message)) : ok(m.result); } };
  const send = (method, params = {}) => new Promise((ok, fail) => { id += 1; pending.set(id, [ok, fail]); ws.send(JSON.stringify({ id, method, params })); });
  await send("Page.enable");
  // The window is the same size as Safari's and in front: a window behind another, or a smaller one, would be drawn (and throttled) differently.
  try {
    const { windowId } = await send("Browser.getWindowForTarget", { targetId: target.id });
    await send("Browser.setWindowBounds", { windowId, bounds: { windowState: "normal", left: 0, top: 0, width: 1440, height: 900 } });
  } catch { /* the viewport size is reported with every run */ }
  spawn("osascript", ["-e", 'tell application "Google Chrome" to activate'], { stdio: "ignore" });
  await sleep(1000);
  const version = (await (await fetch(`http://127.0.0.1:${port}/json/version`)).json()).Browser;
  return {
    name: version,
    async goto(url) { await send("Page.navigate", { url }); await sleep(1500); },
    async run(script, ...args) {
      const expression = `(function(){${script}}).apply(null, ${JSON.stringify(args)})`;
      const result = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (result.exceptionDetails) throw new Error(result.exceptionDetails.exception?.description ?? "script failed");
      return result.result.value;
    },
    async drag(x, y, points, step) {
      const mouse = (type, px, py, extra = {}) => send("Input.dispatchMouseEvent", { type, x: px, y: py, button: type === "mouseMoved" ? "none" : "left", buttons: type === "mouseReleased" ? 0 : 1, clickCount: 1, ...extra });
      await send("Input.dispatchMouseEvent", { type: "mouseMoved", x, y, button: "none", buttons: 0 });
      await mouse("mousePressed", x, y);
      const start = performance.now();
      for (const [i, [px, py]] of points.entries()) {
        await send("Input.dispatchMouseEvent", { type: "mouseMoved", x: px, y: py, button: "left", buttons: 1 });
        const wait = start + (i + 1) * step - performance.now();
        if (wait > 0) await sleep(wait);
      }
      await mouse("mouseReleased", points.at(-1)[0], points.at(-1)[1]);
    },
    async quit() { try { await send("Browser.close"); } catch { /* closing drops the socket */ } child.kill(); },
  };
}

/** Quantile of a sorted list. */
const q = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
/** The numbers of one recording: timestamps in ms from `requestAnimationFrame`. */
function stats(times) {
  const gaps = times.slice(1).map((t, i) => t - times[i]);
  const sorted = [...gaps].sort((a, b) => a - b);
  const seconds = (times.at(-1) - times[0]) / 1000;
  return { frames: times.length, fps: +(times.length / seconds).toFixed(1), p50: +q(sorted, 0.5).toFixed(1), p95: +q(sorted, 0.95).toFixed(1), worst: +sorted.at(-1).toFixed(1), dropped: gaps.filter((g) => g > 25).length, droppedPercent: +((100 * gaps.filter((g) => g > 25).length) / gaps.length).toFixed(1) };
}

// Each recording has its own object, held by its own loop: a loop left over from the last recording would otherwise see the new one switched on and keep adding samples.
const RECORD_START = "const rec = { t: [], on: true }; window.__fr = rec; const loop = (now) => { if (!rec.on) return; rec.t.push(now); requestAnimationFrame(loop); }; requestAnimationFrame(loop); return true;";
const RECORD_STOP = "const rec = window.__fr; rec.on = false; return rec.t;";

/** Seeds the saved themes (device and account), reloads, and brings the canvas to `count` terminal windows in the Console view. */
/** Waits (up to `ms`) until the page's own probe of the canvas exists, so nothing is driven before the canvas has mounted. */
async function ready(driver, ms = 45_000) {
  for (let waited = 0; waited < ms; waited += 500) {
    if (await driver.run(`return Boolean(window.__tracerClusters) && document.querySelectorAll('[data-window-id^="w-"]').length > 0;`).catch(() => false)) return;
    await sleep(500);
  }
  throw new Error("the canvas did not mount");
}

async function prepare(driver, look, count) {
  await driver.goto(`${BASE}/?mock=1&proto=clusters&scene=3&theme=mocha&bg=soft`);
  await ready(driver);
  const saved = LOOKS[look];
  // Seed this page's saved look and the test double's account copy, then reload so the page starts from them.
  await driver.run(`const saved = arguments[0]; fetch("/__mock/account/appearance", { method: "PUT", headers: { "content-type": "application/json" }, body: JSON.stringify({ themes: saved }) }); if (saved) localStorage.setItem("tracer.themes", JSON.stringify(saved)); else localStorage.removeItem("tracer.themes"); return true;`, saved);
  await sleep(500);
  await driver.goto(`${BASE}/?mock=1&proto=clusters&scene=3&theme=mocha&bg=soft`);
  await ready(driver);
  await sleep(2000);
  // More windows: new shells on the first host; fewer: close the extra ones with their own close button.
  for (let guard = 0; guard < 40; guard++) {
    const have = await driver.run(`return document.querySelectorAll('[data-window-id^="w-"]').length;`);
    if (have === count) break;
    if (have < count) await driver.run(`window.__tracerClusters.newShell("build-01"); return true;`);
    else await driver.run(`const w = [...document.querySelectorAll('[data-window-id^="w-"]')].pop(); const b = w && w.querySelector('.ui-window-action[data-action="close"]'); if (b) b.click(); return Boolean(b);`);
    await sleep(350);
  }
  await driver.run(`window.__tracerClusters.flyView("console"); return true;`);
  await sleep(2500);
  // Blur is paid by the windows on screen, so zoom out until all `count` of them are, but never to the level where the canvas draws windows as thumbnails
  // (`lod` "thumb"): that is not the cost of live windows. The run records the zoom it ended at and how many windows were on screen.
  let last = null;
  for (const z of [null, 0.9, 0.8, 0.7, 0.65, 0.6, 0.55, 0.5]) {
    if (z !== null) {
      await driver.run(`const c = window.__tracerClusters.camera(); window.__tracerClusters.setCamera(c.cx, c.cy, arguments[0]); return true;`, z);
      await sleep(1200);
      if (await driver.run(`return window.__tracerClusters.camera().lod === "thumb";`)) {
        if (last !== null) await driver.run(`const c = window.__tracerClusters.camera(); window.__tracerClusters.setCamera(c.cx, c.cy, arguments[0]); return true;`, last);
        await sleep(1200);
        break;
      }
    }
    last = z ?? 1;
    const seen = await driver.run(`return document.querySelectorAll('[data-window-id^="w-"][data-onscreen]').length;`);
    if (seen >= count) break;
  }
}

async function measure(driver, look, count, run) {
  await prepare(driver, look, count);
  const meta = await driver.run(`
    const wins = [...document.querySelectorAll('[data-window-id^="w-"]')];
    const gl = document.createElement("canvas").getContext("webgl");
    const info = gl && gl.getExtension("WEBGL_debug_renderer_info");
    const cam = window.__tracerClusters.camera();
    return { zoom: +cam.z.toFixed(2), lod: cam.lod, windows: wins.length, onscreen: wins.filter((w) => w.hasAttribute("data-onscreen")).length, look: document.documentElement.dataset.look, blur: document.documentElement.style.getPropertyValue("--look-blur"), tint: document.documentElement.style.getPropertyValue("--look-tint"), viewport: innerWidth + "x" + innerHeight, dpr: devicePixelRatio, renderer: info ? gl.getParameter(info.UNMASKED_RENDERER_WEBGL) : (gl ? gl.getParameter(gl.RENDERER) : "no webgl") };`);
  // Idle.
  await driver.run(RECORD_START);
  await sleep(SPAN_MS);
  const idle = stats(await driver.run(RECORD_STOP));
  // Dragging a window by its pill: a circle of 100 px, one point every 16 ms, for the same span.
  const pill = await driver.run(`const w = [...document.querySelectorAll('[data-window-id^="w-"][data-onscreen]')][0]; const p = w && w.querySelector(".ui-window-pill"); if (!p) return null; const r = p.getBoundingClientRect(); return [r.left + r.width / 2, r.top + r.height / 2];`);
  let drag = null;
  if (pill) {
    const step = 16, points = Array.from({ length: Math.round(SPAN_MS / step) }, (_, i) => [Math.round(pill[0] + 100 * Math.sin(i / 20)), Math.round(pill[1] + 60 * Math.sin(i / 14))]);
    await driver.run(RECORD_START);
    await driver.drag(pill[0], pill[1], points, step);
    drag = stats(await driver.run(RECORD_STOP));
  }
  const line = { browser: driver.name, run, ...meta, look, themeId: meta.look, idle, drag };
  appendFileSync(out, JSON.stringify(line) + "\n");
  console.log(JSON.stringify(line));
}

writeFileSync(out, "");
const driver = await (browser === "safari" ? safariDriver() : chromeDriver());
try {
  for (let run = 1; run <= REPEATS; run++) for (const count of (process.env.BENCH_COUNTS ?? "4,12").split(",").map(Number)) for (const look of Object.keys(LOOKS)) await measure(driver, look, count, run);
} finally { await driver.quit(); }
