/** Functional document-listener oracle for the pinned renderer; no network authority or timing collected (#189). */
import { chromium } from "../../../apps/tracer/node_modules/playwright/index.mjs";

const port = Number(process.env.TRACER_TEST_PORT);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Set a unique TRACER_TEST_PORT");
const renderer = process.env.RENDERER_DISPOSAL_ARTIFACT ?? new URL("../../../apps/tracer/vendor/ghostty-web/dist/ghostty-web.js", import.meta.url).pathname;
const build = await Bun.build({ entrypoints: [renderer], target: "browser" });
if (!build.success) throw new Error("Renderer fixture build failed");
const script = await build.outputs[0].text();
const server = Bun.serve({ hostname: "127.0.0.1", port, fetch(request) {
  return new URL(request.url).pathname === "/renderer.js"
    ? new Response(script, { headers: { "content-type": "text/javascript" } })
    : new Response('<!doctype html><script type="module">import * as renderer from "/renderer.js"; window.renderer = renderer;</script>', { headers: { "content-type": "text/html" } });
} });
let browser;
try {
  browser = await chromium.launch({ headless: true });
  for (const partial of [false, true]) {
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${port}`);
  await page.waitForFunction(() => !!window.renderer);
  const result = await page.evaluate(async (partial) => {
    await window.renderer.init();
    const listeners = new Map();
    const add = document.addEventListener;
    const remove = document.removeEventListener;
    document.addEventListener = function(type, listener, options) {
      if (listener && (type === "mouseup" || type === "mousedown")) {
        const key = type + ":" + String(typeof options === "boolean" ? options : options?.capture ?? false);
        let keys = listeners.get(listener);
        if (!keys) listeners.set(listener, keys = new Set());
        keys.add(key);
      }
      return add.call(this, type, listener, options);
    };
    document.removeEventListener = function(type, listener, options) {
      const keys = listeners.get(listener);
      keys?.delete(type + ":" + String(typeof options === "boolean" ? options : options?.capture ?? false));
      if (keys?.size === 0) listeners.delete(listener);
      return remove.call(this, type, listener, options);
    };
    const host = document.createElement("div");
    host.style.cssText = "width:800px;height:480px";
    document.body.append(host);
    const terminal = new window.renderer.Terminal({ cols: 80, rows: 24, scrollback: 0 });
    if (partial) terminal.startRenderLoop = () => { throw new Error("synthetic renderer opening refusal"); };
    try {
      let refused = false;
      try { terminal.open(host); } catch { refused = true; }
      terminal.dispose();
      return { refused, partial, documentListeners: [...listeners.values()].reduce((n, keys) => n + keys.size, 0) };
    } finally {
      document.addEventListener = add;
      document.removeEventListener = remove;
      host.remove();
    }
  }, partial);
  console.log(JSON.stringify(result));
  if (result.documentListeners !== 0 || result.refused !== partial) throw new Error("Renderer disposal leaked document listeners");
  await page.close();
  }
} finally {
  await browser?.close();
  await server.stop(true);
}
