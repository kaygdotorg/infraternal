/** Functional real-browser preparation/disposal oracle; records counts, never timing or authority (#189). */
import { chromium } from "../../../apps/tracer/node_modules/playwright/index.mjs";

const port = Number(process.env.TRACER_TEST_PORT);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Set a unique TRACER_TEST_PORT");
const build = await Bun.build({ entrypoints: [new URL("./renderer-prepare-entry.ts", import.meta.url).pathname], target: "browser" });
if (!build.success) throw new Error("Renderer fixture build failed");
const script = await build.outputs[0].text();
const server = Bun.serve({ hostname: "127.0.0.1", port, fetch(request) {
  return new URL(request.url).pathname === "/entry.js"
    ? new Response(script, { headers: { "content-type": "text/javascript" } })
    : new Response('<!doctype html><script type="module" src="/entry.js"></script>', { headers: { "content-type": "text/html" } });
} });
let browser;
try {
  browser = await chromium.launch({ headless: true });
  for (const retry of [false, true]) {
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${port}`);
    await page.waitForFunction(() => typeof window.resourceProof === "function");
    const result = await page.evaluate((retry) => window.resourceProof(retry), retry);
    console.log(JSON.stringify({ retry, ...result }));
    if (result.documentListeners !== 0 || result.opens !== 1 || result.sockets !== 0 || !result.focusPreserved || !result.childrenUnchanged) throw new Error("Renderer preparation leaked resources");
    if (retry ? result.laterLoads !== 1 || result.first.some(x => x !== "rejected") || result.later.some(x => x !== "fulfilled") : result.loads !== 1 || result.first.some(x => x !== "fulfilled")) throw new Error("Renderer preparation singleflight/retry failed");
    await page.close();
  }
} finally {
  await browser?.close();
  await server.stop(true);
}
