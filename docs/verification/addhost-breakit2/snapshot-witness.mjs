/** Functional real-engine oracle regression; no terminal text, authority or timing is logged (#189). */
import { chromium } from "../../../apps/tracer/node_modules/playwright/index.mjs";

const port = Number(process.env.TRACER_TEST_PORT);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Set a unique TRACER_TEST_PORT");
const source = await Bun.file(process.env.ADDHOST_WITNESS_SNAPSHOT).text();
const build = await Bun.build({ entrypoints: [new URL("./snapshot-witness-entry.ts", import.meta.url).pathname], target: "browser" });
if (!build.success) throw new Error("Snapshot witness fixture build failed");
const script = await build.outputs[0].text();
const server = Bun.serve({ hostname: "127.0.0.1", port, fetch(request) {
  return new URL(request.url).pathname === "/entry.js"
    ? new Response(script, { headers: { "content-type": "text/javascript" } })
    : new Response('<!doctype html><script type="module" src="/entry.js"></script>', { headers: { "content-type": "text/html" } });
} });
let browser;
try {
  browser = await chromium.launch({ headless: true });
  for (const [name, snapshot, expected] of [
    ["faithful", source, true],
    ["corrupt", source.replace("AFTER_HANDOVER", "AFTER_HANDOVEX"), false],
    ["extra glyph", source.replace("AFTER_HANDOVER", "AFTER_HANDOVERx"), false],
  ]) {
    const page = await browser.newPage();
    page.on("pageerror", (error) => console.error(`Public fixture error: ${error.name}: ${error.message}`));
    await page.goto(`http://127.0.0.1:${port}`);
    await page.waitForFunction(() => typeof window.snapshotWitness === "function");
    const result = await page.evaluate((bytes) => window.snapshotWitness(bytes), [...new TextEncoder().encode(snapshot)]);
    console.log(JSON.stringify({ name, expected, ...result }));
    const actual = process.env.ADDHOST_WITNESS_MODE === "raw" ? result.rawWitness : result.completeRows;
    if (actual !== expected) throw new Error("Painted output witness refused a faithful row or accepted corruption");
    await page.close();
  }
} finally { await browser?.close(); await server.stop(true); }
