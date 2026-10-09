/**
 * Frame cost of the canvas under load (#121): the owner's target is every canvas operation at 120 fps (60 at the very
 * least) on real devices. A headless browser here runs at 60 Hz in software, so this bench reports the shape rather
 * than the device's number: the frame-time distribution per scenario against the 120 Hz budget (8.3 ms), and what
 * the compositor was asked to do (rasterisation, paints, frames drawn) while nothing was supposed to move.
 *
 * Setup is the owner's: Tokyo Night, the mesh background, Frosted cards and windows, DPR 2, many windows. Scenarios:
 * idle (only blinking cursors and the connection icon animate), view flights, a burst of splits, rapid view
 * switches, a burst of closes. Numbers print as `BENCH <scenario> ...`; the spec asserts only that it ran.
 */
import { expect, test, type CDPSession, type Page } from "playwright/test";

type Dist = { n: number; p50: number; p95: number; p99: number; max: number; over8: number };
const dist = (frames: number[]): Dist => {
  const s = [...frames].sort((a, b) => a - b);
  const at = (q: number): number => s[Math.min(s.length - 1, Math.floor(s.length * q))] ?? 0;
  return { n: s.length, p50: +at(0.5).toFixed(1), p95: +at(0.95).toFixed(1), p99: +at(0.99).toFixed(1), max: +(s.at(-1) ?? 0).toFixed(1), over8: s.filter((f) => f > 8.4).length };
};

async function meter(page: Page, cdp: CDPSession, name: string, run: () => Promise<void>): Promise<void> {
  const events: Array<{ name: string; ph: string; dur?: number }> = [];
  (cdp as unknown as { on(n: string, f: (e: { value: typeof events }) => void): void }).on("Tracing.dataCollected", (e) => { events.push(...e.value); });
  await page.evaluate(() => { const w = window as unknown as { __f: number[]; __stop: boolean }; w.__f = []; w.__stop = false; let last = performance.now(); const tick = (t: number): void => { w.__f.push(t - last); last = t; if (!w.__stop) requestAnimationFrame(tick); }; requestAnimationFrame(tick); });
  await cdp.send("Tracing.start", { categories: "devtools.timeline,cc,gpu,viz", transferMode: "ReportEvents" });
  await run();
  const done = new Promise<void>((resolve) => cdp.once("Tracing.tracingComplete", () => resolve()));
  await cdp.send("Tracing.end");
  await done;
  const frames = await page.evaluate(() => { const w = window as unknown as { __f: number[]; __stop: boolean }; w.__stop = true; return w.__f.slice(2); });
  const count = (n: string): number => events.filter((e) => e.name === n && (e.ph === "X" || e.ph === "B" || e.ph === "b")).length;
  const ms = (n: string): number => +events.filter((e) => e.name === n && e.ph === "X").reduce((a, e) => a + (e.dur ?? 0), 0) / 1000;
  console.log(`BENCH ${name.padEnd(14)} frames ${JSON.stringify(dist(frames))} | raster ${count("RasterTask")} (${ms("RasterTask").toFixed(0)} ms) paint ${count("Paint")} layerize ${count("Layerize")} drawFrame ${count("DrawFrame")} compositeLayers ${count("CompositeLayers")}`);
}

test("frame cost per scenario at DPR 2 with the owner's look", async ({ browser }) => {
  test.setTimeout(240_000);
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  const page = await context.newPage();
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=tokyo&bg=mesh&card=4&windows=4");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  if (process.env.EXTRA_CSS) await page.addStyleTag({ content: process.env.EXTRA_CSS });
  await page.waitForTimeout(1500);
  const cdp = await context.newCDPSession(page);
  const api = (fn: string, ...args: unknown[]): Promise<unknown> => page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Record<string, (...x: unknown[]) => unknown> }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);

  await meter(page, cdp, "idle", async () => { await page.waitForTimeout(3000); });

  // Grow the canvas: a burst of splits, as fast as the page takes them.
  await api("flyView", "console");
  await page.waitForTimeout(1200);
  await meter(page, cdp, "split burst", async () => {
    for (let i = 0; i < 12; i++) { await page.keyboard.press("Control+Shift+D"); await page.waitForTimeout(40); }
    await page.waitForTimeout(1200);
  });
  const windows = await page.locator(".ui-window").count();
  console.log(`BENCH windows on the canvas: ${windows}`);

  await api("overview");
  await page.waitForTimeout(1500);
  await meter(page, cdp, "idle many", async () => { await page.waitForTimeout(3000); });

  const ids = ["console", "containers", "mesh", "settings"];
  await meter(page, cdp, "view flights", async () => {
    for (const id of [...ids, ...ids.slice().reverse()]) { await api("flyView", id); await page.waitForTimeout(900); }
  });
  await meter(page, cdp, "rapid switches", async () => {
    for (let i = 0; i < 24; i++) { await api("flyView", ids[i % ids.length]); await page.waitForTimeout(110); }
    await page.waitForTimeout(900);
  });
  await api("flyView", "console");
  await page.waitForTimeout(1200);
  await meter(page, cdp, "close burst", async () => {
    for (let i = 0; i < 10; i++) { await page.locator('.cl[data-view="console"] .ui-window [data-action="close"]').last().evaluate((b) => (b as HTMLElement).click()).catch(() => undefined); await page.waitForTimeout(60); }
    await page.waitForTimeout(1200);
  });
  await context.close();
});
