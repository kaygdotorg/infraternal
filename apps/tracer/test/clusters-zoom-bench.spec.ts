/**
 * Zoom cost with 21 windows (#121). The canvas is zoomed out and back in with ctrl+wheel steps (the trackpad pinch
 * sends the same), through the thumbnail band 0.3 to 0.7, and the work is read from a trace, not from animation-frame
 * intervals (which hide everything under the display's refresh): the renderer main thread's task time, the raster
 * tasks and the Layerize and Commit time, each divided by the number of frames the page produced. Frosted and Solid.
 * Logged as evidence; the assertion is a generous ceiling so the spec stays stable on loaded or software-rendered hosts.
 */
import { expect, test, type Page } from "playwright/test";

async function bench(page: Page, cdp: import("playwright/test").CDPSession, name: string, steps: number[]): Promise<{ perFrame: number }> {
  type Ev = { name: string; ph: string; dur?: number; tid?: number; args?: { elementCount?: number } };
  const events: Ev[] = [];
  const onData = (e: { value: Ev[] }): void => { events.push(...e.value); };
  (cdp as unknown as { on(n: string, f: typeof onData): void }).on("Tracing.dataCollected", onData);
  await page.evaluate(() => { const w = window as unknown as { __n: number; __stop: boolean }; w.__n = 0; w.__stop = false; const tick = (): void => { w.__n++; if (!w.__stop) requestAnimationFrame(tick); }; requestAnimationFrame(tick); });
  await cdp.send("Tracing.start", { categories: "devtools.timeline,disabled-by-default-devtools.timeline", transferMode: "ReportEvents" });
  for (const dy of steps) {
    await page.evaluate((d) => { document.querySelector(".cl-viewport")!.dispatchEvent(new WheelEvent("wheel", { deltaY: d, ctrlKey: true, clientX: 720, clientY: 450, bubbles: true, cancelable: true })); }, dy);
    await page.waitForTimeout(16);
  }
  // Stop before the camera's rest delay (140 ms) ends: the one raster at rest is a separate, one-time cost.
  await page.waitForTimeout(60);
  const done = new Promise<void>((r) => cdp.once("Tracing.tracingComplete", () => r()));
  await cdp.send("Tracing.end");
  await done;
  (cdp as unknown as { off?(n: string, f: typeof onData): void }).off?.("Tracing.dataCollected", onData);
  const frames = await page.evaluate(() => { const w = window as unknown as { __n: number; __stop: boolean }; w.__stop = true; return w.__n; });
  const tid = events.find((e) => e.name === "EventDispatch")?.tid;
  const sum = (n: string, main: boolean): number => events.filter((e) => e.name === n && e.ph === "X" && (!main || e.tid === tid)).reduce((a, e) => a + (e.dur ?? 0), 0) / 1000;
  const mainMs = sum("RunTask", true), raster = sum("RasterTask", false), layerize = sum("Layerize", true), commit = sum("Commit", true), style = sum("UpdateLayoutTree", true);
  const perFrame = (mainMs + raster) / Math.max(1, frames);
  const agg: Record<string, number> = {};
  for (const e of events) if (e.tid === tid && e.ph === "X" && e.dur && e.name !== "RunTask") agg[e.name] = (agg[e.name] ?? 0) + e.dur / 1000;
  const top = Object.entries(agg).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([n, d]) => `${n} ${(d / frames).toFixed(1)}`).join(", ");
  console.log(`ZOOMTOP ${name}: ${top}`);
  const restyled = events.filter((e) => e.name === "UpdateLayoutTree").reduce((a, e) => a + (e.args?.elementCount ?? 0), 0) / frames;
  const more = ["FunctionCall", "Layout", "PrePaint", "Paint", "FireAnimationFrame", "HitTest", "UpdateLayer"].map((n) => `${n} ${(sum(n, true) / frames).toFixed(1)}`).join(" ");
  console.log(`ZOOMSUM ${name} total ${((mainMs + raster)).toFixed(0)} ms main ${mainMs.toFixed(0)} raster ${raster.toFixed(0)} per step ${((mainMs + raster) / 36).toFixed(1)} ms, restyled/step ${(restyled * frames / 36).toFixed(0)}`);
  console.log(`ZOOM ${name}: ${frames} frames | per frame: main ${(mainMs / frames).toFixed(1)} ms, raster ${(raster / frames).toFixed(1)} ms, total ${perFrame.toFixed(1)} ms | Layerize ${(layerize / frames).toFixed(1)} Commit ${(commit / frames).toFixed(1)} style ${(style / frames).toFixed(1)} ms/frame (${restyled.toFixed(0)} elements) | main breakdown ms/frame: ${more}`);
  return { perFrame };
}

for (const look of [{ name: "Frosted", q: "card=4&windows=4" }, { name: "Solid", q: "card=1&windows=1" }]) {
  test(`zoom with 21 windows, ${look.name}`, async ({ browser }) => {
    test.setTimeout(120_000);
    const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
    const page = await context.newPage();
    await page.goto(`/?mock=1&proto=clusters&scene=1&theme=tokyo&bg=mesh&${look.q}`);
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(1500);
    const count = await page.locator(".ui-window").count();
    await page.evaluate(() => { const a = (window as unknown as { __tracerClusters: { overview(): void; setCanvasLock(on: boolean): void } }).__tracerClusters; a.setCanvasLock(false); a.overview(); });
    await page.waitForTimeout(1500);
    // Start in the middle of the thumbnail band's upper edge and zoom through it: 0.75 down to about 0.31 and back.
    await page.evaluate(() => { const a = (window as unknown as { __tracerClusters: { camera(): { cx: number; cy: number }; setCamera(x: number, y: number, z: number): void } }).__tracerClusters; const c = a.camera(); a.setCamera(c.cx, c.cy, 0.75); });
    await page.waitForTimeout(1500);
    const cdp = await context.newCDPSession(page);
    // ctrl+wheel: the camera zoom is z * exp(-deltaY * 0.01); out by 1.5 e-folds in 60 steps, then back in.
    const out = Array.from({ length: 36 }, () => 2.4), back = Array.from({ length: 36 }, () => -2.4);
    const zAt = (): Promise<number> => page.evaluate(() => (window as unknown as { __tracerClusters: { camera(): { z: number } } }).__tracerClusters.camera().z);
    const z0 = await zAt();
    const zoomOut = await bench(page, cdp, `${look.name} zoom out (${count} windows)`, out);
    const z1 = await zAt();
    await page.waitForTimeout(800);
    const zoomIn = await bench(page, cdp, `${look.name} zoom in`, back);
    console.log(`ZOOM ${look.name} zoom ${z0.toFixed(2)} -> ${z1.toFixed(2)} -> ${(await zAt()).toFixed(2)}`);
    expect(Math.max(zoomOut.perFrame, zoomIn.perFrame)).toBeLessThan(400);
  });
}
