/**
 * What a close and a split cost the main thread (#121): a trace of the renderer's main thread only (the machine's other
 * threads and the software rasteriser would drown it). A reflow plays as compositor animations, so Layerize, Commit
 * and style stay small however many windows move. The numbers are logged as evidence; the limit is generous.
 */
import { expect, test } from "playwright/test";

test("a close and a split cost the main thread little", async ({ browser }) => {
  test.setTimeout(120_000);
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  const page = await context.newPage();
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=tokyo&bg=mesh&card=4&windows=4");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(2000);
  const cdp = await context.newCDPSession(page);
  type Ev = { name: string; ph: string; dur?: number; tid?: number; args?: { elementCount?: number } };
  const events: Ev[] = [];
  (cdp as unknown as { on(n: string, f: (e: { value: Ev[] }) => void): void }).on("Tracing.dataCollected", (e) => { events.push(...e.value); });
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
  if (process.env.NOLOCK) await page.evaluate(() => (window as unknown as { __tracerClusters: { setCanvasLock(on: boolean): void } }).__tracerClusters.setCanvasLock(false));
  await page.waitForTimeout(1200);
  const results: Record<string, number> = {};
  const trace = async (name: string, act: () => Promise<void>): Promise<void> => {
    events.length = 0;
    await cdp.send("Tracing.start", { categories: "devtools.timeline,disabled-by-default-devtools.timeline", transferMode: "ReportEvents" });
    await act();
    await page.waitForTimeout(1300);
    const done = new Promise<void>((r) => cdp.once("Tracing.tracingComplete", () => r()));
    await cdp.send("Tracing.end");
    await done;
    const tid = events.find((e) => e.name === "EventDispatch")?.tid;
    const main = events.filter((e) => e.tid === tid && e.ph === "X");
    const sum = (n: string): number => main.filter((e) => e.name === n).reduce((a, e) => a + (e.dur ?? 0), 0) / 1000;
    const count = (n: string): number => main.filter((e) => e.name === n).length;
    const total = sum("RunTask");
    results[name] = total;
    console.log(`REFLOW ${name}: main thread ${total.toFixed(0)} ms | Layerize ${sum("Layerize").toFixed(0)} ms x${count("Layerize")} | Commit ${sum("Commit").toFixed(0)} ms x${count("Commit")} | style ${sum("UpdateLayoutTree").toFixed(0)} ms | paint ${sum("Paint").toFixed(0)} ms | FireAnimationFrame ${sum("FireAnimationFrame").toFixed(0)} ms x${count("FireAnimationFrame")}`);
  };
  const close = () => page.locator('.cl[data-view="console"] .ui-window [data-action="close"]').last().evaluate((b) => (b as HTMLElement).click());
  await trace("split", async () => { await page.keyboard.press("Control+Shift+D"); });
  await trace("split again", async () => { await page.keyboard.press("Control+Shift+D"); });
  await trace("close", close);
  await trace("close again", close);
  expect(Math.max(results["close"]!, results["close again"]!)).toBeLessThan(600);
});
