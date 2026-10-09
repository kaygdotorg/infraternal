/**
 * What an appearance switch costs the page (#121). Each switch (theme, glass level of cards and of windows, background)
 * is made on a busy canvas with Frosted cards and Frosted windows, and the time from the call until the next two frames
 * have been produced is measured: the freeze a person sees. The limit is generous for software rendering; the logged
 * numbers are the evidence.
 */
import { expect, test } from "playwright/test";

test("appearance switches never freeze the page", async ({ browser }) => {
  test.setTimeout(180_000);
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  const page = await context.newPage();
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=tokyo&bg=mesh&card=4&windows=4");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  if (process.env.EXTRA_CSS) await page.addStyleTag({ content: process.env.EXTRA_CSS });
  await page.waitForTimeout(1500);
  const api = (fn: string, ...args: unknown[]): Promise<unknown> => page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Record<string, (...x: unknown[]) => unknown> }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);
  await api("flyView", "console");
  for (let i = 0; i < 6; i++) { await page.keyboard.press("Control+Shift+D"); await page.waitForTimeout(80); }
  await page.waitForTimeout(1500);
  let worst = 0;
  const cdp = await context.newCDPSession(page);
  const events: Array<{ name: string; ph: string; dur?: number; args?: { elementCount?: number } }> = [];
  (cdp as unknown as { on(n: string, f: (e: { value: typeof events }) => void): void }).on("Tracing.dataCollected", (e) => { events.push(...e.value); });
  const traced = async (action: string): Promise<string> => {
    events.length = 0;
    await cdp.send("Tracing.start", { categories: "devtools.timeline,cc,gpu,viz", transferMode: "ReportEvents" });
    const total = await cost(action);
    await page.waitForTimeout(400);
    const end = new Promise<void>((resolve) => cdp.once("Tracing.tracingComplete", () => resolve()));
    await cdp.send("Tracing.end");
    await end;
    const sum = (n: string): number => events.filter((e) => e.name === n && e.ph === "X").reduce((a, e) => a + (e.dur ?? 0), 0) / 1000;
    worst = Math.max(worst, total);
    // Elements restyled is independent of how busy the machine is; the milliseconds are not.
    const elements = events.filter((e) => e.name === "UpdateLayoutTree").reduce((a, e) => a + (e.args?.elementCount ?? 0), 0);
    return `${action} ${total.toFixed(0)} ms (restyled ${elements} elements, style ${sum("UpdateLayoutTree").toFixed(0)} layout ${sum("Layout").toFixed(0)} paint ${sum("Paint").toFixed(0)} raster ${sum("RasterTask").toFixed(0)})`;
  };
  const cost = (action: string): Promise<number> => page.evaluate(([a]) => new Promise<number>((done) => {
    const t0 = performance.now();
    (window as unknown as { __tracerClusters: { act(x: string): void } }).__tracerClusters.act(a!);
    requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(() => done(performance.now() - t0), 0)));
  }), [action] as const);
  const rows: string[] = [];
  for (const action of ["theme:mocha", "theme:latte", "theme:tokyo", "card:2", "card:3", "card:4", "windows:2", "windows:3", "windows:4", "card:1", "card:4", "bg:none", "bg:mesh"]) {
    rows.push(await traced(action));
    await page.waitForTimeout(300);
  }
  console.log(`APPEARANCE ${"\n  " + rows.join("\n  ")} | worst ${worst.toFixed(0)} ms`);
  expect(worst).toBeLessThan(1500);
});
