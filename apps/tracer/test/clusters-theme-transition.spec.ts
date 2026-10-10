/**
 * Does a View Transition hide a theme switch's restyle behind one committed frame (#121)? Each theme switch is made
 * three ways on the busy canvas with Frosted cards and windows: as it is (instant), inside document.startViewTransition
 * (the old frame is captured, the theme applies, one snapshot crossfades for 180 ms), and with the transition skipped.
 * Per switch the longest gap between animation frames and the time to the first frame after it are logged.
 */
import { expect, test, type Page } from "playwright/test";

async function switchTheme(page: Page, id: string, viaTransition: boolean): Promise<{ worst: number; first: number; total: number }> {
  return page.evaluate(([theme, vt]) => new Promise<{ worst: number; first: number; total: number }>((done) => {
    const w = window as unknown as { __tracerClusters: { act(a: string): void } };
    const gaps: number[] = [];
    let last = performance.now(), first = 0;
    const t0 = last;
    const tick = (t: number): void => {
      gaps.push(t - last); last = t;
      if (!first && gaps.length > 1) first = t - t0;
      if (t - t0 < 700) requestAnimationFrame(tick); else done({ worst: Math.max(...gaps), first, total: t - t0 });
    };
    const apply = (): void => w.__tracerClusters.act(`theme:${theme}`);
    const doc = document as unknown as { startViewTransition?: (cb: () => void) => unknown };
    if (vt && doc.startViewTransition) doc.startViewTransition(apply); else apply();
    requestAnimationFrame(tick);
  }), [id, viaTransition] as const);
}

test("theme switch: instant against a view transition", async ({ browser }) => {
  test.setTimeout(180_000);
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  const page = await context.newPage();
  await page.addStyleTag({ content: "" }).catch(() => undefined);
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=tokyo&bg=mesh&card=4&windows=4");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.addStyleTag({ content: "::view-transition-group(root) { animation-duration: 180ms; } ::view-transition-old(root), ::view-transition-new(root) { animation-duration: 180ms; }" });
  await page.waitForTimeout(2000);
  const rows: string[] = [];
  for (const mode of ["instant", "viewtransition"] as const) {
    const worsts: number[] = [], firsts: number[] = [];
    for (const id of ["mocha", "latte", "tokyo", "mocha", "latte", "tokyo"]) {
      const r = await switchTheme(page, id, mode === "viewtransition");
      worsts.push(r.worst); firsts.push(r.first);
      await page.waitForTimeout(500);
    }
    const f = (xs: number[]): string => xs.map((x) => x.toFixed(0)).join("/");
    rows.push(`${mode}: worst frame gap ${f(worsts)} ms (max ${Math.max(...worsts).toFixed(0)}), first frame after ${f(firsts)} ms`);
  }
  console.log("THEME\n  " + rows.join("\n  "));
});
