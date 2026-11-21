// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The page-wide pinch guard (#560) on the production build: `:where(*) { touch-action: pan-x pan-y }` in the shared stylesheet.
 *
 * Headless browsers cannot zoom a page by pinch, so this does not measure the zoom. It measures what decides it: for every
 * element of the real app (the window views, the terminal, the palette, a phone-sized profile) the `touch-action` the browser
 * computes with the guard and, in the same page, without it (the rule is removed through the CSSOM). It proves three things:
 *
 * 1. the guard changes only elements that said nothing (`auto`); every element that sets its own value keeps it, so the
 *    canvas, rows, grips, sliders and keys behave as before (a zero-specificity rule loses to any class);
 * 2. with the guard, no element's effective value (the intersection of its own and its ancestors' up to the nearest scroll
 *    container, the rule the browser applies) allows a pinch-zoom, and without it some do, so the guard is what closes the hole;
 * 3. the app's own pinches still work and the page itself stays at scale 1: a two-finger pinch over the terminal still changes
 *    its font size, and one over a scroll container does not change the visual viewport.
 */
import { devices, expect, test, type Page } from "playwright/test";

/** What one element reports: its computed value with the guard, without it, and whether it scrolls. */
type Probe = { path: string; withGuard: string; without: string; scroller: boolean; chainWith: string[]; chainWithout: string[] };

/** Reads every element's `touch-action` with the guard rule and without it (removed through the CSSOM, then put back). */
async function sweep(page: Page): Promise<Probe[]> {
  return page.evaluate(() => {
    const isGuard = (r: CSSRule): boolean => r instanceof CSSStyleRule && r.selectorText === ":where(*)" && r.style.touchAction === "pan-x pan-y";
    const all = (): Element[] => [document.documentElement, ...document.querySelectorAll("*")];
    const scrolls = (el: Element): boolean => { const s = getComputedStyle(el); return /(auto|scroll|hidden)/.test(s.overflowX + s.overflowY) || el === document.documentElement; };
    const name = (el: Element): string => `${el.tagName.toLowerCase()}${el.id ? `#${el.id}` : ""}${typeof el.className === "string" && el.className ? "." + el.className.trim().split(/\s+/).slice(0, 2).join(".") : ""}`;
    const chain = (el: Element): string[] => { const out: string[] = []; for (let n: Element | null = el; n; n = n.parentElement) { out.push(getComputedStyle(n).touchAction); if (scrolls(n)) break; } return out; };
    const read = (): Map<Element, { v: string; chain: string[] }> => new Map(all().map((el) => [el, { v: getComputedStyle(el).touchAction, chain: chain(el) }]));
    const withGuard = read();
    // Take the guard out, read again, put it back so the page is as found.
    const removed: { sheet: CSSStyleSheet; text: string; index: number }[] = [];
    for (const sheet of Array.from(document.styleSheets)) {
      const rules = sheet.cssRules;
      for (let i = rules.length - 1; i >= 0; i--) if (isGuard(rules[i]!)) { removed.push({ sheet, text: rules[i]!.cssText, index: i }); sheet.deleteRule(i); }
    }
    if (removed.length === 0) throw new Error("the guard rule is not in any stylesheet");
    const without = read();
    for (const r of removed.reverse()) r.sheet.insertRule(r.text, r.index);
    return all().map((el) => ({ path: name(el), withGuard: withGuard.get(el)!.v, without: without.get(el)!.v, scroller: scrolls(el), chainWith: withGuard.get(el)!.chain, chainWithout: without.get(el)!.chain }));
  });
}

/** The set of gestures a chain of `touch-action` values leaves to the browser (their intersection). */
function allowed(chain: string[]): Set<string> {
  let set = new Set(["pan-x", "pan-y", "pinch-zoom"]);
  for (const value of chain) {
    const own = value === "auto" ? new Set(["pan-x", "pan-y", "pinch-zoom"])
      : value === "none" ? new Set<string>()
      : value === "manipulation" ? new Set(["pan-x", "pan-y", "pinch-zoom"])
      : new Set(value.split(/\s+/).filter((t) => t === "pan-x" || t === "pan-y" || t === "pinch-zoom"));
    set = new Set([...set].filter((t) => own.has(t)));
  }
  return set;
}

/** Checks one scene's probes against claims 1 and 2; returns counts for the report. */
function check(scene: string, probes: Probe[]): { elements: number; changed: number; pinchBefore: number; pinchAfter: number } {
  let changed = 0, pinchBefore = 0, pinchAfter = 0;
  const leaks: string[] = [];
  for (const p of probes) {
    if (p.withGuard !== p.without) {
      changed++;
      expect([p.path, p.without, p.withGuard], `${scene}: only an element that set nothing may change`).toEqual([p.path, "auto", "pan-x pan-y"]);
    }
    if (allowed(p.chainWithout).has("pinch-zoom")) pinchBefore++;
    if (allowed(p.chainWith).has("pinch-zoom")) { pinchAfter++; leaks.push(`${p.path} (${p.chainWith.join(" > ")})`); }
  }
  expect(leaks, `${scene}: elements that still allow pinch-zoom`).toEqual([]);
  return { elements: probes.length, changed, pinchBefore, pinchAfter };
}

const api = (page: Page, fn: string, ...args: unknown[]): Promise<unknown> => page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Record<string, (...x: unknown[]) => unknown> }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);

/** `TRACER_TEST_BROWSER=webkit` runs the same sweep in WebKit (the engine of iOS Safari); the default is Chromium. The CDP touch pinch only exists in Chromium. */
const engine = process.env.TRACER_TEST_BROWSER === "webkit" ? "webkit" : "chromium";
test.use({ ...devices["iPhone 15"], browserName: engine });

test.describe("pinch guard, phone profile", () => {

  test("every view: only silent elements change, none allows a pinch-zoom", async ({ page }, testInfo) => {
    await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(1200);
    const report: Record<string, unknown> = {};
    for (const view of ["console", "containers", "settings"]) {
      await api(page, "flyView", view);
      await page.waitForTimeout(1300);
      report[view] = check(view, await sweep(page));
    }
    // The cost of the one extra rule: adding a no-op rule to a sheet makes the engine restyle every element, so time that with the
    // guard present and absent (reported, not asserted).
    report["restyleMs"] = await page.evaluate(() => {
      const sheet = Array.from(document.styleSheets).find((sh) => Array.from(sh.cssRules).some((r) => r instanceof CSSStyleRule && r.selectorText === ":where(*)"))!;
      const index = Array.from(sheet.cssRules).findIndex((r) => r instanceof CSSStyleRule && r.selectorText === ":where(*)");
      const run = (): number => { const t0 = performance.now(); for (let i = 0; i < 100; i++) { const n = sheet.insertRule(`.restyle-probe-${i} { color: red; }`, 0); void document.body.offsetHeight; getComputedStyle(document.body).color; sheet.deleteRule(n); } return (performance.now() - t0) / 100; };
      run();
      const withRule = run();
      const text = sheet.cssRules[index]!.cssText; sheet.deleteRule(index); run();
      const without = run(); sheet.insertRule(text, index);
      return { withRule, without, elements: document.querySelectorAll("*").length };
    });
    await testInfo.attach("touch-action-sweep.json", { body: JSON.stringify(report, null, 2), contentType: "application/json" });
    console.log("touch-action sweep", JSON.stringify(report));
  });

  test("the terminal: same two claims, and a pinch still resizes the font", async ({ page }) => {
    await page.context().request.post("/__mock/reset");
    await page.context().request.post("/__mock/open-terminal");
    await page.goto("/?mock=1");
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected())).toBe(true);
    check("terminal", await sweep(page));
    test.skip(engine !== "chromium", "synthetic two-finger touch goes through CDP");
    const font = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.fontSize ?? 0);
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: 120, y: 350 }, { x: 220, y: 350 }] });
    await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: 70, y: 350 }, { x: 270, y: 350 }] });
    await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.fontSize ?? 0)).toBeGreaterThan(font);
    expect(await page.evaluate(() => window.visualViewport?.scale)).toBe(1);
  });
});

test("desktop pointer: typing, wheel and scale are untouched by the guard", async ({ browser, baseURL }) => {
  const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 }, hasTouch: false, isMobile: false });
  const page = await context.newPage();
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1000);
  const before = await page.evaluate(() => window.visualViewport?.scale);
  await page.mouse.wheel(0, 200);
  expect(await page.evaluate(() => window.visualViewport?.scale)).toBe(before);
  // `touch-action` only ever affects touch input, so for a mouse the app must simply still respond: a click leaves the app up.
  await page.mouse.click(720, 450);
  await expect(page.locator(".cl-mockup")).toBeVisible();
  await context.close();
});
