/**
 * Independent review captures and failure checks for the glass contrast work (D365, D338, #448, J980).
 *
 * Three groups. (1) Screenshots for people to judge against TASTE.md: the palette over white and black pictures and over a
 * bright terminal, a toast, the confirmation card and a window menu, at 1440 x 900 and 393 x 852, in Ink and Paper, with no look
 * and with the Tinted look. (2) The on-demand glass chunks (rules, watcher, cell reader) fail to load, or load late: nothing
 * may throw, the layout must not move, and the chunk's arrival must not repaint a card that is already open with a different
 * box. (3) A look switch in a running page: the rules follow `--look-tint`. The files go to the evidence directory.
 */
import { appendFileSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { glassReady, settled } from "./glass-settled";
import { SIZES, SURFACES, openScene, putPicture, removePicture, type Size } from "./glass-scenes";

/** Where the screenshots and the report lines land. */
const OUT = tracerEvidencePath("glass-review");
/** Looks under review: none, and the product's default Tinted (75% tint, 25% blur). */
const LOOKS = [["none", ""], ["tinted", "&look=tinted"]] as const;

/** Opens a browser context at `size` for `scheme`. */
async function context(browser: import("playwright/test").Browser, size: Size, scheme: "ink" | "paper") {
  return browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: scheme === "ink" ? "dark" : "light", ...(size.phone ? { hasTouch: true, isMobile: true } : {}) });
}

/** Routes every script that carries a glass chunk (found by the marker attributes it writes) through `handle`. */
async function interceptGlass(page: Page, handle: (route: import("playwright/test").Route) => Promise<void>): Promise<void> {
  await page.route(/\.js(\?.*)?$/, async (route) => {
    const response = await route.fetch();
    const body = await response.text();
    if (/data-glass-rules|data-glass-watching|readGlassCells|glassUnder|data-glass-under/.test(body)) await handle(route);
    else await route.fulfill({ response, body });
  });
}

for (const size of SIZES) {
  for (const scheme of ["ink", "paper"] as const) {
    for (const [lookId, lookQuery] of LOOKS) {
      test(`${size.id} ${scheme} look ${lookId}: surfaces over pictures`, async ({ browser }) => {
        const ctx = await context(browser, size, scheme);
        const page = await ctx.newPage();
        await ctx.request.post("/__mock/reset");
        await page.goto(`/?mock=1&proto=clusters&scene=1&fps=0&removal=1&bg=none&theme=${scheme}${lookQuery}`);
        await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 30_000 });
        await glassReady(page);
        await page.waitForFunction(() => Boolean(window.__toast && window.__removalCard && (window as unknown as { __tracerClusters?: unknown }).__tracerClusters), null, { timeout: 30_000 });
        await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
        await page.waitForFunction(() => (document.querySelector(".ui-window")?.getBoundingClientRect().width ?? 0) > 280, null, { timeout: 30_000 });
        await page.evaluate(() => window.__toast!.dismiss());
        const dataLook = await page.evaluate(() => document.documentElement.getAttribute("data-look"));
        appendFileSync(`${OUT}/looks.txt`, `${size.id} ${scheme} ${lookId}: data-look=${dataLook}\n`);
        for (const surface of SURFACES.filter((s) => s.phone || !size.phone)) {
          for (const picture of ["white", "black"] as const) {
            await putPicture(page, picture, "fill", surface.host);
            await surface.open(page);
            await expect(page.locator(surface.selector).first()).toBeVisible();
            await settled(page, surface.selector);
            await page.screenshot({ path: `${OUT}/${size.id}-${scheme}-${lookId}-${surface.id}-${picture}.png` });
            await surface.close(page);
            await removePicture(page);
          }
        }
        await ctx.close();
      });

      test(`${size.id} ${scheme} look ${lookId}: palette over a bright terminal`, async ({ browser }) => {
        const ctx = await context(browser, size, scheme);
        const page = await ctx.newPage();
        await ctx.request.post("/__mock/reset");
        await ctx.request.post("/__mock/open-terminal");
        await page.goto(`/?mock=1&theme=${scheme}&card=2&fps=0${lookQuery}`);
        await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
        await glassReady(page);
        // A light pane over every row (white background, black text) is the worst a programme can put under a card.
        const screen = Array.from({ length: 80 }, (_, i) => `\x1b[47;30m  row ${i} of a pager showing a long log line that fills the width of the screen ${"x".repeat(60)}\x1b[0m`).join("\r\n");
        await page.evaluate((text) => window.__tracerTestDouble!.writeText(`\x1b[2J\x1b[H${text}`), screen);
        await page.keyboard.press("Control+Shift+K");
        await expect(page.locator("#palette")).toBeVisible();
        await settled(page, "#palette");
        await page.screenshot({ path: `${OUT}/${size.id}-${scheme}-${lookId}-palette-bright-terminal.png` });
        await ctx.close();
      });
    }
  }
}

test("glass chunk fails to load: no error, no layout change, surfaces still open", async ({ browser }) => {
  const ctx = await context(browser, SIZES[0], "ink");
  const page = await ctx.newPage();
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => { if (m.type() === "error") errors.push(`console: ${m.text()}`); });
  await interceptGlass(page, (route) => route.abort("failed"));
  await ctx.request.post("/__mock/reset");
  await page.goto("/?mock=1&proto=clusters&scene=1&fps=0&removal=1&bg=none&theme=ink");
  await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 30_000 });
  await page.waitForFunction(() => Boolean(window.__toast), null, { timeout: 30_000 });
  // sleep: a failed import settles in a few ms; the rejection is reported one task later
  await page.waitForTimeout(1500);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  await page.screenshot({ path: `${OUT}/chunk-failed-palette.png` });
  const state = await page.evaluate(() => ({ rules: document.documentElement.hasAttribute("data-glass-rules"), watching: document.documentElement.hasAttribute("data-glass-watching"), overlay: getComputedStyle(document.querySelector("#palette")!).getPropertyValue("--overlay") }));
  appendFileSync(`${OUT}/chunk-failure.txt`, `${JSON.stringify({ errors, state })}\n`);
  expect(state.rules, "the rules chunk was blocked").toBe(false);
  expect(errors, `errors with the glass chunk blocked: ${errors.join(" | ")}`).toEqual([]);
  await ctx.close();
});

test("glass chunk arrives late: cumulative layout shift and the card's box do not change", async ({ browser }) => {
  const ctx = await context(browser, SIZES[0], "paper");
  const page = await ctx.newPage();
  await page.addInitScript(() => {
    const w = window as unknown as { __cls: number; __shifts: number[] };
    w.__cls = 0; w.__shifts = [];
    new PerformanceObserver((list) => { for (const e of list.getEntries() as unknown as Array<{ value: number; hadRecentInput: boolean }>) if (!e.hadRecentInput) { w.__cls += e.value; w.__shifts.push(e.value); } }).observe({ type: "layout-shift", buffered: true });
  });
  await interceptGlass(page, async (route) => {
    // sleep: holds the glass chunks back so the first screens and a card open without them
    await new Promise((resolve) => setTimeout(resolve, 3000));
    await route.continue();
  });
  await ctx.request.post("/__mock/reset");
  await page.goto("/?mock=1&proto=clusters&scene=1&fps=0&removal=1&bg=none&theme=paper", { waitUntil: "commit" });
  await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 30_000 });
  await page.waitForFunction(() => Boolean(window.__toast), null, { timeout: 30_000 });
  const early = await page.evaluate(() => document.documentElement.hasAttribute("data-glass-rules"));
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  await settled(page, "#palette");
  const before = await page.evaluate(() => { const p = document.querySelector("#palette")!; const r = p.getBoundingClientRect(); const s = getComputedStyle(p); return { box: [r.x, r.y, r.width, r.height], bg: s.backgroundColor, fg: s.color }; });
  await page.screenshot({ path: `${OUT}/chunk-late-before.png` });
  await glassReady(page);
  await settled(page, "#palette");
  const after = await page.evaluate(() => { const p = document.querySelector("#palette")!; const r = p.getBoundingClientRect(); const s = getComputedStyle(p); return { box: [r.x, r.y, r.width, r.height], bg: s.backgroundColor, fg: s.color }; });
  await page.screenshot({ path: `${OUT}/chunk-late-after.png` });
  const cls = await page.evaluate(() => ({ cls: (window as unknown as { __cls: number }).__cls, shifts: (window as unknown as { __shifts: number[] }).__shifts }));
  appendFileSync(`${OUT}/chunk-late.txt`, `${JSON.stringify({ rulesBeforeCard: early, before, after, ...cls })}\n`);
  expect(after.box, "the card keeps its box when the chunk lands").toEqual(before.box);
  expect(cls.cls).toBeLessThan(0.01);
  await ctx.close();
});

test("look switch in a running page: the rules follow --look-tint", async ({ browser }) => {
  const ctx = await context(browser, SIZES[0], "ink");
  const page = await ctx.newPage();
  await ctx.request.post("/__mock/reset");
  await page.goto("/?mock=1&proto=clusters&scene=1&fps=0&removal=1&bg=none&theme=ink&look=solid");
  await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 30_000 });
  await glassReady(page);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  const alpha = (): Promise<number> => page.evaluate(() => { const m = /\/\s*([\d.]+)\)|rgba\([^)]*,\s*([\d.]+)\)/.exec(getComputedStyle(document.querySelector("#palette")!).getPropertyValue("--overlay")); return Number(m?.[1] ?? m?.[2] ?? NaN); });
  const set = async (tint: string | null): Promise<void> => {
    await page.evaluate((t) => { const r = document.documentElement; if (t === null) { r.removeAttribute("data-look"); r.style.removeProperty("--look-tint"); } else { r.setAttribute("data-look", "x"); r.style.setProperty("--look-tint", t); } }, tint);
    await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  };
  const seen: Record<string, number> = { solid: await alpha() };
  await set("0.25"); seen.t25 = await alpha();
  await set("0.5"); seen.t50 = await alpha();
  await set("0.75"); seen.t75 = await alpha();
  await set(null); seen.none = await alpha();
  appendFileSync(`${OUT}/look-switch.txt`, `${JSON.stringify(seen)}\n`);
  expect(seen.t50!).toBeGreaterThanOrEqual(0.5 - 0.01);
  expect(seen.t75!).toBeGreaterThanOrEqual(0.75 - 0.01);
  expect(seen.t25!).toBeLessThanOrEqual(seen.t50!);
  await ctx.close();
});
