/**
 * Phone window width (TASTE: "Full width means full width; edge to edge peeks"; D191, Settings -> Window Sizes).
 *
 * On a phone "Full width" is exactly the screen between the safe areas with no neighbour showing, and "Edge to edge" (the
 * default) is narrower by the gap and a slice for each neighbour, so a thin slice of each shows. Neither may overflow the
 * visual viewport, and the terminal's columns come from the window's real width. Runs on the test double's canvas (the
 * product canvas code), touch profiles at 393x852 and 375x667, ink theme. Review screenshots land in job scratch.
 */
import { tracerEvidencePath } from "./evidence-path";
import { expect, test, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const captures = tracerEvidencePath("phone-window-width");
const PEEK = 10, GAP = 12;
const SIZES = [{ w: 393, h: 852 }, { w: 375, h: 667 }] as const;
const KEY = "tracer.window-size.phone";

async function open(page: Page, setting: string | undefined): Promise<void> {
  if (setting) await page.addInitScript(([k, v]) => localStorage.setItem(k!, v!), [KEY, setting]);
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none&sessions=0");
  await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(4, { timeout: 20_000 });
  await page.addStyleTag({ content: ".test-double-badge, .cl-mockup, .perf-hud, .ui-toast { display: none !important; }" });
  await page.waitForTimeout(1200);
}

/** The window nearest the middle of the screen, its neighbours' visible slices, and its terminal. */
const measure = (page: Page) => page.evaluate(() => {
  const cols = [...document.querySelectorAll<HTMLElement>("[data-view='console'] .cl-col")];
  const wins = cols.map((c) => c.querySelector<HTMLElement>(".ui-window")!);
  const rects = wins.map((n) => n.getBoundingClientRect());
  const vw = window.visualViewport?.width ?? innerWidth;
  const mid = vw / 2;
  const at = rects.map((r, i) => ({ i, d: Math.abs((r.left + r.right) / 2 - mid) })).sort((a, b) => a.d - b.d)[0]!.i;
  const shown = (r: DOMRect) => Math.max(0, Math.min(r.right, vw) - Math.max(r.left, 0));
  const own = rects[at]!;
  // The test double runs one live terminal (the first window); the others are previews. Its columns are read wherever it is.
  const live = wins[0]!;
  const host = live.querySelector<HTMLElement>(".terminal-host");
  const canvas = host?.querySelector("canvas")?.getBoundingClientRect();
  const liveBox = rects[0]!;
  return {
    vw, at, count: cols.length, left: own.left, right: own.right, width: own.width, centre: (own.left + own.right) / 2 - mid,
    leftSlice: at > 0 ? shown(rects[at - 1]!) : 0, rightSlice: at < cols.length - 1 ? shown(rects[at + 1]!) : 0,
    liveRight: liveBox.right, liveW: liveBox.width, cols: Number(host?.dataset.cols ?? 0), hostW: host?.clientWidth ?? 0, canvasRight: canvas?.right ?? 0, canvasW: canvas?.width ?? 0, docScroll: document.documentElement.scrollWidth,
  };
});

for (const { w, h } of SIZES) test(`phone ${w}x${h}: full width is the screen with no neighbour, a lone window is full width in both`, async ({ browser }) => {
  test.setTimeout(180_000);
  await mkdir(captures, { recursive: true });
  const context = await browser.newContext({ viewport: { width: w, height: h }, hasTouch: true, isMobile: true, deviceScaleFactor: 3 });
  const page = await context.newPage();
  try {
    await open(page, undefined);
    const press = async (id: string) => { await page.locator(`[data-cv='${id}']`).tap(); await page.waitForTimeout(800); };
    const stepTo = async (i: number) => { for (let k = 0; k < 4; k++) { const s = await measure(page); if (s.at === i) break; await press(i > s.at ? "next" : "previous"); } };
    const set = async (value: string) => {
      // The choice belongs to the account's look (D352, #400): a person changes it in Settings, and the old device-wide key is read
      // only once at load (the seed in `open`). So switch it live the way a person does, then come back to the console view.
      const clusters = (fn: string, arg: string) => page.evaluate(([f, a]) => (window as unknown as { __tracerClusters: Record<string, (x: string) => void> }).__tracerClusters[f!]!(a!), [fn, arg]);
      await clusters("openSettings", "appearance.layout");
      const row = page.locator(`[data-kind="window-size-phone"] .ui-sp-row[data-id="${value}"]`);
      await expect(row).toBeVisible({ timeout: 10_000 });
      await row.evaluate((button) => (button as HTMLElement).click());
      await expect(row).toHaveAttribute("aria-checked", "true");
      await clusters("flyView", "console");
      await page.waitForTimeout(1500);
    };
    const fits = (s: Awaited<ReturnType<typeof measure>>, label: string) => {
      expect(s.left, `${label}: window inside the left edge`).toBeGreaterThanOrEqual(-0.5);
      expect(s.right, `${label}: window inside the right edge`).toBeLessThanOrEqual(s.vw + 0.5);
      expect(s.docScroll, `${label}: page does not scroll sideways`).toBeLessThanOrEqual(s.vw);
      expect(s.cols, `${label}: columns`).toBeGreaterThan(10);
      expect(s.canvasRight, `${label}: terminal text stays inside the window`).toBeLessThanOrEqual(s.liveRight + 0.5);
      expect(s.canvasW, `${label}: terminal fits its box`).toBeLessThanOrEqual(s.hostW + 0.5);
    };

    // The default is edge to edge.
    await stepTo(1);
    const edge = await measure(page);
    expect(edge.count).toBe(3);
    fits(edge, "edge to edge");
    expect(edge.width, "edge to edge width").toBeCloseTo(w - 2 * (GAP + PEEK), 0);
    for (const slice of [edge.leftSlice, edge.rightSlice]) { expect(slice).toBeGreaterThanOrEqual(PEEK - 1.5); expect(slice).toBeLessThanOrEqual(PEEK + 1.5); }
    expect(Math.abs(edge.centre)).toBeLessThanOrEqual(1);
    await page.screenshot({ path: `${captures}/phone-${w}x${h}-ink-edge-to-edge.png` });

    // Live switch to full width: the window is the whole screen and no neighbour shows.
    await set("full");
    await stepTo(1);
    const full = await measure(page);
    fits(full, "full width");
    expect(full.width, "full width is the viewport width").toBeCloseTo(full.vw, 0);
    expect(full.leftSlice, "no neighbour at full width").toBe(0);
    expect(full.rightSlice, "no neighbour at full width").toBe(0);
    expect(edge.width, "edge to edge is narrower than full width").toBeLessThan(full.width);
    expect(full.cols, "terminal columns follow the width").toBeGreaterThan(edge.cols);
    expect(full.canvasW).toBeGreaterThan(edge.canvasW);
    expect(full.liveW).toBeGreaterThan(edge.liveW);
    await page.screenshot({ path: `${captures}/phone-${w}x${h}-ink-full-width.png` });

    // Back to edge to edge, live: the slices return and the width is the same as before.
    await set("edge");
    await stepTo(1);
    const again = await measure(page);
    expect(again.width).toBeCloseTo(edge.width, 0);
    expect(again.leftSlice).toBeGreaterThanOrEqual(PEEK - 1.5);

    // A lone window, edge to edge: the full width (as at full width), centred, nothing peeking. Closing the others
    // grows it through the re-layout transition.
    const close = (host: string) => page.locator("[data-view='console'] .ui-window").filter({ has: page.locator(".ui-window-host", { hasText: host }) }).first()
      .locator(".ui-window-action[aria-label='Close']").dispatchEvent("click");
    for (const host of ["studio-mac", "nix-cache"]) { await close(host); await page.waitForTimeout(1200); }
    // The last neighbour closes: the remaining window grows to the full width through the re-layout transition, with
    // in-between widths and no jump.
    await page.evaluate(() => {
      const seen: number[] = [];
      (window as unknown as { __widths: number[] }).__widths = seen;
      const tick = () => { const w = document.querySelector<HTMLElement>("[data-view='console'] .ui-window"); if (w) seen.push(w.getBoundingClientRect().width); if (seen.length < 120) requestAnimationFrame(tick); };
      requestAnimationFrame(tick);
    });
    await close("edge-arm");
    await page.waitForTimeout(1500);
    const widths = await page.evaluate(() => (window as unknown as { __widths: number[] }).__widths);
    expect(widths.some((x) => x > edge.width + 3 && x < w - 3), `growing to the full width animates: ${widths.filter((_, i) => i % 6 === 0).map(Math.round).join(",")}`).toBe(true);
    const lone = await measure(page);
    expect(lone.count).toBe(1);
    expect(lone.width, "a lone window is the full width").toBeCloseTo(lone.vw, 0);
    expect(lone.width).toBeGreaterThan(edge.width);
    expect(Math.abs(lone.centre)).toBeLessThanOrEqual(1);
    expect(lone.leftSlice + lone.rightSlice).toBe(0);
    fits(lone, "lone edge to edge");
    await page.screenshot({ path: `${captures}/phone-${w}x${h}-ink-edge-to-edge-lone.png` });
  } finally { await context.close(); }
});
