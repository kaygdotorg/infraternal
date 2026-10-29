/**
 * The top pill on a phone (TASTE: "the top pill sits on the screen's centre line"). At iPhone SE, iPhone and Plus widths,
 * portrait and landscape, ink and paper, in the locked Mesh view and on the normal canvas, with a long host count
 * ("Mesh · 128 hosts"), the pill:
 *  - has its centre within 1 px of the viewport centre,
 *  - overlaps no top-bar control (sidebar toggle, "+", canvas buttons) and no badge,
 *  - shows no keyboard-hint chip on a touch device, and
 *  - never clips a glyph mid-way: the label is shortened by whole words, never cut.
 * `PHONE_PILL_CAPTURES=1` writes screenshots to the external evidence directory.
 */
import { tracerEvidencePath } from "./evidence-path";
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";

const OUT = tracerEvidencePath("phone-pill");
mkdirSync(OUT, { recursive: true });
const SIZES = [
  { name: "se-portrait", w: 375, h: 667 }, { name: "se-landscape", w: 667, h: 375 },
  { name: "iphone-portrait", w: 390, h: 844 }, { name: "iphone-landscape", w: 844, h: 390 },
  { name: "plus-portrait", w: 430, h: 932 }, { name: "plus-landscape", w: 932, h: 430 },
] as const;
/** Narrow windows with a mouse (a small desktop window, a split-view tablet): the canvas buttons beside "+" are shown there. */
const NARROW = [{ name: "mouse-375", w: 375, h: 667 }, { name: "mouse-430", w: 430, h: 700 }, { name: "mouse-600", w: 600, h: 700 }, { name: "mouse-740", w: 740, h: 700 }, { name: "mouse-820", w: 820, h: 700 }] as const;
const THEMES = ["ink", "paper"] as const;
const VIEWS = ["mesh", "canvas"] as const;

async function open(page: Page, view: (typeof VIEWS)[number], theme: string): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=${view === "mesh" ? 6 : 3}&theme=${theme}&bg=none&mesh=128&sessions=0`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(600);
  if (view === "mesh") {
    // Fly to the Mesh view and lock the canvas on it, as a phone does after the pill's swipe.
    await page.evaluate(() => { const p = (window as unknown as { __tracerClusters: { flyView(id: string): void; setCanvasLock(on: boolean): void } }).__tracerClusters; p.flyView("mesh"); });
    await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerClusters: { canvasLock(): { view: string } } }).__tracerClusters.canvasLock().view), { timeout: 10_000 }).toBe("mesh");
    await page.waitForTimeout(1200);
    await page.evaluate(() => (window as unknown as { __tracerClusters: { setCanvasLock(on: boolean): void } }).__tracerClusters.setCanvasLock(true));
    await page.waitForTimeout(800);
  }
}

const measure = (page: Page) => page.evaluate(() => {
  const box = (el: Element) => { const r = el.getBoundingClientRect(); return { l: r.left, r: r.right, t: r.top, b: r.bottom }; };
  const cap = document.querySelector<HTMLElement>("#capsule")!;
  const others = [...document.querySelectorAll<HTMLElement>(".sidebar-toggle, .top .ui-pill:not(#capsule), .top > .tabs > *, .test-double-badge, .cl-mockup")]
    .filter((el) => { const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); return r.width > 0 && r.height > 0 && cs.display !== "none" && cs.visibility !== "hidden"; })
    .map((el) => ({ name: el.className.toString().slice(0, 40) || el.tagName, ...box(el) }));
  const c = box(cap);
  const hits = others.filter((o) => c.l < o.r && c.r > o.l && c.t < o.b && c.b > o.t).map((o) => o.name);
  const kbd = [...cap.querySelectorAll(".capsule-kbd")].some((k) => k.getBoundingClientRect().width > 0);
  // Any element in the pill whose text is wider than its box is clipped (ellipsis or overflow hidden).
  const clipped = [...cap.querySelectorAll<HTMLElement>("*")].filter((e) => !e.closest(".ui-conn") && e.scrollWidth > e.clientWidth + 0.5 && e.clientWidth > 0).map((e) => e.className.toString());
  const capClipped = cap.scrollWidth > cap.clientWidth + 0.5;
  return { centreError: (c.l + c.r) / 2 - window.innerWidth / 2, hits, kbd, clipped, capClipped, text: cap.innerText.replace(/\s+/g, " "), width: c.r - c.l, left: c.l, right: c.r };
});

const CASES = [...SIZES.map((s) => ({ ...s, touch: true })), ...NARROW.map((s) => ({ ...s, touch: false }))];
for (const size of CASES) for (const theme of THEMES) for (const view of VIEWS) {
  test(`${size.name} ${theme} ${view}: pill centred, no overlap, no clipped glyphs`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: size.w, height: size.h }, hasTouch: size.touch, isMobile: size.touch, deviceScaleFactor: size.touch ? 3 : 2 });
    const page = await context.newPage();
    await open(page, view, theme);
    if (view === "mesh") await expect(page.locator("#capsule-host")).toHaveText("Mesh", { timeout: 8_000 });
    const m = await measure(page);
    console.log(`${size.name} ${theme} ${view}: ${JSON.stringify(m)}`);
    if (process.env.PHONE_PILL_CAPTURES) await page.screenshot({ path: `${OUT}/${process.env.PHONE_PILL_CAPTURES}-${size.name}-${theme}-${view}.png`, fullPage: false });
    expect(Math.abs(m.centreError), "pill centre vs viewport centre").toBeLessThanOrEqual(1);
    expect(m.hits, "controls overlapped by the pill").toEqual([]);
    if (size.touch) expect(m.kbd, "keyboard hint on a touch device").toBe(false);
    expect(m.clipped, "elements with clipped text").toEqual([]);
    expect(m.capClipped).toBe(false);
    await context.close();
  });
}
