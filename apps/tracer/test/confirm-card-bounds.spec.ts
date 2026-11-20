// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Where the glass confirmation card sits relative to the window it is about (D385, #486 review F5; TASTE: overlays stay inside
 * the window they belong to). The card is opened on a window's pill through the test double's hook (`__removalCard`, only with
 * `?removal=1`). The unit test `packages/ui/src/confirm-bounds.test.ts` pins the arithmetic; this checks the real surface at the
 * window's edges: a normal window, a window partly panned off screen and a window too small for the card. In each the card's box
 * lies inside the viewport, and inside the window too unless the window is too small for it (then the viewport is the limit).
 * Functional: measurements of boxes, never speed.
 */
import { expect, test, type Page } from "playwright/test";

/** The inset a card keeps from its window's edge, in pixels. */
const INSET = 9;
/** Sub-pixel slack when comparing boxes. */
const TOLERANCE = 0.5;

/** Opens the Console view of the clusters double with the card hook installed. */
async function open(page: Page): Promise<void> {
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none&removal=1");
  await page.waitForFunction(() => (window as unknown as { __removalCard?: unknown; __tracerClusters?: unknown }).__removalCard && (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  // sleep: the mock scene settles before the camera flight
  await page.waitForTimeout(700);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
  // sleep: the camera flight to the view lasts under 300 ms; margin for a loaded VM
  await page.waitForTimeout(900);
}

/** The card's box and its window's box, after opening the card on that window's pill. */
async function measure(page: Page): Promise<{ card: DOMRect; win: DOMRect; view: { w: number; h: number } }> {
  await page.evaluate(() => {
    const pill = document.querySelector<HTMLElement>(".ui-window .ui-window-pill")!;
    (window as unknown as { __removalCard: (a: HTMLElement) => void }).__removalCard(pill);
  });
  await expect(page.locator(".ui-confirm-tip[data-open='true']")).toBeVisible();
  // sleep: the card's entrance (under 300 ms) so its box is final
  await page.waitForTimeout(450);
  return page.evaluate(() => ({
    card: document.querySelector(".ui-confirm-tip")!.getBoundingClientRect().toJSON(),
    win: document.querySelector(".ui-window")!.getBoundingClientRect().toJSON(),
    view: { w: innerWidth, h: innerHeight },
  }));
}

/** The rectangles of the window's own header controls (its pill and action buttons), which a card must never cover. */
async function headerControls(page: Page): Promise<DOMRect[]> {
  return page.evaluate(() => [...document.querySelector(".ui-window")!.querySelectorAll(".ui-window-head .ui-window-pill, .ui-window-head .ui-window-action")].map((e) => e.getBoundingClientRect().toJSON()));
}
/** Whether two boxes share any area (touching edges do not count). */
const overlaps = (a: DOMRect, b: DOMRect): boolean => a.left < b.right - TOLERANCE && a.right > b.left + TOLERANCE && a.top < b.bottom - TOLERANCE && a.bottom > b.top + TOLERANCE;
/** Whether the card lies inside the viewport. */
const insideView = (m: { card: DOMRect; view: { w: number; h: number } }): boolean => m.card.left >= -TOLERANCE && m.card.top >= -TOLERANCE && m.card.right <= m.view.w + TOLERANCE && m.card.bottom <= m.view.h + TOLERANCE;
/** Whether the card lies inside its window with the inset on every side. */
const insideWindow = (m: { card: DOMRect; win: DOMRect }): boolean => m.card.left >= m.win.left + INSET - TOLERANCE && m.card.top >= m.win.top + INSET - TOLERANCE && m.card.right <= m.win.right - INSET + TOLERANCE && m.card.bottom <= m.win.bottom - INSET + TOLERANCE;

test.describe("desktop", () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  test("a card on a window's pill stays inside that window with the 9 px inset", async ({ page }) => {
    await open(page);
    const m = await measure(page);
    expect(insideWindow(m), `card ${JSON.stringify(m.card)} in window ${JSON.stringify(m.win)}`).toBe(true);
    expect(insideView(m)).toBe(true);
  });

  test("a window partly panned off screen keeps the card on screen", async ({ page }) => {
    await open(page);
    // The window is shifted left by 40 % of its width: its box is cut by the viewport's left edge.
    await page.evaluate(() => { const w = document.querySelector<HTMLElement>(".ui-window")!; w.style.transform = `translateX(${-w.getBoundingClientRect().left - w.getBoundingClientRect().width * 0.4}px)`; });
    const m = await measure(page);
    expect(m.win.left, "the window really is cut by the screen edge").toBeLessThan(0);
    expect(insideView(m), `card ${JSON.stringify(m.card)}`).toBe(true);
  });

  test("a window just tall enough for the card keeps the card below its header controls, not on top of them", async ({ page }) => {
    await open(page);
    // Probe the card's height once, then make the window only a few pixels taller than the card plus its insets: the box then
    // fits the card but not the header above it, so a clamp alone would slide the card up over the pill.
    const probe = await measure(page);
    await page.keyboard.press("Escape");
    await expect(page.locator(".ui-confirm-tip")).toHaveCount(0);
    await page.evaluate((h) => { const w = document.querySelector<HTMLElement>(".ui-window")!; w.style.flex = "none"; w.style.minHeight = "0"; w.style.height = `${h}px`; w.style.maxHeight = `${h}px`; }, Math.ceil(probe.card.height) + 2 * INSET + 6);
    const m = await measure(page);
    for (const control of await headerControls(page)) expect(overlaps(m.card, control), `card ${JSON.stringify(m.card)} covers control ${JSON.stringify(control)}`).toBe(false);
    expect(insideView(m)).toBe(true);
  });

  test("a card that flips above the pill near the screen's bottom does not cover the header controls", async ({ page }) => {
    await open(page);
    await page.evaluate(() => { const w = document.querySelector<HTMLElement>(".ui-window")!; w.style.transform = `translateY(${innerHeight - 70 - w.getBoundingClientRect().top}px)`; });
    const m = await measure(page);
    expect(m.card.bottom, "the card is above the pill").toBeLessThanOrEqual((await headerControls(page))[0]!.top + TOLERANCE);
    for (const control of await headerControls(page)) expect(overlaps(m.card, control), `card ${JSON.stringify(m.card)} covers control ${JSON.stringify(control)}`).toBe(false);
    expect(insideView(m)).toBe(true);
  });

  test("a window too small for the card falls back to the viewport and is never cut off", async ({ page }) => {
    await open(page);
    await page.evaluate(() => { const w = document.querySelector<HTMLElement>(".ui-window")!; w.style.flex = "none"; w.style.minHeight = "0"; w.style.height = "90px"; w.style.maxHeight = "90px"; w.style.width = "220px"; w.style.minWidth = "0"; w.style.maxWidth = "220px"; });
    // Near the bottom of the screen, where a card pinned to the window's top would run off the viewport.
    await page.evaluate(() => { const w = document.querySelector<HTMLElement>(".ui-window")!; w.style.transform = `translateY(${innerHeight - 100 - w.getBoundingClientRect().top}px)`; });
    const m = await measure(page);
    expect(m.win.height, "the window is smaller than the card plus its inset").toBeLessThan(m.card.height + 2 * INSET);
    expect(insideView(m), `card ${JSON.stringify(m.card)}`).toBe(true);
    for (const control of await headerControls(page)) expect(overlaps(m.card, control), `card ${JSON.stringify(m.card)} covers control ${JSON.stringify(control)}`).toBe(false);
  });
});

test.describe("phone", () => {
  test.use({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });

  test("on a phone the card is inset inside its window, never edge to edge", async ({ page }) => {
    await open(page);
    const m = await measure(page);
    expect(insideWindow(m), `card ${JSON.stringify(m.card)} in window ${JSON.stringify(m.win)}`).toBe(true);
    expect(m.card.left, "inset from the left screen edge").toBeGreaterThan(0);
    expect(m.card.right, "inset from the right screen edge").toBeLessThan(m.view.w);
  });
});
