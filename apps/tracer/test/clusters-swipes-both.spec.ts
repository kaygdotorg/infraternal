/**
 * Every swipe moves, on both axes, and a swipe during an animation retargets instead of being dropped (#122, #141).
 * Six consecutive trackpad swipes (a ramp, then a momentum tail) are sent as one stream of wheel events, 330 ms and 50 ms
 * apart. Horizontally: the Docs view, twelve windows side by side, swiping over a window's pill (D374). Vertically: one column of thirteen windows. Each
 * run must end exactly six windows further, and no swipe may be a no-op.
 */
import { expect, test, type Page } from "playwright/test";

async function swipes(page: Page, axis: "x" | "y", count: number, gapMs: number, at: { x: number; y: number }): Promise<void> {
  await page.evaluate(({ axis, count, gapMs, at }) => new Promise<void>((done) => {
    const slots: number[] = [];
    for (let n = 0; n < count; n++) {
      const deltas: number[] = [];
      for (let i = 1; i <= 8; i++) deltas.push(10 * i);
      for (let i = 0; i < 30; i++) deltas.push(50 * Math.pow(0.88, i));
      const start = Math.round((n * gapMs) / 16);
      deltas.forEach((d, i) => { slots[start + i] = d; });
    }
    let k = 0;
    const tick = (): void => {
      if (k >= slots.length) { setTimeout(done, 1200); return; }
      const d = slots[k++];
      if (d) (document.elementFromPoint(at.x, at.y) ?? document.querySelector(".cl-viewport")!).dispatchEvent(new WheelEvent("wheel", { deltaX: axis === "x" ? d : 0, deltaY: axis === "y" ? d : 0, clientX: at.x, clientY: at.y, bubbles: true, cancelable: true }));
      setTimeout(tick, 16);
    };
    tick();
  }), { axis, count, gapMs, at });
}

const api = (page: Page, fn: string, ...args: unknown[]): Promise<unknown> => page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Record<string, (...x: unknown[]) => unknown> }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);

for (const gap of [330, 50]) {
  test(`six horizontal swipes ${gap} ms apart move six windows`, async ({ page }) => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none&docs=1");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    // The Docs view has a window per page (12 stops), so six swipes always have room; Settings now frames fewer than eight.
    await api(page, "flyView", "docs");
    await page.waitForTimeout(1500);
    const before = (await api(page, "canvasLock")) as { index: number };
    // Swipes start over the framed window's pill: chrome, which gives a sideways swipe to the canvas (D374). Every swipe lands
    // on a whole window, so the pill is under the same point after each one.
    const pill = (await page.locator('.cl[data-view="docs"] .ui-window-pill').evaluateAll((els) => els.map((el) => el.getBoundingClientRect()).filter((r) => r.left >= 0 && r.right <= innerWidth && r.width > 0).map((r) => ({ x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) }))))[0]!;
    await swipes(page, "x", 6, gap, pill);
    const after = (await api(page, "canvasLock")) as { index: number };
    expect(after.index - before.index).toBe(6);
  });

  test(`six vertical swipes ${gap} ms apart move six windows down a column`, async ({ page }) => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/?mock=1&proto=clusters&scene=1&theme=mocha&bg=none");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(1200);
    await api(page, "flyView", "console");
    await page.waitForTimeout(1500);
    await page.locator('.cl[data-view="console"] .ui-window .ui-window-body').first().click({ position: { x: 20, y: 40 } });
    for (let i = 0; i < 12; i++) { await page.keyboard.press("Control+Shift+E"); await page.waitForTimeout(150); }
    await page.waitForTimeout(500);
    const col = page.locator('.cl[data-view="console"] .cl-col').first();
    const box = (await col.boundingBox())!;
    const pos = { x: Math.round(box.x + box.width / 2), y: 450 };
    // Window index of the column's scroll position: the window whose top is nearest to it.
    const index = (): Promise<number> => col.evaluate((c) => { const w = [...c.querySelectorAll<HTMLElement>(":scope > .ui-window")]; let best = 0; w.forEach((n, i) => { if (Math.abs(n.offsetTop - c.scrollTop) < Math.abs(w[best]!.offsetTop - c.scrollTop)) best = i; }); return best; });
    await col.evaluate((c) => { c.scrollTop = 0; });
    await page.waitForTimeout(600);
    expect(await index()).toBe(0);
    await swipes(page, "y", 6, gap, pos);
    expect(await index()).toBe(6);
  });
}
