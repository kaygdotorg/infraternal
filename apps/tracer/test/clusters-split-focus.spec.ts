/**
 * A split lands you in the new window (TASTE), on a phone and on a desktop, ten times each way: after the split
 * settles the camera is at rest, the new window is the active one, it is fully inside the canvas area, the screen has
 * not been scrolled sideways, and (phones) no keyboard was asked for. Also: closing a window never makes a neighbour
 * overshoot its final place.
 */
import { expect, test, type Page } from "playwright/test";

async function boot(page: Page): Promise<void> {
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
}

async function state(page: Page): Promise<{ active: string | null; rect: [number, number, number, number] | null; view: [number, number, number, number]; screenScroll: number; moving: boolean; windows: number }> {
  return page.evaluate(() => {
    const v = document.querySelector<HTMLElement>(".cl-viewport")!.getBoundingClientRect();
    const a = document.querySelector<HTMLElement>(".cl[data-view=\"console\"] .ui-window[data-active]");
    const r = a?.getBoundingClientRect();
    return {
      active: a?.dataset.windowId ?? null,
      rect: r ? [r.left, r.top, r.right, r.bottom] as [number, number, number, number] : null,
      view: [v.left, v.top, v.right, v.bottom] as [number, number, number, number],
      screenScroll: document.querySelector("#terminal-screen")!.scrollLeft,
      moving: (document.querySelector(".cl-world") as HTMLElement).style.willChange === "transform",
      windows: document.querySelectorAll('.cl[data-view="console"] .ui-window').length,
    };
  });
}

async function splitTen(page: Page, label: string, phone: boolean): Promise<void> {
  await boot(page);
  // Start from a window the person tapped.
  await page.locator('.cl[data-view="console"] .ui-window .ui-window-body').first().click({ position: { x: 20, y: 40 } });
  await page.waitForTimeout(400);
  for (let i = 0; i < 10; i++) {
    // Right is a new window beside (D212): split right needs a window with its column to itself, and the alternating
    // splits down stack the active window. Splits divide in clusters-window-actions.spec.ts.
    const direction = i % 2 === 0 ? "right" : "down";
    const action = i % 2 === 0 ? "canvas:new:right" : "canvas:split:down";
    const before = await state(page);
    await page.evaluate((a) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: a, source: "pointer" } })), action);
    // Settled: the active window's box has not moved for 300 ms (a slow host takes longer than any fixed wait).
    let s = await state(page);
    for (let k = 0; k < 40; k++) {
      await page.waitForTimeout(300);
      const next = await state(page);
      const same = next.active === s.active && next.windows === s.windows && next.rect && s.rect && next.rect.every((v, j) => Math.abs(v - s.rect![j]!) < 0.01);
      s = next;
      if (same && k >= 3) break;
    }
    const where = `${label} split ${i + 1} (${direction})`;
    expect(s.windows, `${where}: a window was added`).toBe(before.windows + 1);
    expect(s.active, `${where}: the new window is the active one`).not.toBe(before.active);
    expect(s.moving, `${where}: the camera is at rest`).toBe(false);
    expect(s.rect, `${where}: the new window has a box`).not.toBeNull();
    const [l, t, r, b] = s.rect!;
    expect(l, `${where}: left edge in view`).toBeGreaterThanOrEqual(s.view[0] - 1);
    expect(r, `${where}: right edge in view`).toBeLessThanOrEqual(s.view[2] + 1);
    expect(t, `${where}: top edge in view`).toBeGreaterThanOrEqual(s.view[1] - 1);
    expect(b, `${where}: bottom edge in view`).toBeLessThanOrEqual(s.view[3] + 1);
    // Nothing is left mid-split: no gap held open, no leftover transform on a window or a column.
    const leftovers = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .cl-col, .cl[data-view="console"] .ui-window')].filter((n) => n.hasAttribute("data-split") || n.hasAttribute("data-goo") || n.style.transform !== "").map((n) => n.className));
    expect(leftovers, `${where}: nothing left mid-split`).toEqual([]);
    expect(s.screenScroll, `${where}: the screen did not scroll`).toBe(0);
    if (phone) expect(await page.evaluate(() => document.activeElement?.tagName === "TEXTAREA" && matchMedia("(pointer: coarse)").matches), `${where}: no keyboard`).toBe(false);
  }
}

test("phone 393x852: a split lands you in the new window, ten times", async ({ browser }) => {
  test.setTimeout(240_000);
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });
  await splitTen(await context.newPage(), "393x852", true);
});

test("phone 440x956: a split lands you in the new window, ten times", async ({ browser }) => {
  test.setTimeout(240_000);
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 440, height: 956 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });
  await splitTen(await context.newPage(), "440x956", true);
});

test("desktop 1440x900: a split lands you in the new window, ten times", async ({ browser }) => {
  test.setTimeout(240_000);
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  await splitTen(await context.newPage(), "1440x900", false);
});

/** After a close the neighbours glide into the gap and never pass their final place (no bounce), ten times, phone and desktop. */
async function closeTen(page: Page, label: string): Promise<void> {
  await boot(page);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { setCanvasLock(on: boolean): void } }).__tracerClusters.setCanvasLock(false));
  for (let i = 0; i < 10; i++) {
    // Make sure there are windows to the right of the one that closes: open one more beside the first when few remain.
    const n = await page.locator('.cl[data-view="console"] .cl-col').count();
    if (n < 3) {
      await page.locator('.cl[data-view="console"] .ui-window .ui-window-body').first().click({ position: { x: 20, y: 40 }, force: true });
      for (let k = 0; k < 3; k++) { await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:split:right", source: "pointer" } }))); await page.waitForTimeout(1800); }
    }
    await page.evaluate(() => (window as unknown as { __tracerClusters: { setCanvasLock(on: boolean): void } }).__tracerClusters.setCanvasLock(false));
    await page.waitForTimeout(500);
    const samples = await page.evaluate(() => new Promise<{ ids: string[]; frames: number[][] }>((done) => {
      const wins = [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window')];
      const first = wins[0]!;
      const others = wins.slice(1);
      const frames: number[][] = [];
      const t0 = performance.now();
      (first.querySelector('[data-action="close"]') as HTMLElement).click();
      const tick = (): void => {
        frames.push(others.map((w) => w.isConnected ? w.getBoundingClientRect().left : NaN));
        if (performance.now() - t0 < 1800) requestAnimationFrame(tick); else done({ ids: others.map((w) => w.dataset.windowId!), frames });
      };
      requestAnimationFrame(tick);
    }));
    const last = samples.frames[samples.frames.length - 1]!;
    samples.ids.forEach((id, j) => {
      const xs = samples.frames.map((f) => f[j]!).filter((x) => !Number.isNaN(x));
      const start = xs[0]!, end = last[j]!;
      if (Math.abs(end - start) < 2) return;
      const dir = Math.sign(end - start);
      const passed = Math.max(...xs.map((x) => (x - end) * dir));
      expect(passed, `${label} close ${i + 1}: ${id} never passes its final x (${start.toFixed(0)} -> ${end.toFixed(0)})`).toBeLessThanOrEqual(0.5);
    });
  }
}

test("phone: closing a window never makes a neighbour overshoot, ten times", async ({ browser }) => {
  test.setTimeout(240_000);
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });
  await closeTen(await context.newPage(), "393x852");
});

test("desktop: closing a window never makes a neighbour overshoot, ten times", async ({ browser }) => {
  test.setTimeout(240_000);
  const context = await browser.newContext({ baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  await closeTen(await context.newPage(), "1440x900");
});
