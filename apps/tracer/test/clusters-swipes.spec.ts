/**
 * Quick swipes are never swallowed (#122). In a view with nine windows side by side, six trackpad swipes in
 * two seconds land six windows further, with and without momentum events: a swipe is a run of wheel events that ramps
 * up and, with momentum, tails off for a few hundred milliseconds. The next swipe may start inside that tail.
 *
 * The run is built in the Console with "New window right" (nine full-size columns). The Settings view cannot be used for it any more:
 * it is a grid of rows now, one row for each component, so its horizontal stops are the columns of one row, five at most (D212, #304).
 */
import { expect, test, type Page } from "playwright/test";

/** One stream, like a real pad: each swipe's ramp and tail are laid onto 16 ms slots and a later swipe's start replaces
 * what is left of the earlier tail (the pad reports the finger, not the sum of two gestures). */
async function swipes(page: Page, count: number, gapMs: number, momentum: boolean): Promise<void> {
  await page.evaluate(({ count, gapMs, momentum }) => new Promise<void>((done) => {
    const target = document.querySelector(".cl-viewport")!;
    const slots: number[] = [];
    for (let n = 0; n < count; n++) {
      const deltas: number[] = [];
      for (let i = 1; i <= 8; i++) deltas.push(10 * i);
      if (momentum) for (let i = 0; i < 30; i++) deltas.push(50 * Math.pow(0.88, i));
      const at = Math.round((n * gapMs) / 16);
      deltas.forEach((d, i) => { slots[at + i] = d; });
    }
    let k = 0;
    const tick = (): void => {
      if (k >= slots.length) { setTimeout(done, 900); return; }
      const d = slots[k++];
      if (d) target.dispatchEvent(new WheelEvent("wheel", { deltaX: d, deltaY: 0, clientX: 700, clientY: 450, bubbles: true, cancelable: true }));
      setTimeout(tick, 16);
    };
    tick();
  }), { count, gapMs, momentum });
}

for (const momentum of [false, true]) {
  test(`six swipes in 2 s land six windows further ${momentum ? "with" : "without"} momentum events`, async ({ page }) => {
    test.setTimeout(60_000);
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    const api = (fn: string, ...args: unknown[]): Promise<unknown> => page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Record<string, (...x: unknown[]) => unknown> }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);
    await api("flyView", "console");
    // sleep: the fly-in to the Console must end before a window in it is clicked
    await page.waitForTimeout(1500);
    await page.locator('.cl[data-view="console"] .ui-window .ui-window-body').first().click({ position: { x: 20, y: 40 } });
    // Each "New window right" adds one column; wait for it to be there before the next one, so none is lost to the focus moving.
    const columns = page.locator('.cl[data-view="console"] .cl-col');
    for (let want = (await columns.count()) + 1; want <= 9; want++) {
      await page.keyboard.press("Control+Shift+Enter");
      await expect(columns).toHaveCount(want);
    }
    // The camera follows the newest window; fly away and back so the run is measured from its first column.
    await api("flyView", "settings");
    await api("flyView", "console");
    await expect.poll(async () => ((await api("canvasLock")) as { index: number }).index, { timeout: 5000 }).toBe(0);
    const lock = (await api("canvasLock")) as { on: boolean; index: number; stops: number };
    expect(lock.on).toBe(true);
    expect(lock.stops).toBeGreaterThanOrEqual(8);
    await swipes(page, 6, 330, momentum);
    const after = (await api("canvasLock")) as { index: number };
    expect(after.index - lock.index, "windows moved by six swipes").toBe(6);
  });
}
