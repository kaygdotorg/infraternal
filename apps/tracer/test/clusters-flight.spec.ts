/**
 * How long a view flight takes to settle (within 1 px of where it ends, camera centre and screen position): pointer
 * and touch flights about 320 to 380 ms, key flights jump at once (#427; keyboard-instant.spec.ts checks the first frame). Prints `FLIGHT kind ms`.
 * Measured on a busy machine: median 360 (was 1300) and 210 (was 430); the ceilings below leave room for load.
 */
import { expect, test, type Page } from "playwright/test";

async function settle(page: Page, start: () => Promise<void>): Promise<number> {
  await page.evaluate(() => {
    const w = window as unknown as { __flight: { t0: number; done: number; samples: Array<[number, number, number]> }; __tracerClusters: { camera(): { cx: number; cy: number; z: number } } };
    w.__flight = { t0: performance.now(), done: 0, samples: [] };
    const tick = (): void => {
      const c = w.__tracerClusters.camera();
      w.__flight.samples.push([performance.now() - w.__flight.t0, c.cx, c.z]);
      if (performance.now() - w.__flight.t0 < 3000) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
  await start();
  await page.waitForTimeout(3200);
  return page.evaluate(() => {
    const s = (window as unknown as { __flight: { samples: Array<[number, number, number]> } }).__flight.samples;
    const last = s[s.length - 1]!;
    const sx = Math.abs(last[1]) > 0 ? 1 : 1;
    let at = 0;
    for (let i = 0; i < s.length; i++) if (Math.abs(s[i]![1] - last[1]) * s[i]![2] > sx || Math.abs(s[i]![2] - last[2]) * Math.abs(last[1]) > 1) at = s[i]![0];
    // The first sample at which the camera is in place and stays there; the motion starts a frame after the trigger.
    return Math.round(at);
  });
}

test("view flights settle quickly: pointer about 350 ms, key at once", async ({ page }) => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  const results: Record<string, number> = {};
  // Pointer: the view list.
  await page.locator("#capsule").click(); await page.waitForTimeout(700);
  results.pointer = await settle(page, async () => { await page.locator(".cl-viewlist li, .cl-viewrow").nth(3).click(); });
  await page.waitForTimeout(800);
  // Pill swipe is the same flight (flyView) driven by a gesture end; the capsule's step buttons use it too.
  await page.locator("#capsule").click(); await page.waitForTimeout(700);
  results.pointerBack = await settle(page, async () => { await page.locator(".cl-viewlist li, .cl-viewrow").nth(0).click(); });
  await page.waitForTimeout(800);
  results.key = await settle(page, async () => { await page.keyboard.press("Control+Shift+Digit3"); });
  await page.waitForTimeout(800);
  results.key2 = await settle(page, async () => { await page.keyboard.press("Control+Shift+Digit1"); });
  console.log(`FLIGHT ${JSON.stringify(results)}`);
  expect(results.pointer!).toBeLessThan(550);
  expect(results.pointerBack!).toBeLessThan(550);
  // A key flight has no spring (#427): it ends in the first frame or two. 34 ms is two frames at 60 Hz, which leaves a late sample
  // on a busy machine its slack, and a 190 ms spring (the old key flight) fails it by far.
  expect(results.key!).toBeLessThanOrEqual(34);
  expect(results.key2!).toBeLessThanOrEqual(34);
});
