/** Regresses reconnect while received raw output waits behind a render callback. */
import { expect, test } from "playwright/test";

test("owned output drains while detached before the next Attach", async ({ page }) => {
  const context = page.context();
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected())).toBe(true);
  await page.evaluate(() => {
    const real = window.requestAnimationFrame.bind(window);
    const held: FrameRequestCallback[] = [];
    // Hold actual Ghostty render/write callbacks without replacing the renderer.
    window.requestAnimationFrame = (callback) => { held.push(callback); return -held.length; };
    (window as Window & { __releaseDetachedFrames?: () => number }).__releaseDetachedFrames = () => {
      window.requestAnimationFrame = real;
      for (const callback of held) real(callback);
      return held.length;
    };
  });
  const response = await context.request.post("/__mock/unicode-case", { data: { mode: "utf8-split" } });
  expect(response.status()).toBe(200);
  const fixture = await response.json() as { output_sequence: string };
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.receivedSequence)).toBe(fixture.output_sequence);
  expect(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence)).not.toBe(fixture.output_sequence);
  await context.setOffline(true);
  await page.evaluate(() => window.__tracerTestDouble?.dropConnection());
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected())).toBe(false);
  await expect(page.locator("#connection-status")).toContainText("Reconnecting");
  const callbacks = await page.evaluate(() => (window as Window & { __releaseDetachedFrames?: () => number }).__releaseDetachedFrames?.());
  expect(callbacks).toBeGreaterThan(0);
  await context.setOffline(false);
  // Already-owned bytes must complete before Resume declares the painted cursor.
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence), { timeout: 10_000 }).toBe(fixture.output_sequence);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected())).toBe(true);
  expect(await page.evaluate(() => window.__tracerTestDouble?.graphemeText())).toContain("👩🏽‍💻");
  await page.keyboard.press("x");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence)).toBe(String(BigInt(fixture.output_sequence) + 1n));
});
