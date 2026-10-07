/** Regresses document scrolling with iPhone touch input against the real Ghostty WASM. */
import { devices, expect, test } from "playwright/test";

test.use({ ...devices["iPhone 15"], browserName: "chromium" });

test("touch scroll belongs to the terminal and keeps the mobile controls fixed", async ({ page }, testInfo) => {
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  await page.goto("/?mock=1");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected())).toBe(true);
  const injected = await page.context().request.post("/__mock/unicode-case", { data: { mode: "utf8-split" } });
  expect(injected.ok()).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.scrollbackRows ?? 0)).toBeGreaterThan(100);
  const card = page.locator("#terminal-host");
  const controls = await page.locator(".top").boundingBox();
  const tray = await page.locator(".keybar").boundingBox();
  await page.screenshot({ path: testInfo.outputPath("mobile-before.png") });
  const cdp = await page.context().newCDPSession(page);
  let touchTime = Date.now() / 1000;
  await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", timestamp: touchTime, touchPoints: [{ x: 180, y: 250 }] });
  for (let y = 270; y <= 490; y += 20) {
    await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", timestamp: touchTime += 0.016, touchPoints: [{ x: 180, y }] });
    await page.waitForTimeout(16);
  }
  const dragged = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.viewportY ?? 0);
  expect(dragged).toBeGreaterThan(0);
  await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", timestamp: touchTime + 0.016, touchPoints: [] });
  await expect(card).toHaveAttribute("data-scrolled", "true");
  await page.waitForTimeout(800);
  const flung = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.viewportY ?? 0);
  expect(flung).toBeGreaterThan(dragged);
  expect(await page.evaluate(() => document.scrollingElement?.scrollTop)).toBe(0);
  expect(await page.locator(".top").boundingBox()).toEqual(controls);
  expect(await page.locator(".keybar").boundingBox()).toEqual(tray);
  const path = testInfo.outputPath("mobile-after.png");
  await page.screenshot({ path });
  await testInfo.attach("mobile-after", { path, contentType: "image/png" });
  const font = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.fontSize ?? 0);
  await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: 120, y: 350 }, { x: 220, y: 350 }] });
  await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: 70, y: 350 }, { x: 270, y: 350 }] });
  await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.fontSize ?? 0)).toBeGreaterThan(font);
  expect(await page.evaluate(() => window.visualViewport?.scale)).toBe(1);

  // Real Ghostty canvas overflow at the existing minimum column count models a
  // future fixed-width remote grid; a horizontal gesture must pan without scrollback.
  await card.evaluate((host) => { host.style.width = "180px"; });
  await expect.poll(() => card.evaluate((host) => host.scrollWidth > host.clientWidth)).toBe(true);
  const beforePan = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.viewportY ?? 0);
  await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: 160, y: 350 }] });
  await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: 70, y: 355 }] });
  await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  expect(await card.evaluate((host) => host.scrollLeft)).toBeGreaterThan(0);
  expect(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.viewportY)).toBe(beforePan);
  expect(await page.evaluate(() => document.scrollingElement?.scrollTop)).toBe(0);
  console.log(`MOBILE_SCROLL rows=368 drag=${dragged} momentum=${flung} font=${font}->${await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.fontSize)} pan=${await card.evaluate((host) => host.scrollLeft)} document=0 controls=fixed`);
});
