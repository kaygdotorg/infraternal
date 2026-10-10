/**
 * A window in the zoomed-out hover card names itself and never repeats the view's heading (#141). The card lists the
 * five windows used most recently (#121), so its names come from each window's session, not from "user@host".
 */
import { expect, test } from "playwright/test";

test("hover list rows name each window, not the heading", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.evaluate(() => (window as unknown as { __tracerClusters: { overview(): void } }).__tracerClusters.overview());
  await page.waitForTimeout(1800);
  for (const view of ["settings", "console"] as const) {
    await page.locator(`.cl[data-view="${view}"] .cl-label`).hover();
    await expect(page.locator(".cl-summary[data-open=\"true\"]")).toBeVisible();
    const heading = (await page.locator(".cl-summary-name").textContent())!;
    const keys = await page.locator(".cl-summary-k, .cl-summary-pick .cl-viewrow-name").allTextContents();
    expect(keys.length).toBeGreaterThan(1);
    for (const k of keys) { expect(k.toLowerCase()).not.toBe(heading.toLowerCase()); expect(k).not.toBe("settings"); }
    expect(new Set(keys).size, "rows are distinct").toBe(keys.length);
    await page.mouse.move(5, 5);
    await page.waitForTimeout(400);
  }
});
