/** Mock-browser camera-selection regression when a remote edit removes the current shared view (#243). */
import { expect, test } from "playwright/test";
import { openReviewProduct } from "./layout-review-fixture";

test("review: removing the current shared view leaves camera selection on a surviving view", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openReviewProduct(page);
  await page.evaluate(() => (window as Window & { __tracerLayoutReviewDouble?: { removeConsole(): number } }).__tracerLayoutReviewDouble!.removeConsole());
  await expect(page.locator('.cl[data-view="console"]')).toHaveCount(0);
  const selection = await page.evaluate(() => {
    const api = (window as Window & { __tracerLayoutReviewDouble?: { currentView(): string; viewIds(): string[] } }).__tracerLayoutReviewDouble!;
    return { current: api.currentView(), views: api.viewIds() };
  });
  expect(selection.views).toContain(selection.current);
});
