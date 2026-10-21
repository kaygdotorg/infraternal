/** Mock-browser viewport-width regression for account-layout settlement (#243). */
import { expect, test } from "playwright/test";
import { enableReviewCoarsePointer, openReviewProduct, openReviewSettings } from "./layout-review-fixture";

test("review: a phone-width reflow after initial settlement keeps Console clear of Settings", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await enableReviewCoarsePointer(context);
  const page = await context.newPage();
  try {
    await openReviewProduct(page, true);
    await openReviewSettings(page);
    await page.setViewportSize({ width: 400, height: 852 });
    await page.evaluate(() => (window as Window & { __setReviewCoarse?: (coarse: boolean) => void }).__setReviewCoarse?.(true));
    await expect.poll(() => page.evaluate(() => {
      const consoleBox = document.querySelector<HTMLElement>('.cl[data-view="console"]');
      const settingsBox = document.querySelector<HTMLElement>('.cl[data-view="settings"]');
      if (!consoleBox || !settingsBox) return false;
      const a = consoleBox.getBoundingClientRect(), b = settingsBox.getBoundingClientRect();
      return a.left < b.right && b.left < a.right && a.top < b.bottom && b.top < a.bottom;
    })).toBe(false);
  } finally {
    await context.close();
  }
});
