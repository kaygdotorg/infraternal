/** Mock-browser revision-gap regression while Settings is the current canvas view (#243). */
import { expect, test } from "playwright/test";
import { openReviewProduct, openReviewSettings } from "./layout-review-fixture";

test("review: the product canvas recovers a missing layout revision while Settings is open", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openReviewProduct(page);
  await openReviewSettings(page);
  const revisions = await page.evaluate(() => {
    const api = (window as Window & { __tracerLayoutReviewDouble?: { revisions(): { server: number; client: number }; skipRevision(): number } }).__tracerLayoutReviewDouble!;
    api.skipRevision();
    return api.revisions();
  });
  expect(revisions.client).toBe(revisions.server);
});
