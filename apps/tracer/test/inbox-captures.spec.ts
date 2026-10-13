/**
 * Review captures of the generic inbox card (D234, TASTE "The inbox is one generic card"): one item collapsed and
 * expanded, and three items with one expanded, on a phone and a desktop, in both themes. Screenshots land in the
 * external job evidence directory; assertions only prove that the states were reached.
 */
import { tracerEvidencePath } from "./evidence-path";
import { resolve } from "node:path";
import { expect, test } from "playwright/test";

const OUT = tracerEvidencePath("inbox-generic");

for (const [name, viewport, scale] of [["phone", { width: 393, height: 852 }, 3], ["desktop", { width: 1440, height: 900 }, 2]] as const) {
  for (const theme of ["ink", "paper"]) {
    test(`three items, one expanded (${name}, ${theme})`, async ({ browser }) => {
      const context = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });
      const page = await context.newPage();
      await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme}&ca=locked&inbox=3`);
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await page.locator(".ui-toast").getByRole("button", { name: "Dismiss" }).click({ timeout: 8000 });
      await page.locator("#sidebar-toggle").click();
      const card = page.locator(".ui-inbox:not([hidden])");
      await expect(card.locator(".ui-inbox-row")).toHaveCount(3);
      await expect(card.locator(".ui-inbox-count")).toHaveText("3");
      await page.waitForTimeout(500);
      await page.screenshot({ path: resolve(OUT, `three-collapsed-${name}-${theme}.png`) });
      await card.getByRole("button", { name: "Approve build-02" }).click();
      await page.waitForTimeout(400);
      await expect(card.locator('[aria-expanded="true"]')).toHaveCount(1);
      await page.screenshot({ path: resolve(OUT, `three-expanded-${name}-${theme}.png`) });
      // Opening another line closes the first.
      await card.getByRole("button", { name: "Update available" }).click();
      await expect(card.locator('[aria-expanded="true"]')).toHaveCount(1);
      await context.close();
    });
  }
}
