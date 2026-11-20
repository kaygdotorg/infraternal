// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The palette's ranking rule on a production build (#442): a docs page whose title is, or starts with, what was typed comes
 * before a Settings row that only mentions the words, so Enter opens the page the person named. A query that no title
 * starts with keeps the plain order, and a Settings row still comes first when the query is the setting's own name.
 * Runs at 1440x900 and on a phone at 393x852. The test double adds the docs only with `?docs=1`.
 */
import { expect, test, type Page } from "playwright/test";

/** The two viewports the spec runs at: a desktop and a phone with touch. */
const SIZES = [
  { name: "desktop", width: 1440, height: 900, touch: false },
  { name: "phone", width: 393, height: 852, touch: true },
] as const;

/** Opens the palette with the keyboard and types `query` into it. */
async function openPalette(page: Page, query: string): Promise<void> {
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
  await page.keyboard.type(query);
}

/** The group headings and rows of the open palette, in order, as "group" and "label" strings. */
const listed = (page: Page) => page.locator("#palette-results .group-label, #palette-results .result .result-label").evaluateAll((nodes) => nodes.map((node) => `${node.classList.contains("group-label") ? "group" : "row"}:${node.textContent}`));

/** The index in `order` of the group heading a row is listed under, or -1 when the row is not listed. */
function groupOfRow(order: string[], row: string): number {
  for (let at = order.indexOf(row); at >= 0; at--) if (order[at]!.startsWith("group:")) return at;
  return -1;
}

for (const size of SIZES) {
  test.describe(size.name, () => {
    test.use({ viewport: { width: size.width, height: size.height }, hasTouch: size.touch, isMobile: size.touch });

    test("a docs page named by its title is listed before a Settings row that mentions it, and Enter opens the page", async ({ page }) => {
      await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=plain&docs=1");
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await expect.poll(() => page.locator('section.cl[data-view="docs"]').count(), { timeout: 15_000 }).toBeGreaterThan(0);
      await openPalette(page, "infraternal multiplexer");
      // The Settings wording loads on demand and the palette refreshes when it arrives: wait for the row that competes with the page.
      await expect(page.locator("#palette-results .result .result-label", { hasText: /^Offer To Switch$/ })).toHaveCount(1);
      const rows = page.locator("#palette-results .result");
      await expect(rows.first()).toContainText("The Infraternal Multiplexer");
      const order = await listed(page);
      expect(order[0], "the Docs group leads").toBe("group:Docs");
      const offerGroup = groupOfRow(order, "row:Offer To Switch");
      expect(offerGroup, "the setting is listed under a group").toBeGreaterThan(0);
      expect(order.indexOf("group:Docs"), "Docs is listed before the group of the setting that mentions the page").toBeLessThan(offerGroup);
      // The Settings row that mentions the page is still offered, just later.
      await expect(page.locator("#palette-results .result .result-label", { hasText: /^Offer To Switch$/ })).toHaveCount(1);
      await page.keyboard.press("Enter");
      await expect(page.locator('.ui-window[data-window-id="d-terminal/multiplexer"]')).toHaveAttribute("data-active", "");
    });

    test("a query that is not the start of any title keeps the plain order", async ({ page }) => {
      await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=plain&docs=1");
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
      await expect.poll(() => page.locator('section.cl[data-view="docs"]').count(), { timeout: 15_000 }).toBeGreaterThan(0);
      // "switch" begins no page title; it is inside the words of a setting and of the page text.
      await openPalette(page, "offer to switch");
      // Two rows carry that name once everything has loaded: the setting, and the docs heading of the same name (D317).
      await expect(page.locator("#palette-results .result .result-label", { hasText: /^Offer To Switch$/ })).toHaveCount(2);
      const order = await listed(page);
      const offerGroup = groupOfRow(order, "row:Offer To Switch");
      const docs = order.indexOf("group:Docs");
      expect(offerGroup, "the setting is listed under a group").toBeGreaterThanOrEqual(0);
      if (docs >= 0) expect(offerGroup, "the setting keeps its place ahead of Docs").toBeLessThan(docs);
    });
  });
}
