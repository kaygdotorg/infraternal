/**
 * Phone row text is the 15 px body size (D373, refining D372; #345).
 *
 * On a phone the palette's result rows and the sidebar's names read the body size (0.9375 rem, 15 px at the phone's 16 px
 * root), not the 13 px label size; only true labels and captions stay 13 px, so TASTE's "phone text 15-16 px or larger" holds.
 * This spec opens the mock canvas at the two phone review sizes, opens the palette and the sidebar, and reads the computed
 * font sizes from the real production build: row names 15 px, the small hint beside a row 13 px (at a 16 px root, the unit D372 uses). It also checks that a
 * desktop keeps its 13 px row text and 12 px hint, so the touch rule cannot leak out of the touch block.
 */
import { expect, test, type Page } from "playwright/test";

/** The two phone sizes of CLAUDE.md (touch) and the desktop size (fine pointer). */
const SIZES = [
  { name: "393x852", width: 393, height: 852, touch: true },
  { name: "375x667", width: 375, height: 667, touch: true },
  { name: "1440x900", width: 1440, height: 900, touch: false },
] as const;

/** Opens the mock canvas in the ink theme and waits for it to be ready. */
async function openCanvas(page: Page): Promise<void> {
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
}

/** The computed font size of the first element matching `selector`, in px at a 16 px root (the unit D372 names sizes in: a desktop root is 17.6 px). */
async function fontPx(page: Page, selector: string): Promise<number> {
  const target = page.locator(selector).first();
  await expect(target, `${selector} is on screen`).toBeVisible();
  return target.evaluate((el) => parseFloat(getComputedStyle(el).fontSize) / (parseFloat(getComputedStyle(document.documentElement).fontSize) / 16));
}

for (const size of SIZES) {
  test.describe(size.name, () => {
    test.use({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, ...(size.touch ? { hasTouch: true, isMobile: true } : {}) });

    test("palette result rows", async ({ page }) => {
      await openCanvas(page);
      await page.keyboard.press("Meta+k");
      if (!(await page.locator("#palette").isVisible())) await page.keyboard.press("Control+Shift+K");
      await expect(page.locator("#palette")).toBeVisible();
      expect(await fontPx(page, "#palette-results .result-label"), "a result name").toBeCloseTo(size.touch ? 15 : 13, 1);
      expect(await fontPx(page, "#palette-results .result-hint"), "the hint beside it").toBeCloseTo(size.touch ? 13 : 12, 1);
    });

    test("sidebar names", async ({ page }) => {
      await openCanvas(page);
      await page.locator("#sidebar-toggle").click();
      await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1);
      expect(await fontPx(page, "#tree .bm-leaf .bm-label"), "a session name").toBeCloseTo(size.touch ? 15 : 13, 1);
      expect(await fontPx(page, "#tree .bm-subhead .bm-label"), "a host heading is a caption").toBeCloseTo(size.touch ? 13 : 12, 1);
    });
  });
}
