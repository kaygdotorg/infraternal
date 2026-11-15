// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The standalone docs header and search dialog at every width from 320 to 1600 px, on a production build (#339).
 * The header's capsule and links pill never overlap and the search button stays visible and tappable; the page never
 * scrolls sideways; the open search dialog sits fully inside the window, centred, with the input at least 16 px
 * (iOS zooms the page on focus below that, which shifted the dialog off-screen).
 */
import { mkdirSync } from "node:fs";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** Where this spec writes its screenshots (the evidence folder). */
const OUT = tracerEvidencePath("docs-site-layout");
/** Window widths in px: the smallest phone, common phones and tablets, the breakpoints' neighbours, and a wide desktop. */
const WIDTHS = [320, 360, 375, 393, 430, 600, 641, 700, 768, 800, 900, 960, 1024, 1100, 1200, 1279, 1280, 1600];

test("the docs header and search dialog fit at every width", async ({ browser }) => {
  mkdirSync(OUT, { recursive: true });
  for (const width of WIDTHS) {
    const context = await browser.newContext({ viewport: { width, height: 800 }, deviceScaleFactor: 1 });
    const page = await context.newPage();
    try {
      await page.goto("/docs/reference/keys/");
      const box = async (selector: string) => (await page.locator(selector).first().boundingBox())!;
      const visible = async (selector: string) => page.locator(selector).first().isVisible();
      const search = await box(".bar-kbd");
      expect(search.x, `${width}: search button inside window`).toBeGreaterThanOrEqual(0);
      expect(search.x + search.width, `${width}: search button inside window`).toBeLessThanOrEqual(width + 0.5);
      const capsule = await box(".bar-capsule");
      const brand = await box(".bar-brand");
      const apart = (a: { x: number; y: number; width: number; height: number }, b: typeof a) => a.x + a.width <= b.x + 0.5 || b.x + b.width <= a.x + 0.5 || a.y + a.height <= b.y + 0.5 || b.y + b.height <= a.y + 0.5;
      expect(apart(capsule, brand), `${width}: capsule clear of the name`).toBe(true);
      if (await visible(".bar-links")) expect(apart(capsule, await box(".bar-links")), `${width}: capsule clear of the links`).toBe(true);
      else expect(await visible(".bar-menu"), `${width}: links fold into the menu`).toBe(true);
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `${width}: no sideways scroll`).toBe(true);
      await page.locator(".bar-kbd").click();
      const dialog = page.locator("dialog.search");
      await expect(dialog).toBeVisible();
      const d = (await dialog.boundingBox())!;
      expect(d.x, `${width}: dialog left edge`).toBeGreaterThanOrEqual(0);
      expect(d.x + d.width, `${width}: dialog right edge`).toBeLessThanOrEqual(width + 0.5);
      expect(Math.abs(d.x - (width - d.x - d.width)), `${width}: dialog centred`).toBeLessThanOrEqual(1);
      expect(await page.locator(".search-field input").evaluate((el) => parseFloat(getComputedStyle(el).fontSize)), `${width}: input font`).toBeGreaterThanOrEqual(16);
      if ([375, 800, 1280].includes(width)) await page.screenshot({ path: `${OUT}/${width}.png` });
    } finally { await context.close(); }
  }
});
