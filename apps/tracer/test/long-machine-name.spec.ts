// SPDX-License-Identifier: AGPL-3.0-only
/**
 * A long machine name never breaks the top capsule or the shortcuts panel that grows out of it, on desktop and phone widths.
 *
 * The test double's "this host" is short by default (`double-hostname.ts`). A real machine can be named like
 * `infraternal-dev-01-compute01` (28 characters): the capsule then measures 573.7 px, wider than the panel's 560 px, and the
 * panel used to shrink on opening. Here the double is given that name and the panel must be at least as wide as its capsule,
 * and both must stay inside the viewport.
 */
import { expect, test, type Page } from "playwright/test";

const LONG_NAME = "infraternal-dev-01-compute01";

async function openWithName(page: Page, width: number, height: number): Promise<void> {
  await page.setViewportSize({ width, height });
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/hostname", { data: { name: LONG_NAME } });
  await page.goto("/?mock=1&proto=windows&bg=none&fixture=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect(page.locator("#capsule")).toBeVisible();
}

for (const [width, height] of [[1440, 900], [393, 852]] as const) {
  test(`a ${LONG_NAME.length}-character machine name: the capsule and the shortcuts panel fit at ${width}x${height}`, async ({ page }) => {
    await openWithName(page, width, height);
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    const pill = (await page.locator("#capsule").boundingBox())!;
    expect(pill.x, "the capsule starts inside the viewport").toBeGreaterThanOrEqual(-0.5);
    expect(pill.x + pill.width, "the capsule ends inside the viewport").toBeLessThanOrEqual(width + 0.5);
    await page.keyboard.press("?");
    const panel = page.locator(".ui-shortcuts");
    await expect(panel).toBeVisible();
    await expect.poll(() => panel.evaluate((node) => getComputedStyle(node).clipPath)).toBe("none");
    const box = (await panel.boundingBox())!;
    expect(box.width, "the panel is never narrower than the capsule it grows out of").toBeGreaterThanOrEqual(pill.width - 0.5);
    expect(box.x, "the panel starts inside the viewport").toBeGreaterThanOrEqual(-0.5);
    expect(box.x + box.width, "the panel ends inside the viewport").toBeLessThanOrEqual(width + 0.5);
  });
}
