/**
 * Every floating card follows the glass level the person picked (D338, D380; #490). The three built-in looks set the cards' fill
 * through `--look-tint` (Solid 100%, Tinted 75%, Frosted 50%), so the confirmation card's fill opacity must equal it, in both
 * themes and on desktop and phone sizes. At Solid that means opaque: the card paints no see-through fill. (The palette is thicker
 * than the other cards by design, so it is not held to the tint.)
 * This reads computed styles, so it holds whatever the terminal behind shows; the pixel checks for the removal card are in
 * `host-removal-confirm.spec.ts`. The level is chosen the way a person chooses it (see `openDenseConsole`), never by writing
 * `data-card` by hand, which does not select a level.
 */
import { expect, type Page, test } from "playwright/test";
import { LEVELS, openDenseConsole, SIZES, startRemovalFromPalette, THEMES } from "./removal-fixture";

/** The fill opacity each look must give a floating card (the built-in looks' tint, D338). */
const TINT: Record<(typeof LEVELS)[number], number> = { solid: 1, tinted: 0.75, frosted: 0.5 };

/** The opacity (0 to 1) of the background colour of the first element matching `selector`. */
async function fillAlpha(page: Page, selector: string): Promise<number> {
  return await page.evaluate((sel) => {
    const colour = getComputedStyle(document.querySelector(sel)!).backgroundColor;
    const slash = /\/\s*([\d.]+%?)\s*\)/.exec(colour)?.[1];
    if (slash === undefined) return 1;
    return slash.endsWith("%") ? Number(slash.slice(0, -1)) / 100 : Number(slash);
  }, selector);
}

for (const size of SIZES.filter((s) => s.id !== "small-phone")) for (const theme of THEMES) for (const level of LEVELS) test(`floating cards follow the ${level} look ${size.id} ${theme}`, async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 1, hasTouch: size.touch, isMobile: size.touch });
  const page = await context.newPage();
  try {
    await openDenseConsole(page, theme, level);
    await startRemovalFromPalette(page);
    await expect(page.locator(".ui-confirm-tip[data-open='true']")).toBeVisible();
    // sleep: the card's open animation must finish so the computed fill is the resting one
    await page.waitForTimeout(500);
    expect(await fillAlpha(page, ".ui-confirm-tip"), `the confirmation card's fill at ${level}`).toBeCloseTo(TINT[level], 2);
  } finally { await context.close(); }
});
