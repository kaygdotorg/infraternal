// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Selecting text that soft-wraps across terminal rows (#426), by finger and by mouse, on a production build against the
 * terminal test double.
 *
 * The owner's real case is a pairing code, and on a phone's 37–39 columns a code or URL longer than the row wraps. The contract:
 * - a word that wraps selects whole, from either of its rows, and copies as one piece;
 * - a drag across a soft wrap copies no newline, because the program never printed one;
 * - a hard newline (the program's own line break) still copies as a newline;
 * - the mouse path (double-click, drag) obeys the same rules, because both paths share one extraction.
 */
import { expect, test } from "playwright/test";
import { CALLOUT, cellCentre, columns, longPress, openTerminal, selected, show, SIZES, THEMES, WINDOW } from "./terminal-select-fixture";

/** A pairing-code-shaped word long enough to wrap on any phone width. */
const TOKEN = "WRAPTOKEN-AAAA-BBBB-CCCC";

/**
 * The screen: a word of `x` that fills the row up to a space, then TOKEN, which starts 8 columns before the right edge and
 * so wraps; below it, two lines the program ended itself.
 */
const screen = (cols: number): string =>
  "\u001b[2J\u001b[H" + ["x".repeat(cols - 9) + " " + TOKEN, "after", "tail"].join("\r\n");

for (const size of SIZES) {
  for (const theme of THEMES) {
    test(`touch: wrapped words select whole and soft wraps copy no newline, ${size.name} ${theme}`, async ({ browser }) => {
      test.setTimeout(240_000);
      const { context, page, cdp } = await openTerminal(browser, theme, size);
      try {
        const cols = await columns(page);
        await show(page, screen(cols), "tail");
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: { x: 40, y: 300 } });
        await expect(page.locator(WINDOW)).toHaveAttribute("data-active", "");

        // Long press on the part of the token on its second row, then on the part on its first row: the whole token each time.
        await longPress(page, cdp!, await cellCentre(page, 3, 1));
        await expect.poll(() => selected(page), "second row part selects the whole token").toBe(TOKEN);
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: { x: 40, y: 300 } });
        await expect.poll(() => selected(page)).toBe("");
        await longPress(page, cdp!, await cellCentre(page, cols - 3, 0));
        await expect.poll(() => selected(page), "first row part selects the whole token").toBe(TOKEN);
        await expect(page.locator(CALLOUT)).toBeVisible();
        await page.locator(`${CALLOUT} button`).tap();
        await expect.poll(() => page.evaluate(() => navigator.clipboard.readText()), "the wrapped token copies intact").toBe(TOKEN);
        await expect.poll(() => selected(page)).toBe("");

        // A drag from the long word, across the wrap, copies no newline.
        await longPress(page, cdp!, await cellCentre(page, 2, 0), await cellCentre(page, cols - 4, 0), await cellCentre(page, 5, 1));
        await expect.poll(() => selected(page), "no newline at a soft wrap").toBe("x".repeat(cols - 9) + " " + TOKEN.slice(0, 8 + 6));
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: { x: 40, y: 300 } });
        await expect.poll(() => selected(page)).toBe("");

        // A hard newline still copies as one.
        await longPress(page, cdp!, await cellCentre(page, 1, 2), await cellCentre(page, 1, 3));
        await expect.poll(() => selected(page), "a hard newline stays a newline").toBe("after\nta");
      } finally {
        await context.close();
      }
    });
  }
}

for (const theme of THEMES) {
  test(`mouse: wrapped words select whole and soft wraps copy no newline, ${theme}`, async ({ browser }) => {
    test.setTimeout(240_000);
    const { context, page } = await openTerminal(browser, theme);
    try {
      const cols = await columns(page);
      await show(page, screen(cols), "tail");
      await page.locator(`${WINDOW} .terminal-host`).click({ position: { x: 40, y: 400 } });

      // Double-click on either row of the token selects it whole.
      const second = await cellCentre(page, 3, 1);
      await page.mouse.dblclick(second.x, second.y);
      await expect.poll(() => selected(page), "double-click on the second row part").toBe(TOKEN);
      const first = await cellCentre(page, cols - 3, 0);
      await page.mouse.click(first.x, first.y + 200);
      await page.mouse.dblclick(first.x, first.y);
      await expect.poll(() => selected(page), "double-click on the first row part").toBe(TOKEN);

      // A drag across the soft wrap copies no newline; across a hard newline it does.
      const drag = async (from: { x: number; y: number }, to: { x: number; y: number }): Promise<void> => {
        await page.mouse.move(from.x, from.y);
        await page.mouse.down();
        await page.mouse.move((from.x + to.x) / 2, (from.y + to.y) / 2, { steps: 6 });
        await page.mouse.move(to.x, to.y, { steps: 6 });
        await page.mouse.up();
      };
      await drag(await cellCentre(page, cols - 8, 0), await cellCentre(page, 5, 1));
      await expect.poll(() => selected(page), "no newline at a soft wrap").toBe(TOKEN.slice(0, 8 + 6));
      await drag(await cellCentre(page, 0, 2), await cellCentre(page, 1, 3));
      await expect.poll(() => selected(page), "a hard newline stays a newline").toBe("after\nta");
    } finally {
      await context.close();
    }
  });
}
