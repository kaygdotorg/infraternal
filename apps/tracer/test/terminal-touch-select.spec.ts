// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Selecting and copying terminal text with a finger (#426), on a production build against the terminal test double, in a touch
 * context at both phone sizes (393×852 and 375×667) in ink and paper.
 *
 * The owner could not select a pairing code on a phone: the terminal is a canvas, one finger is always scrollback (D159), and the
 * canvas's own selection listens to the mouse only. The contract these cases pin:
 * - a long press selects the word under the finger, and dragging then extends the selection by cell;
 * - a double tap selects the word too (a pairing code is one word);
 * - a Copy callout appears by the selection, inside the window and never over its title pill, sized to its content;
 * - tapping Copy puts exactly the selected text on the clipboard and answers on the row itself ("Copied");
 * - a plain swipe still scrolls the scrollback and never selects;
 * - a tap elsewhere clears the selection and the callout;
 * - a second finger landing after the hold keeps the selection and its callout;
 * - a long press in the host's padding, outside the canvas, selects nothing.
 * Wrapped words and the mouse path are in `terminal-selection-wrap.spec.ts`.
 *
 * Captures go to the external evidence directory. Playwright WebKit is not iOS Safari: the real-device check is on the issue.
 */
import { mkdirSync } from "node:fs";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { boxOf, CALLOUT, cellCentre, hold, longPress, openTerminal, selected, show, SIZES, THEMES, touch, WINDOW } from "./terminal-select-fixture";

/** Where this spec writes its captures (the external evidence directory). */
const OUT = tracerEvidencePath("terminal-touch-select");
/** The pairing-code-shaped word the owner could not select. */
const CODE = "ABCD-EFGH-1234";
/** The screen the cases select from: row 0 holds the pairing code, row 1 the sentence the drag covers. */
const SCREEN = "\u001b[2J\u001b[H" + [`pair: ${CODE} now`, "second line of output", "third"].join("\r\n");
/** Where a tap lands on empty terminal, below the text. */
const EMPTY = { x: 40, y: 300 };

for (const size of SIZES) {
  for (const theme of THEMES) {
    test(`touch selection and copy, ${size.name} ${theme}`, async ({ browser }) => {
      test.setTimeout(240_000);
      mkdirSync(OUT, { recursive: true });
      const { context, page, cdp } = await openTerminal(browser, theme, size);
      try {
        await show(page, SCREEN, "third");
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: { x: 40, y: 200 } });
        await expect(page.locator(WINDOW)).toHaveAttribute("data-active", "");

        // 1. Long press on the pairing code selects exactly that word.
        const onCode = await cellCentre(page, 10, 0);
        await longPress(page, cdp!, onCode);
        await expect.poll(() => selected(page), "long press selects the word").toBe(CODE);
        await expect(page.locator(CALLOUT)).toBeVisible();
        await page.screenshot({ path: `${OUT}/${size.name}-${theme}-word-callout.png` });

        // 2. Copy puts exactly the selection on the clipboard.
        await page.locator(`${CALLOUT} button`, { hasText: "Copy" }).tap();
        await expect.poll(() => page.evaluate(() => navigator.clipboard.readText()), "Copy fills the clipboard").toBe(CODE);

        // 3. A tap elsewhere clears the selection and the callout.
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: EMPTY });
        await expect.poll(() => selected(page)).toBe("");
        await expect(page.locator(CALLOUT)).toHaveCount(0);

        // 4. Long press, then drag over the second row: the selection extends by cell and spans the word onwards.
        const start = await cellCentre(page, 2, 1);
        await longPress(page, cdp!, start, await cellCentre(page, 9, 1), await cellCentre(page, 20, 1));
        await expect.poll(() => selected(page), "long press then drag extends").toBe("second line of output");
        await expect(page.locator(CALLOUT)).toBeVisible();
        await page.screenshot({ path: `${OUT}/${size.name}-${theme}-drag-callout.png` });
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: EMPTY });
        await expect.poll(() => selected(page)).toBe("");

        // 5. A double tap selects the word.
        await page.touchscreen.tap(onCode.x, onCode.y);
        await page.touchscreen.tap(onCode.x, onCode.y);
        await expect.poll(() => selected(page), "double tap selects the word").toBe(CODE);
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: EMPTY });
        await expect.poll(() => selected(page)).toBe("");

        // 6. A plain swipe still scrolls the scrollback and selects nothing.
        const lines = Array.from({ length: 120 }, (_, i) => `scroll line ${i}`).join("\r\n") + "\r\n";
        await page.evaluate((text) => window.__tracerTestDouble!.writeText(text), lines);
        await expect.poll(() => page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()?.scrollbackRows ?? 0)).toBeGreaterThan(50);
        const from = await cellCentre(page, 6, 4);
        await touch(cdp!, "touchStart", from);
        for (let i = 1; i <= 10; i++) await touch(cdp!, "touchMove", { x: from.x, y: from.y + i * 18 });
        await touch(cdp!, "touchEnd");
        await expect.poll(() => page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()?.viewportY ?? 0), "swipe scrolls").toBeGreaterThan(0);
        expect(await selected(page)).toBe("");
        await expect(page.locator(CALLOUT)).toHaveCount(0);
      } finally {
        await context.close();
      }
    });

    test(`callout placement, Copy answer, second finger and padding, ${size.name} ${theme}`, async ({ browser }) => {
      test.setTimeout(240_000);
      mkdirSync(OUT, { recursive: true });
      const { context, page, cdp } = await openTerminal(browser, theme, size);
      try {
        await show(page, SCREEN, "third");
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: { x: 40, y: 200 } });
        await expect(page.locator(WINDOW)).toHaveAttribute("data-active", "");

        // The callout on the top row, at the left edge, is the worst case: it must stay in the window and off the title pill.
        await longPress(page, cdp!, await cellCentre(page, 1, 0));
        await expect.poll(() => selected(page)).toBe("pair");
        await expect(page.locator(CALLOUT)).toBeVisible();
        await page.screenshot({ path: `${OUT}/${size.name}-${theme}-edge-callout.png` });
        const callout = (await boxOf(page, CALLOUT))!;
        const body = (await boxOf(page, `${WINDOW} .ui-window-body`))!;
        const pill = (await boxOf(page, `${WINDOW} .ui-window-pill`))!;
        expect.soft(callout.left, "inside the window's content area, left").toBeGreaterThanOrEqual(body.left);
        expect.soft(callout.top, "inside the window's content area, top").toBeGreaterThanOrEqual(body.top);
        expect.soft(callout.right, "inside the window's content area, right").toBeLessThanOrEqual(body.right);
        expect.soft(callout.bottom, "inside the window's content area, bottom").toBeLessThanOrEqual(body.bottom);
        const overlap = callout.left < pill.right && callout.right > pill.left && callout.top < pill.bottom && callout.bottom > pill.top;
        expect.soft(overlap, "never covers the title pill").toBe(false);
        expect.soft(callout.right - callout.left, "sized to its content, not the shared menu's minimum").toBeLessThan(130);
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: EMPTY });
        await expect.poll(() => selected(page)).toBe("");

        // Copy answers on the row itself, then the callout and the selection go.
        await longPress(page, cdp!, await cellCentre(page, 10, 0));
        await expect.poll(() => selected(page)).toBe(CODE);
        await page.locator(`${CALLOUT} button`).tap();
        await expect(page.locator(`${CALLOUT} button`), "the row says Copied").toContainText("Copied");
        await page.screenshot({ path: `${OUT}/${size.name}-${theme}-copied.png` });
        await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(CODE);
        await expect(page.locator(CALLOUT)).toHaveCount(0, { timeout: 5000 });
        expect(await selected(page)).toBe("");

        // A second finger after the hold keeps the selection and its callout.
        const finger = await cellCentre(page, 10, 0);
        const other = await cellCentre(page, 12, 3);
        await touch(cdp!, "touchStart", finger);
        await hold(page);
        await cdp!.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: finger.x, y: finger.y, id: 0 }, { x: other.x, y: other.y, id: 1 }] });
        await cdp!.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
        await expect(page.locator(CALLOUT), "the callout survives a second finger").toBeVisible();
        expect(await selected(page)).toBe(CODE);
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: EMPTY });
        await expect.poll(() => selected(page)).toBe("");

        // A long press in the host's padding, outside the canvas, selects nothing.
        const canvas = (await boxOf(page, ".terminal-host canvas"))!;
        const row = await cellCentre(page, 1, 1);
        await longPress(page, cdp!, { x: canvas.left - 6, y: row.y });
        expect(await selected(page), "padding selects nothing").toBe("");
        await expect(page.locator(CALLOUT)).toHaveCount(0);
      } finally {
        await context.close();
      }
    });
  }
}

/** The mouse path is the renderer's own and must be untouched by the touch work: a drag over a row selects it, and no callout appears. */
test("desktop: dragging with the mouse still selects text", async ({ browser }) => {
  test.setTimeout(240_000);
  const { context, page } = await openTerminal(browser, "ink");
  try {
    await show(page, SCREEN, "third");
    await page.locator(`${WINDOW} .terminal-host`).click({ position: { x: 40, y: 300 } });
    const from = await cellCentre(page, 0, 1);
    const to = await cellCentre(page, 20, 1);
    await page.mouse.move(from.x, from.y);
    await page.mouse.down();
    await page.mouse.move((from.x + to.x) / 2, to.y, { steps: 6 });
    await page.mouse.move(to.x, to.y, { steps: 6 });
    await page.mouse.up();
    await expect.poll(() => selected(page), "a mouse drag selects the row's text").toBe("second line of output");
    await expect(page.locator(CALLOUT)).toHaveCount(0);
  } finally {
    await context.close();
  }
});
