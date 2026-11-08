// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Selecting and copying terminal text with a finger (#426), on a production build against the terminal test double, in a touch
 * context at both phone sizes (393×852 and 375×667) in ink and paper.
 *
 * The owner could not select a pairing code on a phone: the terminal is a canvas, one finger is always scrollback (D159), and the
 * canvas's own selection listens to the mouse only. The contract these cases pin:
 * - a long press selects the word under the finger, and dragging then extends the selection by cell;
 * - a double tap selects the word too (a pairing code is one word);
 * - a Copy callout appears by the selection, and tapping it puts exactly the selected text on the clipboard;
 * - a plain swipe still scrolls the scrollback and never selects;
 * - a tap elsewhere clears the selection and the callout.
 *
 * Touches go through the DevTools protocol (`Input.dispatchTouchEvent`) because Playwright has no long press. Captures go to the
 * external evidence directory. Playwright WebKit is not iOS Safari: the real-device check is on the issue.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type CDPSession, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("terminal-touch-select");
const WINDOW = '.ui-window[data-window-id="w-build-01"]';
const CALLOUT = '.ui-window-menu[aria-label="Selected text"]';
const SIZES = [{ name: "393x852", width: 393, height: 852 }, { name: "375x667", width: 375, height: 667 }] as const;
const THEMES = ["ink", "paper"] as const;
const CODE = "ABCD-EFGH-1234";
/** The screen the cases select from: row 0 holds the pairing code, row 1 the sentence the drag covers. */
const SCREEN = "\u001b[2J\u001b[H" + [`pair: ${CODE} now`, "second line of output", "third"].join("\r\n");

type Point = { x: number; y: number };
const touch = (cdp: CDPSession, type: "touchStart" | "touchMove" | "touchEnd", at?: Point): Promise<unknown> =>
  cdp.send("Input.dispatchTouchEvent", { type, touchPoints: at && type !== "touchEnd" ? [{ x: at.x, y: at.y }] : [] });
// sleep: a long press is defined by the finger staying down; the app times it, so the test must really wait.
const hold = (page: Page, ms = 650): Promise<void> => page.waitForTimeout(ms);
const selected = (page: Page): Promise<string> => page.evaluate(() => window.__tracerTestDouble?.selectionText() ?? "");

/** The centre of the cell at (col, row) on the visible canvas, in client pixels. */
async function cellCentre(page: Page, col: number, row: number): Promise<Point> {
  return page.evaluate(([c, r]) => {
    const m = window.__tracerTestDouble!.rendererMetrics()!;
    const rect = document.querySelector<HTMLCanvasElement>(".terminal-host canvas")!.getBoundingClientRect();
    return { x: rect.left + (c! + 0.5) * m.cellWidth, y: rect.top + (r! + 0.5) * m.cellHeight };
  }, [col, row] as const);
}

for (const size of SIZES) {
  for (const theme of THEMES) {
    test(`touch selection and copy, ${size.name} ${theme}`, async ({ browser }) => {
      test.setTimeout(240_000);
      mkdirSync(OUT, { recursive: true });
      const context = await browser.newContext({
        viewport: { width: size.width, height: size.height }, deviceScaleFactor: 3, hasTouch: true, isMobile: true,
        colorScheme: theme === "ink" ? "dark" : "light", permissions: ["clipboard-read", "clipboard-write"],
      });
      const page = await context.newPage();
      const cdp = await context.newCDPSession(page);
      try {
        await context.request.post("/__mock/reset");
        await context.request.post("/__mock/open-terminal");
        await page.goto(`/?mock=1&proto=clusters&scene=1&theme=${theme}&bg=none`);
        await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
        await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
        await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
        const host = page.locator(`${WINDOW} .terminal-host`);
        await expect(host).toBeVisible({ timeout: 15_000 });
        await page.evaluate((text) => window.__tracerTestDouble!.writeText(text), SCREEN);
        await expect.poll(() => page.evaluate(() => window.__tracerTestDouble!.screenText().includes("third"))).toBe(true);
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: { x: 40, y: 200 } });
        await expect(page.locator(WINDOW)).toHaveAttribute("data-active", "");

        // 1. Long press on the pairing code selects exactly that word.
        const onCode = await cellCentre(page, 10, 0);
        await touch(cdp, "touchStart", onCode);
        await hold(page);
        await touch(cdp, "touchEnd");
        await expect.poll(() => selected(page), "long press selects the word").toBe(CODE);
        await expect(page.locator(CALLOUT)).toBeVisible();
        await page.screenshot({ path: `${OUT}/${size.name}-${theme}-word-callout.png` });

        // 2. Copy puts exactly the selection on the clipboard.
        await page.locator(`${CALLOUT} button`, { hasText: "Copy" }).tap();
        await expect.poll(() => page.evaluate(() => navigator.clipboard.readText()), "Copy fills the clipboard").toBe(CODE);
        // 3. A tap elsewhere clears the selection and the callout.
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: { x: 40, y: 300 } });
        await expect.poll(() => selected(page)).toBe("");
        await expect(page.locator(CALLOUT)).toHaveCount(0);

        // 4. Long press, then drag over the second row: the selection extends by cell and spans the word onwards.
        const start = await cellCentre(page, 2, 1);
        const end = await cellCentre(page, 20, 1);
        await touch(cdp, "touchStart", start);
        await hold(page);
        await touch(cdp, "touchMove", await cellCentre(page, 9, 1));
        await touch(cdp, "touchMove", end);
        await touch(cdp, "touchEnd");
        await expect.poll(() => selected(page), "long press then drag extends").toBe("second line of output");
        await expect(page.locator(CALLOUT)).toBeVisible();
        await page.screenshot({ path: `${OUT}/${size.name}-${theme}-drag-callout.png` });
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: { x: 40, y: 300 } });
        await expect.poll(() => selected(page)).toBe("");
        // 5. A double tap selects the word.
        await page.touchscreen.tap(onCode.x, onCode.y);
        await page.touchscreen.tap(onCode.x, onCode.y);
        await expect.poll(() => selected(page), "double tap selects the word").toBe(CODE);
        await page.locator(`${WINDOW} .terminal-host`).tap({ position: { x: 40, y: 300 } });
        await expect.poll(() => selected(page)).toBe("");
        // 6. A plain swipe still scrolls the scrollback and selects nothing.
        const lines = Array.from({ length: 120 }, (_, i) => `scroll line ${i}`).join("\r\n") + "\r\n";
        await page.evaluate((text) => window.__tracerTestDouble!.writeText(text), lines);
        await expect.poll(() => page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()?.scrollbackRows ?? 0)).toBeGreaterThan(50);
        const from = await cellCentre(page, 6, 4);
        await touch(cdp, "touchStart", from);
        for (let i = 1; i <= 10; i++) await touch(cdp, "touchMove", { x: from.x, y: from.y + i * 18 });
        await touch(cdp, "touchEnd");
        await expect.poll(() => page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()?.viewportY ?? 0), "swipe scrolls").toBeGreaterThan(0);
        expect(await selected(page)).toBe("");
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
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  try {
    await context.request.post("/__mock/reset");
    await context.request.post("/__mock/open-terminal");
    await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
    await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
    await expect(page.locator(`${WINDOW} .terminal-host`)).toBeVisible({ timeout: 15_000 });
    await page.evaluate((text) => window.__tracerTestDouble!.writeText(text), SCREEN);
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble!.screenText().includes("third"))).toBe(true);
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
