/**
 * The stale-screen note on the production build against the test double (D309): after a reattach, a
 * program that repaints never shows it (not even for a frame), a shell that stays silent shows it,
 * and output arriving later takes it down. The screenshots are review evidence outside the checkout.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const NOTE = ".ui-terminal-note";
const SCREEN = "$ ls\r\nREADME.md  src  target\r\n$ ";

/** Records every time the note has been up, from the first frame, so a one-frame flash cannot slip by. */
async function recordNote(page: Page): Promise<void> {
  await page.evaluate((selector) => {
    const w = window as unknown as { __noteShown: number };
    w.__noteShown = 0;
    const seen = (el: Element): void => { if (el.hasAttribute("data-shown") || !(el as HTMLElement).hidden) w.__noteShown += 1; };
    new MutationObserver((records) => {
      for (const record of records) {
        const target = record.target as Element;
        if (target.matches?.(selector)) seen(target);
        for (const node of record.addedNodes) if (node instanceof Element && node.matches(selector)) seen(node);
      }
    }).observe(document.body, { subtree: true, childList: true, attributes: true });
  }, NOTE);
}

async function openAttachedTerminal(page: Page, theme: "ink" | "paper"): Promise<void> {
  const context = page.context();
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.goto(`/?mock=1&theme=${theme}&bg=none`);
  await expect(page.getByText("TEST DOUBLE")).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
  // The double accepts a fixture only for a fresh attached terminal; the previous test's socket may still be closing.
  await expect.poll(async () => (await context.request.post("/__mock/text-output", { data: { text: SCREEN } })).status(), { timeout: 10_000 }).toBe(200);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("README.md");
}

async function reattach(page: Page): Promise<void> {
  await page.evaluate(() => window.__tracerTestDouble?.dropConnection());
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === false)).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 15_000 }).toBe(true);
}

const noteShown = (page: Page) => page.locator(`${NOTE}[data-shown]`);
const everShown = (page: Page) => page.evaluate(() => (window as unknown as { __noteShown: number }).__noteShown);

for (const [name, viewport] of [["desktop", { width: 1440, height: 900 }], ["phone", { width: 390, height: 844 }]] as const) {
  test.describe(name, () => {
    test.use({ viewport, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });

    test("a shell that cannot redraw shows the note after reattach, and new output clears it", async ({ page }) => {
      test.setTimeout(60_000);
      await openAttachedTerminal(page, "ink");
      await expect(page.locator(NOTE)).toHaveCount(1);
      await expect(noteShown(page)).toHaveCount(0);
      await reattach(page);
      await expect(noteShown(page)).toHaveCount(1, { timeout: 5_000 });
      await expect(page.locator(NOTE)).toHaveText("screen may be out of date");
      // It never takes the click, and sits away from the cursor row.
      expect(await page.locator(NOTE).evaluate((el) => getComputedStyle(el).pointerEvents)).toBe("none");
      const geometry = await page.evaluate(() => {
        const note = document.querySelector(".ui-terminal-note")!.getBoundingClientRect();
        const cursor = document.querySelector(".terminal-cursor-layer:not([hidden])")?.getBoundingClientRect();
        return { note: { top: note.top, bottom: note.bottom }, cursor: cursor ? { top: cursor.top, bottom: cursor.bottom } : undefined };
      });
      if (geometry.cursor) {
        const overlap = geometry.note.top < geometry.cursor.bottom && geometry.note.bottom > geometry.cursor.top;
        expect(overlap, "the note must not share the cursor line").toBe(false);
      }
      await page.screenshot({ path: tracerEvidencePath(`stale-note-${name}-ink.png`) });
      await page.context().request.post("/__mock/live-output", { data: { text: "x" } });
      await expect(noteShown(page)).toHaveCount(0);
      await expect(page.locator(NOTE)).toBeHidden();
    });

    test("a shell that cannot redraw shows the note in the paper theme", async ({ page }) => {
      test.setTimeout(60_000);
      await openAttachedTerminal(page, "paper");
      await reattach(page);
      await expect(noteShown(page)).toHaveCount(1, { timeout: 5_000 });
      await page.screenshot({ path: tracerEvidencePath(`stale-note-${name}-paper.png`) });
    });

    test("a program that repaints after reattach never shows the note, not for a frame", async ({ page }) => {
      test.setTimeout(60_000);
      await openAttachedTerminal(page, "ink");
      await recordNote(page);
      await page.context().request.post("/__mock/redraw-on-attach", { data: { text: "\u001b[2J\u001b[H$ ls\r\nREADME.md  src  target\r\n$ ", delay_ms: 30 } });
      await reattach(page);
      await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""), { timeout: 5_000 }).toContain("README.md");
      // Wait past the longest wait the client allows, so a late flash would have shown.
      await page.waitForTimeout(2_000);
      expect(await everShown(page)).toBe(0);
      await expect(noteShown(page)).toHaveCount(0);
    });
  });
}
