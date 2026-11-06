/**
 * The stale-screen state on the production build against the product canvas and the test double (D309): it is the
 * connection indicator's "stale" state in the window's machine pill, with the sentence in its tooltip and accessible
 * name, and never a floating note. After a reattach that resized the session, a program that repaints never shows it
 * (not even for a frame), a shell that stays silent shows it, and output arriving later takes it down. A reattach at
 * the size the session already had expects no repaint, so an idle shell there never shows it (#257). The pill must not
 * change size or move anything when the state opens or closes. The screenshots are review evidence outside the checkout.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { everShown, FLOATING_NOTE, ICON, NOTE, recordNote } from "./stale-note-recorder";

const SCREEN = "$ ls\r\nREADME.md  src  target\r\n$ ";
/** The words the tooltip and accessible name carry. */
const SENTENCE = "Screen may be out of date";

/** The product canvas's own handle on its first terminal. */
const door = (page: Page) => ({
  connected: () => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() === true),
  text: () => page.evaluate(() => window.__tracerProductTestDouble?.screenText() ?? ""),
  drop: () => page.evaluate(() => window.__tracerProductTestDouble?.dropConnection()),
});

/** Opens the product canvas against the test double and waits until its terminal shows the fixture screen. */
async function openAttachedTerminal(page: Page, theme: "ink" | "paper"): Promise<void> {
  const context = page.context();
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.goto(`/?mock=1&proto=product&fresh=1&bg=none&theme=${theme}`);
  await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 20_000 });
  await expect.poll(door(page).connected, { timeout: 30_000 }).toBe(true);
  // The double accepts a fixture only for a fresh attached terminal; the previous test's socket may still be closing,
  // and a request on a connection the double just dropped fails with "socket hang up", which is worth another try.
  await expect.poll(async () => {
    try { return (await context.request.post("/__mock/text-output", { data: { text: SCREEN } })).status(); } catch { return 0; }
  }, { timeout: 10_000 }).toBe(200);
  await expect.poll(door(page).text).toContain("README.md");
}

/** Another device resizes the session while this page is away, so the reattach changes the size again. */
async function resizeWhileAway(page: Page): Promise<void> {
  await page.context().request.post("/__mock/resize-session", { data: { cols: 50, rows: 12 } });
}

/** Drops the socket and waits for the terminal to attach again. */
async function reattach(page: Page): Promise<void> {
  await door(page).drop();
  await expect.poll(async () => !(await door(page).connected())).toBe(true);
  await expect.poll(door(page).connected, { timeout: 15_000 }).toBe(true);
}

/** The pill's size and the centre lines of its parts: none of these may change when the state opens or closes. */
const pillBox = (page: Page) => page.evaluate(() => {
  const box = (selector: string) => document.querySelector(selector)!.getBoundingClientRect();
  const pill = box(".ui-window-pill");
  const host = box(".ui-window-host");
  const conn = box(".ui-window-conn");
  return { pillLeft: pill.left, pillWidth: pill.width, pillTop: pill.top, pillHeight: pill.height, hostLeft: host.left, hostWidth: host.width, hostMid: host.top + host.height / 2, connMid: conn.top + conn.height / 2 };
});

/** Hover (desktop) or tap (phone) the indicator and wait for the shared tooltip to say the sentence. */
async function openTooltip(page: Page, phone: boolean): Promise<void> {
  const icon = page.locator(`.ui-window ${ICON}`).first();
  if (phone) await icon.tap(); else await icon.hover();
  await expect(page.locator(".tip")).toContainText(SENTENCE);
}

/** The window pill's indicator while it shows the stale state. */
const stateShown = (page: Page) => page.locator(NOTE);

for (const [name, viewport] of [["desktop", { width: 1440, height: 900 }], ["phone", { width: 390, height: 844 }]] as const) {
  test.describe(name, () => {
    test.use({ viewport, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });

    test("a shell that cannot redraw shows the pill icon after a resized reattach, and new output takes it down", async ({ page }) => {
      test.setTimeout(90_000);
      await openAttachedTerminal(page, "ink");
      await expect(stateShown(page)).toHaveCount(0);
      const icon = page.locator(`.ui-window ${ICON}`).first();
      const before = await pillBox(page);
      await resizeWhileAway(page);
      await reattach(page);
      await expect(stateShown(page)).toHaveCount(1, { timeout: 5_000 });
      await expect(page.locator(FLOATING_NOTE)).toHaveCount(0);
      // The one indicator carries the sentence as its accessible name and its tooltip.
      await expect(icon).toHaveAttribute("aria-label", SENTENCE);
      await expect(icon).toHaveAttribute("role", "img");
      // Nothing in the pill moves or resizes: the mark is the same box as the dot it replaces, and shares the text's centre line.
      // sleep: the glyph cross-fade (160-240 ms) plus margin, so the layout is at rest before it is measured
      await page.waitForTimeout(400);
      const after = await pillBox(page);
      expect(after.pillWidth).toBeCloseTo(before.pillWidth, 0);
      expect(after.hostWidth).toBeCloseTo(before.hostWidth, 0);
      expect(after.pillLeft).toBeCloseTo(before.pillLeft, 0);
      expect(after.pillTop).toBeCloseTo(before.pillTop, 1);
      expect(Math.abs(after.connMid - after.hostMid)).toBeLessThanOrEqual(0.5);
      await openTooltip(page, name === "phone");
      // A tap on the mark only says why; it does not also open the machine details (frame.ts).
      if (name === "phone") await expect(page.locator(".canvas-popover")).toHaveCount(0);
      await page.screenshot({ path: tracerEvidencePath(`stale-icon-${name}-ink-tooltip.png`) });
      await page.context().request.post("/__mock/live-output", { data: { text: "x" } });
      await expect(stateShown(page)).toHaveCount(0);
      // Clearing is as steady as opening: nothing moves, and a tooltip that a tap opened does not outlive the state.
      // sleep: the glyph cross-fade (160-240 ms) plus margin, so the layout is at rest before it is measured
      await page.waitForTimeout(400);
      expect(await pillBox(page)).toEqual(expect.objectContaining({ pillWidth: before.pillWidth, hostWidth: before.hostWidth }));
      if (name === "phone") await expect(page.locator(".tip")).toBeHidden();
      await expect(page.locator(FLOATING_NOTE)).toHaveCount(0);
    });

    test("an idle shell reattached at the same size never shows the icon, not for a frame", async ({ page }) => {
      test.setTimeout(90_000);
      await openAttachedTerminal(page, "ink");
      await recordNote(page);
      await reattach(page);
      // The replay is the screen; the shell stays silent because nothing asked it to redraw.
      await expect.poll(door(page).text).toContain("README.md");
      // Wait past the longest wait the client allows, so a late state would have shown.
      // sleep: D309's longest silence wait is 1.5 s; this is a functional silence check, not a latency measurement
      await page.waitForTimeout(2_000);
      expect(await everShown(page)).toBe(0);
      await expect(stateShown(page)).toHaveCount(0);
      await page.screenshot({ path: tracerEvidencePath(`stale-icon-${name}-same-size.png`) });
    });

    test("a shell that cannot redraw shows the pill icon in the paper theme", async ({ page }) => {
      test.setTimeout(90_000);
      await openAttachedTerminal(page, "paper");
      await resizeWhileAway(page);
      await reattach(page);
      await expect(stateShown(page)).toHaveCount(1, { timeout: 5_000 });
      await openTooltip(page, name === "phone");
      await page.screenshot({ path: tracerEvidencePath(`stale-icon-${name}-paper.png`) });
    });

    test("a program that repaints after reattach never shows the icon, not for a frame", async ({ page }) => {
      test.setTimeout(90_000);
      await openAttachedTerminal(page, "ink");
      await recordNote(page);
      await resizeWhileAway(page);
      await page.context().request.post("/__mock/redraw-on-attach", { data: { text: "\u001b[2J\u001b[H$ ls\r\nREADME.md  src  target\r\n$ ", delay_ms: 30 } });
      await reattach(page);
      await expect.poll(door(page).text, { timeout: 5_000 }).toContain("README.md");
      // Wait past the longest wait the client allows, so a late flash would have shown.
      // sleep: D309's longest silence wait is 1.5 s; this is a functional silence check, not a latency measurement
      await page.waitForTimeout(2_000);
      expect(await everShown(page)).toBe(0);
      await expect(stateShown(page)).toHaveCount(0);
    });
  });
}
