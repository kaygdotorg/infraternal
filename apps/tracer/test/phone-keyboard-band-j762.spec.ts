// SPDX-License-Identifier: AGPL-3.0-only
/**
 * No dark band around the phone keyboard (#510, J762). Two states from the iPhone Simulator, each modelled here by
 * shrinking `visualViewport` the way iOS does (the layout viewport keeps its size; only the visual one gets shorter):
 *
 * 1. While the keyboard is up, the screen is fitted to the visible area, so the strip behind Safari's own accessory bar
 *    belongs to the page behind the screen: `html`. It used to be a fixed dark `#101113`, a black strip on a light theme.
 *    It now follows the theme background.
 * 2. When a terminal window ends while the keyboard is up (a shell that exits), its keyboard watcher stops with it, so
 *    the keyboard-sized height it had put on the shared screen stayed forever: a band under the page after the
 *    keyboard closed. Disposing a terminal now hands the screen back at full height.
 *
 * Both run in a production build at 393 x 852; `J762_CAPTURES=<label>` writes light and dark screenshots to the
 * external evidence directory.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const PHONE = { width: 393, height: 852 };
/** How much shorter the visual viewport is with the keyboard up, in CSS px (about an iPhone keyboard and its bar). */
const KEYBOARD = 336;
const CAPTURES = process.env.J762_CAPTURES;
test.use({ viewport: PHONE, hasTouch: true, isMobile: true, deviceScaleFactor: 3 });

/** Replaces `visualViewport.height` with a value the test controls, and tells the page about every change. */
async function installFakeViewport(page: Page): Promise<void> {
  await page.addInitScript(() => {
    let shrink = 0;
    const vv = window.visualViewport!;
    Object.defineProperty(vv, "height", { configurable: true, get: () => window.innerHeight - shrink });
    (window as unknown as { __setKeyboard(px: number): void }).__setKeyboard = (px: number) => { shrink = px; vv.dispatchEvent(new Event("resize")); };
  });
}
const setKeyboard = (page: Page, px: number): Promise<void> => page.evaluate((v) => (window as unknown as { __setKeyboard(px: number): void }).__setKeyboard(v), px);

async function open(page: Page, theme: "light" | "dark"): Promise<void> {
  await page.emulateMedia({ colorScheme: theme });
  await page.request.post("/__mock/reset", { maxRetries: 1 });
  await page.goto(`/?mock=1&proto=product&fresh=1&theme=${theme === "dark" ? "ink" : "paper"}&bg=none`);
  await expect(page.locator("[data-view='console'] .ui-window").first()).toBeVisible({ timeout: 45_000 });
}
/** Focuses the terminal's text input, which is what makes the phone raise its keyboard. */
async function focusTerminal(page: Page): Promise<void> {
  await page.locator("[data-view='console'] textarea").first().focus();
}
const geometry = (page: Page): Promise<{ bottom: number; innerHeight: number; screenBg: string; rootBg: string }> =>
  page.evaluate(() => {
    const screen = document.querySelector(".terminal-screen") as HTMLElement;
    return {
      bottom: screen.getBoundingClientRect().bottom,
      innerHeight: window.innerHeight,
      screenBg: getComputedStyle(screen).backgroundColor,
      rootBg: getComputedStyle(document.documentElement).backgroundColor,
    };
  });
async function capture(page: Page, name: string, theme: string): Promise<void> {
  if (CAPTURES) await page.screenshot({ path: tracerEvidencePath("phone-keyboard-band-j762", CAPTURES, `${name}-${theme}.png`) });
}

for (const theme of ["light", "dark"] as const) {
  test(`with the keyboard up, the page behind the screen has the theme's colour (${theme})`, async ({ page }) => {
    await installFakeViewport(page);
    await open(page, theme);
    await focusTerminal(page);
    await setKeyboard(page, KEYBOARD);
    // sleep: the keyboard watcher re-reads 120 ms after the event; the fitted state is what this check wants to see
    await page.waitForTimeout(400);
    const up = await geometry(page);
    expect(up.bottom, "the screen is fitted to the visible area").toBeLessThan(up.innerHeight - 100);
    expect(up.rootBg, "the strip behind the accessory bar is the theme background, not a fixed dark").toBe(up.screenBg);
    await capture(page, "keyboard-up", theme);
  });

  test(`a window that ends while the keyboard is up leaves no band after the keyboard closes (${theme})`, async ({ page }) => {
    await installFakeViewport(page);
    await open(page, theme);
    await focusTerminal(page);
    await setKeyboard(page, KEYBOARD);
    // sleep: the keyboard watcher re-reads 120 ms after the event; the fitted state must be in place before the window ends
    await page.waitForTimeout(400);
    // The only window ends (a shell that exits); its terminal is disposed with the keyboard still up.
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:close", source: "keyboard" } })));
    await expect(page.locator(".cl-empty")).toBeVisible({ timeout: 10_000 });
    await setKeyboard(page, 0);
    // sleep: the watcher's last re-read is 1 s after an event; a stuck height would still be there after it
    await page.waitForTimeout(1_300);
    const after = await geometry(page);
    expect(after.bottom).toBe(after.innerHeight);
    await capture(page, "after-close", theme);
  });
}
