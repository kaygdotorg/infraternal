// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Two phone findings from J600's real-device check (#510, #500), each checked in a production build at 393 x 852:
 *
 * 1. The first-run setup-token field tells iOS not to capitalise, correct or spell-check a pasted or typed token.
 * 2. After the actions palette closes, the app surface fills the whole layout viewport. It is sized by `inset: 0`, so a
 *    viewport unit that stayed at the keyboard's height cannot leave a black band under it (see `src/screen-height.test.ts`).
 *
 * `J624_CAPTURES=<label>` writes light and dark screenshots to the external evidence directory (`phone-viewport-j624/<label>/`).
 * The token field is empty in every capture: a setup token is never put on screen.
 */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const PHONE = { width: 393, height: 852 };
const CAPTURES = process.env.J624_CAPTURES;
test.use({ viewport: PHONE, hasTouch: true, isMobile: true, deviceScaleFactor: 3 });

/** Takes a review capture when `J624_CAPTURES` is set. */
async function capture(page: Page, name: string, theme: "light" | "dark"): Promise<void> {
  if (CAPTURES) await page.screenshot({ path: tracerEvidencePath("phone-viewport-j624", CAPTURES, `${name}-${theme}.png`) });
}

for (const theme of ["light", "dark"] as const) {
  test(`the setup-token field keeps iOS from capitalising or correcting it (${theme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: theme });
    await page.request.post("/__mock/reset", { maxRetries: 1 });
    await page.goto("/?mock=1");
    const token = page.locator("#setup-token");
    await expect(token).toBeVisible({ timeout: 45_000 });
    expect(await token.getAttribute("autocapitalize")).toBe("none");
    expect(await token.getAttribute("autocorrect")).toBe("off");
    expect(await token.getAttribute("spellcheck")).toBe("false");
    await capture(page, "setup-token-field", theme);
  });

  test(`after the palette closes the surface fills the viewport (${theme})`, async ({ page }) => {
    await page.emulateMedia({ colorScheme: theme });
    await page.request.post("/__mock/reset", { maxRetries: 1 });
    await page.request.post("/__mock/bootstrap/reset", { maxRetries: 1 });
    await page.goto(`/?mock=1&proto=clusters&scene=3&theme=${theme === "dark" ? "ink" : "paper"}&bg=none`);
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
    const fills = (): Promise<{ top: number; bottom: number; innerHeight: number; width: number; innerWidth: number }> =>
      page.evaluate(() => {
        const r = document.querySelector(".terminal-screen")!.getBoundingClientRect();
        return { top: r.top, bottom: r.bottom, innerHeight: innerHeight, width: r.width, innerWidth: innerWidth };
      });
    await page.keyboard.press("Control+Shift+K");
    await expect(page.locator("#palette-input")).toBeVisible();
    await page.locator("#palette-input").focus();
    await capture(page, "palette-open", theme);
    await page.keyboard.press("Escape");
    await expect(page.locator("#palette-input")).toBeHidden();
    // sleep: the keyboard watcher re-reads the layout 120 ms, 400 ms and 1 s after a close; a stuck state would show after the last
    await page.waitForTimeout(1_200);
    const after = await fills();
    expect(after.top).toBe(0);
    expect(after.bottom).toBe(after.innerHeight);
    expect(after.width).toBe(after.innerWidth);
    await capture(page, "palette-closed", theme);
  });
}
