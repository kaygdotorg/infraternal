/**
 * Captures of the three thin glass levels over the terminal, for review (D322, D365, #448).
 *
 * The owner approved Tinted, Clear and Frosted as three different densities. The contrast work must not flatten them, so
 * this opens the mockup's phone terminal with the machine picker (`appmock=phone-terminal&pop=picker`) at `card=2..4`, in
 * Ink and Paper, at 1440 x 900 and 393 x 852, and saves `<size>-<theme>-card<N>.png` to the evidence directory. It asserts
 * only that each state was reached and that the three levels paint three different surface colours; people judge the pictures.
 * Skipped until the #146 mockup is on the branch.
 */
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** Whether the #146 mockup this spec opens is on this branch. */
const HAS_MOCKUP = existsSync(resolve(import.meta.dirname, "../src/canvas/mock/appwin-scenes/mount.on-demand.ts"));
test.skip(!HAS_MOCKUP, "the app-window mockup (#146) is not on this branch");

/**
 * The terminal scene is the phone's (its machine picker is the toolbar pill's), so both sizes are captured with touch emulation; the
 * wide one shows the phone layout on a wide screen, which is where the tray and picker sit over the terminal.
 */
/** Where the captures land. */
const OUT = tracerEvidencePath("glass-levels");

for (const size of [{ id: "1440x900", width: 1440, height: 900, phone: false }, { id: "393x852", width: 393, height: 852, phone: true }]) {
  for (const scheme of ["dark", "light"] as const) {
    test(`${size.id} ${scheme === "dark" ? "Ink" : "Paper"}: Tinted, Clear and Frosted over the terminal`, async ({ browser }) => {
      const fills: string[] = [];
      for (const card of [2, 3, 4]) {
        const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: scheme, hasTouch: true, isMobile: true });
        const page = await context.newPage();
        await page.goto(`/?mock=1&proto=clusters&fps=0&appmock=phone-terminal&pop=picker&card=${card}`);
        const pop = page.locator(".awm-pickerpop").first();
        await expect(pop).toBeVisible({ timeout: 20_000 });
        await page.evaluate(() => document.fonts.ready);
        // sleep: the popover grows in over 200 ms before it is captured
        await page.waitForTimeout(900);
        await page.screenshot({ path: `${OUT}/${size.id}-${scheme === "dark" ? "ink" : "paper"}-card${card}.png` });
        fills.push(await pop.evaluate((el) => getComputedStyle(el).backgroundColor));
        await context.close();
      }
      expect(new Set(fills).size, `three levels, three fills: ${fills.join(" | ")}`).toBe(3);
    });
  }
}
