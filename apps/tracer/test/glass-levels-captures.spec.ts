/**
 * Captures of the three thin glass levels over a real terminal, for review (D322, D365, #448).
 *
 * The owner approved Tinted, Clear and Frosted as three different densities. The contrast work must not flatten them, so this
 * writes a screen of dense text into the real terminal of the mock page, opens the palette over it at `card=2..4`, in Ink and
 * Paper, at 1440 x 900 and 393 x 852, and saves `<size>-<theme>-card<N>.png` to the evidence directory. It asserts only that the
 * palette was reached and that the three levels paint three different fills; people judge the pictures. No mockup is needed.
 */
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { glassReady, settled } from "./glass-settled";
import { SIZES } from "./glass-scenes";

/** Where the captures land. */
const OUT = tracerEvidencePath("glass-levels");
/** A screenful of dense text, as `ls -la` would leave it. */
const DENSE = Array.from({ length: 60 }, (_, i) => `drwxr-xr-x  12 kayg kayg  ${String(4096 + i * 37).padStart(6)} Nov  9 12:${String(i % 60).padStart(2, "0")} infraternal-${i.toString(16)}-build-output`).join("\r\n");

for (const size of SIZES) {
  for (const scheme of ["ink", "paper"] as const) {
    test(`${size.id} ${scheme === "ink" ? "Ink" : "Paper"}: Tinted, Clear and Frosted over the terminal`, async ({ browser }) => {
      const fills: string[] = [];
      for (const card of [2, 3, 4]) {
        const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: scheme === "ink" ? "dark" : "light", ...(size.phone ? { hasTouch: true, isMobile: true } : {}) });
        const page = await context.newPage();
        await page.context().request.post("/__mock/reset");
        await page.context().request.post("/__mock/open-terminal");
        await page.goto(`/?mock=1&theme=${scheme}&card=${card}&fps=0`);
        await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
        await glassReady(page);
        await page.evaluate((text) => window.__tracerTestDouble!.writeText(`\x1b[2J\x1b[H${text}`), DENSE);
        await page.keyboard.press("Control+Shift+K");
        const palette = page.locator("#palette");
        await expect(palette).toBeVisible();
        await settled(page, "#palette");
        await page.screenshot({ path: `${OUT}/${size.id}-${scheme}-card${card}.png` });
        fills.push(await palette.evaluate((el) => getComputedStyle(el).backgroundColor));
        await context.close();
      }
      expect(new Set(fills).size, `three levels, three fills: ${fills.join(" | ")}`).toBe(3);
    });
  }
}
