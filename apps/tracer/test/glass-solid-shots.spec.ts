/**
 * Screenshots for the review of #448 (job J1020), taken from the production build the tests serve: the palette and the confirmation
 * card, Paper over black and Ink over white (the cases that must turn solid) and over the easy backdrops (which stay glass), over a
 * picture and over the real terminal screen, at 1440 x 900 and 393 x 852, Frosted (card 4). Each also saves a 3x close-up of the
 * card's text. Not assertions: the receipts for the issue; `glass-surfaces.spec.ts` and `glass-solid-review.spec.ts` assert.
 */
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { mkdirSync } from "node:fs";
import { openScene, putPicture, removePicture, SIZES, surfacesFor, type Picture } from "./glass-scenes";
import { glassReady, settled } from "./glass-settled";

/** Where the pictures land. */
const OUT = tracerEvidencePath("glass-solid-shots");
mkdirSync(OUT, { recursive: true });

/** The cases: the hard backdrop for each scheme, and the easy one (a matching or middling backdrop that stays glass). */
const CASES: Array<{ scheme: "ink" | "paper"; picture: Picture; verdict: string }> = [
  { scheme: "paper", picture: "black", verdict: "solid" }, { scheme: "paper", picture: "white", verdict: "glass" }, { scheme: "paper", picture: "grey", verdict: "glass" },
  { scheme: "ink", picture: "white", verdict: "solid" }, { scheme: "ink", picture: "black", verdict: "glass" }, { scheme: "ink", picture: "grey", verdict: "glass" },
];

for (const size of SIZES) {
  for (const surface of surfacesFor(size).filter((s) => s.id === "palette" || s.id === "confirm")) {
    for (const c of CASES) {
      test(`${size.id} ${c.scheme} ${surface.id} over ${c.picture} picture (${c.verdict})`, async ({ browser }) => {
        const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: c.scheme === "ink" ? "dark" : "light", ...(size.phone ? { hasTouch: true, isMobile: true } : {}) });
        const page = await context.newPage();
        await openScene(page, c.scheme, 4);
        await putPicture(page, c.picture, "fill", surface.host);
        await surface.open(page);
        await expect(page.locator(surface.selector).first()).toBeVisible();
        await settled(page, surface.selector);
        const name = `${size.id}-${c.scheme}-${surface.id}-over-${c.picture}-${c.verdict}`;
        await page.screenshot({ path: `${OUT}/${name}.png` });
        const box = (await page.locator(surface.selector).first().boundingBox())!;
        await page.screenshot({ path: `${OUT}/${name}-zoom.png`, clip: { x: box.x, y: box.y, width: Math.min(box.width, 360), height: Math.min(box.height, 140) }, scale: "device" });
        await surface.close(page);
        await removePicture(page);
        await context.close();
      });
    }
  }
  // The owner's own case: the real terminal screen, filled with black (Paper) or white (Ink), the palette over it.
  for (const c of [{ scheme: "paper", g: 0 }, { scheme: "ink", g: 255 }] as const) {
    test(`${size.id} ${c.scheme} palette over the real terminal, ${c.g === 0 ? "black" : "white"} screen`, async ({ browser }) => {
      const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: c.scheme === "ink" ? "dark" : "light", ...(size.phone ? { hasTouch: true, isMobile: true } : {}) });
      const page = await context.newPage();
      await page.context().request.post("/__mock/reset");
      await page.context().request.post("/__mock/open-terminal");
      await page.goto(`/?mock=1&theme=${c.scheme}&card=4&fps=0`);
      await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
      await glassReady(page);
      await page.evaluate((level) => {
        const m = window.__tracerTestDouble!.rendererMetrics()!;
        let text = `\x1b[48;2;${level};${level};${level}m`;
        for (let r = 1; r <= m.rows; r++) text += `\x1b[${r};1H${" ".repeat(m.cols)}`;
        window.__tracerTestDouble!.writeText(`${text}\x1b[0m\x1b[1;1H\x1b[38;2;128;128;128mgit status  ls -la  cargo build`);
      }, c.g);
      await page.keyboard.press("Control+Shift+K");
      await expect(page.locator("#palette")).toBeVisible();
      await settled(page, "#palette");
      const name = `${size.id}-${c.scheme}-palette-over-terminal-${c.g === 0 ? "black" : "white"}-solid`;
      await page.screenshot({ path: `${OUT}/${name}.png` });
      const box = (await page.locator("#palette").boundingBox())!;
      await page.screenshot({ path: `${OUT}/${name}-zoom.png`, clip: { x: box.x, y: box.y, width: Math.min(box.width, 360), height: Math.min(box.height, 140) }, scale: "device" });
      await context.close();
    });
  }
}
