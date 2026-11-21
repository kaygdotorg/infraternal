/**
 * The window's ⋯ menu over a window picture it hangs out of (D365, #448, J1058).
 *
 * The menu is mounted in the window and hangs over the picture's edge, so part of it is over the picture and part over the page.
 * The glass sampler used to give up on such a card and leave it on the solid floor. It now solves for both parts together: the
 * menu must stay glass where 4.5:1 is reachable at the adaptive limit and be the solid card where it is not, and its text must
 * reach 4.5:1 on the rendered pixels either way. The pictures are the matching one (dark over Ink, light over Paper: glass), the
 * opposing one (solid), a busy mid-tone mosaic and a black and white checker (the hardest: solid).
 *
 * Captures of each case, cropped to the window and its menu, go to the evidence directory (`menu-<scheme>-<picture>.png`).
 */
import { writeFileSync } from "node:fs";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { LINE, openScene, paintOf } from "./glass-scenes";
import { measure } from "./glass-pixels";
import { settled } from "./glass-settled";

/** Where the captures land. */
const OUT = tracerEvidencePath("glass-menu-straddle");

/** The pictures, and what the menu must be over each in Ink and in Paper: `glass`, `solid`, or `either` (the solver decides; only the contrast is asserted). */
const CASES = [
  { picture: "white", ink: "solid", paper: "glass" },
  { picture: "black", ink: "glass", paper: "solid" },
  { picture: "grey", ink: "either", paper: "either" },
  { picture: "busy", ink: "either", paper: "either" },
  { picture: "checker", ink: "solid", paper: "solid" },
] as const;

for (const scheme of ["ink", "paper"] as const) {
  test(`${scheme === "ink" ? "Ink" : "Paper"} card 4: the window menu hanging over a picture's edge stays glass where it can and is solid where it cannot`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: scheme === "ink" ? "dark" : "light" });
    const page = await context.newPage();
    await openScene(page, scheme, 4);
    for (const c of CASES) {
      // A 64 x 64 picture, filled the way the case says, in the window and stretched over it (`fill`, which the sampler can read).
      await page.evaluate(async (picture) => {
        const cv = document.createElement("canvas");
        cv.width = cv.height = 64;
        const g = cv.getContext("2d")!;
        for (let y = 0; y < 64; y += 8) for (let x = 0; x < 64; x += 8) {
          const odd = ((x + y) / 8) % 2 === 1;
          // busy: mid-tone blocks in several hues, 80 to 180 per channel; checker: pure black and white.
          g.fillStyle = picture === "white" ? "#fff" : picture === "black" ? "#000" : picture === "grey" ? "#777"
            : picture === "checker" ? (odd ? "#fff" : "#000") : `rgb(${80 + ((x * 7 + y * 3) % 100)} ${80 + ((x * 5 + y * 11) % 100)} ${80 + ((x * 13 + y) % 100)})`;
          g.fillRect(x, y, 8, 8);
        }
        const img = document.createElement("img");
        img.dataset.testPicture = picture;
        img.src = cv.toDataURL("image/png");
        img.style.cssText = "position:absolute;inset:0;width:100%;height:100%;z-index:0;object-fit:fill;image-rendering:pixelated";
        document.querySelector(".ui-window")!.append(img);
        await img.decode();
      }, c.picture);
      await page.locator(".ui-window .ui-window-more").first().evaluate((b) => { (b as HTMLElement).click(); });
      const menu = page.locator(".ui-window-menu").first();
      await expect(menu).toBeVisible({ timeout: 8000 });
      await settled(page, ".ui-window-menu");
      // The menu really hangs over the picture's edge: otherwise this case proves nothing about straddling.
      const straddles = await page.evaluate(() => {
        const m = document.querySelector(".ui-window-menu")!.getBoundingClientRect(), p = document.querySelector("img[data-test-picture]")!.getBoundingClientRect();
        return m.left < p.left || m.right > p.right || m.top < p.top || m.bottom > p.bottom;
      });
      expect(straddles, `${c.picture}: the menu hangs over the picture's edge`).toBe(true);
      const win = await page.locator(".ui-window").first().boundingBox();
      const box = (await menu.boundingBox())!;
      const x = Math.max(0, Math.min(win!.x, box.x) - 16), y = Math.max(0, Math.min(win!.y, box.y) - 16);
      await page.screenshot({ path: `${OUT}/menu-${scheme}-${c.picture}.png`, clip: { x, y, width: Math.min(1440 - x, Math.max(win!.x + win!.width, box.x + box.width) - x + 16), height: Math.min(900 - y, Math.max(win!.y + win!.height, box.y + box.height) - y + 16) } });
      const paint = await paintOf(page, ".ui-window-menu");
      const results = await measure(page, ".ui-window-menu");
      writeFileSync(`${OUT}/menu-${scheme}-${c.picture}.json`, JSON.stringify({ alpha: paint.alpha, blur: paint.blur, lowest: results[0]?.ratio }));
      expect.soft(paint.shadowed, `${c.picture}: no text shadow`).toEqual([]);
      expect.soft(results[0]!.ratio, `${c.picture}: lowest "${results[0]!.text}" ${results[0]!.ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(LINE);
      if (c[scheme] === "solid") { expect.soft(paint.alpha, `${c.picture}: solid fill`).toBe(1); expect.soft(paint.blur, `${c.picture}: solid has no blur`).toBe(0); }
      if (c[scheme] === "glass") expect.soft(paint.alpha, `${c.picture}: stays glass`).toBeLessThan(1);
      await page.keyboard.press("Escape");
      await expect(menu).toBeHidden({ timeout: 8000 });
      await page.evaluate(() => { document.querySelectorAll("img[data-test-picture]").forEach((i) => { i.remove(); }); });
    }
    await context.close();
  });
}
