/**
 * Every glass surface of the product over a worst-case picture (D365, #448).
 *
 * The palette, the toasts, the confirmation card and a window's ⋯ menu are opened over a full-window picture that is white,
 * black, middle grey or half white and half black, in Ink and Paper (named with `&theme=`), at Tinted, Clear and Frosted, at
 * 1440 x 900 and 393 x 852, and their text is measured on the rendered pixels (`glass-pixels.ts`). It runs on what the product
 * ships (`glass-scenes.ts`): no mockup, nothing to skip. Each case also asserts, from a per-frame log, that the surface already
 * carried `data-glass-under="picture"` in the first frame it was visible, so the very first thing a person sees is the safe one.
 *
 * Two passes per case. `adaptive`: a picture the glass can sample, measured once the glass has settled (nothing animating, the
 * tint and text colours unchanged over a sample interval). `floor`: a picture it cannot sample, so the surface never leaves the
 * static floor; that is the surface exactly as the first frame shows it, and it must reach 4.5:1 on its own.
 * The lowest ratio of each case goes to `ratios.jsonl` in the evidence directory next to its screenshot.
 */
import { appendFileSync, writeFileSync } from "node:fs";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { frames, LINE, openScene, PICTURES, putPicture, removePicture, SIZES, surfacesFor, watchFirstFrame } from "./glass-scenes";
import { measure } from "./glass-pixels";
import { settled } from "./glass-settled";

/** Where the captures and the table land. */
const OUT = tracerEvidencePath("glass-surfaces");

for (const size of SIZES) {
  for (const scheme of ["ink", "paper"] as const) {
    for (const surface of surfacesFor(size)) {
      for (const pass of ["adaptive", "floor"] as const) {
        for (const card of [2, 3, 4]) {
          test(`${size.id} ${scheme === "ink" ? "Ink" : "Paper"} card ${card} ${pass}: the ${surface.id} over white, black, grey and split pictures reaches ${LINE}:1`, async ({ browser }) => {
            const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: scheme === "ink" ? "dark" : "light", ...(size.phone ? { hasTouch: true, isMobile: true } : {}) });
            const page = await context.newPage();
            await openScene(page, scheme, card);
            // One page for the four pictures: each is laid, the surface opened afresh over it, measured and closed.
            for (const picture of PICTURES) {
              await putPicture(page, picture, pass === "adaptive" ? "fill" : "cover", surface.host);
              await watchFirstFrame(page, surface.selector);
              await surface.open(page);
              const el = page.locator(surface.selector).first();
              await expect(el).toBeVisible({ timeout: 8000 });
              await settled(page, surface.selector);
              await page.screenshot({ path: `${OUT}/${size.id}-${scheme}-${surface.id}-${picture}-${pass}-card${card}.png` });
              await expect.soft(el, `${picture}: marked as over a picture`).toHaveAttribute("data-glass-under", "picture");
              const first = (await frames(page)).find((f) => f.shown);
              expect.soft(first, `${picture}: the surface was painted`).toBeDefined();
              expect.soft(first?.under, `${picture}: marked as over a picture in the first frame it is visible`).toBe("picture");
              const results = await measure(page, surface.selector);
              expect(results.length, "text runs found").toBeGreaterThan(0);
              if (results[0]!.ratio < LINE) writeFileSync(`${OUT}/low-${size.id}-${scheme}-${surface.id}-${picture}-${pass}-card${card}.png`, results.hidden);
              appendFileSync(`${OUT}/ratios.jsonl`, `${JSON.stringify({ size: size.id, scheme, surface: surface.id, picture, pass, card, lowest: Number(results[0]!.ratio.toFixed(2)), text: results[0]!.text })}\n`);
              expect.soft(results[0]!.ratio, `${picture}: lowest "${results[0]!.text}" ${results[0]!.ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(LINE);
              await surface.close(page);
              await expect(el).toBeHidden({ timeout: 8000 });
              await removePicture(page);
            }
            await context.close();
          });
        }
      }
    }
  }
}
