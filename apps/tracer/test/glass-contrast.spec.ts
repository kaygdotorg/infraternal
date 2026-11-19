/**
 * Hover and press on glass controls over worst-case pictures (D365, #448): the controls' own fills sit under their labels.
 *
 * `glass-surfaces.spec.ts` measures a surface at rest. A menu row or a card button paints a fill when it is hovered or pressed,
 * and the label sits on that fill, so this opens the two surfaces that carry controls (a window's ⋯ menu and the confirmation
 * card) over a white, black and middle grey picture, in Ink and Paper, at Tinted, Clear and Frosted, at 1440 x 900 and
 * 393 x 852, and measures every text run at rest, with the first and the last control hovered and with them pressed. It runs on
 * the product's own scene (`glass-scenes.ts`); there is no mockup and nothing to skip. The lowest ratio of each state goes to
 * `ratios.jsonl` in the evidence directory.
 */
import { appendFileSync } from "node:fs";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { LINE, openScene, putPicture, removePicture, SIZES, SURFACES } from "./glass-scenes";
import { measure, type Result } from "./glass-pixels";
import { settled } from "./glass-settled";

/** Where the table lands. */
const OUT = tracerEvidencePath("glass-contrast");
/** The surfaces that carry controls. */
const WITH_CONTROLS = SURFACES.filter((s) => s.id === "menu" || s.id === "confirm");

for (const size of SIZES) {
  for (const scheme of ["ink", "paper"] as const) {
    for (const surface of WITH_CONTROLS) {
      for (const card of [2, 3, 4]) {
        test(`${size.id} ${scheme === "ink" ? "Ink" : "Paper"} card ${card}: the ${surface.id}'s controls hovered and pressed reach ${LINE}:1`, async ({ browser }) => {
          const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: scheme === "ink" ? "dark" : "light", ...(size.phone ? { hasTouch: true, isMobile: true } : {}) });
          const page = await context.newPage();
          await openScene(page, scheme, card);
          for (const picture of ["white", "black", "grey"] as const) {
            await putPicture(page, picture, "fill", surface.host);
            await surface.open(page);
            await expect(page.locator(surface.selector).first()).toBeVisible({ timeout: 8000 });
            await settled(page, surface.selector);
            const buttons = page.locator(`${surface.selector} button:not([disabled])`);
            const states: Array<{ state: string; act?: () => Promise<void> }> = [
              { state: "rest" },
              { state: "hover first", act: () => buttons.first().hover() },
              { state: "press first", act: async () => { await buttons.first().hover(); await page.mouse.down(); } },
              // The press is released away from the control, so it is not a click (a click would close the surface).
              { state: "hover last", act: async () => { await page.mouse.move(2, 2); await page.mouse.up(); await buttons.last().hover(); } },
              { state: "press last", act: async () => { await buttons.last().hover(); await page.mouse.down(); } },
            ];
            let worst: Result | undefined, worstState = "";
            for (const { state, act } of states) {
              if (act) await act();
              // Waits for the control's fill to finish easing in, not for a time.
              await settled(page, `${surface.selector} button:not([disabled])`);
              const results = await measure(page, surface.selector);
              expect(results.length, "text runs found").toBeGreaterThan(0);
              appendFileSync(`${OUT}/ratios.jsonl`, `${JSON.stringify({ size: size.id, scheme, surface: surface.id, picture, card, state, lowest: Number(results[0]!.ratio.toFixed(2)), text: results[0]!.text })}\n`);
              if (!worst || results[0]!.ratio < worst.ratio) { worst = results[0]!; worstState = state; }
            }
            await page.mouse.move(2, 2);
            await page.mouse.up();
            expect.soft(worst!.ratio, `${picture}, ${worstState}: lowest "${worst!.text}" ${worst!.ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(LINE);
            await surface.close(page);
            await expect(page.locator(surface.selector).first()).toBeHidden({ timeout: 8000 });
            await removePicture(page);
          }
          await context.close();
        });
      }
    }
  }
}
