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

/** The table of ratios. */
const OUT = tracerEvidencePath("glass-contrast", "ratios.jsonl");
/** The surfaces that carry controls. */
const WITH_CONTROLS = SURFACES.filter((s) => s.id === "menu" || s.id === "confirm");

for (const size of SIZES) {
  for (const scheme of ["ink", "paper"] as const) {
    for (const surface of WITH_CONTROLS.filter((s) => s.phone || !size.phone)) {
      for (const card of [2, 3, 4]) {
        test(`${size.id} ${scheme === "ink" ? "Ink" : "Paper"} card ${card}: the ${surface.id}'s controls hovered and pressed reach ${LINE}:1`, async ({ browser }) => {
          // Three pictures with five states each: more than the default 90 s on a loaded host.
          test.setTimeout(300_000);
          const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: scheme === "ink" ? "dark" : "light", ...(size.phone ? { hasTouch: true, isMobile: true } : {}) });
          const page = await context.newPage();
          await openScene(page, scheme, card);
          const cdp = await context.newCDPSession(page);
          await cdp.send("DOM.enable");
          await cdp.send("CSS.enable");
          for (const picture of ["white", "black", "grey"] as const) {
            await putPicture(page, picture, "fill", surface.host);
            await surface.open(page);
            await expect(page.locator(surface.selector).first()).toBeVisible({ timeout: 8000 });
            await settled(page, surface.selector);
            // Hover and press are forced on the control through the browser's own pseudo-state hook, not by moving a pointer to it: a
            // menu that opens over the top bar has its first row under another element, which would take the pointer instead.
            const force = async (which: "first" | "last" | "none", states: string[]): Promise<void> => {
              const { root } = await cdp.send("DOM.getDocument", { depth: 0 });
              const { nodeIds } = await cdp.send("DOM.querySelectorAll", { nodeId: root.nodeId, selector: `${surface.selector} button:not([disabled])` });
              for (const nodeId of nodeIds) await cdp.send("CSS.forcePseudoState", { nodeId, forcedPseudoClasses: [] });
              const target = which === "first" ? nodeIds[0] : which === "last" ? nodeIds.at(-1) : undefined;
              if (target !== undefined) await cdp.send("CSS.forcePseudoState", { nodeId: target, forcedPseudoClasses: states });
            };
            const states: Array<{ state: string; act: () => Promise<void> }> = [
              { state: "rest", act: () => force("none", []) },
              { state: "hover first", act: () => force("first", ["hover"]) },
              { state: "press first", act: () => force("first", ["hover", "active"]) },
              { state: "hover last", act: () => force("last", ["hover"]) },
              { state: "press last", act: () => force("last", ["hover", "active"]) },
            ];
            let worst: Result | undefined, worstState = "";
            for (const { state, act } of states) {
              await act();
              // Waits for the control's fill to finish easing in, not for a time.
              await settled(page, `${surface.selector} button:not([disabled])`);
              const results = await measure(page, surface.selector);
              expect(results.length, "text runs found").toBeGreaterThan(0);
              appendFileSync(OUT, `${JSON.stringify({ size: size.id, scheme, surface: surface.id, picture, card, state, lowest: Number(results[0]!.ratio.toFixed(2)), text: results[0]!.text })}\n`);
              if (!worst || results[0]!.ratio < worst.ratio) { worst = results[0]!; worstState = state; }
            }
            await force("none", []);
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
