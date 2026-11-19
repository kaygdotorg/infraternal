/**
 * Text on glass over worst-case backdrops (D365, #448): the owner's Send keys case, measured on the rendered pixels.
 *
 * The owner saw the Send keys popover's section labels and key hints as faint grey on light grey over a light app window.
 * This spec opens the #146 mockup's popovers (`appmock=desktop&pop=keys` on a desktop, `appmock=phone-app&pop=gear` on a
 * phone) in Ink (dark) and Paper (light), at every card level (`card=1..4`), over four backdrops: the mockup's own light
 * window, the same picture inverted (a dark window), pure white and pure black. For each text run in the popover it takes the
 * run's own colour from the computed style and its backdrop from a screenshot of the popover with all text made
 * transparent, then asserts the lowest contrast against the lightest and the darkest pixel under the run is at least 4.5:1, at
 * rest and with the first and last control hovered and pressed (their fills sit under the labels). Nothing is marked on the
 * window or the stage: the surface must be found to be over a picture by itself (`data-glass-under` on the surface).
 * Measuring pixels (not tokens) means the check also sees blur, saturation, the glass bed and the page behind, which the unit
 * audit (`packages/ui/src/glass-contrast.test.ts`) does not.
 *
 * Screenshots of every case land in the external evidence directory as `<size>-<scheme>-<backdrop>-card<N>.png`, and the lowest
 * contrast of each case as a line of `ratios.jsonl` next to them.
 * Needs the preview build, which this config's web server already builds, and the #146 mockup (skipped without it). The mockup's
 * picture says `data-glass-picture`, as the real stream canvas is found by `packages/ui/src/glass-under.ts`.
 */
import { appendFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { measure, type Result } from "./glass-pixels";

/** The #146 mockup is what these cases open; until it is on this branch they are skipped, and they run the day it lands. */
const HAS_MOCKUP = existsSync(resolve(import.meta.dirname, "../src/canvas/mock/appwin-scenes/mount.on-demand.ts"));
test.skip(!HAS_MOCKUP, "the app-window mockup (#146) is not on this branch");

/** Where this spec writes its screenshots and `ratios.jsonl`. */
const OUT = tracerEvidencePath("glass-contrast");
/** The line every text run must reach (D365). */
const LINE = 4.5;

/** One viewport and the popover that opens in it: its mockup query and the selector that says it is ready. */
interface Size {
  id: string; width: number; height: number; phone: boolean; query: string; ready: string;
  /** What the case is called in its title and file names. */
  what: string;
  /** Only these (scheme, backdrop) pairs, when not every one. */
  only?: Array<["dark" | "light", string]>;
}
/** The desktop's Send keys list, the phone's gear popover and the desktop's close confirmation. */
const SIZES: Size[] = [
  { id: "1440x900", width: 1440, height: 900, phone: false, query: "appmock=desktop&pop=keys", ready: ".awm-keys", what: "" },
  { id: "393x852", width: 393, height: 852, phone: true, query: "appmock=phone-app&pop=gear", ready: ".awm-gearpop", what: "" },
  // The close confirmation (D380) is a glass card that opens centred and is not hit-testable while it opens.
  { id: "1440x900", width: 1440, height: 900, phone: false, query: "appmock=desktop&pop=confirm", ready: '.ui-confirm-tip[data-open="true"]', what: "confirm-", only: [["dark", "white"], ["light", "black"], ["dark", "light"], ["light", "dark"]] },
];

/** CSS that turns the mockup's picture into each backdrop; the popover is not inside `.awm-surface`, so it is untouched. */
const BACKDROPS: Record<string, string> = {
  light: "",
  dark: ".awm-surface { filter: invert(1) hue-rotate(180deg) !important; }",
  white: ".awm-surface { filter: brightness(0) invert(1) !important; }",
  black: ".awm-surface { filter: brightness(0) !important; }",
};

for (const size of SIZES) {
  for (const scheme of ["dark", "light"] as const) {
    for (const [backdrop, css] of Object.entries(BACKDROPS)) {
      if (size.only && !size.only.some(([sc, bd]) => sc === scheme && bd === backdrop)) continue;
      for (const card of size.only ? [2, 3, 4] : [1, 2, 3, 4]) {
        test(`${size.id} ${size.what}${scheme === "dark" ? "Ink" : "Paper"} card ${card} over ${backdrop}: every text run reaches ${LINE}:1`, async ({ browser }) => {
          const context = await browser.newContext({
            viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: scheme,
            ...(size.phone ? { hasTouch: true, isMobile: true } : {}),
          });
          const page = await context.newPage();
          // `theme=` is explicit: without it the page picks Mocha or Latte from the colour scheme, not Ink or Paper.
          await page.goto(`/?mock=1&proto=clusters&fps=0&theme=${scheme === "dark" ? "ink" : "paper"}&${size.query}&card=${card}`);
          await expect(page.locator(".awm")).toBeVisible({ timeout: 20_000 });
          await expect(page.locator(size.ready).first()).toBeVisible({ timeout: 8000 });
          if (css) await page.addStyleTag({ content: css });
          await page.evaluate(() => document.fonts.ready);
          // sleep: the popover grows in over 200 ms and the filter's transition runs 200 ms
          await page.waitForTimeout(900);
          await page.screenshot({ path: `${OUT}/${size.id}-${size.what}${scheme === "dark" ? "ink" : "paper"}-${backdrop}-card${card}.png` });
          // The surface itself is marked as being over a picture, with nothing marked on the window or the stage.
          await expect(page.locator(size.ready).first()).toHaveAttribute("data-glass-under", "picture");
          // Rest, then the first and the last control hovered and pressed: hover and press paint fills under labels (D365, #448).
          const buttons = page.locator(`${size.ready} button:not([disabled])`);
          const states: Array<{ state: string; act?: () => Promise<void> }> = [
            { state: "rest" },
            { state: "hover first", act: () => buttons.first().hover() },
            { state: "press first", act: async () => { await buttons.first().hover(); await page.mouse.down(); } },
            // The press is released away from the button, so it is not a click (a click would close the popover).
            { state: "hover last", act: async () => { await page.mouse.move(2, 2); await page.mouse.up(); await buttons.last().hover(); } },
            { state: "press last", act: async () => { await buttons.last().hover(); await page.mouse.down(); } },
          ];
          let worst: Result | undefined, worstState = "";
          for (const { state, act } of states) {
            if (act) await act();
            // sleep: the control's hover colour eases in over 160 ms
            if (act) await page.waitForTimeout(250);
            const results = await measure(page, size.ready);
            expect(results.length, "text runs found in the popover").toBeGreaterThan(3);
            // One line per case and state, so a run leaves a table of the lowest contrast it measured, passing or not.
            appendFileSync(`${OUT}/ratios.jsonl`, `${JSON.stringify({ size: size.id, what: size.what, scheme, backdrop, card, state, lowest: Number(results[0]!.ratio.toFixed(2)), text: results[0]!.text, colour: results[0]!.colour })}\n`);
            if (!worst || results[0]!.ratio < worst.ratio) { worst = results[0]!; worstState = state; }
          }
          expect(worst!.ratio, `lowest (${worstState}): "${worst!.text}" ${worst!.colour} ${worst!.ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(LINE);
          await context.close();
        });
      }
    }
  }
}
