/**
 * Every glass surface over a picture, not only popovers (D365, #448).
 *
 * The palette and a toast were never covered by the contrast floor, because only two components asked for it. One watcher
 * now covers every glass surface, so this opens the palette and a toast (the #146 mockup's Screenshot action) over a
 * full-window picture that is pure white or pure black, in Ink and Paper (named with `&theme=`), at Tinted, Clear and Frosted,
 * at 1440 x 900 and 393 x 852, and measures their text on the rendered pixels (`glass-pixels.ts`). Each also asserts that the
 * surface was found to be over a picture (`data-glass-under="picture"`).
 *
 * The picture is a real `<img>` inside the terminal screen (the stacking context the palette and toasts live in) at a z-index below theirs, so it is under them as a stream is, and it is what a hit test sees. The toast is raised by dispatching the menu item's click, so
 * the picture covering the page does not need to be clicked through. Skipped until the #146 mockup is on the branch.
 */
import { appendFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";
import { measure } from "./glass-pixels";

/** Whether the #146 mockup this spec opens is on this branch. */
const HAS_MOCKUP = existsSync(resolve(import.meta.dirname, "../src/canvas/mock/appwin-scenes/mount.on-demand.ts"));
test.skip(!HAS_MOCKUP, "the app-window mockup (#146) is not on this branch");

/** Where the captures and the table land. */
const OUT = tracerEvidencePath("glass-surfaces");
/** The line every text run must reach (D365). */
const LINE = 4.5;
/** A one pixel PNG of each colour, stretched to the window. */
const PIXEL = { white: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGP4//8/AAX+Av4N70a4AAAAAElFTkSuQmCC", black: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR4nGNgYGAAAAAEAAH2FzhVAAAAAElFTkSuQmCC" } as const;

for (const size of [{ id: "1440x900", width: 1440, height: 900, phone: false }, { id: "393x852", width: 393, height: 852, phone: true }]) {
  for (const [scheme, backdrop] of [["ink", "white"], ["paper", "black"], ["ink", "black"], ["paper", "white"]] as const) {
    // The toast is raised from the desktop scene's window menu; the phone scene has none, so toasts are measured at the desktop size only.
    for (const surface of (size.phone ? ["palette"] : ["palette", "toast"]) as Array<"palette" | "toast">) {
      for (const card of [2, 3, 4]) {
        test(`${size.id} ${scheme === "ink" ? "Ink" : "Paper"} card ${card}: the ${surface} over a ${backdrop} picture reaches ${LINE}:1`, async ({ browser }) => {
          const context = await browser.newContext({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: 2, colorScheme: scheme === "ink" ? "dark" : "light", ...(size.phone ? { hasTouch: true, isMobile: true } : {}) });
          const page = await context.newPage();
          const scene = size.phone ? "phone-app" : "desktop";
          await page.goto(`/?mock=1&proto=clusters&fps=0&theme=${scheme}&appmock=${scene}${surface === "toast" ? "&pop=more" : ""}&card=${card}`);
          await expect(page.locator(".awm")).toBeVisible({ timeout: 20_000 });
          if (surface === "toast") await expect(page.locator(".ui-window-menu").first()).toBeVisible({ timeout: 8000 });
          await page.evaluate((src) => {
            const img = document.createElement("img");
            img.src = `data:image/png;base64,${src}`;
            img.style.cssText = "position:fixed;inset:0;width:100vw;height:100vh;object-fit:fill;z-index:20";
            (document.querySelector("#terminal-screen") ?? document.body).append(img);
            return img.decode();
          }, PIXEL[backdrop]);
          let selector: string;
          if (surface === "palette") {
            await page.keyboard.press("Control+Shift+K");
            selector = "#palette";
          } else {
            await page.locator('.ui-window-menu [role="menuitem"]', { hasText: "Screenshot" }).dispatchEvent("click");
            selector = ".ui-toast";
          }
          await expect(page.locator(selector).first()).toBeVisible({ timeout: 8000 });
          // sleep: the surface grows in over 200 ms and the watcher marks it within a frame
          await page.waitForTimeout(700);
          await page.screenshot({ path: `${OUT}/${size.id}-${scheme}-${surface}-${backdrop}-card${card}.png` });
          await expect(page.locator(selector).first()).toHaveAttribute("data-glass-under", "picture");
          const results = await measure(page, selector);
          appendFileSync(`${OUT}/ratios.jsonl`, `${JSON.stringify({ size: size.id, scheme, surface, backdrop, card, lowest: Number(results[0]!.ratio.toFixed(2)), text: results[0]!.text })}\n`);
          expect(results[0]!.ratio, `lowest: "${results[0]!.text}" ${results[0]!.ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(LINE);
          await context.close();
        });
      }
    }
  }
}
