/**
 * Screenshots of the window actions on a stacked column (D212), for review against TASTE.md. Run on demand:
 * `D212_CAPTURE=1 bun x playwright test test/clusters-splits-captures.spec.ts`. The PNGs land in
 * captures/splits-d212/ as `<viewport>-<theme>-<step>.png`.
 *
 * The steps: a column of three windows (two split downs), then split right on the middle window (refused: it shares
 * its column), split down on it, new window right, new window below. Each step is captured after it has settled.
 */
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

const enabled = process.env.D212_CAPTURE === "1";
const OUT = resolve(import.meta.dirname, "..", "captures", "splits-d212");
const VIEWPORTS = [{ w: 1440, h: 900 }, { w: 393, h: 852 }] as const;
const THEMES = ["ink", "paper"] as const;

/** A phone is a touch device: the window header and the canvas row follow `coarse` (the split-focus spec does the same). */
async function boot(page: Page, theme: string, w: number, h: number): Promise<void> {
  await page.setViewportSize({ width: w, height: h });
  await page.goto(`/?mock=1&proto=clusters&scene=1&theme=${theme}&bg=none`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
  await page.locator('.cl[data-view="console"] .ui-window .ui-window-body').first().click({ position: { x: 20, y: 40 } });
  await page.waitForTimeout(500);
}

async function press(page: Page, chord: string[]): Promise<void> {
  for (const k of chord) await page.keyboard.down(k);
  for (const k of [...chord].reverse()) await page.keyboard.up(k);
  await page.waitForTimeout(900);
}

test.describe("D212 captures", () => {
  test.skip(!enabled, "set D212_CAPTURE=1 to take the screenshots");
  test.setTimeout(600_000);

  for (const v of VIEWPORTS) {
    for (const theme of THEMES) {
      test(`${v.w}x${v.h} ${theme}: a stacked column through the four actions`, async ({ browser }) => {
        const phone = v.w < 720;
        const context = await browser.newContext({
          baseURL: `http://localhost:${process.env.TRACER_TEST_PORT ?? "4621"}`,
          viewport: { width: v.w, height: v.h },
          deviceScaleFactor: phone ? 3 : 2,
          ...(phone ? { hasTouch: true, isMobile: true } : {}),
        });
        const page = await context.newPage();
        mkdirSync(OUT, { recursive: true });
        const shot = (step: string): Promise<Buffer> => page.screenshot({ path: resolve(OUT, `${v.w}x${v.h}-${theme}-${step}.png`) });
        await boot(page, theme, v.w, v.h);
        // Stack the active window twice: a column of three.
        await press(page, ["Control", "Shift", "Alt", "KeyD"]);
        await press(page, ["Control", "Shift", "Alt", "KeyD"]);
        await shot("1-stack-before");
        // Split right on the middle window: it shares its column, so it is refused and says why.
        await page.locator('.cl[data-view="console"] .ui-window').nth(1).locator(".ui-window-body").click({ position: { x: 20, y: 40 } });
        await page.waitForTimeout(400);
        await press(page, ["Control", "Shift", "KeyD"]);
        await page.waitForTimeout(300);
        await shot("2-split-right-refused");
        await press(page, ["Control", "Shift", "Alt", "KeyD"]);
        await shot("3-split-down");
        await press(page, ["Control", "Alt", "KeyR"]);
        await shot("4-new-window-right");
        await press(page, ["Control", "Alt", "KeyD"]);
        await shot("5-new-window-below");
        await context.close();
      });
    }
  }
});
