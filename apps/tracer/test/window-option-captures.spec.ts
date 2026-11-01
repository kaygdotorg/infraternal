/**
 * Review captures of Option / Alt on a window's split buttons (#280, D212): the buttons at rest, with the key held (the
 * morph's end), and mid-morph frames, on a Mac-keyboard and a Windows-keyboard profile, in ink and paper at 1440 x 900 (DPR 2),
 * plus a video of the pair morphing and a new window opening beside. A phone has no modifier (the canvas row carries the
 * other pair), so its capture shows the header with two actions only (393 x 852, DPR 3). Screenshots land in the external
 * evidence directory; the assertions only prove that each state was reached.
 */
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("split-option");
const VIEW = '.cl[data-view="console"]';
const ACTIVE = `${VIEW} .ui-window[data-active]`;
const URL = (theme: string): string => `/?mock=1&proto=clusters&scene=1&theme=${theme}&bg=none`;

async function boot(page: Page, theme: string, platform: string): Promise<void> {
  await page.addInitScript((value) => { Object.defineProperty(navigator, "platform", { get: () => value }); }, platform);
  await page.goto(URL(theme));
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
  await page.locator(`${VIEW} .ui-window .ui-window-body`).first().click({ position: { x: 20, y: 40 } });
  await page.waitForTimeout(500);
}

const hover = async (page: Page): Promise<void> => {
  const box = (await page.locator(`${ACTIVE} [data-action="split-right"]`).boundingBox())!;
  await page.mouse.move(box.x + box.width / 2 - 6, box.y + box.height / 2 - 4);
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 4 });
  await page.waitForTimeout(900);
};

/** The header's top-right: the actions pill and the tooltip under it, cropped so the 2x pixels show the glyphs. */
async function crop(page: Page, file: string): Promise<void> {
  const pill = (await page.locator(`${ACTIVE} .ui-window-actions`).boundingBox())!;
  await page.screenshot({ path: resolve(OUT, file), clip: { x: Math.max(0, pill.x - 190), y: Math.max(0, pill.y - 14), width: 330, height: 96 } });
}

for (const [label, platform, key] of [["mac", "MacIntel", "Option"], ["windows", "Win32", "Alt"]] as const) {
  for (const theme of ["ink", "paper"]) {
    test(`${label} ${theme}: rest, key held, and the new-window click`, async ({ browser }) => {
      test.setTimeout(180_000);
      const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
      const page = await context.newPage();
      await boot(page, theme, platform);
      await hover(page);
      await crop(page, `rest-${label}-${theme}.png`);
      await page.screenshot({ path: resolve(OUT, `rest-full-${label}-${theme}.png`) });
      await page.keyboard.down("Alt");
      await page.waitForTimeout(700);
      await expect(page.locator(`${ACTIVE} [data-action="split-right"]`)).toHaveAttribute("aria-label", "New window right");
      await crop(page, `held-${label}-${theme}.png`);
      await page.screenshot({ path: resolve(OUT, `held-full-${label}-${theme}.png`) });
      void key;
      await page.keyboard.up("Alt");
      await context.close();
    });
  }
}

test("mid-morph frames (the pair at 0, 40, 80, 120 and 200 ms after the key goes down)", async ({ browser }) => {
  test.setTimeout(180_000);
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  const page = await context.newPage();
  await boot(page, "ink", "Win32");
  await hover(page);
  const start = Date.now();
  await page.keyboard.down("Alt");
  for (const ms of [0, 40, 80, 120, 200]) {
    const wait = ms - (Date.now() - start);
    if (wait > 0) await page.waitForTimeout(wait);
    await crop(page, `morph-${String(ms).padStart(3, "0")}ms-windows-ink.png`);
  }
  await page.keyboard.up("Alt");
  await context.close();
});

test("video: Alt held near the buttons, the tooltip changes, a click opens a new window beside", async ({ browser }) => {
  test.setTimeout(180_000);
  const viewport = { width: 1440, height: 900 };
  const context = await browser.newContext({ viewport, deviceScaleFactor: 1, recordVideo: { dir: resolve(OUT, "video"), size: viewport } });
  const page = await context.newPage();
  await boot(page, "ink", "Win32");
  await hover(page);
  await page.waitForTimeout(800);
  await page.keyboard.down("Alt");
  await page.waitForTimeout(1500);
  await page.keyboard.up("Alt");
  await page.waitForTimeout(1200);
  await page.keyboard.down("Alt");
  await page.waitForTimeout(600);
  await page.locator(`${ACTIVE} [data-action="split-right"]`).click();
  await page.keyboard.up("Alt");
  await page.waitForTimeout(2200);
  await context.close();
});

test("a phone has no modifier: the header holds two actions and nothing morphs", async ({ browser }) => {
  test.setTimeout(180_000);
  const context = await browser.newContext({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });
  const page = await context.newPage();
  await page.goto(URL("ink"));
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: resolve(OUT, "phone-ink.png") });
  expect(await page.locator(`${VIEW} .ui-window-actions [data-action="split-right"]`).count()).toBe(0);
  await context.close();
});
