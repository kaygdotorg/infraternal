/**
 * The machine tab of the details popover (TASTE: no "More" tab). With "Extended machine info" off it lists only the
 * essentials; with it on, every fact sits under a titled section. No control labelled "More" exists either way.
 * Also saves the review captures under captures/machine-sections/.
 */
import { expect, test, type Page } from "playwright/test";

const SHOTS = "captures/machine-sections";
const open = async (page: Page, extended: boolean, mobile: boolean): Promise<void> => {
  await page.addInitScript((on) => { try { localStorage.setItem("tracer.extended-info", on ? "1" : "0"); } catch { /* no storage */ } }, extended);
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  const pill = page.locator(`.ui-window[data-window-id="${mobile ? "w-build-01" : "w-nix-cache"}"] .ui-window-pill`);
  if (mobile) {
    const box = (await pill.boundingBox())!;
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
  } else await pill.click();
  await expect(page.locator(".canvas-popover")).toBeVisible();
  await page.waitForTimeout(400);
};
const popover = (page: Page) => page.locator(".canvas-popover");

for (const [name, viewport, mobile] of [["desktop", { width: 1440, height: 900 }, false], ["phone", { width: 393, height: 852 }, true]] as const) {
  for (const extended of [false, true]) {
    test(`${name}: machine tab with extended info ${extended ? "on" : "off"}`, async ({ browser }) => {
      const context = await browser.newContext(mobile ? { viewport, deviceScaleFactor: 3, hasTouch: true, isMobile: true } : { viewport, deviceScaleFactor: 1 });
      const page = await context.newPage();
      await open(page, extended, mobile);
      await expect(popover(page).getByText("More", { exact: true })).toHaveCount(0);
      await expect(popover(page).getByRole("button", { name: /more/i })).toHaveCount(0);
      const titles = popover(page).locator(".ui-kv-group");
      if (extended) {
        await expect(titles).toHaveText(["System", "Resources", "Access"]);
        await expect(popover(page).locator(".ui-kv-key").filter({ hasText: "Kernel" })).toBeVisible();
        await expect(popover(page).locator(".ui-kv-key").filter({ hasText: "Locale" })).toBeVisible();
      } else {
        await expect(titles).toHaveCount(0);
        await expect(popover(page).locator(".ui-kv-key").filter({ hasText: "Kernel" })).toHaveCount(0);
      }
      await page.screenshot({ path: `${SHOTS}/${name}-ink-${extended ? "on" : "off"}.png` });
      await context.close();
    });
  }
}

test("Settings has the Extended machine info switch, off by default, persisted when turned on", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => {
    const p = (window as unknown as { __tracerClusters: { views(): Array<{ id: string; x: number; y: number }>; setCamera(x: number, y: number, z: number): void } }).__tracerClusters;
    const v = p.views().find((view) => view.id === "settings")!;
    p.setCamera(v.x + 40, v.y + 700, 1);
  });
  await page.waitForTimeout(900);
  const input = page.getByRole("switch", { name: "Extended machine info" });
  await expect(input).toHaveCount(1);
  await input.scrollIntoViewIfNeeded();
  await expect(input).not.toBeChecked();
  await page.screenshot({ path: `${SHOTS}/settings-switch.png` });
  await input.click();
  await expect(input).toBeChecked();
  expect(await page.evaluate(() => localStorage.getItem("tracer.extended-info"))).toBe("1");
});
