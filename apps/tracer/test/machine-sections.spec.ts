/**
 * The machine tab of the details popover (TASTE: no "More" tab). With "Extended machine info" off it lists only the
 * essentials; with it on, every fact sits under a titled section. No control labelled "More" exists either way.
 * Also saves the review captures under captures/machine-sections/.
 */
import { expect, test, type Page } from "playwright/test";

const SIZES = [["desktop", { width: 1440, height: 900 }, false], ["phone", { width: 393, height: 852 }, true], ["phone-small", { width: 375, height: 667 }, true]] as const;
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

for (const [name, viewport, mobile] of SIZES) {
  for (const extended of name === "phone-small" ? [true] : [false, true]) {
    test(`${name}: machine tab with extended info ${extended ? "on" : "off"}`, async ({ browser }) => {
      const context = await browser.newContext(mobile ? { viewport, deviceScaleFactor: 3, hasTouch: true, isMobile: true } : { viewport, deviceScaleFactor: 1 });
      const page = await context.newPage();
      await open(page, extended, mobile);
      // The header names the machine as the machine reports it, so it agrees with the System row.
      await expect(popover(page).locator(".canvas-popover-title")).toHaveText(mobile ? "Ubuntu" : "NixOS");
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

for (const [name, viewport] of [["desktop", { width: 1440, height: 900 }], ["phone", { width: 393, height: 852 }]] as const) {
  test(`${name}: the Hosts section has the Extended info switch, off by default, persisted when turned on`, async ({ browser }) => {
    const context = await browser.newContext(name === "phone" ? { viewport, deviceScaleFactor: 3, hasTouch: true, isMobile: true } : { viewport, deviceScaleFactor: 1 });
    const page = await context.newPage();
    await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(1200);
    // Settings is a view of tiled windows; focus the Hosts window.
    const input = page.getByRole("switch", { name: "Extended info" });
    await page.evaluate(() => (window as unknown as { __tracerClusters: { openSettings(section: string): void } }).__tracerClusters.openSettings("hosts"));
    await page.waitForTimeout(900);
    await expect(input).toHaveCount(1);
    await expect(page.locator('.ui-window[data-window-id="s-hosts"]')).toContainText("Details");
    // The title pill carries the host mark the details popover's Host tab uses.
    const pillIcon = page.locator('.ui-window[data-window-id="s-hosts"] .ui-window-pill svg').first();
    await expect(pillIcon.locator("rect")).toHaveAttribute("width", "18");
    await expect(pillIcon.locator("path")).toHaveAttribute("d", "M8 20h8M12 16v4");
    // It is not in Appearance.
    await expect(page.locator('.ui-window[data-window-id="s-appearance"]').getByRole("switch")).toHaveCount(0);
    await expect(input).not.toBeChecked();
    await page.screenshot({ path: `${SHOTS}/settings-hosts-${name}.png` });
    await input.click();
    await expect(input).toBeChecked();
    expect(await page.evaluate(() => localStorage.getItem("tracer.extended-info"))).toBe("1");
    await context.close();
  });
}
