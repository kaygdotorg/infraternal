/**
 * Unlocking host connections from the palette and Settings → Hosts (D168, D217), against the mock canvas.
 *
 * Locked: the palette offers "Unlock host connections" and Settings shows "Locked" with an Unlock button. After the
 * ceremony the row is gone and Settings says "Unlocked". A viewer who is not an administrator sees the state and
 * no button, and the palette offers nothing. Review screenshots land in the external job evidence directory.
 */
import { paletteOpen } from "./settings-palette";
import { tracerEvidencePath } from "./evidence-path";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

const CAPTURES = tracerEvidencePath("ca-unlock");
mkdirSync(CAPTURES, { recursive: true });
const LABEL = "Unlock host connections";
const SETTINGS_ROW = '.ui-sp [data-kind="host-connections"]';

async function open(page: Page, query: string): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=${query.includes("role=") ? 5 : 3}&theme=ink&${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  // The state is learned shortly after the first paint.
  await page.waitForTimeout(1800);
}

async function paletteLabels(page: Page, filter = ""): Promise<string[]> {
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible();
  if (filter) await page.keyboard.type(filter);
  await page.waitForTimeout(250);
  return page.locator("#palette-results .result-label").allTextContents();
}

async function openSettingsHosts(page: Page): Promise<void> {
  await paletteOpen(page, "Terminal › Hosts", "terminal.hosts");
  await expect(page.locator(".ui-sp [data-kind=extended-info]")).toBeVisible({ timeout: 5000 });
  await page.waitForTimeout(900);
}

for (const [name, viewport, scale] of [["desktop", { width: 1440, height: 900 }, 1], ["phone", { width: 393, height: 852 }, 3]] as const) {
  test(`locked then unlocked (${name})`, async ({ browser }) => {
    const context = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });
    const page = await context.newPage();
    await open(page, "ca=locked");
    const labels = await paletteLabels(page, "unlock");
    expect(labels).toContain(LABEL);
    await page.screenshot({ path: resolve(CAPTURES, `palette-row-${name}.png`) });
    await page.keyboard.press("Escape");

    await openSettingsHosts(page);
    const row = page.locator(SETTINGS_ROW);
    await expect(row).toContainText("Locked until an administrator confirms with a passkey");
    const button = row.locator("button");
    await expect(button).toHaveText("Unlock");
    await expect(button).toBeEnabled();
    await page.screenshot({ path: resolve(CAPTURES, `settings-locked-${name}.png`) });
    await button.click();
    await expect(row).toContainText("Unlocked");
    await expect(button).toHaveAttribute("data-shown", "false");
    await page.waitForTimeout(500);
    await page.screenshot({ path: resolve(CAPTURES, `settings-unlocked-${name}.png`) });

    // The palette row is gone.
    const after = await paletteLabels(page, "unlock");
    expect(after).not.toContain(LABEL);
    await context.close();
  });
}

test("the palette row runs the ceremony and the lock clears", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page, "ca=locked");
  await paletteLabels(page, "unlock host");
  await page.keyboard.press("Enter");
  await expect(page.locator("#palette")).toBeHidden();
  await expect(page.locator(".ui-toast")).toContainText("Host connections unlocked");
  expect(await paletteLabels(page, "unlock host")).not.toContain(LABEL);
  await page.keyboard.press("Escape");
  await openSettingsHosts(page);
  await expect(page.locator(SETTINGS_ROW)).toContainText("Unlocked");
});

test("already unlocked: no palette row, Settings says Unlocked with no button", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page, "ca=ready");
  expect(await paletteLabels(page, "unlock")).not.toContain(LABEL);
  await page.keyboard.press("Escape");
  await openSettingsHosts(page);
  await expect(page.locator(SETTINGS_ROW)).toContainText("Unlocked");
  await expect(page.locator(SETTINGS_ROW).locator("button")).toHaveAttribute("data-shown", "false");
});

test("a viewer who is not an administrator sees the state and no button", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page, "ca=locked&role=viewer");
  expect(await paletteLabels(page, "unlock")).not.toContain(LABEL);
  await page.keyboard.press("Escape");
  await openSettingsHosts(page);
  const row = page.locator(SETTINGS_ROW);
  await expect(row).toContainText("Locked until an administrator confirms with a passkey");
  await expect(row.locator("button")).toHaveAttribute("data-shown", "false");
  await expect(row.locator("button")).toHaveAttribute("inert", "");
});

test("the inbox line is collapsed, expands to Unlock, and unlocking clears the card", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page, "ca=locked");
  await page.locator(".ui-toast").getByRole("button", { name: "Dismiss" }).click({ timeout: 8000 });
  await page.locator("#sidebar-toggle").click();
  const card = page.locator(".ui-inbox:not([hidden])");
  const line = card.getByRole("button", { name: LABEL });
  await expect(line).toHaveAttribute("aria-expanded", "false");
  await expect(card.getByRole("button", { name: "Unlock", exact: true })).toHaveCount(0);
  await line.click();
  const unlock = card.getByRole("button", { name: "Unlock", exact: true });
  await expect(unlock).toBeVisible();
  await unlock.click();
  await expect(card).toHaveCount(0);
  await expect(page.locator(".ui-toast")).toContainText("Host connections unlocked");
});
