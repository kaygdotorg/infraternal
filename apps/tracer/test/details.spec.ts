/**
 * The window details popover on the product canvas (#127): a press on a window's pill that does not move opens it,
 * a drag still moves the window, the keyboard opens and closes it, a press outside closes it, every value copies, and on
 * a phone it stays inside the visual viewport and above the key row. Mockup data; the words are the product's.
 */
import { expect, test, type Page } from "playwright/test";

const open = async (page: Page, query = "", size = { width: 1440, height: 900 }): Promise<void> => {
  await page.setViewportSize(size);
  await page.goto(`/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
};
const pill = (page: Page, id = "w-nix-cache") => page.locator(`.ui-window[data-window-id="${id}"] .ui-window-pill`);
const popover = (page: Page) => page.locator(".canvas-popover");

test("a click on the pill opens the popover, with plain names and a subtitle for the technical one", async ({ page }) => {
  await open(page);
  await pill(page).click();
  await expect(popover(page)).toBeVisible();
  await expect(popover(page).locator(".canvas-popover-title")).toHaveText("NixOS");
  await expect(popover(page).locator(".canvas-popover-sub")).toContainText("nix-cache");
  await expect(popover(page).locator(".ui-tab")).toHaveText(["Host", "Connection", "Session"]);
  await expect(popover(page).locator(".ui-kv-key").filter({ hasText: "Address" })).toBeVisible();
  await expect(popover(page).locator(".ui-kv-key").filter({ hasText: "Kernel" })).toHaveCount(1); // D126 default fact, shown without the extended switch
  await popover(page).locator(".ui-tab", { hasText: "Connection" }).click();
  const delay = popover(page).locator(".ui-kv-row", { hasText: "Connection delay" });
  await expect(delay.locator(".ui-kv-hint")).toHaveText("Round-trip time to the server");
  await expect(delay.locator(".ui-kv-value")).toContainText("ms");
  // Every value copies on click.
  await popover(page).locator(".ui-tab", { hasText: "Host" }).click();
  await popover(page).locator(".ui-kv-value").first().click();
  await expect(popover(page).locator(".ui-kv-cell[data-copied]")).toHaveCount(1);
  // The pill toggles it.
  await pill(page).click();
  await expect(popover(page)).toHaveCount(0);
});

test("dragging the pill moves the window and opens nothing", async ({ page }) => {
  await open(page);
  const colOf = (): Promise<string | undefined> => page.locator('.ui-window[data-window-id="w-nix-cache"]').evaluate((n) => (n.parentElement as HTMLElement).dataset.id);
  const before = await colOf();
  const p = (await pill(page).boundingBox())!;
  await page.mouse.move(p.x + p.width / 2, p.y + p.height / 2);
  await page.mouse.down();
  await page.mouse.move(p.x + p.width / 2 + 430, p.y + p.height / 2 + 200, { steps: 14 });
  await page.mouse.up();
  await page.waitForTimeout(700);
  await expect(popover(page)).toHaveCount(0);
  expect(await colOf()).not.toBe(before); // it moved to another column
});

test("the keyboard opens it instantly and Escape closes it; a press outside closes it", async ({ page }) => {
  await open(page);
  await pill(page).focus();
  await page.keyboard.press("Enter");
  await expect(popover(page)).toBeVisible();
  expect(await popover(page).evaluate((n) => n.getAnimations().length)).toBe(0); // no motion for a key
  await page.keyboard.press("Escape");
  await expect(popover(page)).toHaveCount(0);
  await pill(page).focus();
  await page.keyboard.press("Space");
  await expect(popover(page)).toBeVisible();
  await page.mouse.click(700, 760);
  await expect(popover(page)).toHaveCount(0, { timeout: 2000 });
});

test("on a phone the popover stays inside the visual viewport and above the key row", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });
  const page = await context.newPage();
  try {
    await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=soft");
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(1200);
    const target = pill(page, "w-build-01");
    const box = (await target.boundingBox())!;
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await expect(popover(page)).toBeVisible();
    await page.waitForTimeout(400);
    const r = (await popover(page).boundingBox())!;
    const tray = (await page.locator("#keybar").boundingBox())!;
    expect(r.x).toBeGreaterThanOrEqual(0);
    expect(r.x + r.width).toBeLessThanOrEqual(393 + 0.5);
    expect(r.y + r.height).toBeLessThanOrEqual(tray.y + 0.5);
    expect(r.y + r.height).toBeLessThanOrEqual(852);
    // A tap outside closes it.
    await page.touchscreen.tap(300, 93); // the window header beside its pill: the taller popover now covers y=120
    await expect(popover(page)).toHaveCount(0, { timeout: 2000 });
  } finally { await context.close(); }
});
