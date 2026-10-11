/**
 * The inbox (D234) against the mock canvas: a pending host-connection unlock reaches the person where they are.
 *
 * Locked: sign-in shows one persistent toast with Unlock; dismissing it moves the item to the sidebar card, and
 * while the sidebar is closed the toggle carries a dot. Unlock from the card clears the card and the dot. A reload
 * after unlocking (a new sign-in) shows nothing. A viewer who is not an administrator sees nothing at all.
 * Captures land in captures/inbox/ for the visual review.
 */
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

const CAPTURES = resolve(import.meta.dirname, "..", "captures", "inbox");
mkdirSync(CAPTURES, { recursive: true });
const TITLE = "Host connections are locked";

async function signIn(page: Page, query: string, theme = "ink"): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=${query.includes("role=") ? 5 : 3}&theme=${theme}&${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
}

const toast = (page: Page) => page.locator(".ui-toast:not([hidden])");
const card = (page: Page) => page.locator(".ui-inbox:not([hidden])");
const toggle = (page: Page) => page.locator("#sidebar-toggle");

async function openSidebar(page: Page): Promise<void> {
  await toggle(page).click();
  await expect(page.locator("#sidebar")).toBeVisible();
  await page.waitForTimeout(500);
}

for (const [name, viewport, scale] of [["desktop", { width: 1440, height: 900 }, 1], ["phone", { width: 393, height: 852 }, 3], ["small", { width: 375, height: 667 }, 2]] as const) {
  test(`locked: toast, then inbox card and dot, then unlocked (${name})`, async ({ browser }) => {
    const context = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(name !== "desktop" ? { hasTouch: true, isMobile: true } : {}) });
    const page = await context.newPage();
    await signIn(page, "ca=locked");
    await expect(toast(page)).toContainText(TITLE, { timeout: 8000 });
    await expect(toast(page).getByRole("button", { name: "Unlock" })).toBeVisible();
    // The item waits behind its toast: no card, no dot yet.
    await expect(card(page)).toHaveCount(0);
    await expect(toggle(page)).not.toHaveAttribute("data-pending", "");
    await page.waitForTimeout(400);
    await page.screenshot({ path: resolve(CAPTURES, `toast-${name}.png`) });

    await toast(page).getByRole("button", { name: "Dismiss" }).click();
    await expect(toggle(page)).toHaveAttribute("data-pending", "");
    await expect(toggle(page)).toHaveAttribute("aria-label", /1 waiting for you/);
    await page.waitForTimeout(400);
    await page.screenshot({ path: resolve(CAPTURES, `closed-dot-${name}.png`) });

    await openSidebar(page);
    await expect(card(page)).toContainText(TITLE);
    const sidebar = await page.locator("#sidebar").boundingBox();
    const box = await card(page).boundingBox();
    expect(box && sidebar && box.x >= sidebar.x && box.x + box.width <= sidebar.x + sidebar.width && box.y + box.height <= sidebar.y + sidebar.height).toBeTruthy();
    await page.screenshot({ path: resolve(CAPTURES, `card-${name}.png`) });
    // The toggle's dot yields to the card while the sidebar is open.
    await expect.poll(() => toggle(page).evaluate((el) => getComputedStyle(el, "::after").opacity)).toBe("0");

    await card(page).getByRole("button", { name: "Unlock" }).click();
    await expect(card(page)).toHaveCount(0);
    await expect(toggle(page)).not.toHaveAttribute("data-pending", "");
    await expect(toast(page)).toContainText("Host connections unlocked");
    await page.waitForTimeout(500);
    await page.screenshot({ path: resolve(CAPTURES, `unlocked-${name}.png`) });

    // A new sign-in finds it unlocked: no toast, no card, no dot.
    await page.reload();
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(2500);
    await expect(toast(page)).toHaveCount(0);
    await expect(card(page)).toHaveCount(0);
    await expect(toggle(page)).not.toHaveAttribute("data-pending", "");
    await context.close();
  });
}

test("the toast's own action unlocks and leaves nothing behind", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, "ca=locked");
  await toast(page).getByRole("button", { name: "Unlock" }).click({ timeout: 8000 });
  await expect(toast(page)).toContainText("Host connections unlocked");
  await expect(card(page)).toHaveCount(0);
  await expect(toggle(page)).not.toHaveAttribute("data-pending", "");
});

test("an unlock in another tab clears the item here when the page returns", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, "ca=locked");
  await expect(toast(page)).toContainText(TITLE, { timeout: 8000 });
  await toast(page).getByRole("button", { name: "Dismiss" }).click();
  await expect(toggle(page)).toHaveAttribute("data-pending", "");
  // The server's answer changes (here: the double's storage); the page learns it the next time it is shown.
  await page.evaluate(() => sessionStorage.setItem("mock-ca-unlocked", "1"));
  await page.waitForTimeout(5300);
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await expect(toggle(page)).not.toHaveAttribute("data-pending", "");
});

test("already unlocked: no toast, no card, no dot", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, "ca=ready");
  await page.waitForTimeout(2500);
  await expect(toast(page)).toHaveCount(0);
  await expect(card(page)).toHaveCount(0);
  await expect(toggle(page)).not.toHaveAttribute("data-pending", "");
});

test("a viewer who is not an administrator sees nothing", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, "ca=locked&role=viewer");
  await page.waitForTimeout(2500);
  await expect(toast(page)).toHaveCount(0);
  await expect(card(page)).toHaveCount(0);
  await expect(toggle(page)).not.toHaveAttribute("data-pending", "");
});

test("paper theme: the card reads on light glass", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await signIn(page, "ca=locked", "paper");
  await toast(page).getByRole("button", { name: "Dismiss" }).click({ timeout: 8000 });
  await openSidebar(page);
  await expect(card(page)).toContainText(TITLE);
  await page.screenshot({ path: resolve(CAPTURES, "card-paper-desktop.png") });
});
