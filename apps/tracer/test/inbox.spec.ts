/**
 * The inbox (D234) against the mock canvas: a pending host-connection unlock reaches the person where they are.
 *
 * Locked: sign-in shows one persistent toast with Unlock; dismissing it moves the item to the sidebar card, and
 * while the sidebar is closed the toggle carries a dot. Unlock from the card clears the card and the dot. A reload
 * after unlocking (a new sign-in) shows nothing. A viewer who is not an administrator sees nothing at all.
 * Review screenshots land in the external job evidence directory.
 */
import { tracerEvidencePath } from "./evidence-path";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

const CAPTURES = tracerEvidencePath("inbox-generic");
mkdirSync(CAPTURES, { recursive: true });
const TITLE = "Host connections are locked";
const LINE = "Unlock host connections";

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
    // A waiting state is not success: the lock glyph shows, not the tick.
    await expect(toast(page).locator(".ui-toast-glyph")).toBeVisible();
    await expect(toast(page).locator(".ui-toast-marker")).toBeHidden();
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
    await expect(card(page)).toContainText("Inbox");
    await expect(card(page).locator(".ui-inbox-count")).toHaveText("1");
    // One compact line, collapsed by default: the explanation and the action are not on screen yet.
    const row = card(page).getByRole("button", { name: LINE });
    await expect(row).toHaveAttribute("aria-expanded", "false");
    await expect(card(page).getByRole("button", { name: "Unlock", exact: true })).toHaveCount(0);
    const sidebar = await page.locator("#sidebar").boundingBox();
    const box = await card(page).boundingBox();
    expect(box && sidebar && box.x >= sidebar.x && box.x + box.width <= sidebar.x + sidebar.width && box.y + box.height <= sidebar.y + sidebar.height).toBeTruthy();
    await page.screenshot({ path: resolve(CAPTURES, `collapsed-${name}.png`) });
    // Expanding grows the card upward inside the sidebar; Enter and Escape work from the row.
    await row.click();
    await expect(row).toHaveAttribute("aria-expanded", "true");
    await expect(card(page).locator(".ui-inbox-body")).toContainText("Confirm with your passkey");
    await page.waitForTimeout(400);
    const open = await card(page).boundingBox();
    expect(open && sidebar && open.y >= sidebar.y && open.y + open.height <= sidebar.y + sidebar.height).toBeTruthy();
    await page.screenshot({ path: resolve(CAPTURES, `expanded-${name}.png`) });
    await row.focus();
    await page.keyboard.press("Escape");
    await expect(row).toHaveAttribute("aria-expanded", "false");
    await expect(card(page).locator(".ui-inbox-panel[inert]")).toHaveCount(1);
    await page.keyboard.press("Enter");
    await expect(row).toHaveAttribute("aria-expanded", "true");
    await page.waitForTimeout(300);
    // The toggle's dot yields to the card while the sidebar is open.
    await expect.poll(() => toggle(page).evaluate((el) => getComputedStyle(el, "::after").opacity)).toBe("0");

    await card(page).getByRole("button", { name: "Unlock", exact: true }).click();
    await expect(card(page)).toHaveCount(0);
    await expect(toggle(page)).not.toHaveAttribute("data-pending", "");
    await expect(toast(page)).toContainText("Host connections unlocked");
    // The outcome keeps the success look.
    await expect(toast(page).locator(".ui-toast-marker")).toBeVisible();
    await expect(toast(page).locator(".ui-toast-glyph")).toBeHidden();
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
  await expect(card(page)).toContainText(LINE);
  await page.screenshot({ path: resolve(CAPTURES, "collapsed-paper-desktop.png") });
  await card(page).getByRole("button", { name: LINE }).click();
  await page.waitForTimeout(400);
  await page.screenshot({ path: resolve(CAPTURES, "expanded-paper-desktop.png") });
});
