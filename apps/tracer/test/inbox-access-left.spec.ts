/**
 * What a revoked person left behind (D356, D398) as an Inbox item, against the mock canvas (`?accessleft=`).
 *
 * The owner sees one line per report with the host first; opening it shows the server's sentence and the files and
 * lines, and Dismiss removes it. A clean report says "No changes found in the N places we watch ... Access outside
 * these checks isn't covered." and never "unchanged". A report that arrives while the page is open is said once in a
 * toast and then waits in the Inbox. Someone who is not the owner sees nothing. Review screenshots (production build,
 * desktop and phone, ink and paper) land in the external job evidence directory.
 */
import { tracerEvidencePath } from "./evidence-path";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

/** Where the review screenshots go (outside the checkout). */
const OUT = tracerEvidencePath("access-left");
/** The toast that is showing. */
const toast = (page: Page) => page.locator(".ui-toast:not([hidden])");
/** The Inbox card, when it is drawn. */
const card = (page: Page) => page.locator(".ui-inbox:not([hidden])");

/** Open the mock canvas with the scene in `query`, in `theme`. */
async function open(page: Page, query: string, theme = "ink"): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=${query.includes("role=") ? 5 : 3}&theme=${theme}&${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
}

/** Open the sidebar, where the Inbox card lives, and let its motion finish. */
async function openSidebar(page: Page): Promise<void> {
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#sidebar")).toBeVisible();
  // sleep: the card grows out of the pill; the screenshot and the next click wait for the 180 ms transition to end.
  await page.waitForTimeout(500);
}

for (const [name, viewport, scale] of [["desktop", { width: 1440, height: 900 }, 2], ["phone", { width: 393, height: 852 }, 3]] as const) {
  for (const theme of ["ink", "paper"]) {
    test(`a changed report: the line, then its files and lines (${name}, ${theme})`, async ({ browser }) => {
      const context = await browser.newContext({ viewport, deviceScaleFactor: scale, ...(name === "phone" ? { hasTouch: true, isMobile: true } : {}) });
      const page = await context.newPage();
      await open(page, "accessleft=changed", theme);
      await openSidebar(page);
      const row = card(page).getByRole("button", { name: /build-01: access left behind/ });
      await expect(row).toBeVisible({ timeout: 8000 });
      await expect(card(page).locator(".ui-inbox-count")).toHaveText("1");
      await page.screenshot({ path: resolve(OUT, `changed-collapsed-${name}-${theme}.png`) });
      await row.click();
      await expect(row).toHaveAttribute("aria-expanded", "true");
      const body = card(page).locator(".ui-inbox-body");
      await expect(body).toContainText("Dana was revoked here and the host stayed.");
      const details = card(page).locator(".ui-inbox-details");
      await expect(details).toBeVisible();
      await expect(details).toContainText("~/.ssh/authorized_keys");
      await expect(details).toContainText("+ ssh-ed25519 AAAAC3NzaC1lZDI1NTE5");
      await expect(details).toContainText("infraternal did not change these files.");
      // sleep: the line opens by a 180 ms height transition; the screenshot waits for it to settle.
      await page.waitForTimeout(400);
      await page.screenshot({ path: resolve(OUT, `changed-expanded-${name}-${theme}.png`) });
      await context.close();
    });
  }
}

test("a clean report says what was watched and what it does not cover, never 'unchanged'", async ({ page }) => {
  await open(page, "accessleft=clean");
  await openSidebar(page);
  const row = card(page).getByRole("button", { name: /web-02: no changes found/ });
  await row.click();
  const body = card(page).locator(".ui-inbox-body");
  await expect(body).toContainText("No changes found in the 214 places we watch");
  await expect(body).toContainText("They had no root access through sudo, doas, polkit or admin groups.");
  await expect(body).toContainText("Access outside these checks isn't covered.");
  expect((await card(page).innerText()).toLowerCase()).not.toContain("unchanged");
});

test("three reports, one open at a time, and Dismiss removes only that one", async ({ page }) => {
  await open(page, "accessleft=all");
  await openSidebar(page);
  await expect(card(page).locator(".ui-inbox-row")).toHaveCount(3, { timeout: 8000 });
  await expect(card(page).locator(".ui-inbox-count")).toHaveText("3");
  await card(page).getByRole("button", { name: /pi-garage: not fully checked/ }).click();
  // Collapsed lines stay in the page (inert), so the open one is addressed by its state.
  const opened = card(page).locator('.ui-inbox-item[data-expanded="true"]');
  await expect(opened.locator(".ui-inbox-details")).toContainText("not verified");
  await opened.getByRole("button", { name: "Dismiss" }).click();
  await expect(card(page).locator(".ui-inbox-row")).toHaveCount(2);
  await expect(card(page).getByRole("button", { name: /pi-garage/ })).toHaveCount(0);
  await expect(card(page).getByRole("button", { name: /build-01: access left behind/ })).toBeVisible();
});

test("a report that arrives while the page is open is said once in a toast, then waits in the Inbox", async ({ page }) => {
  await open(page, "accessleft=changed&accesslater=1");
  await expect(card(page)).toHaveCount(0);
  await expect(toast(page)).toContainText("Dana left access behind on build-01. See the list in your Inbox.", { timeout: 10_000 });
  await openSidebar(page);
  await expect(card(page).getByRole("button", { name: /build-01: access left behind/ })).toBeVisible();
});

test("someone who is not the owner sees no report", async ({ page }) => {
  await open(page, "accessleft=changed&role=viewer");
  // sleep: a negative check: wait past the first ask (1.5 s) so a wrongly shown card would have appeared.
  await page.waitForTimeout(2500);
  await expect(page.locator(".ui-inbox:not([hidden])")).toHaveCount(0);
});
