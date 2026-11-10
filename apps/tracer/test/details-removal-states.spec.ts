// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The states of Remove host at the end of the machine card's Connection tab (D385, #486 review F1–F3), on the windows
 * prototype's removal double (`?removal=1|pending|fail|refused`; it answers after 400 ms and changes nothing):
 * Remove succeeding, a removal left pending, a failure and a refusal shown in the panel with a retry, the host going
 * offline or already removed while the question is open, the question resetting on a tab change, and where the focus goes
 * after Keep, Escape and Remove. Functional: it asserts states and focus, never speed.
 */
import { expect, test, type Page } from "playwright/test";

/** The double's host state the spec plays: set on the page, read by the card on its next refresh. */
type Status = "ready" | "offline" | "gone";

/** Opens the first window's machine card with the removal double in `mode` and shows the Connection tab. */
async function openConnection(page: Page, mode: string): Promise<void> {
  await page.context().request.post("/__mock/reset").catch(() => undefined);
  await page.goto(`/?mock=1&proto=windows&bg=none&fixture=none&removal=${mode}`);
  await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0), { timeout: 30_000 }).toBeGreaterThan(2);
  await page.locator(".ui-window").first().locator(".ui-window-pill").click();
  await expect(page.locator(".canvas-popover")).toBeVisible();
  await page.locator(".canvas-popover .ui-tab", { hasText: "Connection" }).click();
  await expect(page.locator(".canvas-popover-action .ui-sp-row")).toBeVisible();
}
/** The danger row at the end of the Connection tab. */
const row = (page: Page) => page.locator(".canvas-popover-action .ui-sp-row");
/** The in-panel question. */
const ask = (page: Page) => page.locator(".canvas-popover-ask");
/** The question's confirming button. */
const yes = (page: Page) => ask(page).locator("[data-yes]");
/** The question's Keep button. */
const keep = (page: Page) => ask(page).locator("[data-keep]");
/** The question's note line (pending, failure, outcome). */
const note = (page: Page) => ask(page).locator(".canvas-popover-ask-note");
/** Whether the focused element is `selector`'s element. */
const focused = (page: Page, selector: string): Promise<boolean> => page.evaluate((s) => document.activeElement === document.querySelector(s), selector);
/** Plays the host's state changing while the question is open. */
const setStatus = (page: Page, status: Status): Promise<void> => page.evaluate((s) => { (window as unknown as { __removalStatus?: string }).__removalStatus = s; }, status);

test("Remove: both buttons are disabled and say Removing… while it runs, the focus stays in the question, then the card closes", async ({ page }) => {
  await openConnection(page, "1");
  await row(page).click();
  await yes(page).click();
  await expect(yes(page)).toBeDisabled();
  await expect(keep(page)).toBeDisabled();
  await expect(yes(page)).toHaveText("Removing…");
  await expect(note(page)).toHaveText("Removing…");
  expect(await focused(page, ".canvas-popover-ask"), "focus moves to the question, not lost to a disabled button").toBe(true);
  await expect(page.locator(".canvas-popover")).toHaveCount(0); // removed: the card closes with the host's window
});

test("a removal left pending says so in the panel and keeps the card open with the answers disabled", async ({ page }) => {
  await openConnection(page, "pending");
  await row(page).click();
  await yes(page).click();
  await expect(note(page)).toHaveText("Access revoked. It uninstalls infraternal as soon as it connects.");
  await expect(yes(page)).toBeDisabled();
  await expect(keep(page)).toBeDisabled();
  await expect(page.locator(".canvas-popover")).toBeVisible();
});

test("a failure shows its reason in the panel as an alert, Remove becomes Try again, and a retry can succeed", async ({ page }) => {
  await openConnection(page, "fail");
  await row(page).click();
  await yes(page).click();
  await expect(note(page)).toHaveText("The host could not be removed. Sign in again, then try again.");
  await expect(note(page)).toHaveAttribute("role", "alert");
  await expect(yes(page)).toHaveText("Try again");
  await expect(yes(page)).toBeEnabled();
  await expect(keep(page)).toBeEnabled();
  expect(await focused(page, ".canvas-popover-ask [data-yes]"), "focus lands on Try again").toBe(true);
  await yes(page).click();
  await expect(page.locator(".canvas-popover")).toHaveCount(0);
});

test("a removal that cannot start says why in the panel and offers Try again; Keep restores the row without the old reason", async ({ page }) => {
  await openConnection(page, "refused");
  await row(page).click();
  await yes(page).click();
  await expect(note(page)).toHaveText("Another host removal is still running. Try again in a moment.");
  await expect(yes(page)).toHaveText("Try again");
  await keep(page).click();
  await expect(row(page)).toBeVisible();
  await row(page).click();
  await expect(note(page)).toBeHidden();
  await expect(yes(page)).toHaveText("Remove");
});

test("a host that goes offline while the question is open says the uninstall waits; one removed elsewhere turns the question into a note", async ({ page }) => {
  await openConnection(page, "1");
  await row(page).click();
  await expect(ask(page).locator(".canvas-popover-ask-effect")).toHaveText("Revokes its access, then uninstalls the infraternal agent from it.");
  await setStatus(page, "offline");
  await expect(ask(page).locator(".canvas-popover-ask-effect")).toContainText("is offline, so the uninstall waits until it connects.");
  await expect(yes(page)).toBeEnabled();
  await setStatus(page, "ready");
  await expect(ask(page).locator(".canvas-popover-ask-effect")).not.toContainText("offline");
  await setStatus(page, "gone");
  await expect(note(page)).toContainText("is already removed.");
  await expect(yes(page)).toBeDisabled();
  await expect(keep(page)).toBeDisabled();
});

test("a host already removed while the row is showing takes the block away", async ({ page }) => {
  await openConnection(page, "1");
  await setStatus(page, "gone");
  await expect(page.locator(".canvas-popover-action")).toBeHidden();
});

test("switching tabs takes an open question back to the row", async ({ page }) => {
  await openConnection(page, "1");
  await row(page).click();
  await expect(ask(page)).toBeVisible();
  await page.locator(".canvas-popover .ui-tab", { hasText: "Machine" }).click();
  await expect(page.locator(".canvas-popover-action")).toBeHidden();
  await page.locator(".canvas-popover .ui-tab", { hasText: "Connection" }).click();
  await expect(row(page)).toBeVisible();
  await expect(ask(page)).toBeHidden();
});

test("the focus returns to the row after Keep and after Escape, and the card stays open", async ({ page }) => {
  await openConnection(page, "1");
  await row(page).click();
  expect(await focused(page, ".canvas-popover-ask [data-keep]"), "the question opens on Keep").toBe(true);
  await keep(page).click();
  expect(await focused(page, ".canvas-popover-action .ui-sp-row")).toBe(true);
  await row(page).click();
  await page.keyboard.press("Escape");
  expect(await focused(page, ".canvas-popover-action .ui-sp-row")).toBe(true);
  await expect(page.locator(".canvas-popover")).toBeVisible();
});
