/**
 * A logs window behaves like tail -f (#141): the backlog fills the window (varied lines with warnings and errors, not
 * one repeated request), new lines keep arriving, the view stays on the newest line, and when the person scrolls up to
 * read it stays where they are and a "Jump to latest" button brings them back.
 */
import { expect, test, type Page } from "playwright/test";

async function open(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=mocha&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("containers"));
  await page.waitForTimeout(1500);
}
const logs = (page: Page) => page.locator('.ui-window[data-window-id="w-logs"] .cl-logs');
const state = (page: Page) => logs(page).evaluate((n) => ({ top: n.scrollTop, max: n.scrollHeight - n.clientHeight, lines: n.querySelectorAll(".cl-log-line").length, client: n.clientHeight }));

test("the backlog fills the window, is varied, and stays on the newest line", async ({ page }) => {
  test.setTimeout(60_000);
  await open(page);
  const s = await state(page);
  expect(s.max, "there is more than a window of lines").toBeGreaterThan(s.client);
  expect(Math.abs(s.top - s.max), "pinned to the end").toBeLessThanOrEqual(1);
  const text = (await logs(page).textContent())!;
  expect(text).toContain("WARN");
  expect(text).toContain("ERROR");
  expect(new Set(text.match(/(GET|POST) \S+/g)).size, "varied requests").toBeGreaterThan(5);
  // The last line's bottom edge is at the bottom of the window, not a quarter of the way down.
  const gap = await logs(page).evaluate((n) => n.getBoundingClientRect().bottom - n.lastElementChild!.getBoundingClientRect().bottom);
  expect(gap).toBeLessThan(40);
  await page.waitForTimeout(4000);
  const later = await state(page);
  expect(later.lines).toBeGreaterThan(s.lines);
  expect(Math.abs(later.top - later.max), "still pinned after new lines").toBeLessThanOrEqual(1);
  await page.screenshot({ path: "captures/logs/after-pinned.png" });
});

test("scrolling up stops the follow and shows Jump to latest", async ({ page }) => {
  test.setTimeout(60_000);
  await open(page);
  const jump = page.locator('.ui-window[data-window-id="w-logs"] .cl-log-jump');
  await expect(jump).toBeHidden();
  await logs(page).hover();
  await page.mouse.wheel(0, -400);
  await expect(jump).toBeVisible();
  const before = await state(page);
  expect(before.top).toBeLessThan(before.max - 100);
  await page.waitForTimeout(4000);
  const after = await state(page);
  expect(Math.abs(after.top - before.top), "reading position does not move while lines arrive").toBeLessThanOrEqual(1);
  expect(after.lines).toBeGreaterThan(before.lines);
  await page.screenshot({ path: "captures/logs/after-scrolled-up.png" });
  await jump.click();
  await expect(jump).toBeHidden();
  const end = await state(page);
  expect(Math.abs(end.top - end.max)).toBeLessThanOrEqual(1);
});
