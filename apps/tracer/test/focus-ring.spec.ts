/** Guards TASTE.md section 1: focus rings only during Tab navigation, never after clicks or shortcuts. */
import { expect, test, type Page } from "playwright/test";

async function openScreen(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  await page.goto("/?mock=1&bg=none");
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
}

/** The focused element's outline, with the mouse moved away so hover styles don't interfere. */
async function focusedOutline(page: Page): Promise<{ id: string; ring: boolean }> {
  await page.mouse.move(900, 600);
  return page.evaluate(() => {
    const active = document.activeElement as HTMLElement;
    const style = getComputedStyle(active);
    return { id: active.id || active.className, ring: style.outlineStyle !== "none" && style.outlineWidth !== "0px" };
  });
}

test("clicks and shortcuts draw no focus ring; Tab does", async ({ page }) => {
  await openScreen(page);

  await page.click("#sidebar-toggle");
  expect(await focusedOutline(page)).toEqual({ id: "sidebar-toggle", ring: false });
  await page.click("#sidebar-toggle");
  expect(await focusedOutline(page)).toEqual({ id: "sidebar-toggle", ring: false });

  await page.click("#sidebar-toggle");
  await page.keyboard.press("Escape");
  expect((await focusedOutline(page)).ring).toBe(false);

  await page.keyboard.press("Control+k");
  expect(await focusedOutline(page)).toEqual({ id: "palette-input", ring: false });
  await page.keyboard.press("Escape");
  expect((await focusedOutline(page)).ring).toBe(false);

  await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
  await page.keyboard.press("Shift+Tab");
  expect((await focusedOutline(page)).ring).toBe(true);

  // A click after keyboard navigation hides the ring again.
  await page.click("#sidebar-toggle");
  expect(await focusedOutline(page)).toEqual({ id: "sidebar-toggle", ring: false });
});
