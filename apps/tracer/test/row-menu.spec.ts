/**
 * The row menu and swipes of the sidebar tree (D309, #242): right-click opens our menu and selects no text, Shift +
 * right-click leaves the browser's own menu alone, the context-menu key opens it with focus on its first row and no ring,
 * a short wheel swipe reveals a button and a long one asks before ending (in the row), Escape closes a revealed row without closing the
 * sidebar, and a direction without an action comes back. Behaviour only; the review screenshots are taken by hand.
 */
import { expect, test, type Page } from "playwright/test";

const open = async (page: Page): Promise<void> => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator('#tree [data-id="s:build-01/journal"]')).toBeVisible();
};
const row = (page: Page, id: string) => page.locator(`#tree [data-id="${id}"]`);
/** One trackpad-like stream laid on 16 ms slots, dispatched in the page so a slow frame cannot stretch the gaps. */
const wheel = (page: Page, id: string, count: number, dx: number): Promise<void> => page.evaluate(([target, n, d]) => new Promise<void>((done) => {
  const el = document.querySelector(`#tree [data-id="${target}"]`)!;
  const box = el.getBoundingClientRect();
  let k = 0;
  const tick = (): void => {
    if (k++ >= (n as number)) { setTimeout(done, 700); return; }
    el.dispatchEvent(new WheelEvent("wheel", { deltaX: d as number, deltaY: 0, clientX: box.left + 60, clientY: box.top + 12, bubbles: true, cancelable: true }));
    setTimeout(tick, 16);
  };
  tick();
}), [id, count, dx] as const);

test("right-click opens our menu, selects no text, and Shift leaves the browser's own", async ({ page }) => {
  await open(page);
  const prevented = await page.evaluate(() => {
    const t = document.querySelector('#tree [data-id="s:build-01/deploy"]')!;
    const shifted = new MouseEvent("contextmenu", { bubbles: true, cancelable: true, shiftKey: true });
    t.dispatchEvent(shifted);
    const plain = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    t.dispatchEvent(plain);
    return [shifted.defaultPrevented, plain.defaultPrevented];
  });
  expect(prevented).toEqual([false, true]);
  await page.keyboard.press("Escape");
  await row(page, "s:build-01/release").click({ button: "right" });
  const items = page.locator(".ui-window-menu-item");
  await expect(items).toHaveText(["Open", "Open beside", "Rename", "Copy name", "End session…"]);
  expect(await page.evaluate(() => getSelection()?.toString() ?? "")).toBe("");
  // The page's own menu is still reachable elsewhere in the sidebar (a view head is not a row).
  expect(await page.evaluate(() => { const e = new MouseEvent("contextmenu", { bubbles: true, cancelable: true }); document.querySelector("#tree .bm-head")!.dispatchEvent(e); return e.defaultPrevented; })).toBe(false);
});

test("the context-menu key opens the menu on the first row with no ring and Escape gives the focus back", async ({ page }) => {
  await open(page);
  await row(page, "s:build-01/journal").focus();
  await page.keyboard.press("ContextMenu");
  await expect(page.locator(".ui-window-menu")).toBeVisible();
  expect(await page.evaluate(() => (document.activeElement as HTMLElement).dataset.action)).toBe("open");
  expect(await page.evaluate(() => document.documentElement.dataset.focusRing)).toBeUndefined();
  await page.keyboard.press("Escape");
  await expect(page.locator(".ui-window-menu")).toHaveCount(0);
  expect(await page.evaluate(() => (document.activeElement as HTMLElement).dataset.id)).toBe("s:build-01/journal");
  await expect(page.locator("#sidebar")).toBeVisible();
});

test("a short swipe reveals End, Escape closes only the row, a long one asks first", async ({ page }) => {
  await open(page);
  await wheel(page, "s:build-01/journal", 6, 10);
  await expect(page.locator("#tree [data-swiped='left']")).toHaveCount(1);
  await page.keyboard.press("Escape");
  await expect(page.locator("#tree [data-swiped]")).toHaveCount(0);
  await expect(page.locator("#sidebar")).toBeVisible();
  await wheel(page, "s:build-01/journal", 24, 10);
  // The question is in the row itself, not in a card over it (TASTE: a destructive row action asks in its own row).
  const ask = page.locator(".bm-row[data-asking] .ui-row-ask");
  await expect(ask).toBeVisible();
  await expect(ask).toContainText(/End( session)?\?/);
  await expect(page.locator(".ui-confirm-tip")).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(page.locator(".ui-row-ask")).toHaveCount(0);
});

test("a direction without an action gives a little and comes back; vertical scrolling is left alone", async ({ page }) => {
  await open(page);
  await wheel(page, "n-nix-cache", 10, 12);
  expect(await row(page, "n-nix-cache").evaluate((el) => (el as HTMLElement).style.transform)).toBe("");
  expect(await page.evaluate(() => {
    const e = new WheelEvent("wheel", { deltaX: 1, deltaY: 40, bubbles: true, cancelable: true });
    document.querySelector('#tree [data-id="s:build-01/journal"]')!.dispatchEvent(e);
    return e.defaultPrevented;
  })).toBe(false);
});

test("every action of the focused row is a palette row", async ({ page }) => {
  await open(page);
  await row(page, "s:build-01/deploy").focus();
  await page.keyboard.press("Control+Shift+K");
  await page.keyboard.type("deploy");
  await expect(page.getByText("Rename 'deploy'")).toBeVisible();
  await expect(page.getByText("End session 'deploy'")).toBeVisible();
});
