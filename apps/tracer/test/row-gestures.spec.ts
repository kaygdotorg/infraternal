/**
 * The remaining gestures of the sidebar's row menu and swipes (#242): Shift+F10 on the desktop, and on a phone the long
 * press, the left swipe that ends (short: reveals End; long: asks in the row), a tap on the revealed End, and the swipe that
 * has no action in its direction. row-menu.spec.ts covers the right-click, the context-menu key and the trackpad; row-ask.spec.ts
 * the question in the row; row-swipe-continuity.spec.ts the right swipe. Real touch events through the DevTools protocol.
 */
import { expect, test, type Page } from "playwright/test";

const ID = "s:build-01/deploy";
const URL = "/?mock=1&proto=clusters&scene=3&theme=ink&bg=none";
const leaf = (page: Page, id = ID) => page.locator(`#tree [data-id="${id}"]`);

async function open(page: Page, width: number, height: number): Promise<void> {
  await page.setViewportSize({ width, height });
  await page.goto(URL);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.locator("#sidebar-toggle").click();
  await expect(leaf(page)).toBeVisible();
  await page.waitForTimeout(700);
}

test("Shift+F10 opens the menu under the focused row, on its first item, with no ring", async ({ page }) => {
  await open(page, 1440, 900);
  await leaf(page).focus();
  await page.keyboard.press("Shift+F10");
  await expect(page.locator(".ui-window-menu")).toBeVisible();
  expect(await page.evaluate(() => (document.activeElement as HTMLElement).dataset.action)).toBe("open");
  expect(await page.evaluate(() => document.documentElement.dataset.focusRing)).toBeUndefined();
  // The menu hangs from the row: it starts at the row's left part and is not above it.
  const menu = (await page.locator(".ui-window-menu").boundingBox())!;
  const row = (await leaf(page).boundingBox())!;
  expect(menu.y).toBeGreaterThanOrEqual(row.y + row.height - 4);
  await page.keyboard.press("Escape");
  await expect(page.locator(".ui-window-menu")).toHaveCount(0);
  expect(await page.evaluate(() => (document.activeElement as HTMLElement).dataset.id)).toBe(ID);
});

test.describe("phone 393×852", () => {
  test.use({ hasTouch: true, isMobile: true, deviceScaleFactor: 3 });
  test.beforeEach(async ({ page }) => { await open(page, 393, 852); });

  /** One finger: down at `x0`, a drag of `dx` in `steps`, then up (or held for `hold` ms first). */
  async function finger(page: Page, id: string, x0: number, dx: number, opts: { steps?: number; hold?: number } = {}): Promise<void> {
    const box = (await leaf(page, id).boundingBox())!;
    const y = box.y + box.height / 2;
    const cdp = await page.context().newCDPSession(page);
    const send = (type: "touchStart" | "touchMove" | "touchEnd", x = 0): Promise<unknown> => cdp.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x, y }] });
    await send("touchStart", x0);
    const steps = opts.steps ?? 20;
    for (let i = 1; i <= steps; i += 1) { await send("touchMove", x0 + (dx * i) / steps); await page.waitForTimeout(8); }
    if (opts.hold) await page.waitForTimeout(opts.hold);
    await send("touchEnd");
    await page.waitForTimeout(700);
  }

  test("a long press opens the menu at the finger and does not open the session", async ({ page }) => {
    const box = (await leaf(page).boundingBox())!;
    const cdp = await page.context().newCDPSession(page);
    const y = box.y + box.height / 2;
    await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: box.x + 80, y }] });
    await page.waitForTimeout(700);
    await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
    await expect(page.locator(".ui-window-menu")).toBeVisible();
    await expect(page.locator(".ui-window-menu-item")).toHaveText(["Open", "Open beside", "Rename", "Copy name", "End session…"]);
    expect(await page.locator("#sidebar").evaluate((e) => (e as HTMLElement).hidden), "the sidebar stays open: the press did not open the session").toBe(false);
    // 44 px targets on touch.
    expect((await page.locator(".ui-window-menu-item").first().boundingBox())!.height).toBeGreaterThanOrEqual(43.5);
    await page.keyboard.press("Escape");
  });

  test("a short left swipe reveals End on the row's edge; tapping it asks in the row; Cancel puts the row back", async ({ page }) => {
    const box = (await leaf(page).boundingBox())!;
    await finger(page, ID, box.x + box.width - 30, -110);
    await expect(page.locator("#tree [data-swiped='left']")).toHaveCount(1);
    const act = page.locator("#tree .ui-row-swipe-act[data-action='end']");
    await expect(act).toBeVisible();
    // The revealed button is whole and pinned to the row's right edge, its icon and word on one centre line.
    const a = (await act.locator(".ui-row-swipe-in").boundingBox())!, r = (await page.locator(`#tree .bm-row:has([data-id="${ID}"])`).boundingBox())!;
    expect(Math.abs(a.x + a.width - (r.x + r.width)), "button against the row's right edge").toBeLessThanOrEqual(0.5);
    const centres = await act.evaluate((el) => { const c = (n: Element): number => { const q = n.getBoundingClientRect(); return q.top + q.height / 2; }; return [c(el.querySelector("svg")!), c(el.querySelector(".ui-row-swipe-in > span:last-child")!)]; });
    expect(Math.abs(centres[0]! - centres[1]!), "icon and word share a centre line").toBeLessThanOrEqual(0.5);
    await act.tap();
    const ask = page.locator(".ui-row-ask");
    await expect(ask).toBeVisible();
    await expect(page.locator(".ui-confirm-tip")).toHaveCount(0);
    await page.getByRole("button", { name: "Cancel" }).tap();
    await expect(ask).toHaveCount(0);
    await expect(page.locator("#tree [data-swiped]")).toHaveCount(0);
    await expect(leaf(page)).toHaveCount(1);
  });

  test("a long left swipe asks in the row at once, and End ends the session", async ({ page }) => {
    const box = (await leaf(page).boundingBox())!;
    await finger(page, ID, box.x + box.width - 20, -(box.width - 60), { steps: 28 });
    const ask = page.locator(".ui-row-ask");
    await expect(ask).toBeVisible();
    await expect(ask).toContainText("End");
    await ask.getByRole("button", { name: "End", exact: true }).tap();
    await expect(leaf(page)).toHaveCount(0);
  });

  test("a swipe in a direction with no action gives a little and comes back (a Mesh node has none)", async ({ page }) => {
    const id = "n-nix-cache";
    const box = (await leaf(page, id).boundingBox())!;
    await finger(page, id, box.x + 60, -120);
    expect(await leaf(page, id).evaluate((el) => (el as HTMLElement).style.transform)).toBe("");
    await expect(page.locator("#tree [data-swiped]")).toHaveCount(0);
  });
});
