// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Remove host on the sidebar's machine row (D385, #486 review F4): a left swipe on touch reveals "Remove", the row stays
 * listed (`swipeKeeps`), pressing it opens the glass confirmation card (never removing at once), a long swipe opens the card
 * by itself, a vertical drag only scrolls, and on desktop the hover pill's bin does the same. Functional: real touch events
 * go through the DevTools protocol on a phone-sized page (the swipe machinery itself is the shared row menu's, covered by
 * row-swipe-continuity.spec.ts); nothing here asserts speed. The test double's removal (`?removal=1`) only asks and says so.
 */
import { expect, test, type Page } from "playwright/test";

const URL = "/?mock=1&proto=clusters&scene=1&theme=ink&bg=none&removal=1";
const HOST = 'li.bm-subhead[data-id="h:edge-arm"]';

/** Opens the Console view with the sidebar open and the row actions ready. */
async function open(page: Page): Promise<void> {
  await page.goto(URL);
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  // sleep: the mock scene settles before the camera flight
  await page.waitForTimeout(700);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
  // sleep: the camera flight to the view lasts under 300 ms; margin for a loaded VM
  await page.waitForTimeout(900);
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1); // the row actions load with the sidebar
  await expect(page.locator(HOST)).toBeVisible();
  // sleep: the sidebar's slide-in settles so the row's box is final
  await page.waitForTimeout(500);
}

/** A touch drag on the host row through CDP: from `dx0` inside its right edge by `dx` (negative is left), `dy` vertical, in `steps`. */
async function drag(page: Page, dx: number, dy = 0, steps = 14): Promise<void> {
  const b = (await page.locator(HOST).boundingBox())!;
  const x0 = b.x + b.width - 30, y0 = b.y + b.height / 2;
  const cdp = await page.context().newCDPSession(page);
  const send = (type: "touchStart" | "touchMove" | "touchEnd", x = 0, y = 0): Promise<unknown> => cdp.send("Input.dispatchTouchEvent", { type, touchPoints: type === "touchEnd" ? [] : [{ x, y }] });
  await send("touchStart", x0, y0);
  for (let i = 1; i <= steps; i += 1) {
    await send("touchMove", x0 + (dx * i) / steps, y0 + (dy * i) / steps);
    // sleep: one touch step per frame, so the drag is recognised as a gesture
    await page.waitForTimeout(8);
  }
  await send("touchEnd");
  await cdp.detach();
}

/** The host row's leaf x translation in pixels (negative while the row is swiped left). */
const offset = (page: Page): Promise<number> => page.evaluate((sel) => {
  const leaf = document.querySelector(sel)!.closest(".bm-row")!.firstElementChild as HTMLElement;
  return new DOMMatrix(getComputedStyle(leaf).transform).m41;
}, HOST);
const action = (page: Page) => page.locator("#tree .ui-row-swipe-act[data-action='remove']");
const card = (page: Page) => page.locator(".ui-confirm-tip[data-open='true']");

test.describe("phone", () => {
  test.use({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });

  test("a short left swipe reveals Remove and the row stays put, listed", async ({ page }) => {
    await open(page);
    await drag(page, -112);
    await expect(action(page)).toBeVisible();
    await expect(action(page)).toContainText("Remove");
    await expect.poll(() => offset(page), { message: "the row rests open, showing the button" }).toBeLessThan(-40);
    await expect(page.locator(HOST)).toBeVisible();
    expect(await card(page).count(), "revealing asks nothing yet").toBe(0);
  });

  test("pressing the revealed Remove opens the glass confirmation card, inside the screen; Keep closes it and the row is still listed", async ({ page }) => {
    await open(page);
    await drag(page, -112);
    await action(page).tap();
    await expect(card(page)).toBeVisible();
    await expect(card(page).locator(".ui-confirm-tip-message")).toHaveText("Remove edge-arm?");
    await expect(card(page).locator(".ui-confirm-tip-detail")).toHaveText("Revokes its access, then uninstalls the infraternal agent from it.");
    const inside = await card(page).evaluate((el) => { const r = el.getBoundingClientRect(); return r.left >= 0 && r.top >= 0 && r.right <= innerWidth && r.bottom <= innerHeight; });
    expect(inside, "the card is inside the screen").toBe(true);
    await card(page).getByRole("button", { name: "Keep" }).click();
    await expect(card(page)).toHaveCount(0);
    await expect(page.locator(HOST)).toBeVisible();
    await expect(page.locator(".toast, .ui-toast")).toHaveCount(0); // nothing was removed
  });

  test("a long left swipe opens the card by itself, and the row settles back, still listed", async ({ page }) => {
    await open(page);
    await drag(page, -330, 0, 24);
    await expect(card(page)).toBeVisible();
    await expect(page.locator(HOST)).toBeVisible();
    await expect.poll(() => offset(page), { message: "the row returns to rest: it is still in the list" }).toBeGreaterThan(-4);
  });

  test("a vertical drag over the row reveals nothing", async ({ page }) => {
    await open(page);
    await drag(page, -6, -120);
    expect(await action(page).isVisible(), "no Remove button from a vertical drag").toBe(false);
    expect(Math.abs(await offset(page))).toBeLessThan(4);
  });
});

test.describe("desktop", () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  test("the hover pill's bin says Remove host and opens the same card", async ({ page }) => {
    await open(page);
    const b = (await page.locator(HOST).boundingBox())!;
    await page.mouse.move(b.x + 60, b.y + b.height / 2);
    const bin = page.locator(".cl-ha button[data-act='remove']");
    await expect(bin).toBeVisible();
    await expect(bin).toHaveAttribute("data-tip", "Remove host");
    await bin.click();
    await expect(card(page)).toBeVisible();
    await expect(card(page).locator(".ui-confirm-tip-message")).toHaveText("Remove edge-arm?");
    await page.keyboard.press("Escape");
    await expect(card(page)).toHaveCount(0);
    await expect(page.locator(HOST)).toBeVisible();
  });
});
