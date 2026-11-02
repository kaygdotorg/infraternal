/**
 * "End" asks in its own row (#242, owner 2026-11-01, TASTE "A destructive row action asks in its own row"): the row's text
 * becomes "End session? End · Cancel", never a dialog or a floating card. The row keeps its height and its neighbours stay
 * put; the words are reachable by keyboard; Escape and Cancel put the row back; a press elsewhere is a no.
 */
import { expect, test, type Page } from "playwright/test";

const ID = "s:build-01/deploy";
const NEIGHBOUR = "s:build-01/journal";
const URL = "/?mock=1&proto=clusters&scene=3&theme=ink&bg=none";

const open = async (page: Page, width = 1440, height = 900): Promise<void> => {
  await page.setViewportSize({ width, height });
  await page.goto(URL);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator(`#tree [data-id="${ID}"]`)).toBeVisible();
  await page.waitForTimeout(700);
};
const leaf = (page: Page, id = ID) => page.locator(`#tree [data-id="${id}"]`);
/** Each row's layout box (offsets, which no transform can fake): the row and its neighbour must not move or change size. */
const boxes = (page: Page, ids: string[]) => page.evaluate((list) => list.map((id) => {
  const r = document.querySelector(`#tree [data-id="${id}"]`)!.closest(".bm-row") as HTMLElement;
  return [r.offsetLeft, r.offsetTop, r.offsetWidth, r.offsetHeight];
}), ids);

test.describe("End asks in its row", () => {
  test("a swipe opens the question in the row; no card, same height, neighbours stay put; Cancel and Escape restore it", async ({ page }) => {
    await open(page);
    const before = await boxes(page, [ID, NEIGHBOUR]);
    // A long wheel swipe left performs "End", which asks first.
    await page.evaluate(([id]) => new Promise<void>((done) => {
      const el = document.querySelector(`#tree [data-id="${id}"]`)!;
      const r = el.getBoundingClientRect();
      let k = 0;
      const tick = (): void => { if (k++ >= 26) { setTimeout(done, 700); return; } el.dispatchEvent(new WheelEvent("wheel", { deltaX: 10, deltaY: 0, clientX: r.left + 60, clientY: r.top + 12, bubbles: true, cancelable: true })); setTimeout(tick, 16); };
      tick();
    }), [ID]);
    const ask = page.locator(".ui-row-ask");
    await expect(ask).toBeVisible();
    await expect(ask).toHaveText(/End( session)?\?\s*End\s*·\s*Cancel/);
    // Never cut off: the whole row fits inside the row's own box, with the full question or its short form.
    expect(await page.evaluate(() => { const a = document.querySelector(".ui-row-ask")!, r = a.parentElement!.getBoundingClientRect(), last = a.querySelector(".ui-row-ask-no")!.getBoundingClientRect(); return last.right <= r.right + 0.5; })).toBe(true);
    expect(["End session?", "End?"]).toContain(await page.evaluate(() => document.querySelector(".ui-row-ask-q")!.textContent));
    // No card of any kind: the shared confirmation tip is absent and the only dialog left is the palette, which was there before.
    await expect(page.locator(".ui-confirm-tip, [role='alertdialog']")).toHaveCount(0);
    expect(await page.evaluate(() => [...document.querySelectorAll("[role='dialog']")].map((e) => e.id))).toEqual(["palette"]);
    expect(await boxes(page, [ID, NEIGHBOUR])).toEqual(before);
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(ask).toHaveCount(0);
    expect(await boxes(page, [ID, NEIGHBOUR])).toEqual(before);
    expect(await page.evaluate(() => (document.querySelector(".bm-row[data-asking]") ? "asking" : "idle"))).toBe("idle");
  });

  test("by keyboard: the menu's End session lands on End; arrows move; Enter on End ends the session; Escape cancels and refocuses the row", async ({ page }) => {
    await open(page);
    await leaf(page).focus();
    await page.keyboard.press("ContextMenu");
    await page.locator(".ui-window-menu-item", { hasText: "End session" }).focus();
    await page.keyboard.press("Enter");
    const ask = page.locator(".ui-row-ask");
    await expect(ask).toBeVisible();
    expect(await page.evaluate(() => document.activeElement?.textContent)).toBe("End");
    await page.keyboard.press("ArrowRight");
    expect(await page.evaluate(() => document.activeElement?.textContent)).toBe("Cancel");
    await page.keyboard.press("ArrowLeft");
    await page.keyboard.press("Escape");
    await expect(ask).toHaveCount(0);
    expect(await page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.id)).toBe(ID);
    // Again, and this time answer.
    await page.keyboard.press("ContextMenu");
    await page.locator(".ui-window-menu-item", { hasText: "End session" }).focus();
    await page.keyboard.press("Enter");
    await expect(ask).toBeVisible();
    await page.keyboard.press("Enter");
    await expect(leaf(page)).toHaveCount(0);
  });

  test("a press elsewhere is a no, and the palette's End session asks in the row too", async ({ page }) => {
    await open(page);
    await leaf(page).focus();
    await page.keyboard.press("Control+Shift+K");
    await page.keyboard.type("End session 'deploy'");
    await page.keyboard.press("Enter");
    await expect(page.locator(".ui-row-ask")).toBeVisible();
    await page.locator("#sidebar .bm-head").first().click();
    await expect(page.locator(".ui-row-ask")).toHaveCount(0);
  });
});
