/**
 * Renaming and removing hosts and sessions from the sidebar (#215, owner 2026-10-14 and the approval of 2026-11-02): hover a
 * row for its action pill, double-click or double-tap a name, F2, Delete, and the same actions in the row menu. Each check
 * walks one gesture the owner will use and measures what TASTE asks of it: the field and the in-row question start at the
 * label's x (±0.5 px), the pill sits on the row's centre line, and no row moves.
 *
 * Desktop 1440×900, phone 393×852. The test double's inventory can end sessions (`can` is absent); the product's cannot
 * yet (#100), where End and Remove do not appear. `?removal=1` gives the test double a host removal.
 */
import { expect, test, type Page } from "playwright/test";

const URL = "/?mock=1&proto=clusters&scene=1&theme=ink&bg=none&removal=1";
const leaf = (page: Page, id: string) => page.locator(`#tree .bm-leaf[data-id="s:build-01/${id}"]`);
const caption = (page: Page, host: string) => page.locator(`#tree li.bm-subhead[data-id="h:${host}"]`);
const field = (page: Page) => page.locator(".ui-inline-rename");

async function open(page: Page, width: number, height: number): Promise<void> {
  await page.setViewportSize({ width, height });
  await page.goto(URL);
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  await page.waitForTimeout(700);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(900);
  await page.click("#sidebar-toggle");
  await expect(leaf(page, "journal")).toBeVisible();
  await page.waitForTimeout(700);
}
/** The first line of an element's text: its left edge and centre line, in the page's coordinates. */
const textBox = (page: Page, selector: string) => page.evaluate((sel) => {
  const el = document.querySelector(sel)!;
  const range = document.createRange();
  range.selectNodeContents(el);
  const r = [...range.getClientRects()].find((q) => q.width > 0.5)!;
  // `cy` is the centre of the label's box: an input's text is centred in the input's box, so the two boxes are what share a centre line.
  const box = el.getBoundingClientRect();
  return { left: r.left, cy: box.top + box.height / 2 };
}, selector);
/** Each row's layout box (offsets no transform can fake): a rename or a question must not move or resize any row. */
const boxes = (page: Page) => page.evaluate(() => [...document.querySelectorAll<HTMLElement>("#tree .bm-row")].map((r) => [r.offsetLeft, r.offsetTop, r.offsetWidth, r.offsetHeight]));
const meshCalls = (page: Page) => page.evaluate(() => (window as unknown as { __tracerClusters: { mesh: { server(): { calls: Array<{ action: string; input: Record<string, unknown> }> } } } }).__tracerClusters.mesh.server().calls.filter((c) => c.action === "mesh.node.rename").map((c) => c.input));

test.describe("desktop 1440×900", () => {
  // DPR 2: text in an input is snapped to a device pixel, so the 0.5 px alignment rule is measurable (it is not at DPR 1).
  test.use({ deviceScaleFactor: 2 });
  test.beforeEach(async ({ page }) => { await open(page, 1440, 900); });

  test("hover shows the pill on the row's centre line and keeps it while the pointer travels to it", async ({ page }) => {
    const row = page.locator('#tree .bm-row:has(.bm-leaf[data-id="s:build-01/journal"])');
    await expect(row.locator(".cl-ha")).toHaveCount(0); // made when the pointer first reaches the row: a long list carries no hidden buttons at rest
    const box = (await row.boundingBox())!;
    await page.mouse.move(box.x + 40, box.y + box.height / 2);
    const pill = row.locator(".cl-ha");
    await expect(pill).toHaveCSS("opacity", "1");
    const buttons = row.locator("[data-act]");
    // A session without a window has no Info; the next test's open session has one.
    expect(await buttons.evaluateAll((n) => n.map((b) => b.getAttribute("aria-label")))).toEqual(["Rename journal", "End session journal"]);
    const target = (await row.locator('[data-act="rename"]').boundingBox())!;
    for (let i = 1; i <= 8; i += 1) { await page.mouse.move(box.x + 40 + ((target.x + target.width / 2 - box.x - 40) * i) / 8, box.y + box.height / 2); await expect(pill).toHaveCSS("opacity", "1"); }
    // Alignment: each icon button's centre is on the row's centre line, and the pill ends inside the row.
    const row2 = (await row.boundingBox())!;
    for (const b of await buttons.all()) {
      const bb = (await b.boundingBox())!;
      expect(Math.abs(bb.y + bb.height / 2 - (row2.y + row2.height / 2)), "button centre against the row's").toBeLessThanOrEqual(0.5);
      expect(bb.x + bb.width).toBeLessThanOrEqual(row2.x + row2.width + 0.5);
    }
    // No ring from the mouse.
    await row.locator('[data-act="rename"]').click();
    expect(await page.evaluate(() => getComputedStyle(document.activeElement!).outlineStyle)).toBe("none");
    await page.keyboard.press("Escape");
  });

  test("double-click renames in place at the label's x; Enter saves, Escape cancels and keeps the sidebar, no row moves", async ({ page }) => {
    const before = await boxes(page);
    const label = await textBox(page, '#tree .bm-leaf[data-id="s:build-01/bench"] .bm-label');
    await leaf(page, "bench").dblclick();
    await expect(field(page)).toBeVisible();
    await expect(field(page)).toBeFocused();
    await expect(field(page)).toHaveValue("bench");
    // The text starts where the label started, on its centre line (the field's left edge plus its padding).
    const at = await field(page).evaluate((i) => { const r = i.getBoundingClientRect(), cs = getComputedStyle(i); return { left: r.left + parseFloat(cs.paddingLeft) + parseFloat(cs.borderLeftWidth), cy: r.top + r.height / 2 }; });
    expect(Math.abs(at.left - label.left), "rename text against the label").toBeLessThanOrEqual(0.5);
    expect(Math.abs(at.cy - label.cy), "rename centre line against the label").toBeLessThanOrEqual(0.5);
    expect(await boxes(page)).toEqual(before);
    await page.keyboard.type("bench-all");
    await page.keyboard.press("Escape");
    await expect(field(page)).toHaveCount(0);
    expect(await page.locator("#sidebar").evaluate((e) => (e as HTMLElement).hidden)).toBe(false);
    await expect(leaf(page, "bench").locator(".bm-label")).toHaveText("bench");
    await leaf(page, "bench").dblclick();
    await page.keyboard.type("bench-all");
    await page.keyboard.press("Enter");
    await expect(leaf(page, "bench").locator(".bm-label")).toHaveText("bench-all");
    expect(await boxes(page)).toEqual(before);
  });

  test("F2 renames the focused row; Delete asks in the row, Escape keeps it, End ends it", async ({ page }) => {
    await leaf(page, "migrate").focus();
    await page.keyboard.press("F2");
    await expect(field(page)).toBeFocused();
    await page.keyboard.type("migrate-db");
    await page.keyboard.press("Enter");
    await expect(leaf(page, "migrate").locator(".bm-label")).toHaveText("migrate-db");
    await leaf(page, "migrate").focus();
    const before = await boxes(page);
    await page.keyboard.press("Delete");
    const ask = page.locator(".ui-row-ask");
    await expect(ask).toBeVisible();
    await expect(ask).toContainText(/End( session)?\?/);
    await expect(page.locator(".ui-confirm-tip")).toHaveCount(0);
    expect(await boxes(page)).toEqual(before);
    await page.keyboard.press("Escape");
    await expect(ask).toHaveCount(0);
    await expect(leaf(page, "migrate")).toHaveCount(1);
    expect(await page.evaluate(() => (document.activeElement as HTMLElement | null)?.dataset.id)).toBe("s:build-01/migrate");
    await page.keyboard.press("Delete");
    await expect(ask).toBeVisible();
    await page.keyboard.press("Enter");
    await expect(leaf(page, "migrate")).toHaveCount(0);
  });

  test("the pill's Rename and the row menu's Rename open the same field", async ({ page }) => {
    const row = page.locator('#tree .bm-row:has(.bm-leaf[data-id="s:build-01/deploy"])');
    const box = (await row.boundingBox())!;
    await page.mouse.move(box.x + 40, box.y + box.height / 2);
    await row.locator('[data-act="rename"]').click();
    await expect(field(page)).toHaveValue("deploy");
    await page.keyboard.press("Escape");
    await leaf(page, "deploy").click({ button: "right" });
    await page.locator(".ui-window-menu-item", { hasText: "Rename" }).click();
    await expect(field(page)).toHaveValue("deploy");
    await page.keyboard.press("Escape");
    await expect(field(page)).toHaveCount(0);
  });

  test("a host renames through the Mesh; F2 on its caption, the server sees one rename, an empty name changes nothing", async ({ page }) => {
    await caption(page, "edge-arm").focus();
    const label = await textBox(page, '#tree li.bm-subhead[data-id="h:edge-arm"] .bm-label');
    await page.keyboard.press("F2");
    await expect(field(page)).toHaveValue("edge-arm");
    const at = await field(page).evaluate((i) => { const r = i.getBoundingClientRect(), cs = getComputedStyle(i); return { left: r.left + parseFloat(cs.paddingLeft), cy: r.top + r.height / 2 }; });
    expect(Math.abs(at.left - label.left)).toBeLessThanOrEqual(0.5);
    expect(Math.abs(at.cy - label.cy)).toBeLessThanOrEqual(0.5);
    await page.keyboard.press("Control+A");
    await page.keyboard.press("Backspace");
    await page.keyboard.press("Enter");
    expect(await meshCalls(page)).toEqual([]);
    await caption(page, "edge-arm").dblclick();
    await page.keyboard.type("arm-box");
    await page.keyboard.press("Enter");
    await expect.poll(async () => (await meshCalls(page)).map((c) => c.name)).toEqual(["arm-box"]);
  });

  test("Delete on a host asks to remove it; Escape keeps it", async ({ page }) => {
    await caption(page, "edge-arm").focus();
    await page.keyboard.press("Delete");
    const tip = page.locator(".ui-confirm-tip[data-open='true']");
    await expect(tip).toContainText("Remove edge-arm?");
    await page.keyboard.press("Escape");
    await expect(tip).toHaveCount(0);
    await expect(caption(page, "edge-arm")).toHaveCount(1);
  });

  test("Tab shows the ring on a session row; the mouse, F2 and Escape never do", async ({ page }) => {
    await page.locator("#sidebar-toggle").focus();
    let seen = false;
    for (let i = 0; i < 14 && !seen; i += 1) {
      await page.keyboard.press("Tab");
      const state = await page.evaluate(() => { const a = document.activeElement as HTMLElement; return { ring: document.documentElement.dataset.focusRing, row: Boolean(a.closest("#tree .bm-row")), style: getComputedStyle(a).outlineStyle }; });
      if (state.row) { expect(state.ring).toBe("on"); seen = true; }
    }
    expect(seen).toBe(true);
    await page.keyboard.press("F2");
    await page.keyboard.press("Escape");
    await page.mouse.click(700, 500);
    expect(await page.evaluate(() => document.documentElement.dataset.focusRing)).not.toBe("on");
  });
});

test.describe("phone 393×852", () => {
  test.use({ hasTouch: true, isMobile: true, deviceScaleFactor: 3 });
  test.beforeEach(async ({ page }) => { await open(page, 393, 852); });

  test("a double tap on a session's name renames it in place at the label's x and keeps the sidebar open", async ({ page }) => {
    const label = await textBox(page, '#tree .bm-leaf[data-id="s:build-01/bench"] .bm-label');
    const b = (await leaf(page, "bench").locator(".bm-label").boundingBox())!;
    await page.touchscreen.tap(b.x + 10, b.y + b.height / 2);
    await page.waitForTimeout(90);
    await page.touchscreen.tap(b.x + 10, b.y + b.height / 2);
    await expect(field(page)).toBeVisible();
    const at = await field(page).evaluate((i) => { const r = i.getBoundingClientRect(), cs = getComputedStyle(i); return { left: r.left + parseFloat(cs.paddingLeft), cy: r.top + r.height / 2, size: parseFloat(cs.fontSize) }; });
    expect(Math.abs(at.left - label.left)).toBeLessThanOrEqual(0.5);
    expect(Math.abs(at.cy - label.cy)).toBeLessThanOrEqual(0.5);
    expect(at.size, "16 px so the phone never zooms into the field").toBeGreaterThanOrEqual(16);
    expect(await page.locator("#sidebar").evaluate((e) => (e as HTMLElement).hidden)).toBe(false);
    await page.keyboard.press("Escape");
  });

  test("the long-press menu offers Rename and opens the field", async ({ page }) => {
    const b = (await leaf(page, "deploy").boundingBox())!;
    const cdp = await page.context().newCDPSession(page);
    const y = b.y + b.height / 2;
    await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: b.x + 60, y }] });
    await page.waitForTimeout(700);
    await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
    await expect(page.locator(".ui-window-menu")).toBeVisible();
    await page.locator(".ui-window-menu-item", { hasText: "Rename" }).tap();
    await expect(field(page)).toHaveValue("deploy");
    await page.keyboard.press("Escape");
  });
});
