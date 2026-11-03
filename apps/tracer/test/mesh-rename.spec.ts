/**
 * Renaming a Mesh host in place (#259): double click or double tap on its name, on the Mesh view's card and in the Views
 * tree, and "Rename <host>" in the palette. The real adapter runs against the fake Mesh server, which answers
 * `mesh.node.rename` like the real one (a duplicate name is a conflict, a refusal is "forbidden").
 *
 * What must hold: a single click and a drag keep their meaning; Enter and a click elsewhere save, Escape cancels;
 * the server sees one `mesh.node.rename` with the node id and the trimmed name; a refusal says why in plain words and
 * the old name comes back; double tap does not zoom (the name's `touch-action`). Review screenshots go to the external
 * evidence directory when `RENAME_CAPTURES=1`.
 */
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

type FakeServer = { calls: Array<{ action: string; input: Record<string, unknown> }>; failNext(action: string, error?: "refuse" | "network"): void; latency: number };
type Probe = { mesh: { server(): FakeServer }; flyView(id: string): void; views(): Array<{ id: string }>; camera(): { cx: number; cy: number; z: number }; setCamera(cx: number, cy: number, z: number): void };
const probe = <T>(page: Page, fn: (p: Probe) => T): Promise<T> =>
  page.evaluate((source) => (new Function("p", `return (${source})(p)`) as (p: unknown) => T)((window as unknown as { __tracerClusters: unknown }).__tracerClusters), fn.toString());
const renames = (page: Page): Promise<Array<Record<string, unknown>>> => probe(page, (p) => p.mesh.server().calls.filter((c) => c.action === "mesh.node.rename").map((c) => c.input));

const CAPTURES = tracerEvidencePath("sidebar-pill-259");
const shoot = async (page: Page, name: string): Promise<void> => { if (process.env.RENAME_CAPTURES) { mkdirSync(CAPTURES, { recursive: true }); await page.screenshot({ path: resolve(CAPTURES, `${name}.png`) }); } };

const DESKTOP = { width: 1440, height: 900 }, PHONE = { width: 393, height: 852 };
async function open(page: Page, size = DESKTOP, theme = "ink"): Promise<void> {
  await page.setViewportSize(size);
  await page.goto(`/?mock=1&proto=clusters&scene=6&theme=${theme}&bg=none`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await expect.poll(() => probe(page, (p) => p.views().length)).toBeGreaterThan(0);
  await page.waitForTimeout(500);
  await probe(page, (p) => p.flyView("mesh"));
  await expect(page.locator('.ui-window[data-window-id="n-build-01"]')).toBeVisible();
  await page.waitForTimeout(1200);
}
const card = (page: Page, host: string) => page.locator(`.ui-window[data-window-id="n-${host}"]`);
const hostName = (page: Page, host: string) => card(page, host).locator(".ui-window-host");
const field = (page: Page) => page.locator(".ui-inline-rename");
/** Brings a host's card to the middle of the screen by moving the camera (the phone shows one column of the Mesh at a time). */
async function bringIntoView(page: Page, host: string): Promise<void> {
  const at = (await hostName(page, host).boundingBox())!;
  const vp = page.viewportSize()!;
  await page.evaluate(([dx, dy]) => {
    const p = (window as unknown as { __tracerClusters: Probe }).__tracerClusters;
    const { cx, cy, z } = p.camera();
    p.setCamera(cx + dx! / z, cy + dy! / z, z);
  }, [at.x + at.width / 2 - vp.width / 2, at.y + at.height / 2 - vp.height / 2]);
  await page.waitForTimeout(600);
}
const toast = (page: Page) => page.locator(".ui-toast:not([hidden])");

test("double click on a card's name opens the field; Enter saves it through mesh.node.rename and the card follows", async ({ page }) => {
  await open(page);
  await hostName(page, "build-01").dblclick();
  await expect(field(page)).toBeVisible();
  await expect(field(page)).toHaveValue("build-01");
  await expect(field(page)).toBeFocused();
  await shoot(page, "card-editing-desktop-ink");
  await page.keyboard.type("  build-09 ");
  await page.keyboard.press("Enter");
  await expect(field(page)).toHaveCount(0);
  await expect(card(page, "build-09")).toBeVisible();
  await expect(card(page, "build-01")).toHaveCount(0);
  await expect(hostName(page, "build-09")).toHaveText("build-09");
  expect(await renames(page)).toEqual([{ node_id: 1, name: "build-09" }]);
  // The arrows that named it follow it: the grant still ends on this card.
  await expect(page.locator(".cl-arrow")).not.toHaveCount(0);
});

test("Escape cancels, an unchanged or empty name sends nothing, a click elsewhere saves", async ({ page }) => {
  await open(page);
  await hostName(page, "build-01").dblclick();
  await page.keyboard.type("nope");
  await page.keyboard.press("Escape");
  await expect(field(page)).toHaveCount(0);
  await expect(hostName(page, "build-01")).toHaveText("build-01");
  await hostName(page, "build-01").dblclick();
  await page.keyboard.press("Enter"); // unchanged
  await hostName(page, "build-01").dblclick();
  await page.keyboard.press("Control+A");
  await page.keyboard.press("Backspace");
  await page.keyboard.press("Enter"); // empty
  expect(await renames(page)).toEqual([]);
  await expect(hostName(page, "build-01")).toHaveText("build-01");
  // Leaving the field saves.
  await hostName(page, "nix-cache").dblclick();
  await page.keyboard.type("nix-store");
  await page.mouse.click(40, 860);
  await expect(card(page, "nix-store")).toBeVisible();
  expect(await renames(page)).toEqual([{ node_id: 3, name: "nix-store" }]);
});

test("a single click and a drag keep their meaning: no field opens, and the card moves", async ({ page }) => {
  await open(page);
  await hostName(page, "build-01").click();
  await page.waitForTimeout(500);
  await expect(field(page)).toHaveCount(0);
  const before = (await card(page, "build-01").boundingBox())!;
  const at = (await hostName(page, "build-01").boundingBox())!;
  await page.mouse.move(at.x + at.width / 2, at.y + at.height / 2);
  await page.mouse.down();
  await page.mouse.move(at.x + at.width / 2 + 80, at.y + at.height / 2 + 60, { steps: 8 });
  await page.mouse.up();
  const after = (await card(page, "build-01").boundingBox())!;
  expect(Math.abs(after.x - before.x) + Math.abs(after.y - before.y)).toBeGreaterThan(60);
  await expect(field(page)).toHaveCount(0);
});

test("a duplicate name is refused in plain words and the old name comes back; no permission says so", async ({ page }) => {
  await open(page);
  await probe(page, (p) => { p.mesh.server().latency = 250; });
  await hostName(page, "build-01").dblclick();
  await page.keyboard.type("nix-cache");
  await page.keyboard.press("Enter");
  // While the server thinks, the card already says the new name (and is marked as waiting).
  await expect(hostName(page, "build-01")).toHaveText("nix-cache");
  await expect(card(page, "build-01")).toHaveAttribute("data-renaming", "pending");
  await expect(toast(page)).toContainText("Could not rename build-01: another host is already called nix-cache.");
  await expect(hostName(page, "build-01")).toHaveText("build-01");
  await expect(card(page, "build-01")).not.toHaveAttribute("data-renaming", /./);
  await shoot(page, "refused-duplicate-desktop-ink");
  await probe(page, (p) => { p.mesh.server().latency = 0; p.mesh.server().failNext("mesh.node.rename", "refuse"); });
  await hostName(page, "build-01").dblclick();
  await page.keyboard.type("build-02");
  await page.keyboard.press("Enter");
  await expect(toast(page)).toContainText("you are not allowed to rename hosts");
  await expect(hostName(page, "build-01")).toHaveText("build-01");
});

test("the Views tree renames a Mesh host the same way, and a single click still flies to it", async ({ page }) => {
  await open(page);
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1); // the tree's rename starts from the row actions, which load with the sidebar
  await expect(page.locator("#sidebar")).toBeVisible();
  const leaf = page.locator('#tree .bm-leaf[data-id="n-build-01"]');
  await expect(leaf).toBeVisible();
  // Tags and the other views' windows are not renamable here.
  // Mesh hosts are renamable here, and so are the Console's sessions (#215); no other view's row is.
  await expect(page.locator('#tree .bm-sec:not([data-id="view:console"]) .bm-leaf[data-renamable]')).toHaveCount(await page.locator('#tree .bm-sec[data-id="view:mesh"] .bm-leaf[data-renamable]').count());
  await leaf.locator(".bm-label").dblclick();
  await expect(field(page)).toBeVisible();
  await expect(field(page)).toHaveValue("build-01");
  await shoot(page, "tree-editing-desktop-ink");
  await page.keyboard.type("build-07");
  await page.keyboard.press("Enter");
  await expect(page.locator('#tree .bm-leaf[data-id="n-build-07"] .bm-label')).toHaveText("build-07");
  await expect(card(page, "build-07")).toBeVisible();
  expect(await renames(page)).toEqual([{ node_id: 1, name: "build-07" }]);
  // A refusal puts the old name back in the tree.
  await page.locator('#tree .bm-leaf[data-id="n-build-07"] .bm-label').dblclick();
  await page.keyboard.type("nix-cache");
  await page.keyboard.press("Enter");
  await expect(page.locator('#tree .bm-leaf[data-id="n-build-07"] .bm-label')).toHaveText("build-07");
  await expect(toast(page)).toContainText("Could not rename build-07");
});

test("the palette finds 'rename <host>' and opens the field on that card", async ({ page }) => {
  await open(page);
  await probe(page, (p) => p.flyView("settings"));
  await page.waitForTimeout(1000);
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("rename edge");
  await expect(page.locator(".result").first()).toContainText("Rename edge-arm");
  await page.keyboard.press("Enter");
  await expect(field(page)).toBeVisible({ timeout: 8000 });
  await expect(field(page)).toHaveValue("edge-arm");
  await page.keyboard.type("edge-two");
  await page.keyboard.press("Enter");
  await expect(card(page, "edge-two")).toBeVisible();
  expect(await renames(page)).toEqual([{ node_id: 2, name: "edge-two" }]);
});

test.describe("touch", () => {
  test.use({ hasTouch: true, isMobile: true, viewport: PHONE, deviceScaleFactor: 3 });

  test("a double tap on a card's name opens the field, and the name does not zoom the page", async ({ page }) => {
    await open(page, PHONE);
    const host = "build-01";
    await bringIntoView(page, host);
    const touchAction = await hostName(page, host).evaluate((el) => getComputedStyle(el.closest(".ui-window-pill")!).touchAction);
    expect(["none", "manipulation"]).toContain(touchAction);
    const box = (await hostName(page, host).boundingBox())!;
    const x = box.x + box.width / 2, y = box.y + box.height / 2;
    await page.touchscreen.tap(x, y);
    await page.waitForTimeout(500);
    await expect(field(page)).toHaveCount(0); // one tap: nothing
    await page.touchscreen.tap(x, y);
    await page.touchscreen.tap(x, y);
    await expect(field(page)).toBeVisible();
    const scale = await page.evaluate(() => window.visualViewport!.scale);
    expect(scale).toBe(1);
    // The field is 16 px or larger on a phone, so iOS never zooms into it.
    expect(await field(page).evaluate((el) => parseFloat(getComputedStyle(el).fontSize))).toBeGreaterThanOrEqual(16);
    await shoot(page, "card-editing-phone-ink");
    await expect(field(page)).toHaveValue(host);
    await page.keyboard.type("renamed-by-tap");
    await page.keyboard.press("Enter");
    await expect(card(page, "renamed-by-tap")).toBeVisible();
  });

  test("phone 393x852: the open field never sits under the status dot, for short, usual and long names", async ({ page }) => {
    await open(page, PHONE);
    const dblTap = async (host: string): Promise<void> => {
      await bringIntoView(page, host);
      const box = (await hostName(page, host).boundingBox())!;
      const x = box.x + box.width / 2, y = box.y + box.height / 2;
      await page.touchscreen.tap(x, y);
      await page.touchscreen.tap(x, y);
    };
    await checkAndRename(page, "build-01", LONG, dblTap, "393x852");
    await checkAndRename(page, LONG, "db", dblTap, "393x852");
    await dblTap("db");
    await expectFieldClearOnCard(page, "db", "393x852 card \"db\" (after a long name)");
    await shoot(page, "field-clear-393x852-short-name");
    await page.keyboard.press("Escape");
    await page.locator("#sidebar-toggle").tap();
    await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1); // the tree's rename starts from the row actions, which load with the sidebar
    await expect(page.locator("#sidebar")).toBeVisible();
    const label = page.locator('#tree .bm-leaf[data-id="n-nix-cache"] .bm-label');
    await label.scrollIntoViewIfNeeded();
    const box = (await label.boundingBox())!;
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await expect(field(page)).toBeVisible();
    await expectFieldClearInTree(page, "n-nix-cache", "393x852 tree");
  });

  test("in the Views tree the first tap flies and the sidebar waits for the second", async ({ page }) => {
    await open(page, PHONE);
    await page.locator("#sidebar-toggle").tap();
    await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1); // the tree's rename starts from the row actions, which load with the sidebar
    await expect(page.locator("#sidebar")).toBeVisible();
    const label = page.locator('#tree .bm-leaf[data-id="n-build-01"] .bm-label');
    await label.scrollIntoViewIfNeeded(); // the tree is longer than the phone
    const box = (await label.boundingBox())!;
    const x = box.x + box.width / 2, y = box.y + box.height / 2;
    await page.touchscreen.tap(x, y);
    await page.touchscreen.tap(x, y);
    await expect(field(page)).toBeVisible();
    await page.waitForTimeout(600);
    await expect(page.locator("#sidebar")).toBeVisible(); // still open: the person is typing
    await shoot(page, "tree-editing-phone-ink");
    await page.keyboard.type("build-04");
    await page.keyboard.press("Enter");
    await expect(page.locator('#tree .bm-leaf[data-id="n-build-04"] .bm-label')).toHaveText("build-04");
  });

  test("a single tap on a name in the tree still closes the sidebar, a moment later", async ({ page }) => {
    await open(page, PHONE);
    await page.locator("#sidebar-toggle").tap();
    await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1); // the tree's rename starts from the row actions, which load with the sidebar
    const label = page.locator('#tree .bm-leaf[data-id="n-build-01"] .bm-label');
    await label.tap();
    await expect(page.locator("#sidebar")).toBeHidden({ timeout: 3000 });
    await expect(field(page)).toHaveCount(0);
  });
});

/**
 * The open field never sits under what is drawn beside the name (#259, found in the phone captures: the green status dot sat
 * on the last letter of the name). A rect is the drawn box in CSS px; two boxes collide when they share any area.
 */
type Box = { x: number; y: number; w: number; h: number };
const collide = (a: Box, b: Box): boolean => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
const boxOf = (locator: ReturnType<Page["locator"]>): Promise<Box> =>
  locator.evaluate((el) => { const r = el.getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height }; });
/**
 * What the card's header draws around the name: the machine's mark, the status dot, the session name, the header
 * actions, and the round → pill (`.cl-port`, the access connector) beside the name pill. The → pill is its own button,
 * not part of the header actions (those are empty on a Mesh card): the owner's screenshot showed the field's tinted box
 * running under it, which a check of the header actions cannot see.
 */
const CARD_NEIGHBOURS = [".ui-window-mark", ".ui-window-conn", ".ui-window-session", ".ui-window-actions .ui-window-action", ".cl-port"];

/** The field is open on this host's card: it stays inside the pill and clear of each neighbour that is drawn; its text is whole. */
async function expectFieldClearOnCard(page: Page, host: string, what: string): Promise<void> {
  const input = field(page);
  await expect(input, what).toBeVisible();
  const f = await boxOf(input);
  const pill = await boxOf(card(page, host).locator(".ui-window-pill"));
  expect(f.x, `${what}: field starts inside the pill`).toBeGreaterThanOrEqual(pill.x - 0.5);
  expect(f.x + f.w, `${what}: field ends inside the pill`).toBeLessThanOrEqual(pill.x + pill.w + 0.5);
  const dot = await boxOf(card(page, host).locator(".ui-window-conn"));
  expect(dot.w, `${what}: the connection icon is drawn (the check is meaningful)`).toBeGreaterThan(1);
  // The name pill may widen while the field is open (a short name gets room to type in), but its neighbour, the → pill,
  // must move aside with it: the two pills never share area, and both stay inside the card.
  const actions = await boxOf(card(page, host).locator(".cl-port"));
  expect(actions.w, `${what}: the → pill is drawn (the check is meaningful)`).toBeGreaterThan(1);
  expect(collide(pill, actions), `${what}: the widened name pill (${JSON.stringify(pill)}) overlaps the → pill (${JSON.stringify(actions)})`).toBe(false);
  expect(pill.x + pill.w, `${what}: the name pill ends before the → pill starts`).toBeLessThanOrEqual(actions.x + 0.5);
  const frame = await boxOf(card(page, host));
  expect(actions.x + actions.w, `${what}: the → pill stays inside the card`).toBeLessThanOrEqual(frame.x + frame.w + 0.5);
  expect(f.x + f.w, `${what}: the field ends before the → pill starts`).toBeLessThanOrEqual(actions.x + 0.5);
  for (const selector of CARD_NEIGHBOURS) {
    for (const el of await card(page, host).locator(selector).all()) {
      const b = await boxOf(el);
      if (b.w < 1 || b.h < 1) continue; // not drawn (hidden by the width, or no status)
      expect(collide(f, b), `${what}: the field (${JSON.stringify(f)}) covers ${selector} (${JSON.stringify(b)})`).toBe(false);
    }
  }
}
/** Short names open whole: the field never makes a name scroll before anything was typed. */
const expectTextWhole = (page: Page, what: string) =>
  expect.poll(() => field(page).evaluate((el: HTMLInputElement) => el.scrollWidth - el.clientWidth), { message: `${what}: the open field scrolls its own text` }).toBeLessThanOrEqual(1);

/** Opens the field (by double click or double tap on the name), checks it, and renames the host to `to` so the next case has a new shape of name. */
async function checkAndRename(page: Page, host: string, to: string, open: (host: string) => Promise<void>, size: string): Promise<void> {
  await open(host);
  await expectFieldClearOnCard(page, host, `${size} card "${host}"`);
  // A long name is ellipsized on its card, and the field scrolls it as any field does; every name that fits opens whole.
  if (host !== LONG) await expectTextWhole(page, `${size} card "${host}"`);
  await shoot(page, `field-clear-${size}-${host === LONG ? "long" : host.length < 4 ? "short" : "usual"}-name`);
  await page.keyboard.type(to);
  await page.keyboard.press("Enter");
  await expect(card(page, to)).toBeVisible();
  await page.waitForTimeout(400);
}
const LONG = "build-farm-eu-west-central-runner-17";

/** The tree's field stays inside its row and clear of the row's own mark or note, when it has one. */
async function expectFieldClearInTree(page: Page, id: string, what: string): Promise<void> {
  const leaf = page.locator(`#tree .bm-leaf[data-id="${id}"]`);
  const f = await boxOf(field(page));
  const row = await boxOf(leaf);
  expect(f.x + f.w, `${what}: field ends inside its row`).toBeLessThanOrEqual(row.x + row.w + 0.5);
  for (const el of await leaf.locator(".ui-mark, .bm-meta").all()) {
    const b = await boxOf(el);
    if (b.w < 1 || b.h < 1) continue;
    expect(collide(f, b), `${what}: the field covers a mark or note of its row`).toBe(false);
  }
}

test("desktop: the open field never sits under the status dot, for short, usual and long names", async ({ page }) => {
  await open(page, DESKTOP);
  const dbl = async (host: string): Promise<void> => { await hostName(page, host).dblclick(); };
  await checkAndRename(page, "build-01", LONG, dbl, "1440x900");
  await checkAndRename(page, LONG, "db", dbl, "1440x900");
  await dbl("db");
  await expectFieldClearOnCard(page, "db", "1440x900 card \"db\" (after a long name)");
  await shoot(page, "field-clear-1440x900-short-name");
  await page.keyboard.press("Escape");
  // The Views tree: the field in a leaf row.
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator('#tree[data-rows="ready"]')).toHaveCount(1); // the tree's rename starts from the row actions, which load with the sidebar
  await expect(page.locator("#sidebar")).toBeVisible();
  await page.locator('#tree .bm-leaf[data-id="n-nix-cache"] .bm-label').dblclick();
  await expect(field(page)).toBeVisible();
  await expectFieldClearInTree(page, "n-nix-cache", "1440x900 tree");
  await page.keyboard.press("Escape");
});

test("paper theme: the field reads on light", async ({ page }) => {
  await open(page, DESKTOP, "paper");
  await hostName(page, "build-01").dblclick();
  await expect(field(page)).toBeVisible();
  await shoot(page, "card-editing-desktop-paper");
  await page.keyboard.press("Escape");
});
