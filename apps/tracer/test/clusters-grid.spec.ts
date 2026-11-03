/**
 * Groups of columns (D212): a window split right in a stacked column divides only its own column, and the windows around
 * it span both halves. Every action is driven the way a person drives it (key, ⌘K, the header pill, the phone's canvas
 * event) and checked on layout: no window overlaps another, the footprint of the view does not change, spanning windows
 * are level with their neighbours, and closing a half gives back the layout it came from.
 */
import { expect, test, type Page } from "playwright/test";
import { uiFactor } from "./ui-factor";

const VIEW = '.cl[data-view="console"]';

async function boot(page: Page, width = 1440, height = 900, theme = "mocha"): Promise<void> {
  await page.setViewportSize({ width, height });
  await page.goto(`/?mock=1&proto=clusters&scene=1&theme=${theme}&bg=none`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
}

interface Win { id: string; span: number; row: number; rows: number; left: number; top: number; width: number; height: number }
interface Grid { groups: number; cols: { id: string; w: number; wins: Win[] }[]; windows: number; total: number; active: string | null; overlaps: string[] }

/** The view as the person sees it: each window's rectangle in layout px (camera-free), its span and band, and any overlap. */
const grid = (page: Page): Promise<Grid> => page.evaluate((view) => {
  const cols = [...document.querySelectorAll<HTMLElement>(`${view} .cl-col`)];
  const all = [...document.querySelectorAll<HTMLElement>(`${view} .ui-window`)];
  const boxes = all.map((n) => ({ id: n.dataset.windowId!, r: n.getBoundingClientRect() }));
  const overlaps: string[] = [];
  for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
    const a = boxes[i]!.r, b = boxes[j]!.r;
    if (a.left < b.right - 1 && b.left < a.right - 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1) overlaps.push(`${boxes[i]!.id}×${boxes[j]!.id}`);
  }
  const widths = cols.map((c) => Number(c.dataset.w) || 0);
  return {
    groups: document.querySelectorAll(`${view} .cl-group`).length,
    cols: cols.map((c) => ({
      id: c.dataset.id!, w: Number(c.dataset.w) || 0,
      // A column's windows are its own children; a group's columns are display: contents, so these are grid items.
      wins: [...c.querySelectorAll<HTMLElement>(":scope > .ui-window")].map((w) => {
        const r = w.getBoundingClientRect();
        return { id: w.dataset.windowId!, span: Number(w.dataset.span) || 1, row: Number(w.dataset.row ?? 0), rows: Number(w.dataset.rows) || 1, left: Math.round(r.left), top: Math.round(r.top), width: Math.round(r.width), height: Math.round(r.height) };
      }),
    })),
    windows: all.length,
    total: widths.reduce((a, b) => a + b, 0) + 12 * Math.max(0, widths.length - 1),
    active: document.querySelector<HTMLElement>(`${view} .ui-window[data-active]`)?.dataset.windowId ?? null,
    overlaps,
  };
}, VIEW);

/** A narrow window's action, through its ⋯ menu (the same action as the header button of a wide window). */
async function windowMenu(page: Page, id: string, action: string): Promise<void> {
  // The menu's module loads on the first press, so its rows are awaited; the presses are DOM clicks (a window partly off
  // the screen is still a window the person pressed).
  await page.locator(`${VIEW} .ui-window[data-window-id="${id}"] .ui-window-more`).evaluate((b) => (b as HTMLElement).click());
  const item = page.locator(`.ui-window-menu .ui-window-menu-item[data-action="${action}"]`);
  await expect(item).toHaveCount(1, { timeout: 5000 });
  await item.evaluate((b) => (b as HTMLElement).click());
  await page.waitForTimeout(300);
}

const activate = (page: Page, id: string): Promise<void> => page.locator(`${VIEW} .ui-window[data-window-id="${id}"] .ui-window-body`).first().click({ position: { x: 20, y: 40 } }).then(() => page.waitForTimeout(400));

// The default chords off a Mac (D222, shortcuts.ts): Ctrl+Alt is AltGr on many layouts, so no default uses it. These replace
// the D212 chords (Ctrl+Shift+Alt+D, Ctrl+Alt+R, Ctrl+Alt+D) that the keymap left in 2026-10-10 (d0aacfa1e).
const SPLIT_RIGHT = ["Control", "Shift", "KeyD"];
const SPLIT_DOWN = ["Control", "Shift", "KeyE"];
const NEW_RIGHT = ["Control", "Shift", "Enter"];
const NEW_BELOW = ["Control", "Shift", "Alt", "Enter"];

async function press(page: Page, chord: string[]): Promise<void> {
  for (const k of chord) await page.keyboard.down(k);
  for (const k of [...chord].reverse()) await page.keyboard.up(k);
  await page.waitForTimeout(450);
}

/** The canvas-action event the palette and the key handlers send: the same path, without a key chord. */
const act = (page: Page, action: string): Promise<void> => page.evaluate((a) => {
  window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: a, source: "pointer" } }));
}, action).then(() => page.waitForTimeout(900));

/** A three-window stack in the middle column: edge-arm is split down, then the middle window is split right. */
async function stacked(page: Page): Promise<void> {
  await activate(page, "w-edge-arm");
  await press(page, SPLIT_DOWN);
  await activate(page, "w-edge-arm");
  await press(page, SPLIT_RIGHT);
}

function expectNoOverlap(g: Grid): void {
  expect(g.overlaps, "no two windows overlap").toEqual([]);
}

test.describe("split right in a stacked column (D212)", () => {
  test.setTimeout(120_000);

  test("by key: the window's column halves, the windows around it span both halves, the footprint does not change", async ({ page }) => {
    await boot(page);
    const before = await grid(page);
    await stacked(page);
    const after = await grid(page);
    expect(after.groups, "one group").toBe(1);
    expect(after.windows).toBe(before.windows + 2);
    expect(after.total, "footprint").toBe(before.total);
    expectNoOverlap(after);
    const c2 = after.cols.find((c) => c.wins.some((w) => w.id === "w-nix-cache"))!;
    expect(c2.wins.find((w) => w.id === "w-nix-cache")!.span).toBe(2);
    expect(c2.wins.find((w) => w.id === "w-edge-arm")!.span).toBe(1);
    // The spanning window is as wide as both halves together, with the gap between them.
    const half = after.cols.find((c) => c.wins.some((w) => w.id === "w-edge-arm-s2"))!;
    const top = c2.wins.find((w) => w.id === "w-nix-cache")!;
    expect(Math.abs(top.width - (c2.w + 12 + half.w))).toBeLessThanOrEqual(2);
    expect(after.active, "the new window is active").not.toBe(before.active);
  });

  test("by ⌘K: Split right on the stacked window gives the same layout", async ({ page }) => {
    await boot(page);
    await activate(page, "w-edge-arm");
    await press(page, SPLIT_DOWN);
    await activate(page, "w-edge-arm");
    const before = await grid(page);
    await page.keyboard.press("Control+Shift+K");
    await expect(page.locator("#palette")).toBeVisible();
    await page.locator("#palette-input").fill("Split right");
    await expect(page.locator("#palette-results .result").first()).toContainText("Split right");
    await page.keyboard.press("Enter");
    await page.waitForTimeout(900);
    const after = await grid(page);
    expect(after.groups).toBe(1);
    expect(after.windows).toBe(before.windows + 1);
    expect(after.total).toBe(before.total);
    expectNoOverlap(after);
  });

  test("by mouse: the header pill's split right on the middle window divides it the same way", async ({ page }) => {
    await boot(page);
    await activate(page, "w-edge-arm");
    await press(page, SPLIT_DOWN);
    await activate(page, "w-edge-arm");
    const before = await grid(page);
    // A half is narrow: its actions sit behind the ⋯ (TASTE: title first), and the menu holds the same action.
    await windowMenu(page, "w-edge-arm", "split-right");
    await page.waitForTimeout(1500);
    const after = await grid(page);
    expect(after.groups).toBe(1);
    expect(after.windows).toBe(before.windows + 1);
    expect(after.total).toBe(before.total);
    expectNoOverlap(after);
  });

  test("closing the new half gives back the layout it came from, widths and heights", async ({ page }) => {
    await boot(page);
    await activate(page, "w-edge-arm");
    await press(page, SPLIT_DOWN);
    const beforeSplit = await grid(page);
    await activate(page, "w-edge-arm");
    await press(page, SPLIT_RIGHT);
    const newId = (await grid(page)).active!;
    await windowMenu(page, newId, "close");
    await page.waitForTimeout(1000);
    const back = await grid(page);
    expect(back.groups).toBe(0);
    expect(back.cols.map((c) => c.w)).toEqual(beforeSplit.cols.map((c) => c.w));
    const heightsOf = (g: Grid) => g.cols.map((c) => c.wins.map((w) => w.height));
    expect(heightsOf(back)).toEqual(heightsOf(beforeSplit));
    expect(back.total).toBe(beforeSplit.total);
    expectNoOverlap(back);
  });

  test("closing the window it came from: the new half takes its band, and the group dissolves", async ({ page }) => {
    await boot(page);
    await stacked(page);
    const g = await grid(page);
    await windowMenu(page, "w-edge-arm", "close");
    await page.waitForTimeout(1000);
    const after = await grid(page);
    expect(after.groups).toBe(0);
    expect(after.total).toBe(g.total);
    expect(after.windows).toBe(g.windows - 1);
    expectNoOverlap(after);
    const c2 = after.cols.find((c) => c.wins.some((w) => w.id === "w-nix-cache"))!;
    expect(c2.wins.map((w) => w.id)).toContain("w-edge-arm-s2");
    // The default desktop column is 459 px at the standard UI size and grows with it (#283, TASTE "windows grow with it").
    expect(c2.w).toBe(Math.round(459 * (await uiFactor(page))));
  });

  test("split right of a spanning window halves its span inside the existing columns", async ({ page }) => {
    await boot(page);
    await stacked(page);
    const before = await grid(page);
    await activate(page, "w-nix-cache");
    await press(page, SPLIT_RIGHT);
    const after = await grid(page);
    expect(after.total).toBe(before.total);
    expect(after.windows).toBe(before.windows + 1);
    expectNoOverlap(after);
    expect(after.cols.length, "no new column: the span is halved inside the group").toBe(before.cols.length);
    // Only the bottom window still spans: the top one was halved, and nothing outside the group is spanning.
    expect(after.cols.flatMap((c) => c.wins).filter((w) => w.span > 1).map((w) => w.id)).toEqual(["w-edge-arm-s1"]);
  });

  test("new window right after a group opens a plain column after the whole group", async ({ page }) => {
    await boot(page);
    await stacked(page);
    await activate(page, "w-edge-arm");
    const before = await grid(page);
    await press(page, NEW_RIGHT);
    const after = await grid(page);
    expect(after.groups, "the group is untouched").toBe(1);
    expect(after.cols.length).toBe(before.cols.length + 1);
    expect(after.total).toBe(before.total + before.cols.find((c) => c.wins.some((w) => w.id === "w-edge-arm"))!.w + 12);
    expectNoOverlap(after);
  });

  test("new window below in a group grows the column and keeps the windows beside it", async ({ page }) => {
    await boot(page);
    await stacked(page);
    await activate(page, "w-edge-arm");
    const before = await grid(page);
    await press(page, NEW_BELOW);
    const after = await grid(page);
    expect(after.windows).toBe(before.windows + 1);
    expect(after.total).toBe(before.total);
    expectNoOverlap(after);
    expect(after.cols.map((c) => c.w)).toEqual(before.cols.map((c) => c.w));
  });

  test("split down in a group divides only the window's band, and the window beside it keeps its height", async ({ page }) => {
    await boot(page);
    await stacked(page);
    await activate(page, "w-edge-arm-s2");
    const before = await grid(page);
    await press(page, SPLIT_DOWN);
    const after = await grid(page);
    expect(after.windows).toBe(before.windows + 1);
    expectNoOverlap(after);
    expect(after.groups).toBe(1);
    const beside = (g: Grid) => g.cols.find((c) => c.wins.some((w) => w.id === "w-edge-arm"))!.w;
    expect(beside(after)).toBe(beside(before));
  });
});

test.describe("camera and saved layout with a group (D212)", () => {
  test.setTimeout(120_000);

  test("the camera stops of a group are its columns: focusing a window in the new half brings all of it into view", async ({ page }) => {
    await boot(page);
    await stacked(page);
    const lock = await page.evaluate(() => (window as unknown as { __tracerClusters: { canvasLock(): { on: boolean; stops: number } } }).__tracerClusters.canvasLock());
    expect(lock.on, "the canvas lock stays on across a split").toBe(true);
    expect(lock.stops).toBeGreaterThanOrEqual(1);
    await activate(page, "w-edge-arm-s2");
    await page.waitForTimeout(900);
    const r = await page.evaluate(() => {
      const w = document.querySelector<HTMLElement>('.cl[data-view="console"] .ui-window[data-window-id="w-edge-arm-s2"]')!.getBoundingClientRect();
      return { left: w.left, right: w.right, vw: document.documentElement.clientWidth };
    });
    expect(r.left).toBeGreaterThanOrEqual(0);
    expect(r.right).toBeLessThanOrEqual(r.vw);
  });

  test("the saved document holds the span, so a reload places the group the same way", async ({ page }) => {
    await boot(page);
    await stacked(page);
    await page.waitForTimeout(700);
    const doc = await page.evaluate(() => (window as unknown as { __tracerClusters: { mesh: { document(): Promise<unknown> } } }).__tracerClusters.mesh.document());
    const json = JSON.stringify(doc);
    expect(json).toContain('"span":2');
    expect(json).toContain('"row"');
  });
});

test.describe("phone 393x852 with a group (D212)", () => {
  test.setTimeout(120_000);

  test("split right in a stacked column keeps every window on the screen and never scrolls the page sideways", async ({ page }) => {
    await boot(page, 393, 852);
    // The phone starts from the window on screen (as the other phone specs do); a split leaves the new window active.
    await page.locator(`${VIEW} .ui-window .ui-window-body`).first().click({ position: { x: 20, y: 40 } });
    await page.waitForTimeout(400);
    await act(page, "canvas:split:down");
    const before = await grid(page);
    await act(page, "canvas:split:right");
    const after = await grid(page);
    expect(after.groups).toBe(1);
    expect(after.windows).toBe(before.windows + 1);
    expectNoOverlap(after);
    const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(pageWidth).toBeLessThanOrEqual(393);
    // A grouped column keeps its phone width: the spanning window is at least one column wide on screen.
    const spanning = after.cols.flatMap((c) => c.wins).filter((w) => w.span > 1);
    expect(spanning.length).toBeGreaterThan(0);
    for (const w of spanning) expect(w.width).toBeGreaterThan(200);
  });
});

test.describe("moving a window of a group by its pill (D212)", () => {
  test.setTimeout(120_000);

  test("a grouped window dragged to the far column lands there: no overlap, the footprint unchanged, the group closes its hole", async ({ page }) => {
    await boot(page);
    await stacked(page);
    const before = await grid(page);
    const pill = page.locator(`${VIEW} .ui-window[data-window-id="w-edge-arm"] .ui-window-pill`);
    const box = await pill.boundingBox();
    const target = await page.locator(`${VIEW} .ui-window[data-window-id="w-studio-mac"]`).boundingBox();
    expect(box && target).toBeTruthy();
    const from = { x: box!.x + box!.width / 2, y: box!.y + box!.height / 2 };
    const to = { x: target!.x + target!.width / 2, y: target!.y + target!.height / 3 };
    await page.mouse.move(from.x, from.y);
    await page.mouse.down();
    for (let i = 1; i <= 12; i++) await page.mouse.move(from.x + ((to.x - from.x) * i) / 12, from.y + ((to.y - from.y) * i) / 12);
    await page.mouse.up();
    // The window springs from the lift layer into its slot; the layout is read once it has landed.
    await expect.poll(() => page.locator(`${VIEW} .cl-lift .ui-window`).count(), { timeout: 5000 }).toBe(0);
    await page.waitForTimeout(600);
    const after = await grid(page);
    expectNoOverlap(after);
    expect(after.windows).toBe(before.windows);
    expect(after.total).toBe(before.total);
    expect(after.cols.flatMap((c) => c.wins).map((w) => w.id).sort()).toEqual(before.cols.flatMap((c) => c.wins).map((w) => w.id).sort());
  });
});

test.describe("title first in a narrow half (TASTE, D212)", () => {
  test.setTimeout(120_000);

  test("a half too narrow for its actions keeps its title, shows one ⋯, and the menu holds every action", async ({ page }) => {
    await boot(page);
    await stacked(page);
    const half = page.locator(`${VIEW} .ui-window[data-window-id="w-edge-arm"]`);
    const m = await half.evaluate((w) => {
      const title = w.querySelector<HTMLElement>(".ui-window-title")!.getBoundingClientRect();
      const more = w.querySelector<HTMLElement>(".ui-window-more")!;
      const visible = [...w.querySelectorAll<HTMLElement>(".ui-window-action:not(.ui-window-more)")].filter((b) => getComputedStyle(b).display !== "none").map((b) => b.dataset.action);
      return { titleW: Math.round(title.width), moreShown: getComputedStyle(more).display !== "none", visible, width: w.getBoundingClientRect().width };
    });
    expect(m.width).toBeLessThan(260);
    expect(m.moreShown, "the ⋯ shows").toBe(true);
    expect(m.visible, "no action button shows in the header").toEqual([]);
    // The pill stops short of the lock at the frame's centre (TASTE: window chrome), so a 224 px half keeps room for the title:
    // four characters of the host, where five actions left it one. The pill carries a 14 px connection icon since #212 (owner,
    // 2026-11-01: "connection states is approved"), which took about 9 px of the 43 the title had; measured 34.3 px at a UI size
    // of 0.99 and 39.1 px at 1.1, so the room is 34 px at the standard size and grows with the UI (#283).
    expect(m.titleW, "the title keeps room for the host").toBeGreaterThanOrEqual(Math.floor(34 * (await uiFactor(page))));
    await half.locator(".ui-window-more").evaluate((b) => (b as HTMLElement).click());
    await expect(page.locator(".ui-window-menu .ui-window-menu-item")).toHaveCount(4, { timeout: 5000 });
    const items = await page.locator(".ui-window-menu .ui-window-menu-item").evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.action));
    expect(items).toEqual(["split-right", "split-down", "sessions", "close"]);
    await page.keyboard.press("Escape");
  });

  test("a wide window keeps its actions in the header, and no ⋯ is shown", async ({ page }) => {
    await boot(page);
    const wide = page.locator(`${VIEW} .ui-window[data-window-id="w-build-01"]`);
    const more = await wide.evaluate((w) => getComputedStyle(w.querySelector<HTMLElement>(".ui-window-more")!).display);
    expect(more).toBe("none");
    const shown = await wide.evaluate((w) => [...w.querySelectorAll<HTMLElement>(".ui-window-action")].filter((b) => getComputedStyle(b).display !== "none" && !b.classList.contains("ui-window-more")).length);
    expect(shown).toBeGreaterThanOrEqual(2);
  });
});

test.describe("the phone after a split in a group (TASTE: chrome is never clipped)", () => {
  test.setTimeout(120_000);

  test("the new half and the spanning window's header stay on the screen", async ({ page }) => {
    await boot(page, 393, 852);
    await page.locator(`${VIEW} .ui-window .ui-window-body`).first().click({ position: { x: 20, y: 40 } });
    await page.waitForTimeout(400);
    await act(page, "canvas:split:down");
    await act(page, "canvas:split:right");
    const pills = await page.evaluate((v) => [...document.querySelectorAll<HTMLElement>(`${v} .ui-window`)].map((w) => {
      const head = w.querySelector<HTMLElement>(".ui-window-head")!.getBoundingClientRect();
      const r = w.getBoundingClientRect();
      return { id: w.dataset.windowId, left: Math.round(r.left), right: Math.round(r.right), headLeft: Math.round(head.left), span: Number(w.dataset.span) || 1 };
    }), VIEW);
    const vw = await page.evaluate(() => document.documentElement.clientWidth);
    // The windows that the camera frames (those on screen at all) show their header whole: the header's left edge is not off the screen.
    const framed = pills.filter((p) => p.right > 0 && p.left < vw);
    expect(framed.length).toBeGreaterThan(0);
    for (const p of framed) expect(p.headLeft, `${p.id} header left edge`).toBeGreaterThanOrEqual(-1);
    for (const p of framed) expect(p.right, `${p.id} right edge`).toBeLessThanOrEqual(vw + 1);
  });
});
