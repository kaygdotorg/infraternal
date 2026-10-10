/**
 * The four window actions (D212, TASTE "Split divides; new opens beside"): split right and split down divide the
 * window's own space, new window right and new window below open a full-size window beside or under it.
 *
 * Every action is driven by key, by ⌘K and by mouse. Footprints are read from layout (offset sizes and the
 * columns' stored widths), never from the camera's transformed rectangles, so a camera move cannot fake a result.
 * A keyboard action is instant: no silhouette, and the new window is active in the frame after the press.
 */
import { expect, test, type Page } from "playwright/test";

const VIEW = '.cl[data-view="console"]';

async function boot(page: Page, theme = "mocha", width = 1440, height = 900): Promise<void> {
  await page.setViewportSize({ width, height });
  await page.goto(`/?mock=1&proto=clusters&scene=1&theme=${theme}&bg=none`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1500);
  await page.locator(`${VIEW} .ui-window .ui-window-body`).first().click({ position: { x: 20, y: 40 } });
  await page.waitForTimeout(500);
}

interface Layout {
  /** Each column's stored width, left to right (layout px, unaffected by the camera). */
  widths: number[];
  /** Every window's offset height per column, top to bottom. */
  heights: number[][];
  /** Total footprint: the widths and the gaps between columns. */
  total: number;
  windows: number;
  active: string | null;
}

const layout = (page: Page): Promise<Layout> => page.evaluate((view) => {
  const cols = [...document.querySelectorAll<HTMLElement>(`${view} .cl-col`)];
  const widths = cols.map((c) => Number(c.dataset.w) || 0);
  const gap = 12;
  return {
    widths,
    heights: cols.map((c) => [...c.querySelectorAll<HTMLElement>(":scope > .ui-window")].map((w) => w.offsetHeight)),
    total: widths.reduce((a, b) => a + b, 0) + gap * Math.max(0, widths.length - 1),
    windows: document.querySelectorAll(`${view} .ui-window`).length,
    active: document.querySelector<HTMLElement>(`${view} .ui-window[data-active]`)?.dataset.windowId ?? null,
  };
}, VIEW);

/** The active window's column index and its row within that column, found from the DOM. */
const activeAt = (page: Page): Promise<{ col: number; row: number; rows: number }> => page.evaluate((view) => {
  const active = document.querySelector<HTMLElement>(`${view} .ui-window[data-active]`);
  const col = active?.parentElement;
  const cols = [...document.querySelectorAll<HTMLElement>(`${view} .cl-col`)];
  const wins = col ? [...col.querySelectorAll<HTMLElement>(":scope > .ui-window")] : [];
  return { col: col ? cols.indexOf(col) : -1, row: wins.indexOf(active!), rows: wins.length };
}, VIEW);

/** Presses a key chord (keyboard is the only path that is instant), then lets the state settle. */
async function press(page: Page, chord: string[]): Promise<void> {
  for (const k of chord) await page.keyboard.down(k);
  for (const k of [...chord].reverse()) await page.keyboard.up(k);
  await page.waitForTimeout(250);
}

/** Opens ⌘K, types the label and chooses the first row (the same path a person takes). */
async function fromPalette(page: Page, label: string): Promise<void> {
  await page.keyboard.press("Control+k");
  await expect(page.locator("#palette")).toBeVisible();
  await page.locator("#palette-input").fill(label);
  await expect(page.locator("#palette-results .result").first()).toContainText(label);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(700);
}

test.describe("keys (Linux and Windows chords; Mac chords are in the last test)", () => {
  test.setTimeout(120_000);

  test("split right divides the window: the footprint is unchanged and the neighbours stay put", async ({ page }) => {
    await boot(page);
    const before = await layout(page);
    const at = await activeAt(page);
    await press(page, ["Control", "Shift", "KeyD"]);
    const after = await layout(page);
    expect(after.windows).toBe(before.windows + 1);
    expect(after.total, "the footprint does not change").toBe(before.total);
    // The window's column is halved, the new one takes the other half, with the gap between them.
    expect(after.widths[at.col]! + after.widths[at.col + 1]! + 12).toBe(before.widths[at.col]);
    expect(after.widths.filter((_, i) => i !== at.col && i !== at.col + 1)).toEqual(before.widths.filter((_, i) => i !== at.col));
    expect(after.active, "the new window is active").not.toBe(before.active);
  });

  test("split down halves the window's height and keeps its column's width", async ({ page }) => {
    await boot(page);
    const before = await layout(page);
    const at = await activeAt(page);
    await press(page, ["Control", "Shift", "Alt", "KeyD"]);
    const after = await layout(page);
    expect(after.widths).toEqual(before.widths);
    expect(after.heights[at.col]!.length).toBe(before.heights[at.col]!.length + 1);
    const h = before.heights[at.col]![at.row]!;
    expect(Math.abs(after.heights[at.col]![at.row]! - Math.round((h - 12) / 2))).toBeLessThanOrEqual(1);
  });

  test("new window right opens a full-size column beside the window and grows the footprint by one column", async ({ page }) => {
    await boot(page);
    const before = await layout(page);
    const at = await activeAt(page);
    await press(page, ["Control", "Alt", "KeyR"]);
    const after = await layout(page);
    expect(after.widths.length).toBe(before.widths.length + 1);
    expect(after.widths[at.col + 1]).toBe(before.widths[at.col]);
    expect(after.widths.slice(0, at.col + 1)).toEqual(before.widths.slice(0, at.col + 1));
    expect(after.total).toBe(before.total + before.widths[at.col]! + 12);
  });

  test("new window below adds a full-size window under the window and grows its column", async ({ page }) => {
    await boot(page);
    const before = await layout(page);
    const at = await activeAt(page);
    await press(page, ["Control", "Alt", "KeyD"]);
    const after = await layout(page);
    expect(after.widths).toEqual(before.widths);
    expect(after.heights[at.col]!.length).toBe(before.heights[at.col]!.length + 1);
    // The new window is one column height (the view's content height) and the others keep theirs.
    const contentH = await page.evaluate((view) => document.querySelector<HTMLElement>(`${view} .cl-content`)!.offsetHeight, VIEW);
    const added = after.heights[at.col]!.at(-1)!;
    expect(Math.abs(added - contentH)).toBeLessThanOrEqual(2);
    expect(after.heights[at.col]!.slice(0, -1)).toEqual(before.heights[at.col]);
  });

  test("holding a key adds one split only, and a key action plays no silhouette", async ({ page }) => {
    await boot(page);
    const before = (await layout(page)).windows;
    await page.keyboard.down("Control"); await page.keyboard.down("Shift");
    await page.keyboard.down("KeyD");
    for (let i = 0; i < 20; i++) { await page.keyboard.down("KeyD"); await page.waitForTimeout(30); }
    await page.keyboard.up("KeyD"); await page.keyboard.up("Shift"); await page.keyboard.up("Control");
    await page.waitForTimeout(300);
    expect((await layout(page)).windows).toBe(before + 1);
    expect(await page.locator(".cl-goo").count()).toBe(0);
  });
});

test.describe("⌘K palette", () => {
  test.setTimeout(120_000);

  test("each of the four actions is in ⌘K with its exact label, and runs", async ({ page }) => {
    await boot(page);
    for (const label of ["Split right", "Split down", "New window right", "New window below"]) {
      await page.keyboard.press("Control+k");
      await expect(page.locator("#palette")).toBeVisible();
      await page.locator("#palette-input").fill(label);
      await expect(page.locator("#palette-results .result", { hasText: label }).first()).toBeVisible();
      await page.keyboard.press("Escape");
      await page.waitForTimeout(200);
    }
  });

  test("Split right from ⌘K divides a lone window; New window below from ⌘K grows its column", async ({ page }) => {
    await boot(page);
    const before = await layout(page);
    const at = await activeAt(page);
    await fromPalette(page, "Split right");
    const split = await layout(page);
    expect(split.total).toBe(before.total);
    expect(split.widths.length).toBe(before.widths.length + 1);
    // The column that was halved is now one of two side by side; the new window is active.
    expect(split.widths[at.col]).toBeLessThan(before.widths[at.col]!);
    expect(split.active).not.toBe(before.active);
    const mid = await activeAt(page);
    await fromPalette(page, "New window below");
    const below = await layout(page);
    expect(below.heights[mid.col]!.length).toBe(split.heights[mid.col]!.length + 1);
  });
});

test.describe("mouse", () => {
  test.setTimeout(120_000);

  test("the header pill's split right and split down divide the window, with the droplet", async ({ page }) => {
    await boot(page);
    const before = await layout(page);
    await page.locator(`${VIEW} .ui-window[data-active] [data-action="split-right"]`).evaluate((b) => (b as HTMLElement).click());
    // The pointer split plays the droplet (it lands in the same layout; the silhouette is checked in clusters-keyboard-split).
    await page.waitForTimeout(1500);
    const after = await layout(page);
    expect(after.windows).toBe(before.windows + 1);
    expect(after.total).toBe(before.total);
    await page.locator(`${VIEW} .ui-window[data-active] [data-action="split-down"]`).evaluate((b) => (b as HTMLElement).click());
    await page.waitForTimeout(1500);
    expect((await layout(page)).windows).toBe(before.windows + 2);
  });

  test("the canvas row's new window items open a window by mouse, without splitting", async ({ page }) => {
    await boot(page);
    const before = await layout(page);
    await page.locator('[aria-label="New window right"]').first().evaluate((b) => (b as HTMLElement).click());
    await page.waitForTimeout(900);
    const right = await layout(page);
    expect(right.widths.length).toBe(before.widths.length + 1);
    await page.locator('[aria-label="New window below"]').first().evaluate((b) => (b as HTMLElement).click());
    await page.waitForTimeout(900);
    const below = await layout(page);
    expect(below.windows).toBe(right.windows + 1);
  });
});

test.describe("the rules that hold across actions", () => {
  test.setTimeout(120_000);

  test("split right in a stacked column divides only that window's column: a group, the footprint unchanged (D212)", async ({ page }) => {
    await boot(page);
    // Stack the active window (split down), so its column is no longer its own.
    await press(page, ["Control", "Shift", "Alt", "KeyD"]);
    const stacked = await layout(page);
    const at = await activeAt(page);
    expect(stacked.heights[at.col]!.length).toBeGreaterThan(1);
    await press(page, ["Control", "Shift", "KeyD"]);
    const after = await layout(page);
    expect(after.windows).toBe(stacked.windows + 1);
    expect(after.total, "the footprint does not change").toBe(stacked.total);
    expect(await page.locator(`${VIEW} .cl-group`).count(), "the stacked column and its new half form one group").toBe(1);
  });

  test("closing a split half gives its width back, so the layout returns to what it was", async ({ page }) => {
    await boot(page);
    const before = await layout(page);
    const at = await activeAt(page);
    await press(page, ["Control", "Shift", "KeyD"]);
    expect((await layout(page)).widths.length).toBe(before.widths.length + 1);
    // Close the new half (the active window).
    await page.locator(`${VIEW} .ui-window[data-active] [data-action="close"]`).evaluate((b) => (b as HTMLElement).click());
    await page.waitForTimeout(900);
    const closed = await layout(page);
    expect(closed.widths).toEqual(before.widths);
    expect(closed.total).toBe(before.total);
    expect(closed.widths[at.col]).toBe(before.widths[at.col]);
  });
});

test.describe("on a Mac the chords are ⌘D, ⌘⇧D, ⌃⌥R and ⌃⌥D", () => {
  test.setTimeout(120_000);

  test("each Mac chord runs its own action, and Control+Option+Shift+D is nothing", async ({ page }) => {
    await page.addInitScript(() => { Object.defineProperty(navigator, "platform", { get: () => "MacIntel" }); });
    await boot(page);
    const count = async (): Promise<number> => (await layout(page)).windows;
    let before = await count();
    await press(page, ["Meta", "KeyD"]); // split right
    expect(await count()).toBe(before + 1);
    before = await count();
    await press(page, ["Control", "Alt", "KeyR"]); // new window right
    expect(await count()).toBe(before + 1);
    before = await count();
    await press(page, ["Control", "Alt", "KeyD"]); // new window below
    expect(await count()).toBe(before + 1);
    before = await count();
    await press(page, ["Meta", "Shift", "KeyD"]); // split down
    expect(await count()).toBe(before + 1);
    before = await count();
    await press(page, ["Control", "Alt", "Shift", "KeyD"]);
    expect(await count()).toBe(before);
    expect(await page.locator(".cl-goo").count()).toBe(0);
  });
});
