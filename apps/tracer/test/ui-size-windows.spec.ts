/**
 * Windows grow with the UI size (#283, owner 2026-11-01: "windows grow with the UI size"): the default width of a desktop window is
 * multiplied by the UI's factor (the 1.1 base and the slider together), a window the person widened keeps its proportion to the
 * default, the ceiling (99% of the canvas, #267) holds at every size, the camera keeps framing the active window, and at 150 %
 * on 1440 x 900 no window title is cut and no Settings row is clipped.
 *
 * Widths are layout widths (`offsetWidth`) of the Console view's columns, so the camera's zoom is not part of them.
 */
import { expect, test, type Page } from "playwright/test";

const COLS = '.cl[data-view="console"] .cl-col';
/** The canvas area's width: a window's ceiling is 99% of it (window-sizes.ts `maxColumnWidth`). */
const VIEWPORT = ".cl-viewport";
/** The desktop's base factor (16 px x 1.1). */
const BASE = 1.1;

async function open(page: Page, percent?: number): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  if (percent !== undefined) await page.addInitScript((p) => localStorage.setItem("tracer.ui-size.v2", String(p)), percent);
  await page.goto("/?mock=1&proto=clusters&scene=1&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1500);
}
/** Into the Console view at full zoom, as the window specs do (the scene starts as an overview). */
async function enter(page: Page): Promise<void> {
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await page.waitForTimeout(1600);
}
/** The saved (layout) width of every Console column: the default times the UI size's factor, or what the person made of it. */
const saved = (page: Page): Promise<number[]> => page.evaluate((sel) => [...document.querySelectorAll<HTMLElement>(sel)].map((c) => Number(c.dataset.w)), COLS);
const drawn = (page: Page): Promise<number[]> => page.evaluate((sel) => [...document.querySelectorAll<HTMLElement>(sel)].map((c) => c.offsetWidth), COLS);
/** What a default column should be at the factor `f` (the base and the slider): a third of the canvas area, clamped, times the factor. The area is
 *  itself drawn in rem (its gutters grow and shrink with the UI size), so it is read where it is. */
const expectedDefault = async (page: Page, f: number): Promise<number> => Math.min(Math.round((await canvasWidth(page)) * 0.99), Math.round(Math.max(400, Math.min(640, Math.round(((await canvasWidth(page)) - 24) / 3))) * f));
const canvasWidth = (page: Page): Promise<number> => page.evaluate((sel) => document.querySelector<HTMLElement>(sel)!.clientWidth, VIEWPORT);
const showAppearance = async (page: Page): Promise<void> => {
  await page.keyboard.press("Control+Shift+K");
  await page.waitForTimeout(350);
  await page.keyboard.type("Appearance Size", { delay: 6 });
  await page.waitForTimeout(400);
  await page.keyboard.press("Enter");
  await page.waitForTimeout(1800);
};
const slider = (page: Page) => page.getByRole("slider", { name: "UI size" });

test("a default window is as many times wider as the UI is bigger: 50, 100 and 150 %", async ({ page }) => {
  await open(page);
  expect((await saved(page))[0]!, "the standard size: 1.1 times a third of the canvas, less the gaps").toBe(await expectedDefault(page, BASE));
  for (const percent of [50, 150, 100]) {
    await page.evaluate((p) => localStorage.setItem("tracer.ui-size.v2", String(p)), percent);
    await page.reload();
    await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
    await page.waitForTimeout(1500);
    const want = await expectedDefault(page, BASE * (percent / 100));
    const got = await saved(page);
    expect(got.length).toBeGreaterThan(0);
    for (const w of got) expect(Math.abs(w - want), `a default column at ${percent} %: ${w} against ${want}`).toBeLessThanOrEqual(1.5);
  }
});

test("the slider resizes the windows live, with their saved widths following", async ({ page }) => {
  await open(page);
  const before = await saved(page);
  const drawnBefore = await drawn(page);
  await showAppearance(page);
  await slider(page).focus();
  await page.keyboard.press("End");
  await page.waitForTimeout(1800);
  const after = await saved(page);
  expect(after.length).toBe(before.length);
  const want = await expectedDefault(page, BASE * 1.5);
  after.forEach((w, i) => expect(Math.abs(w - want), `column ${i} at 150 %: ${w} against ${want}`).toBeLessThanOrEqual(1.5));
  // What is drawn follows what is saved, and the canvas's own spacing around a window stays what it is (px, like the layout code's).
  (await drawn(page)).forEach((w, i) => expect(Math.abs((w - after[i]!) - (drawnBefore[i]! - before[i]!)), `the spacing of drawn column ${i}`).toBeLessThanOrEqual(1));
  await page.keyboard.press("Home");
  await page.waitForTimeout(1800);
  const small = await expectedDefault(page, BASE * 0.5);
  (await saved(page)).forEach((w, i) => expect(Math.abs(w - small), `column ${i} at 50 %: ${w} against ${small}`).toBeLessThanOrEqual(1.5));
});

/** Drags the first column's right edge by `dx` (the view is entered first: the handle is a pixel wide in the overview). */
async function widen(page: Page, dx: number): Promise<{ width: number; standard: number }> {
  await enter(page);
  const standard = (await saved(page))[1] ?? (await saved(page))[0]!;
  const spot = await page.evaluate((sel) => { const e = document.querySelector<HTMLElement>(`${sel} .ui-window-resize[data-edge="e"]`)!; const r = e.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; }, COLS);
  await page.mouse.move(spot.x, spot.y);
  await page.waitForTimeout(300);
  await page.mouse.down();
  await page.mouse.move(spot.x + dx / 2, spot.y, { steps: 8 });
  await page.mouse.move(spot.x + dx, spot.y, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(700);
  return { width: (await saved(page))[0]!, standard };
}

test("a window the person widened keeps its proportion to the default when the UI size changes", async ({ page }) => {
  await open(page);
  const { width, standard } = await widen(page, 140);
  expect(width, `the drag widened it (${width} against the default ${standard})`).toBeGreaterThan(standard + 60);
  const proportion = width / standard;
  await showAppearance(page);
  await slider(page).focus();
  await page.keyboard.press("End");
  await page.waitForTimeout(1800);
  let now = await saved(page);
  expect(Math.abs(now[0]! / now[1]! - proportion), "the widened column against a default one at 150 %").toBeLessThanOrEqual(0.02);
  await page.keyboard.press("Home");
  await page.waitForTimeout(1800);
  now = await saved(page);
  expect(Math.abs(now[0]! / now[1]! - proportion), "and at 50 %").toBeLessThanOrEqual(0.03);
});

test("the ceiling (99% of the canvas) holds at every size, for a window widened to the limit", async ({ page }) => {
  await open(page);
  await widen(page, 2400);
  const ceiling = Math.round((await canvasWidth(page)) * 0.99);
  expect((await saved(page))[0]!, "widened to the limit at the standard size").toBeLessThanOrEqual(ceiling + 1);
  await showAppearance(page);
  await slider(page).focus();
  // A window at the ceiling is drawn at the ceiling at every size; the saved width scales, the drawing never passes the limit.
  for (const key of ["End", "Home", "End"]) {
    await page.keyboard.press(key);
    await page.waitForTimeout(1600);
    const ceilingNow = Math.round((await canvasWidth(page)) * 0.99);
    const box = await page.evaluate((sel) => document.querySelector<HTMLElement>(`${sel} .ui-window`)!.offsetWidth, COLS);
    expect(box, `the first window's drawn width after ${key}`).toBeLessThanOrEqual(ceilingNow + 1);
  }
});

test("the camera keeps framing the active window after the size changes", async ({ page }) => {
  await open(page);
  await enter(page);
  await page.locator(`${COLS} .ui-window .ui-window-body`).first().click({ position: { x: 20, y: 40 } });
  await page.waitForTimeout(500);
  await showAppearance(page);
  await page.keyboard.press("Control+Shift+K").catch(() => undefined);
  await page.keyboard.press("Escape");
  await slider(page).focus();
  for (const key of ["End", "Home", "ArrowRight"]) {
    await page.keyboard.press(key);
    await page.waitForTimeout(2200);
    const box = await page.evaluate(() => { const r = document.querySelector<HTMLElement>(".ui-window[data-active]")!.getBoundingClientRect(); return { left: r.left, right: r.right, top: r.top, bottom: r.bottom, vw: innerWidth, vh: innerHeight }; });
    expect(box.left, `the active window's left edge after ${key}`).toBeGreaterThanOrEqual(-1);
    expect(box.right, `its right edge after ${key}`).toBeLessThanOrEqual(box.vw + 1);
    expect(box.top).toBeGreaterThanOrEqual(-1);
    expect(box.bottom).toBeLessThanOrEqual(box.vh + 1);
  }
});

test("at 150 % on 1440 x 900 no window title is cut and no Settings row is clipped", async ({ page }) => {
  await open(page, 150);
  await showAppearance(page);
  const found = await page.evaluate(() => {
    const out: string[] = [];
    for (const win of document.querySelectorAll<HTMLElement>('.cl[data-view="settings"] .ui-window')) {
      const name = win.getAttribute("aria-label") ?? win.dataset.windowId ?? "?";
      for (const t of win.querySelectorAll<HTMLElement>(".ui-window-pill, .ui-window-pill *")) {
        if (t.scrollWidth > t.clientWidth + 1 && getComputedStyle(t).overflow !== "visible") out.push(`${name}: title part "${t.textContent?.trim().slice(0, 24)}" is cut`);
      }
      const title = win.querySelector<HTMLElement>(".ui-window-title")?.textContent ?? "";
      if (title.includes("…")) out.push(`${name}: the title reads "${title}"`);
      const pane = win.querySelector<HTMLElement>(".ui-settings-pane");
      if (pane && pane.scrollWidth > pane.clientWidth + 1) out.push(`${name}: the pane scrolls sideways (${pane.scrollWidth} > ${pane.clientWidth})`);
      for (const row of pane?.querySelectorAll<HTMLElement>("*") ?? []) {
        const cs = getComputedStyle(row);
        if ((cs.textOverflow === "ellipsis" || cs.overflowX === "hidden") && row.scrollWidth > row.clientWidth + 1 && row.textContent?.trim()) out.push(`${name}: "${row.textContent.trim().slice(0, 24)}" is clipped`);
      }
    }
    return out;
  });
  expect(found, found.join("\n")).toEqual([]);
});

test("window titles are cut at 150 % exactly where they are at the default and at 50 %: text and window grow together", async ({ page }) => {
  // A session name yields before the host, and a long name is cut at the standard size too (the design: the title gives way before the
  // actions do). What the UI size must not change is which names are cut, so the window and its title grow by the same factor.
  const cutAt = async (percent: number): Promise<string[]> => {
    await page.addInitScript((p) => localStorage.setItem("tracer.ui-size.v2", String(p)), percent);
    await open(page, percent);
    await enter(page);
    return page.evaluate(() => {
      const out: string[] = [];
      for (const part of document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window-host, .cl[data-view="console"] .ui-window-session')) {
        if (getComputedStyle(part).display === "none") continue;
        // The text's own rendered width, not scrollWidth: an ellipsised element reports the width it was clipped to.
        const range = document.createRange();
        range.selectNodeContents(part);
        if (range.getBoundingClientRect().width > part.clientWidth + 1) out.push(part.textContent ?? "");
      }
      return out;
    });
  };
  const standard = await cutAt(100);
  expect(standard, "the first window's title is whole at the standard size").not.toContain("build-01");
  expect(standard).not.toContain("deploy");
  for (const percent of [150, 50]) {
    const cut = await cutAt(percent);
    expect(cut, `names cut at ${percent} %: ${cut.join(", ")}; at 100 %: ${standard.join(", ")}`).toEqual(standard);
  }
});
