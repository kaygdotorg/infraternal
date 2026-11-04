/**
 * Settings → Shortcuts: a changed shortcut is marked by a dot on its key caps, and resetting lives in the row's menu and on
 * the keyboard (owner, 2026-11-03, #306: "agreed" to J95b's finding that an overridden row's reset button pushed its caps one
 * button early). Every row keeps its key caps on one right edge, with and without changes (±0.5 px); the dot is out of the
 * layout flow and carries "Changed from <default>" as a pointer tooltip; Reset is reached by right-click and Shift+F10 (the
 * shared row menu) and by Delete on the focused row; "Reset all" is the last row, appears only while something is changed,
 * and asks in its own row (TASTE "A destructive row action asks in its own row"). 1440×900 and 393×852.
 */
import { paletteOpen } from "./settings-palette";
import { tracerEvidencePath } from "./evidence-path";
import { expect, test, type Locator, type Page } from "playwright/test";import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const captures = tracerEvidencePath("shortcut-reset");
const SIZES = [{ w: 1440, h: 900, touch: false, dpr: 2 }, { w: 393, h: 852, touch: true, dpr: 3 }] as const;
/** Distinct, terminal-safe chords (Ctrl+Alt+F-key): the rows' new bindings. */
const NEW_KEYS = ["Control+Alt+F7", "Control+Alt+F8", "Control+Alt+F9"];

async function open(page: Page): Promise<void> {
  for (let attempt = 0; attempt < 3; attempt++) {
    await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none&sessions=0");
    if (await page.locator("[data-view='console'] .ui-window").nth(3).waitFor({ timeout: 15_000 }).then(() => true, () => false)) break;
  }
  await expect(page.locator("[data-view='console'] .ui-window")).toHaveCount(4, { timeout: 20_000 });
  await page.addStyleTag({ content: ".test-double-badge, .cl-mockup, .perf-hud, .ui-toast { display: none !important; }" });
  await page.waitForTimeout(1000);
  for (let attempt = 0; attempt < 4; attempt++) {
    await paletteOpen(page, "Terminal › Typing", "terminal.typing");
    const ok = await expect.poll(() => page.evaluate(() => document.querySelectorAll('.ui-window[data-window-id="s-terminal-typing"] .ui-ss-row').length), { timeout: 5000 }).toBeGreaterThan(3).then(() => true, () => false);
    if (ok) break;
  }
  await page.waitForTimeout(900);
}

const WIN = '.ui-window[data-window-id="s-terminal-typing"]';
const resetAllRow = (page: Page): Locator => page.locator(`${WIN} .ui-ss-row[data-reset-all]`);

/** Right edge of every row's last key cap, and the left edge of every label. */
const edges = (page: Page) => page.evaluate((win) => [...document.querySelectorAll<HTMLElement>(`${win} .ui-ss-row:not([data-reset-all])`)].map((row) => {
  const caps = row.querySelectorAll("kbd");
  return { id: row.dataset.id ?? "", right: caps[caps.length - 1]!.getBoundingClientRect().right, label: row.querySelector(".ui-ss-label")!.getBoundingClientRect().left };
}), WIN);
/** Every row's layout box (offsets, which no transform can fake). */
const boxes = (page: Page) => page.evaluate((win) => [...document.querySelectorAll<HTMLElement>(`${win} .ui-ss-row`)].map((r) => [r.offsetTop, r.offsetHeight]), WIN);
const changedIds = (page: Page): Promise<string[]> => page.evaluate((win) => [...document.querySelectorAll<HTMLElement>(`${win} .ui-ss-row[data-changed]`)].map((r) => r.dataset.id!), WIN);

const spread = (values: number[]): number => Math.max(...values) - Math.min(...values);

for (const { w, h, touch, dpr } of SIZES) test(`shortcut reset ${w}x${h}`, async ({ browser }) => {
  test.setTimeout(240_000);
  await mkdir(captures, { recursive: true });
  const context = await browser.newContext({ viewport: { width: w, height: h }, hasTouch: touch, isMobile: touch, deviceScaleFactor: dpr });
  const page = await context.newPage();
  try {
    await open(page);
    const where = `${w}x${h}`;

    // ---- nothing changed: caps share one edge, no dot, no "Reset all" --------------------------------------------------
    const before = await edges(page);
    expect(before.length, `${where}: shortcut rows are listed`).toBeGreaterThan(3);
    expect(spread(before.map((r) => r.right)), `${where}: caps end on one edge before any change`).toBeLessThanOrEqual(0.5);
    await expect(page.locator(`${WIN} .ui-ss-dot`)).toHaveCount(0);
    await expect(resetAllRow(page)).toHaveCount(0);
    // A row with nothing to reset has no menu: its right-click is the browser's own.
    expect(await page.evaluate((win) => { const e = new MouseEvent("contextmenu", { bubbles: true, cancelable: true }); document.querySelector(`${win} .ui-ss-row .ui-ss-main`)!.dispatchEvent(e); return e.defaultPrevented; }, WIN)).toBe(false);

    // ---- change three rows through the real capture flow ----------------------------------------------------------------
    const ids = (await page.evaluate((win) => [...document.querySelectorAll<HTMLElement>(`${win} .ui-ss-row:not([data-fixed]):not([data-reset-all])`)].map((r) => r.dataset.id!).filter((id) => id !== "palette"), WIN)).slice(0, 3);
    expect(ids.length).toBe(3);
    const defaults = new Map<string, string>();
    for (const [i, id] of ids.entries()) {
      const row = page.locator(`${WIN} .ui-ss-row[data-id="${id}"]`);
      defaults.set(id, (await row.locator("kbd").allTextContents()).join("+"));
      await row.locator(".ui-ss-main").click();
      await expect(row.locator(".ui-ss-keys[data-capturing]")).toHaveCount(1);
      await page.keyboard.press(NEW_KEYS[i]!);
      await expect(page.locator(`${WIN} .ui-ss-row[data-id="${id}"][data-changed]`)).toHaveCount(1);
    }
    expect(await changedIds(page)).toEqual(ids);

    // ---- the mark: one dot per changed row, none elsewhere, caps still on the edge ---------------------------------------
    await expect(page.locator(`${WIN} .ui-ss-dot`)).toHaveCount(3);
    await expect(page.locator(`${WIN} .ui-ss-reset`)).toHaveCount(0);
    const changed = await edges(page);
    expect(spread(changed.map((r) => r.right)), `${where}: caps end on one edge with three changed rows`).toBeLessThanOrEqual(0.5);
    expect(Math.abs(changed[0]!.right - before[0]!.right), `${where}: the edge did not move because of the changes`).toBeLessThanOrEqual(0.5);
    expect(spread(changed.map((r) => r.label)), `${where}: labels keep one left edge`).toBeLessThanOrEqual(0.5);
    // The dot sits on the first cap's top-left corner and takes no room.
    const dot = await page.evaluate((id) => {
      const row = document.querySelector(`.ui-window[data-window-id="s-terminal-typing"] .ui-ss-row[data-id="${id}"]`)!;
      const d = row.querySelector(".ui-ss-dot")!.getBoundingClientRect(), cap = row.querySelector("kbd")!.getBoundingClientRect();
      return { dx: d.left + d.width / 2 - cap.left, dy: d.top + d.height / 2 - cap.top, size: d.width, position: getComputedStyle(row.querySelector(".ui-ss-dot")!).position };
    }, ids[0]!);
    expect(dot.position).toBe("absolute");
    expect(Math.abs(dot.dx), `${where}: dot x on the cap's corner`).toBeLessThanOrEqual(4);
    expect(Math.abs(dot.dy), `${where}: dot y on the cap's corner`).toBeLessThanOrEqual(4);
    expect(dot.size).toBeGreaterThan(3);
    await page.locator(`${WIN} .ui-ss-row[data-id="${ids[0]}"]`).scrollIntoViewIfNeeded();
    await page.locator(WIN).screenshot({ path: resolve(captures, `changed-${where}.png`) }).catch(() => undefined);

    // ---- the tooltip names the default (pointer only; touch has the menu's "Reset to …") ---------------------------------
    const keys = page.locator(`${WIN} .ui-ss-row[data-id="${ids[0]}"] .ui-ss-keys`);
    if (!touch) {
      await expect(keys).toHaveAttribute("data-tip", `Changed from ${defaults.get(ids[0]!)}`);
      await keys.hover();
      await expect(page.locator(".tip-pos[style*='visible'] .tip-label:not(.is-leaving)")).toHaveText(`Changed from ${defaults.get(ids[0]!)}`, { timeout: 3000 });
      await page.mouse.move(2, 2);
    } else await expect(keys).not.toHaveAttribute("data-tip", /.*/);

    // ---- Reset through the row's menu (right-click) ----------------------------------------------------------------------
    await page.locator(`${WIN} .ui-ss-row[data-id="${ids[0]}"] .ui-ss-label`).click({ button: "right" });
    const items = page.locator(".ui-window-menu-item");
    await expect(items).toHaveText([`Reset to ${defaults.get(ids[0]!)}`]);
    await items.first().click();
    await expect(page.locator(".ui-window-menu")).toHaveCount(0);
    expect(await changedIds(page)).toEqual(ids.slice(1));
    expect(await page.locator(`${WIN} .ui-ss-row[data-id="${ids[0]}"] kbd`).allTextContents()).toEqual((defaults.get(ids[0]!) ?? "").split("+"));
    await expect(page.locator(`${WIN} .ui-ss-dot`)).toHaveCount(2);
    expect(spread((await edges(page)).map((r) => r.right)), `${where}: edge after a menu reset`).toBeLessThanOrEqual(0.5);

    // ---- Reset through the keyboard: Shift+F10 opens the same menu, Enter resets -----------------------------------------
    await page.locator(`${WIN} .ui-ss-row[data-id="${ids[1]}"] .ui-ss-main`).focus();
    await page.keyboard.press("Shift+F10");
    await expect(page.locator(".ui-window-menu")).toBeVisible();
    expect(await page.evaluate(() => (document.activeElement as HTMLElement).dataset.action)).toBe("reset");
    await page.keyboard.press("Enter");
    await expect(page.locator(".ui-window-menu")).toHaveCount(0);
    expect(await changedIds(page)).toEqual(ids.slice(2));
    // The list repaints from scratch; the focus goes to the same row's new button.
    expect(await page.evaluate(() => (document.activeElement as HTMLElement | null)?.closest<HTMLElement>(".ui-ss-row")?.dataset.id)).toBe(ids[1]);

    // ---- Reset through the keyboard: Delete on the focused row -----------------------------------------------------------
    await page.locator(`${WIN} .ui-ss-row[data-id="${ids[2]}"] .ui-ss-main`).focus();
    await page.keyboard.press("Delete");
    await expect(page.locator(`${WIN} .ui-ss-dot`)).toHaveCount(0);
    expect(await changedIds(page)).toEqual([]);
    await expect(resetAllRow(page)).toHaveCount(0);
    expect(await page.evaluate(() => (document.activeElement as HTMLElement | null)?.closest<HTMLElement>(".ui-ss-row")?.dataset.id)).toBe(ids[2]);
    // Delete on a row that is not changed does nothing (no menu, no change).
    await page.keyboard.press("Delete");
    expect(await changedIds(page)).toEqual([]);

    // ---- Reset all: appears with the first change, asks in its own row -------------------------------------------------
    for (const [i, id] of ids.slice(0, 2).entries()) {
      const row = page.locator(`${WIN} .ui-ss-row[data-id="${id}"]`);
      await row.locator(".ui-ss-main").click();
      await page.keyboard.press(NEW_KEYS[i]!);
      await expect(row).toHaveAttribute("data-changed", "");
    }
    const all = resetAllRow(page);
    await expect(all).toHaveCount(1);
    await all.scrollIntoViewIfNeeded();
    const labelLeft = await page.evaluate((win) => document.querySelector(`${win} .ui-ss-row .ui-ss-label`)!.getBoundingClientRect().left, WIN);
    expect(Math.abs((await all.locator(".ui-ss-label").evaluate((e) => e.getBoundingClientRect().left)) - labelLeft), `${where}: "Reset all" starts on the labels' edge`).toBeLessThanOrEqual(0.5);
    const rest = await boxes(page);
    await all.locator(".ui-ss-main").click();
    const ask = all.locator(".ui-row-ask");
    await expect(ask).toBeVisible();
    // The effect line follows in the text but is read out, never drawn (row-confirm.ts), hence no end anchor.
    await expect(ask).toHaveText(/^Reset all( shortcuts)?\?\s*Reset\s*·\s*Cancel/);
    // In its own row: same boxes, no card, no dialog, the question starts where the label did.
    expect(await boxes(page)).toEqual(rest);
    await expect(page.locator(".ui-confirm-tip, [role='alertdialog']")).toHaveCount(0);
    expect(Math.abs((await ask.locator(".ui-row-ask-q").evaluate((e) => e.getBoundingClientRect().left)) - labelLeft), `${where}: the question starts on the label's x`).toBeLessThanOrEqual(0.5);
    // The row's own words fade out as the question fades in: never both on top of each other.
    await expect.poll(() => all.locator(".ui-ss-label").evaluate((e) => getComputedStyle(e).opacity), { timeout: 3000 }).toBe("0");
    await page.locator(WIN).screenshot({ path: resolve(captures, `reset-all-ask-${where}.png`) }).catch(() => undefined);
    // Cancel puts the row back and resets nothing.
    await ask.getByRole("button", { name: "Cancel" }).click();
    await expect(ask).toHaveCount(0);
    expect(await changedIds(page)).toEqual(ids.slice(0, 2));
    expect(await boxes(page)).toEqual(rest);
    // Escape cancels too; a second asking, then Reset does it.
    await all.locator(".ui-ss-main").click();
    await expect(ask).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(ask).toHaveCount(0);
    expect(await changedIds(page)).toEqual(ids.slice(0, 2));
    await all.locator(".ui-ss-main").click();
    await ask.getByRole("button", { name: "Reset", exact: true }).click();
    await expect(page.locator(`${WIN} .ui-ss-dot`)).toHaveCount(0);
    await expect(resetAllRow(page)).toHaveCount(0);
    const final = await edges(page);
    expect(spread(final.map((r) => r.right)), `${where}: caps end on one edge after Reset all`).toBeLessThanOrEqual(0.5);
    expect(Math.abs(final[0]!.right - before[0]!.right), `${where}: back on the original edge`).toBeLessThanOrEqual(0.5);
  } finally { await context.close(); }
});
