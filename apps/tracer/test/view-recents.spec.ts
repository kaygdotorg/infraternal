/**
 * A view's hover card lists the five windows used most recently, most recent first, and one "All N windows" row
 * that opens ⌘K filtered to that view's windows (TASTE: lists stay short; #121). The card is the zoomed-out hover
 * card of a view's label, so the canvas is zoomed out with the overview first.
 *
 * Scenes: scene 1 has a Console view with 4 windows, which this spec grows to 54 through the test double; scene 2
 * has Console with 3 windows, which shows three rows and no "All" row.
 */
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";

const CAPTURES = resolve(import.meta.dirname, "..", "captures", "view-recents");
mkdirSync(CAPTURES, { recursive: true });

interface Probe {
  activateWindow(id: string): boolean;
  views(): Array<{ id: string; windows: string[]; x: number; y: number }>;
  setCamera(cx: number, cy: number, z: number): void;
  newShell(host: string): string | undefined;
}
const probe = <T>(page: Page, fn: string, arg?: unknown): Promise<T> =>
  page.evaluate(({ fn, arg }) => {
    const p = (window as unknown as { __tracerClusters: Record<string, (...a: unknown[]) => unknown> }).__tracerClusters;
    return p[fn]!(arg) as never;
  }, { fn, arg }) as Promise<T>;

async function openScene(page: Page, scene: number, theme: string): Promise<void> {
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=${theme}&bg=none`);
  await expect(page.locator('.cl[data-view="console"] .cl-label')).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(800);
}

/** The Console view's window ids, in the view's own order. */
const consoleWindows = async (page: Page): Promise<string[]> =>
  (await page.evaluate(() => (window as unknown as { __tracerClusters: Probe }).__tracerClusters.views())).find((v) => v.id === "console")!.windows;

/** Hovers the Console label zoomed out and waits for the card to open. */
async function hoverConsole(page: Page): Promise<void> {
  // Zoomed out (band "out", z 0.5) with the Console label near the middle of the screen.
  await page.evaluate(() => {
    const p = (window as unknown as { __tracerClusters: Probe }).__tracerClusters;
    const v = p.views().find((view) => view.id === "console")!;
    p.setCamera(v.x + 60, v.y + 60, 0.5);
  });
  await page.waitForTimeout(600);
  await page.locator('.cl[data-view="console"] .cl-label').hover();
  await expect(page.locator(".cl-summary[data-open=\"true\"]")).toBeVisible();
  await page.waitForTimeout(400);
}

for (const theme of ["ink", "paper"] as const) {
  for (const viewport of [{ width: 1440, height: 900 }, { width: 393, height: 852 }]) {
    test(`54 windows: five recent rows, then All, ${theme} ${viewport.width}`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await openScene(page, 1, theme);
      // Grow Console to 54 windows through the test double's own open path.
      await page.evaluate(() => {
        const p = (window as unknown as { __tracerClusters: Probe }).__tracerClusters;
        for (let n = p.views().find((v) => v.id === "console")!.windows.length; n < 54; n++) p.newShell("build-01");
      });
      await page.waitForTimeout(1200);
      const ids = await consoleWindows(page);
      expect(ids).toHaveLength(54);
      // Seven different windows made active in order; the card shows the last five, most recent first.
      const order = [3, 17, 0, 40, 9, 25, 51].map((i) => ids[i]!);
      for (const id of order) expect(await probe(page, "activateWindow", id)).toBe(true);
      await hoverConsole(page);
      const rows = page.locator(".cl-summary .cl-summary-pick");
      await expect(rows).toHaveCount(5);
      const shown = await rows.evaluateAll((els) => els.map((el) => (el as HTMLElement).dataset.window));
      expect(shown).toEqual([...order].reverse().slice(0, 5));
      const all = page.locator(".cl-summary .cl-summary-all");
      await expect(all).toHaveText(/All 54 windows/);
      const names = await rows.evaluateAll((els) => els.map((el) => [el.querySelector(".cl-viewrow-name")?.textContent, el.querySelector(".cl-viewrow-meta")?.textContent]));
      console.log(`ROWS ${theme} ${viewport.width}: ${JSON.stringify(names)}`);
      await page.screenshot({ path: resolve(CAPTURES, `console-54-${theme}-${viewport.width}.png`) });

      // "All" opens ⌘K with this view's windows only.
      await all.click();
      await expect(page.locator("#palette")).toBeVisible();
      await expect(page.locator("#palette-results [role=\"option\"]")).toHaveCount(54);
      await expect(page.locator("#palette-results .group-label")).toHaveText("Console");
      await page.screenshot({ path: resolve(CAPTURES, `palette-console-54-${theme}-${viewport.width}.png`) });
      await page.keyboard.press("Escape");
      await expect(page.locator("#palette")).toBeHidden();
    });
  }
}

test("three windows: three rows and no All row", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openScene(page, 2, "ink");
  expect(await consoleWindows(page)).toHaveLength(3);
  await hoverConsole(page);
  await expect(page.locator(".cl-summary .cl-summary-pick")).toHaveCount(3);
  await expect(page.locator(".cl-summary .cl-summary-all")).toHaveCount(0);
  await page.screenshot({ path: resolve(CAPTURES, "console-3-ink-1440.png") });
});
