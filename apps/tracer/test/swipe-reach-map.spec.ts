// SPDX-License-Identifier: AGPL-3.0-only
/**
 * An extended map of where a sideways swipe reaches another window (D377, #444, review J1014). swipe-reach.spec.ts samples a
 * 5 by 5 grid that has no point in the 16 px edge bands and almost none on the header; this one adds those and the page chrome
 * around the windows (top bar, the gaps between windows, the bottom gutter), and labels each point with the element under it, so
 * "how many positions reach another window" can be compared between two builds. It measures and prints and asserts nothing about the numbers:
 * the comparison is the report. Production build, 1440×900, window in the middle of the Docs view.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** Where the captures go: the external evidence directory, never the checkout. */
const OUT = tracerEvidencePath("swipe-reach");
/** The docs window used: a long page with neighbours on both sides. */
const MIDDLE = '.ui-window[data-window-id="d-terminal/multiplexer"]';

/** The mock canvas's test hooks, as `window.__tracerClusters` exposes them. */
type Api = Record<string, (...args: unknown[]) => unknown>;
/** Calls one test hook of the mock canvas by name. */
const api = (page: Page, fn: string, ...args: unknown[]): Promise<unknown> =>
  page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Api }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);
/** The canvas stop (window) the locked canvas is on. */
const stopIndex = async (page: Page): Promise<number> => ((await api(page, "canvasLock")) as { index: number }).index;

test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: "dark" });

/** Opens the Docs view and flies to the middle window. */
async function open(page: Page): Promise<void> {
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=plain&docs=1");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  // sleep: the mock canvas finishes its first layout; no event marks it
  await page.waitForTimeout(1200);
  // The Docs view is not the opening view. Open one of its pages through the palette, as the other swipe specs do; that
  // mounts the view, and every page of it has a window, so the camera can then fly to the middle one.
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
  await page.keyboard.type("keys");
  const result = page.locator(".palette .result", { hasText: "Keys and how long they last" }).first();
  await expect(result).toBeVisible({ timeout: 15_000 });
  await result.click();
  await expect(page.locator('.ui-window[data-window-id="d-reference/keys"] .dr-page h1')).toBeVisible({ timeout: 10_000 });
  await fly(page);
  await expect(page.locator(`${MIDDLE} .dr-page h1`)).toBeVisible({ timeout: 15_000 });
  const lock = (await api(page, "canvasLock")) as { index: number; stops: number };
  expect(lock.index, "the window has neighbours on both sides").toBeGreaterThan(0);
  expect(lock.index).toBeLessThan(lock.stops - 1);
}

/** The canvas stop of the multiplexer page in the Docs view: the keys page is the last stop (12), this one is nearer the start. */
const MIDDLE_STOP = 3;

/**
 * Brings the canvas to the middle window with the keyboard's one-window steps (Ctrl+Shift+[ and ]), which update the canvas stop.
 * (`activateWindow` does not move a locked Docs canvas.) Fails if the middle window is not then on screen.
 */
async function fly(page: Page): Promise<void> {
  for (let i = 0; i < 16 && (await stopIndex(page)) !== MIDDLE_STOP; i++) {
    await page.keyboard.press((await stopIndex(page)) > MIDDLE_STOP ? "Control+Shift+[" : "Control+Shift+]");
    // sleep: the camera flies one window; no event marks the end
    await page.waitForTimeout(450);
  }
  // sleep: the camera spring settles; no event marks the end
  await page.waitForTimeout(800);
  expect(await stopIndex(page)).toBe(MIDDLE_STOP);
  const box = (await page.locator(MIDDLE).boundingBox())!;
  expect(box.x + box.width / 2, "the middle window is on screen").toBeGreaterThan(0);
  expect(box.x + box.width / 2).toBeLessThan(1440);
}

/** A trackpad-shaped sideways swipe: pixel steps a frame apart, then a decaying momentum tail. */
async function swipe(page: Page, dx: number): Promise<void> {
  // sleep: one wheel step per frame, like a pad; there is no event to wait for
  for (let i = 0; i < 8; i++) { await page.mouse.wheel(dx, 0); await page.waitForTimeout(16); }
  // sleep: one wheel step per frame, like a pad; there is no event to wait for
  for (let i = 1; i <= 12; i++) { await page.mouse.wheel(Math.round(dx * 0.8 ** i), 0); await page.waitForTimeout(16); }
  // sleep: the camera spring settles; no event marks the end
  await page.waitForTimeout(500);
}

/** Whether a sideways swipe starting at (x, y) moved the canvas off the middle window; the camera is sent back first. */
async function reaches(page: Page, x: number, y: number): Promise<boolean> {
  await fly(page);
  const before = await stopIndex(page);
  await page.mouse.move(x, y);
  await swipe(page, 60);
  return (await stopIndex(page)) !== before;
}


/** What sits under (x, y): the nearest region name the map uses to group points. */
async function regionAt(page: Page, x: number, y: number): Promise<string> {
  return page.evaluate(([px, py]) => {
    const el = document.elementFromPoint(px as number, py as number);
    if (!el) return "outside";
    const win = el.closest<HTMLElement>(".ui-window");
    if (win) {
      const r = win.getBoundingClientRect();
      const edge = (px as number) - r.left < 16 || r.right - (px as number) < 16 ? "+edge" : "";
      if (el.closest(".ui-window-head")) return `window-header${edge}`;
      return `window-body${edge}`;
    }
    if (el.closest(".cl-mockup, .cl-top, header")) return "top-bar";
    return el.className && typeof el.className === "string" ? `canvas:${el.className.split(" ")[0]}` : el.tagName.toLowerCase();
  }, [x, y] as const);
}

test("map: where a sideways swipe reaches another window, with edge bands, header and page chrome", async ({ page }) => {
  test.setTimeout(900_000);
  mkdirSync(OUT, { recursive: true });
  await open(page);
  // `MAP_XS` and `MAP_YS` (comma lists of pixels) replace the default grid, for a closer look at one region.
  const list = (env: string | undefined, fallback: number[]): number[] => (env ? env.split(",").map(Number) : fallback);
  const xs = list(process.env.MAP_XS, [2, 10, 18, 60, 360, 720, 1080, 1400, 1430, 1437]);
  const ys = list(process.env.MAP_YS, [2, 30, 60, 88, 120, 300, 500, 700, 870, 890, 898]);
  const rows: string[] = [];
  const byRegion = new Map<string, { reached: number; total: number }>();
  const points: unknown[] = [];
  let reached = 0, total = 0;
  for (const y of ys) {
    let line = "";
    for (const x of xs) {
      await fly(page);
      const region = await regionAt(page, x, y);
      const ok = await reaches(page, x, y);
      total++; reached += ok ? 1 : 0; line += ok ? "X" : ".";
      const g = byRegion.get(region) ?? { reached: 0, total: 0 };
      g.total++; g.reached += ok ? 1 : 0; byRegion.set(region, g);
      points.push({ x, y, region, reached: ok });
    }
    rows.push(`y=${String(y).padStart(3)} ${line}`);
  }
  console.log(`MAP x=${xs.join(",")}\n${rows.join("\n")}\nMAP-TOTAL ${reached}/${total}`);
  for (const [region, g] of [...byRegion].sort()) console.log(`MAP-REGION ${region}: ${g.reached}/${g.total}`);
  console.log(`MAP-JSON ${JSON.stringify(points)}`);
  await page.screenshot({ path: `${OUT}/map-middle.png` });
});
