// SPDX-License-Identifier: AGPL-3.0-only
/**
 * A swipe on a window's chrome moves the canvas (D377, #444). With a window filling the view there is little bare canvas, so
 * a trackpad or Magic Mouse swipe that starts on the window's own chrome (its header and pill, a band along its left and right
 * edges, a neighbour peeking in at the screen edge) counts as bare canvas; one that starts on its content scrolls the
 * content. Also: a vertical wheel at the end of a page on a window that has neighbours stays with the page, which a last
 * window (nowhere to step) could not show. Production build, 1440×900, window in the middle of the Docs view.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("swipe-reach");
/** The docs window used: a long page with neighbours on both sides. */
const MIDDLE = '.ui-window[data-window-id="d-terminal/multiplexer"]';

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

test("a sideways swipe on a window's chrome moves the canvas, on its content scrolls it", async ({ page }) => {
  test.setTimeout(240_000);
  mkdirSync(OUT, { recursive: true });
  await open(page);
  const win = (await page.locator(MIDDLE).boundingBox())!;
  const pill = (await page.locator(`${MIDDLE} .ui-window-pill`).boundingBox())!;
  const head = (await page.locator(`${MIDDLE} .ui-window-head`).boundingBox())!;
  const mid = win.y + win.height / 2;
  expect(await reaches(page, pill.x + pill.width / 2, pill.y + pill.height / 2), "the pill").toBe(true);
  expect(await reaches(page, head.x + head.width - 4, head.y + head.height / 2), "the header's far end").toBe(true);
  expect(await reaches(page, win.x + 6, mid), "the band along the window's left edge").toBe(true);
  expect(await reaches(page, win.x + win.width - 6, mid), "the band along the window's right edge").toBe(true);
  expect(await reaches(page, win.x + win.width / 2, mid), "the page's content: it scrolls, the canvas stays").toBe(false);
  await page.screenshot({ path: `${OUT}/reach-middle.png` });
});

test("grid of 25 pointer positions: how many reach another window by a sideways swipe", async ({ page }) => {
  test.setTimeout(360_000);
  await open(page);
  let reached = 0;
  const rows: string[] = [];
  for (let r = 0; r < 5; r++) {
    let line = "";
    for (let c = 0; c < 5; c++) {
      const ok = await reaches(page, 72 + c * 324, 72 + r * 189);
      reached += ok ? 1 : 0;
      line += ok ? "X" : ".";
    }
    rows.push(line);
  }
  console.log(`REACH ${reached}/25\n${rows.join("\n")}`);
  // The grid has no point inside the 16 px edge bands and few on the header, so it cannot show the chrome change; the first test pins
  // those. The grid is a measurement: it must not fall below the 12 of 25 measured before chrome counted (the top row and the right).
  expect(reached, "no fewer of the screen's grid points reach another window than the 12 of 25 measured before chrome counted").toBeGreaterThanOrEqual(12);
});

test("a vertical wheel at the end of a page with neighbours stays with the page", async ({ page }) => {
  test.setTimeout(90_000);
  await open(page);
  const box = (await page.locator(`${MIDDLE} .dr-scroll`).boundingBox())!;
  await page.evaluate((sel) => { const s = document.querySelector<HTMLElement>(`${sel} .dr-scroll`)!; s.scrollTop = s.scrollHeight; }, MIDDLE);
  const index = await stopIndex(page);
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  for (let i = 0; i < 5; i++) {
    await page.mouse.wheel(0, 400);
    // sleep: a quiet gap longer than a gesture (150 ms), so each wheel is a fresh gesture at the end
    await page.waitForTimeout(400);
  }
  expect(await stopIndex(page), "fresh gestures at the end did not step to another window").toBe(index);
});
