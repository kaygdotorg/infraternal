// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Content first, and the canvas moves on purpose (D374, A17; amends D159, D177, D275), on a production build.
 *
 * - Touch (393×852): one finger only ever scrolls the content under it, never the canvas, not even at the content's end or
 *   with a sideways drag; two fingers move the canvas.
 * - Desktop (1440×900), with wheel events shaped like a trackpad or Magic Mouse swipe (pixel deltas, many small steps, a
 *   decaying momentum tail): a sideways swipe over scrollable content never moves the canvas, and one that starts over
 *   chrome (a window's pill) does. The modifier plus wheel (`CANVAS_WHEEL_MODIFIER`) moves the canvas from anywhere,
 *   so an ordinary mouse can reach it too.
 *
 * Nothing here asserts wall-clock speed. Captures go to the external evidence directory.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type BrowserContext, type Page } from "playwright/test";
import { CANVAS_WHEEL_MODIFIER } from "../src/canvas/camera/canvas-wheel-modifier";
import { tracerEvidencePath } from "./evidence-path";

const OUT = tracerEvidencePath("swipe-content-first");
const PAGE = '.ui-window[data-window-id="d-reference/keys"]';

type Api = Record<string, (...args: unknown[]) => unknown>;
const api = (page: Page, fn: string, ...args: unknown[]): Promise<unknown> =>
  page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Api }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);
/** Everything the canvas could have moved: the camera and the column strip of the Docs view. */
const canvasState = (page: Page): Promise<string> =>
  page.evaluate(() => {
    const col = document.querySelector<HTMLElement>('.cl[data-view="docs"] .cl-col');
    return `${document.querySelector<HTMLElement>(".cl-world")?.style.transform ?? ""}|${col?.scrollTop}|${col?.scrollLeft}`;
  });
const pageTop = (page: Page): Promise<number> => page.evaluate((sel) => document.querySelector<HTMLElement>(`${sel} .dr-scroll`)!.scrollTop, PAGE);
const stopIndex = async (page: Page): Promise<number> => ((await api(page, "canvasLock")) as { index: number }).index;

/** Opens the clusters mock with the Docs page "Keys and how long they last" in its own window, on a locked canvas. */
async function open(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=plain&docs=1");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await page.waitForTimeout(1200);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
  await page.keyboard.type("keys");
  const result = page.locator(".palette .result", { hasText: "Keys and how long they last" }).first();
  await expect(result).toBeVisible({ timeout: 15_000 });
  await result.click();
  await expect(page.locator(`${PAGE} .dr-page h1`)).toHaveText("Keys and how long they last", { timeout: 10_000 });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(1000);
  expect(await api(page, "canvasLock"), "the canvas is locked to windows, the input lock is off").toMatchObject({ on: true });
  return page;
}

/** One two-finger drag by CDP: both fingers start `gap` apart around (x, y) and move `dx` sideways in `steps`. */
async function twoFingers(page: Page, context: BrowserContext, x: number, y: number, dx: number): Promise<void> {
  const cdp = await context.newCDPSession(page);
  const pts = (d: number) => [{ x: x - 40 + d, y }, { x: x + 40 + d, y }];
  await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: pts(0) });
  for (let i = 1; i <= 12; i++) { await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: pts((dx * i) / 12) }); await page.waitForTimeout(16); }
  await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
}

test.describe("phone: touch", () => {
  test.use({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true, colorScheme: "dark" });

  test("one finger never moves the canvas: sideways, past the content's end, or after it", async ({ context }) => {
    test.setTimeout(90_000);
    mkdirSync(OUT, { recursive: true });
    const page = await open(context);
    const cdp = await context.newCDPSession(page);
    const box = (await page.locator(`${PAGE} .dr-scroll`).boundingBox())!;
    const x = box.x + box.width / 2, y = box.y + box.height * 0.6;
    const before = await canvasState(page), index = await stopIndex(page);
    const drag = async (dx: number, dy: number, steps = 12): Promise<void> => {
      await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x, y }] });
      for (let i = 1; i <= steps; i++) { await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: x + (dx * i) / steps, y: y + (dy * i) / steps }] }); await page.waitForTimeout(16); }
      await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
      await page.waitForTimeout(500);
    };
    await drag(-220, 0); // sideways, left then right: the content has nothing to scroll that way
    await drag(220, 0);
    expect(await canvasState(page), "a one-finger sideways swipe over content left the canvas alone").toBe(before);
    expect(await stopIndex(page)).toBe(index);
    // Read to the end of the page, then keep dragging and swipe diagonally at the end.
    for (let i = 0; i < 8; i++) await drag(0, -300);
    const room = await page.evaluate((sel) => { const s = document.querySelector<HTMLElement>(`${sel} .dr-scroll`)!; return s.scrollHeight - s.clientHeight; }, PAGE);
    expect(await pageTop(page), "the page reached its end").toBeGreaterThanOrEqual(room - 2);
    await drag(-200, -300);
    await drag(-260, 0);
    expect(await canvasState(page), "at the content's end the canvas still did not move").toBe(before);
    expect(await stopIndex(page)).toBe(index);
    await page.screenshot({ path: `${OUT}/phone-one-finger-end.png` });
  });

  test("two fingers move the canvas", async ({ context }) => {
    test.setTimeout(90_000);
    mkdirSync(OUT, { recursive: true });
    const page = await open(context);
    const box = (await page.locator(`${PAGE} .dr-scroll`).boundingBox())!;
    const index = await stopIndex(page);
    await twoFingers(page, context, box.x + box.width / 2, box.y + box.height / 2, -240);
    await expect.poll(() => stopIndex(page)).toBe(index + 1);
    await page.screenshot({ path: `${OUT}/phone-two-fingers.png` });
  });
});

test.describe("desktop: trackpad, Magic Mouse and mouse", () => {
  test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: "dark" });

  /** A swipe as a trackpad delivers it: pixel deltas in many small steps, then a decaying momentum tail. */
  async function swipe(page: Page, dx: number, dy: number): Promise<void> {
    for (let i = 0; i < 8; i++) { await page.mouse.wheel(dx, dy); await page.waitForTimeout(16); }
    for (let i = 1; i <= 14; i++) { await page.mouse.wheel(Math.round(dx * 0.8 ** i), Math.round(dy * 0.8 ** i)); await page.waitForTimeout(16); }
    await page.waitForTimeout(500);
  }

  test("a sideways swipe over scrollable content scrolls the content, and over a window's pill moves the canvas", async ({ context }) => {
    test.setTimeout(90_000);
    mkdirSync(OUT, { recursive: true });
    const page = await open(context);
    const box = (await page.locator(`${PAGE} .dr-scroll`).boundingBox())!;
    const before = await canvasState(page), index = await stopIndex(page);
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await swipe(page, 60, 0);
    await swipe(page, -60, 0);
    expect(await canvasState(page), "over the page a sideways swipe did not move the canvas").toBe(before);
    expect(await stopIndex(page)).toBe(index);
    // The same swipe over the pill (chrome) is the canvas's.
    const pill = (await page.locator(`${PAGE} .ui-window-pill`).boundingBox())!;
    await page.mouse.move(pill.x + pill.width / 2, pill.y + pill.height / 2);
    await swipe(page, 60, 0);
    await expect.poll(() => stopIndex(page), "over chrome a sideways swipe moves to the neighbouring window").not.toBe(index);
    await page.screenshot({ path: `${OUT}/desktop-swipe-chrome.png` });
  });

  test("the modifier plus the wheel moves the canvas from over content; without it the wheel scrolls the content", async ({ context }) => {
    test.setTimeout(90_000);
    mkdirSync(OUT, { recursive: true });
    const page = await open(context);
    const box = (await page.locator(`${PAGE} .dr-scroll`).boundingBox())!;
    const index = await stopIndex(page);
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.keyboard.down(CANVAS_WHEEL_MODIFIER);
    await page.mouse.wheel(0, 300); // an ordinary mouse wheel only has a vertical axis
    await page.keyboard.up(CANVAS_WHEEL_MODIFIER);
    await expect.poll(() => stopIndex(page), "modifier + wheel moves the canvas").not.toBe(index);
    await page.waitForTimeout(600);
    expect(await pageTop(page), "and the page under the pointer did not scroll").toBe(0);
  });
});
