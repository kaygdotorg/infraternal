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

/** Where the captures go: the external evidence directory, never the checkout. */
const OUT = tracerEvidencePath("swipe-content-first");
/** The docs window that shows "Keys and how long they last": a long page that scrolls inside its window. */
const PAGE = '.ui-window[data-window-id="d-reference/keys"]';

/** The mock canvas's test hooks, as `window.__tracerClusters` exposes them. */
type Api = Record<string, (...args: unknown[]) => unknown>;
/** Calls one test hook of the mock canvas by name. */
const api = (page: Page, fn: string, ...args: unknown[]): Promise<unknown> =>
  page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Api }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);
/** Everything the canvas could have moved: the camera and the column strip of the Docs view. */
const canvasState = (page: Page): Promise<string> =>
  page.evaluate(() => {
    const col = document.querySelector<HTMLElement>('.cl[data-view="docs"] .cl-col');
    return `${document.querySelector<HTMLElement>(".cl-world")?.style.transform ?? ""}|${col?.scrollTop}|${col?.scrollLeft}`;
  });
/** How far the docs page has scrolled inside its window. */
const pageTop = (page: Page): Promise<number> => page.evaluate((sel) => document.querySelector<HTMLElement>(`${sel} .dr-scroll`)!.scrollTop, PAGE);
/** The canvas stop (window) the locked canvas is on. */
const stopIndex = async (page: Page): Promise<number> => ((await api(page, "canvasLock")) as { index: number }).index;

/** Opens the clusters mock with the Docs page "Keys and how long they last" in its own window, on a locked canvas. */
async function open(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=plain&docs=1");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  // sleep: the mock canvas finishes its first layout and the page its fonts; no event marks it
  await page.waitForTimeout(1200);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
  await page.keyboard.type("keys");
  const result = page.locator(".palette .result", { hasText: "Keys and how long they last" }).first();
  await expect(result).toBeVisible({ timeout: 15_000 });
  await result.click();
  await expect(page.locator(`${PAGE} .dr-page h1`)).toHaveText("Keys and how long they last", { timeout: 10_000 });
  await page.evaluate(() => document.fonts.ready);
  // sleep: the mock canvas finishes its first layout and the page its fonts; no event marks it
  await page.waitForTimeout(1000);
  expect(await api(page, "canvasLock"), "the canvas is locked to windows, the input lock is off").toMatchObject({ on: true });
  return page;
}

/** One two-finger drag by CDP: both fingers start `gap` apart around (x, y) and move `dx` sideways in `steps`. */
async function twoFingers(page: Page, context: BrowserContext, x: number, y: number, dx: number): Promise<void> {
  const cdp = await context.newCDPSession(page);
  const pts = (d: number) => [{ x: x - 40 + d, y }, { x: x + 40 + d, y }];
  await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: pts(0) });
  // sleep: one touch or wheel step per frame, like a finger or a pad; there is no event to wait for
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
      // sleep: one touch or wheel step per frame, like a finger or a pad; there is no event to wait for
      for (let i = 1; i <= steps; i++) { await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: x + (dx * i) / steps, y: y + (dy * i) / steps }] }); await page.waitForTimeout(16); }
      await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
      // sleep: the camera spring and a gesture's momentum settle; no event marks the end
      await page.waitForTimeout(500);
    };
    await drag(-220, 0); // sideways, left then right: the content has nothing to scroll that way
    await drag(220, 0);
    expect(await canvasState(page), "a one-finger sideways swipe over content left the canvas alone").toBe(before);
    expect(await stopIndex(page)).toBe(index);
    // One real drag scrolls the page; then jump to its end (the page is about 17,000 px long) and keep dragging at the end.
    await drag(0, -300);
    expect(await pageTop(page), "a one-finger drag scrolls the page").toBeGreaterThan(100);
    await page.evaluate((sel) => { const s = document.querySelector<HTMLElement>(`${sel} .dr-scroll`)!; s.scrollTop = s.scrollHeight; }, PAGE);
    await drag(0, -300);
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
    // The page is the last window of the view, so the canvas can only move back: drag the content right.
    await twoFingers(page, context, box.x + box.width / 2, box.y + box.height / 2, 240);
    await expect.poll(() => stopIndex(page)).toBe(index - 1);
    await page.screenshot({ path: `${OUT}/phone-two-fingers.png` });
  });

  /** One finger drags from the middle of `box`, `dx`/`dy` over 12 frames. */
  async function oneFinger(page: Page, context: BrowserContext, at: { x: number; y: number }, dx: number, dy: number): Promise<void> {
    const cdp = await context.newCDPSession(page);
    await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [at] });
    // sleep: one touch or wheel step per frame, like a finger or a pad; there is no event to wait for
    for (let i = 1; i <= 12; i++) { await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: at.x + (dx * i) / 12, y: at.y + (dy * i) / 12 }] }); await page.waitForTimeout(16); }
    await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
    // sleep: the camera spring and a gesture's momentum settle; no event marks the end
    await page.waitForTimeout(500);
  }

  test("one finger on a window with nothing to scroll does not move the canvas either", async ({ context }) => {
    test.setTimeout(90_000);
    const page = await open(context);
    // The first docs page that fits its window (a short page with nothing to scroll).
    const short = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>('.ui-window[data-window-id^="d-"]')].find((w) => { const s = w.querySelector<HTMLElement>(".dr-scroll"); return !!s && s.scrollHeight <= s.clientHeight + 1; })?.dataset.windowId);
    expect(short, "a docs window with nothing to scroll exists").toBeDefined();
    await page.evaluate((id) => (window as unknown as { __tracerClusters: Api }).__tracerClusters.activateWindow!(id), short!);
    // sleep: the camera flies to the activated window; no event marks the end
    await page.waitForTimeout(1500);
    const box = (await page.locator(`.ui-window[data-window-id="${short}"] .dr-scroll`).boundingBox())!;
    const before = await canvasState(page), index = await stopIndex(page);
    const at = { x: box.x + box.width / 2, y: box.y + box.height / 2 };
    await oneFinger(page, context, at, -200, 0);
    await oneFinger(page, context, at, 0, -200);
    await oneFinger(page, context, at, 200, 120);
    expect(await canvasState(page), "one finger over a short window left the canvas alone").toBe(before);
    expect(await stopIndex(page)).toBe(index);
  });

  test("one finger on empty canvas still pans a free canvas (D377)", async ({ context }) => {
    test.setTimeout(90_000);
    mkdirSync(OUT, { recursive: true });
    const page = await open(context);
    await page.evaluate(() => (window as unknown as { __tracerClusters: Api }).__tracerClusters.setCanvasLock!(false));
    await expect.poll(async () => ((await api(page, "canvasLock")) as { on: boolean }).on).toBe(false);
    // Zoom the free canvas out with the overview so bare canvas shows around the windows.
    await api(page, "overview");
    // sleep: the overview's fly-out settles; no event marks the end
    await page.waitForTimeout(1500);
    const bare = await page.evaluate(() => {
      for (let y = 120; y < 800; y += 16) for (let x = 24; x < 370; x += 16) {
        const hit = document.elementFromPoint(x, y);
        if (hit && hit.closest(".cl-viewport") && !hit.closest(".ui-window, button, .cl-label, .cl-edge, .cl-port, .cl-chip, [role=toolbar], #capsule")) return { x, y };
      }
      return undefined;
    });
    expect(bare, "a point of bare canvas exists").toBeDefined();
    const before = await canvasState(page);
    await oneFinger(page, context, bare!, -80, -60);
    expect(await canvasState(page), "one finger on empty canvas pans the free canvas").not.toBe(before);
    await page.screenshot({ path: `${OUT}/phone-free-bare-pan.png` });
  });
});

test.describe("desktop: trackpad, Magic Mouse and mouse", () => {
  test.use({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, colorScheme: "dark" });

  /** A swipe as a trackpad delivers it: pixel deltas in many small steps, then a decaying momentum tail. */
  async function swipe(page: Page, dx: number, dy: number): Promise<void> {
    // sleep: one touch or wheel step per frame, like a finger or a pad; there is no event to wait for
    for (let i = 0; i < 8; i++) { await page.mouse.wheel(dx, dy); await page.waitForTimeout(16); }
    // sleep: one touch or wheel step per frame, like a finger or a pad; there is no event to wait for
    for (let i = 1; i <= 14; i++) { await page.mouse.wheel(Math.round(dx * 0.8 ** i), Math.round(dy * 0.8 ** i)); await page.waitForTimeout(16); }
    // sleep: the camera spring and a gesture's momentum settle; no event marks the end
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
    await swipe(page, -60, 0); // the page is the view's last window: only the previous one can be reached
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
    await page.mouse.wheel(0, -300); // (the previous window: this is the last one) an ordinary mouse wheel only has a vertical axis
    await page.keyboard.up(CANVAS_WHEEL_MODIFIER);
    await expect.poll(() => stopIndex(page), "modifier + wheel moves the canvas").not.toBe(index);
    // sleep: the camera spring and a gesture's momentum settle; no event marks the end
    await page.waitForTimeout(600);
    expect(await pageTop(page), "and the page under the pointer did not scroll").toBe(0);
  });

  test("the canvas modifier is Option/Alt on every OS (D377)", () => {
    expect(CANVAS_WHEEL_MODIFIER).toBe("Alt");
  });

  /** Puts a 2400 px wide block that scrolls sideways at the top of the docs page and returns the point at its middle. */
  async function addWideBlock(page: Page): Promise<{ x: number; y: number }> {
    await page.evaluate((sel) => {
      const d = document.createElement("div");
      d.id = "wide-block";
      d.style.cssText = "overflow-x:auto;overflow-y:hidden;width:100%;height:56px;margin:0 0 12px";
      const inner = document.createElement("div");
      inner.style.cssText = "width:2400px;height:40px";
      d.append(inner);
      document.querySelector(`${sel} .dr-page`)!.prepend(d);
      document.querySelector<HTMLElement>(`${sel} .dr-scroll`)!.scrollTop = 0;
    }, PAGE);
    const r = (await page.locator("#wide-block").boundingBox())!;
    return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
  }
  const blockLeft = (page: Page): Promise<number> => page.evaluate(() => document.getElementById("wide-block")!.scrollLeft);

  test("a sideways swipe over a wide block scrolls it to its end and beyond, and the canvas never moves", async ({ context }) => {
    test.setTimeout(90_000);
    mkdirSync(OUT, { recursive: true });
    const page = await open(context);
    const at = await addWideBlock(page);
    const before = await canvasState(page), index = await stopIndex(page);
    await page.mouse.move(at.x, at.y);
    await swipe(page, 60, 0);
    expect(await blockLeft(page), "the block scrolled sideways").toBeGreaterThan(100);
    for (let i = 0; i < 10; i++) await swipe(page, 60, 0); // far past its end, in fresh gestures
    const max = await page.evaluate(() => { const b = document.getElementById("wide-block")!; return b.scrollWidth - b.clientWidth; });
    expect(await blockLeft(page), "to the end").toBeGreaterThanOrEqual(max - 2);
    expect(await canvasState(page), "at its end the swipe still does not overflow to the canvas").toBe(before);
    expect(await stopIndex(page)).toBe(index);
    await page.screenshot({ path: `${OUT}/desktop-wide-block-end.png` });
  });

  test("Option/Alt plus the wheel over a wide block moves the canvas and the block stays", async ({ context }) => {
    test.setTimeout(90_000);
    const page = await open(context);
    const at = await addWideBlock(page);
    const index = await stopIndex(page);
    await page.mouse.move(at.x, at.y);
    await page.keyboard.down("Alt");
    await page.mouse.wheel(0, -300);
    await page.keyboard.up("Alt");
    await expect.poll(() => stopIndex(page), "Alt + wheel moves the canvas").not.toBe(index);
    expect(await blockLeft(page), "the block did not scroll").toBe(0);
  });

  test("Shift plus the wheel scrolls content sideways and does not move the canvas (D377)", async ({ context }) => {
    test.setTimeout(90_000);
    const page = await open(context);
    const at = await addWideBlock(page);
    const before = await canvasState(page), index = await stopIndex(page);
    await page.mouse.move(at.x, at.y);
    await page.keyboard.down("Shift");
    // sleep: one touch or wheel step per frame, like a finger or a pad; there is no event to wait for
    for (let i = 0; i < 4; i++) { await page.mouse.wheel(0, 100); await page.waitForTimeout(16); }
    await page.keyboard.up("Shift");
    // sleep: the camera spring and a gesture's momentum settle; no event marks the end
    await page.waitForTimeout(500);
    expect(await blockLeft(page), "Shift + wheel scrolled the block sideways").toBeGreaterThan(100);
    expect(await canvasState(page)).toBe(before);
    expect(await stopIndex(page)).toBe(index);
  });
});
