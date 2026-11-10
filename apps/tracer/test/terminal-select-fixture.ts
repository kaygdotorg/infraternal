// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Shared setup for the terminal selection specs (#426): opening the test terminal in a touch or desktop context, finding
 * cells on the canvas once the camera has stopped, and sending touches through the DevTools protocol (Playwright has no
 * long press). Used by `terminal-touch-select.spec.ts` and `terminal-selection-wrap.spec.ts`.
 */
import { expect, type Browser, type BrowserContext, type CDPSession, type Page } from "playwright/test";

/** The window whose terminal every case drives. */
export const WINDOW = '.ui-window[data-window-id="w-build-01"]';
/** The Copy callout: the shared window menu, named for what it acts on. */
export const CALLOUT = '.ui-window-menu[aria-label="Selected text"]';
/** The two phone sizes the contract holds at. */
export const SIZES = [{ name: "393x852", width: 393, height: 852 }, { name: "375x667", width: 375, height: 667 }] as const;
/** Ink is the dark theme and paper the light one. */
export const THEMES = ["ink", "paper"] as const;

/** A point in client pixels. */
export type Point = { x: number; y: number };

/** An opened terminal: its context, page and (in a touch context) a DevTools session for touches. */
export interface OpenTerminal { context: BrowserContext; page: Page; cdp?: CDPSession }

/**
 * Opens the test terminal, flies the camera to its window and waits for it to be live.
 * `touch` gives a phone context at the given size (DPR 3, clipboard allowed); otherwise a 1440×900 desktop one.
 */
export async function openTerminal(browser: Browser, theme: string, touch?: { width: number; height: number }): Promise<OpenTerminal> {
  const context = await browser.newContext(touch
    ? { viewport: touch, deviceScaleFactor: 3, hasTouch: true, isMobile: true, colorScheme: theme === "ink" ? "dark" : "light", permissions: ["clipboard-read", "clipboard-write"] }
    : { viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: theme === "ink" ? "dark" : "light", permissions: ["clipboard-read", "clipboard-write"] });
  const page = await context.newPage();
  // A stuck action fails with its call log in half a minute instead of running out the whole test's time.
  page.setDefaultTimeout(30_000);
  const cdp = touch ? await context.newCDPSession(page) : undefined;
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.goto(`/?mock=1&proto=clusters&scene=1&theme=${theme}&bg=none`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(id: string): void } }).__tracerClusters.flyView("console"));
  await expect(page.locator(`${WINDOW} .terminal-host`)).toBeVisible({ timeout: 15_000 });
  return cdp ? { context, page, cdp } : { context, page };
}

/** Writes `text` to the terminal and waits until `marker` is on its screen. */
export async function show(page: Page, text: string, marker: string): Promise<void> {
  await page.evaluate((value) => window.__tracerTestDouble!.writeText(value), text);
  await expect.poll(() => page.evaluate((m) => window.__tracerTestDouble!.screenText().includes(m), marker)).toBe(true);
}

/** Sends one touch event through the DevTools protocol: a finger down, moved, or lifted. */
export const touch = (cdp: CDPSession, type: "touchStart" | "touchMove" | "touchEnd", at?: Point): Promise<unknown> =>
  cdp.send("Input.dispatchTouchEvent", { type, touchPoints: at && type !== "touchEnd" ? [{ x: at.x, y: at.y }] : [] });

/** Keeps the finger down past the app's long-press time. */
export const hold = (page: Page, ms = 650): Promise<void> =>
  // sleep: a long press is defined by the finger staying down; the app times it, so the test must really wait.
  page.waitForTimeout(ms);

/** The text the terminal has selected right now. */
export const selected = (page: Page): Promise<string> => page.evaluate(() => window.__tracerTestDouble?.selectionText() ?? "");

/** The terminal's width in columns. */
export const columns = (page: Page): Promise<number> => page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()!.cols);

/**
 * The centre of the cell at (col, row) on the visible canvas, in client pixels, taken once the canvas has stopped moving.
 * "Stopped" is observed, not slept for: the canvas box must be identical for 15 animation frames in a row, so a camera that is
 * still flying (the cause of a flaky mouse drag that started on the wrong row) can never hand out coordinates.
 */
export async function cellCentre(page: Page, col: number, row: number): Promise<Point> {
  return page.evaluate(([c, r]) => new Promise<Point>((resolve) => {
    const canvas = document.querySelector<HTMLCanvasElement>(".terminal-host canvas")!;
    let last = "", still = 0;
    const tick = (): void => {
      const rect = canvas.getBoundingClientRect();
      const key = [rect.left, rect.top, rect.width, rect.height].join();
      still = key === last ? still + 1 : 0;
      last = key;
      if (still < 15) { requestAnimationFrame(tick); return; }
      const m = window.__tracerTestDouble!.rendererMetrics()!;
      resolve({ x: rect.left + (c! + 0.5) * m.cellWidth, y: rect.top + (r! + 0.5) * m.cellHeight });
    };
    requestAnimationFrame(tick);
  }), [col, row] as const);
}

/** Presses, holds past the long-press time, optionally drags through `via` to `to`, and lifts. */
export async function longPress(page: Page, cdp: CDPSession, at: Point, ...path: Point[]): Promise<void> {
  await touch(cdp, "touchStart", at);
  await hold(page);
  for (const point of path) await touch(cdp, "touchMove", point);
  await touch(cdp, "touchEnd");
}

/** A client rectangle read from the page. */
export interface Box { left: number; top: number; right: number; bottom: number }

/** The box of the first element matching `selector`, or undefined. */
export function boxOf(page: Page, selector: string): Promise<Box | undefined> {
  return page.evaluate((s) => {
    const el = document.querySelector(s);
    if (!el) return undefined;
    const r = el.getBoundingClientRect();
    return { left: r.left, top: r.top, right: r.right, bottom: r.bottom };
  }, selector);
}

/**
 * Waits until the element matching `selector` has stopped moving and fading: its box and opacity identical for 10 animation
 * frames in a row. (Not `document.getAnimations()`: some animations on the page are paused and never finish.)
 */
export async function settled(page: Page, selector: string): Promise<void> {
  await page.evaluate((s) => new Promise<void>((resolve) => {
    let last = "", still = 0;
    const tick = (): void => {
      const el = document.querySelector(s);
      const key = el ? `${[...Object.values(el.getBoundingClientRect().toJSON() as Record<string, number>)].join()}|${getComputedStyle(el).opacity}` : "";
      still = key && key === last ? still + 1 : 0;
      last = key;
      if (still >= 10) resolve(); else requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }), selector);
}

/**
 * How much a screenshot varies along a thin strip: the mean absolute luminance step between horizontally neighbouring pixels
 * (0 to 255; for a vertical strip, between vertically neighbouring ones). A strip over a flat colour or a heavy blur is near 0; one with text showing through it is several. `png` is a
 * screenshot of the whole page and `strip` a box in CSS pixels: cropping the screenshot already taken, not capturing a clip,
 * because a clipped capture is composited on its own and does not show the same glass.
 */
export async function detailAbove(page: Page, png: Buffer, strip: { x: number; y: number; width: number; height: number }, vertical = false): Promise<number> {
  return page.evaluate(async ([base64, box, along]) => {
    const bitmap = await createImageBitmap(await (await fetch(`data:image/png;base64,${base64}`)).blob());
    const scale = bitmap.width / window.innerWidth;
    const [sx, sy, sw, sh] = [box.x * scale, box.y * scale, Math.floor(box.width * scale), Math.floor(box.height * scale)].map(Math.round) as [number, number, number, number];
    const canvas = new OffscreenCanvas(sw, sh);
    const context = canvas.getContext("2d")!;
    context.drawImage(bitmap, sx, sy, sw, sh, 0, 0, sw, sh);
    const { data, width, height } = context.getImageData(0, 0, sw, sh);
    const luminance = (i: number): number => 0.2126 * data[i]! + 0.7152 * data[i + 1]! + 0.0722 * data[i + 2]!;
    let total = 0, count = 0;
    // Steps are taken along the strip: between horizontal neighbours, or for a vertical strip between vertical ones.
    const [stepX, stepY] = along ? [0, 1] : [1, 0];
    for (let y = 0; y + stepY < height; y++) for (let x = 0; x + stepX < width; x++) { total += Math.abs(luminance(((y + stepY) * width + x + stepX) * 4) - luminance((y * width + x) * 4)); count++; }
    return count ? total / count : 0;
  }, [png.toString("base64"), strip, vertical] as const);
}
