// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Where on a phone (393×852, touch) a one-finger or a two-finger drag moves the canvas, and what a person sees that tells them how
 * (D374, D377, #444, review J1014). It prints one line per drag and saves a screenshot of the middle of the Docs view; it asserts
 * nothing about the numbers. Production build, Chromium touch emulation.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type BrowserContext, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

/** Where the captures go: the external evidence directory, never the checkout. */
const OUT = tracerEvidencePath("swipe-phone-map");
/** The mock canvas's test hooks, as `window.__tracerClusters` exposes them. */
type Api = Record<string, (...args: unknown[]) => unknown>;
/** Calls one test hook of the mock canvas by name. */
const api = (page: Page, fn: string, ...args: unknown[]): Promise<unknown> =>
  page.evaluate(([f, a]) => ((window as unknown as { __tracerClusters: Api }).__tracerClusters[f as string] as (...x: unknown[]) => unknown)(...(a as unknown[])), [fn, args] as const);
/** The canvas stop (window) the locked canvas is on. */
const stopIndex = async (page: Page): Promise<number> => ((await api(page, "canvasLock")) as { index: number }).index;

test.use({ viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true, colorScheme: "dark" });

/** Drags `fingers` fingers from (x, y) by (dx, dy) over 12 frames, then waits for the camera to settle. */
async function drag(page: Page, context: BrowserContext, fingers: 1 | 2, x: number, y: number, dx: number, dy: number): Promise<void> {
  const cdp = await context.newCDPSession(page);
  const pts = (d: number, e: number) => (fingers === 1 ? [{ x: x + d, y: y + e }] : [{ x: x - 40 + d, y: y + e }, { x: x + 40 + d, y: y + e }]);
  await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: pts(0, 0) });
  // sleep: one touch step per frame, like a finger; there is no event to wait for
  for (let i = 1; i <= 12; i++) { await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: pts((dx * i) / 12, (dy * i) / 12) }); await page.waitForTimeout(16); }
  await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  // sleep: the camera spring settles; no event marks the end
  await page.waitForTimeout(700);
  await cdp.detach();
}

test("phone map: which one-finger and two-finger drags move the canvas", async ({ context }) => {
  test.setTimeout(300_000);
  mkdirSync(OUT, { recursive: true });
  const page = await context.newPage();
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=plain&docs=1");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  // sleep: the mock canvas finishes its first layout; no event marks it
  await page.waitForTimeout(1200);
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette-input")).toBeFocused();
  await page.keyboard.type("keys");
  await page.locator(".palette .result", { hasText: "Keys and how long they last" }).first().click();
  await expect(page.locator('.ui-window[data-window-id="d-reference/keys"] .dr-page h1')).toBeVisible({ timeout: 10_000 });
  // sleep: the camera settles on the window and the fonts load; no event marks it
  await page.waitForTimeout(1500);
  const toMiddle = async (): Promise<void> => {
    for (let i = 0; i < 16 && (await stopIndex(page)) !== 3; i++) {
      await page.keyboard.press((await stopIndex(page)) > 3 ? "Control+Shift+[" : "Control+Shift+]");
      // sleep: the camera flies one window; no event marks the end
      await page.waitForTimeout(450);
    }
    // sleep: the camera spring settles; no event marks the end
    await page.waitForTimeout(800);
  };
  await toMiddle();
  const lock = await api(page, "canvasLock");
  const boxes = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>(".ui-window")].map((w) => { const r = w.getBoundingClientRect(); return { id: w.dataset.windowId, x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) }; }).filter((b) => b.x < 393 && b.x + b.w > 0));
  console.log(`PHONE lock=${JSON.stringify(lock)} windows=${JSON.stringify(boxes)}`);
  await page.screenshot({ path: `${OUT}/phone-middle.png` });
  // The window under the middle of the screen (the id differs between the phone and desktop layouts).
  const mid = boxes.find((b) => b.x < 196 && b.x + b.w > 196 && b.y < 426 && b.y + b.h > 426) ?? boxes[0]!;
  const head = await page.locator(`.ui-window[data-window-id="${mid.id}"] .ui-window-head`).boundingBox();
  const cases: { name: string; fingers: 1 | 2; x: number; y: number; dx: number; dy: number }[] = [
    { name: "1 finger, header, sideways", fingers: 1, x: mid.x + mid.w / 2, y: (head?.y ?? mid.y) + (head?.height ?? 40) / 2, dx: -200, dy: 0 },
    { name: "1 finger, content, sideways", fingers: 1, x: mid.x + mid.w / 2, y: mid.y + mid.h / 2, dx: -200, dy: 0 },
    { name: "1 finger, left edge band, sideways", fingers: 1, x: mid.x + 6, y: mid.y + mid.h / 2, dx: -200, dy: 0 },
    { name: "1 finger, top of screen above window, sideways", fingers: 1, x: 196, y: 10, dx: -200, dy: 0 },
    { name: "1 finger, bottom of screen below window, sideways", fingers: 1, x: 196, y: 845, dx: -200, dy: 0 },
    { name: "2 fingers, content, sideways", fingers: 2, x: mid.x + mid.w / 2, y: mid.y + mid.h / 2, dx: -200, dy: 0 },
    { name: "2 fingers, header right of the pill, sideways", fingers: 2, x: mid.x + mid.w - 60, y: (head?.y ?? mid.y) + (head?.height ?? 40) / 2, dx: -200, dy: 0 },
    { name: "2 fingers, left edge band, sideways", fingers: 2, x: mid.x + 45, y: mid.y + mid.h / 2, dx: -200, dy: 0 },
    { name: "2 fingers, on the pill, sideways", fingers: 2, x: mid.x + mid.w / 2, y: (head?.y ?? mid.y) + (head?.height ?? 40) / 2, dx: -200, dy: 0 },
  ];
  for (const c of cases) {
    await toMiddle();
    const before = await stopIndex(page);
    await drag(page, context, c.fingers, c.x, c.y, c.dx, c.dy);
    console.log(`PHONE ${c.name}: stop ${before} -> ${await stopIndex(page)}`);
  }
  // Does anything on screen name a way to reach the next window? List the visible buttons, pagers and hints.
  const controls = await page.evaluate(() => [...document.querySelectorAll<HTMLElement>("button, [role=button], .cl-dots, .cl-pager, [class*=pager], [class*=dots]")].filter((e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && r.x < 393 && r.x + r.width > 0 && r.y < 852; }).map((e) => `${e.tagName.toLowerCase()}.${String(e.className).split(" ")[0]}[${(e.getAttribute("aria-label") ?? e.textContent ?? "").trim().slice(0, 30)}]`));
  console.log(`PHONE-CONTROLS ${JSON.stringify(controls)}`);
});
