// SPDX-License-Identifier: AGPL-3.0-only
/**
 * An open overlay takes the Alt+wheel, and the canvas behind it stays put (D377, #444; J1014's review nit).
 *
 * The canvas moves on Option/Alt plus the wheel from anywhere. The window-level guard that cancels Alt+wheel outside the
 * canvas viewport routed those events to the canvas too, so an Alt+wheel over the command palette (or over the scrim that
 * covers the canvas behind it) or over an open popover moved the canvas behind the overlay. An open overlay must take the
 * wheel, or ignore it: never move the canvas behind it.
 *
 * Each case has a positive control first: the same Alt+wheel over bare canvas, with nothing open, does move the canvas,
 * so a probe that never moves anything cannot pass. Chromium, production build, desktop 1440×900. Nothing asserts speed.
 */
import { expect, test, type Page } from "playwright/test";

/** The mock canvas with one console window and no background, the same scene the access-level popover spec uses. */
const CANVAS = "/?mock=1&proto=clusters&scene=1&theme=ink&bg=none";

/**
 * Where the canvas is: the world's transform and every column's scroll position. Any move of the canvas changes one of them.
 */
const canvasState = (page: Page): Promise<string> =>
  page.evaluate(() => {
    const cols = [...document.querySelectorAll<HTMLElement>(".cl-col")].map((c) => `${c.scrollTop},${c.scrollLeft}`).join(";");
    return `${document.querySelector<HTMLElement>(".cl-world")?.style.transform ?? ""}|${cols}`;
  });

/** Opens the mock canvas and waits until its first layout has settled. */
async function openCanvas(page: Page): Promise<void> {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(CANVAS);
  await page.waitForFunction(() => (window as unknown as { __tracerClusters?: unknown }).__tracerClusters, null, { timeout: 30_000 });
  // sleep: the mock canvas finishes its first layout; no event marks it
  await page.waitForTimeout(900);
}

/**
 * One Alt+wheel gesture of `dy` pixels with the pointer at (`x`, `y`): the way an ordinary mouse wheel with Option/Alt held
 * reaches the page, so the canvas's modifier rule sees `altKey` on every event.
 */
async function altWheel(page: Page, x: number, y: number, dy: number): Promise<void> {
  await page.mouse.move(x, y);
  await page.keyboard.down("Alt");
  await page.mouse.wheel(0, dy);
  // sleep: the wheel handler runs on the next frame and a snap animates; no event marks the canvas at rest
  await page.waitForTimeout(500);
  await page.keyboard.up("Alt");
}

/** The centre of an element's box, for pointing at it. */
async function centre(page: Page, selector: string): Promise<{ x: number; y: number }> {
  const box = await page.locator(selector).first().boundingBox();
  if (!box) throw new Error(`no box for ${selector}`);
  return { x: box.x + box.width / 2, y: box.y + box.height / 2 };
}

test.describe("Alt+wheel over an open overlay (D377, #444)", () => {
  test.use({ viewport: { width: 1440, height: 900 } });

  test("the positive control: Alt+wheel over bare canvas moves the canvas (nothing open)", async ({ page }) => {
    test.setTimeout(60_000);
    await openCanvas(page);
    const before = await canvasState(page);
    await altWheel(page, 720, 450, 300);
    expect(await canvasState(page), "Alt+wheel over bare canvas moves the canvas, or the probe proves nothing").not.toBe(before);
  });

  test("Alt+wheel over the open command palette does not move the canvas behind it", async ({ page }) => {
    test.setTimeout(60_000);
    await openCanvas(page);
    await page.keyboard.press("Control+Shift+K");
    await expect(page.locator("#palette")).toBeVisible();
    const before = await canvasState(page);
    // Over the palette itself (outside the canvas viewport), then over the scrim that covers the canvas centre.
    const palette = await centre(page, "#palette");
    await altWheel(page, palette.x, palette.y, 300);
    expect(await canvasState(page), "Alt+wheel over the palette leaves the canvas where it was").toBe(before);
    await altWheel(page, 720, 450, 300);
    expect(await canvasState(page), "Alt+wheel over the palette's scrim leaves the canvas where it was").toBe(before);
    await expect(page.locator("#palette")).toBeVisible();
  });

  test("Alt+wheel over an open popover does not move the canvas behind it", async ({ page }) => {
    test.setTimeout(60_000);
    await openCanvas(page);
    await page.evaluate(() => (window as unknown as { __tracerClusters: { flyView(v: string): void } }).__tracerClusters.flyView("console"));
    // sleep: the view flies to the console window; no event marks the end of the flight
    await page.waitForTimeout(900);
    await page.locator(".ui-window-pill").first().click();
    await expect(page.locator(".canvas-popover")).toBeVisible();
    // sleep: the popover finishes opening; no event marks it
    await page.waitForTimeout(400);
    const before = await canvasState(page);
    const popover = await centre(page, ".canvas-popover");
    await altWheel(page, popover.x, popover.y, 300);
    expect(await canvasState(page), "Alt+wheel over the popover leaves the canvas where it was").toBe(before);
  });
});
