/**
 * Window canvas prototype (`?proto=windows`, D158–D159, D171): activation without focus,
 * trackpad and two-finger panning, crisp resting offset, copyable key/value cells and the
 * live terminal's cursor staying on its text inside a window card.
 */
import { expect, test, type BrowserContext, type Page } from "playwright/test";

type CanvasOffset = { x: number; y: number; minX: number; moving: boolean; transform: string };

async function openCanvas(page: Page): Promise<void> {
  // The reset closes the previous test's sockets; a pooled keep-alive connection through the
  // latency proxy can be among them, so one retry absorbs that hang-up.
  await page.context().request.post("/__mock/reset").catch(() => page.context().request.post("/__mock/reset"));
  await page.goto("/?mock=1&proto=windows&bg=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => (window as unknown as { __tracerCanvas?: { windows(): string[] } }).__tracerCanvas?.windows().length ?? 0)).toBeGreaterThan(2);
}

const offset = (page: Page): Promise<CanvasOffset> => page.evaluate(() =>
  (window as unknown as { __tracerCanvas: { offset(): CanvasOffset } }).__tracerCanvas.offset());
const activeWindow = (page: Page): Promise<string | undefined> => page.evaluate(() =>
  (window as unknown as { __tracerCanvas: { active(): string | undefined } }).__tracerCanvas.active());

async function touchContext(context: BrowserContext): Promise<Page> {
  const page = await context.newPage();
  await page.setViewportSize({ width: 393, height: 852 });
  return page;
}

test("desktop: horizontal trackpad scrolling pans the canvas over a terminal and rests on whole pixels", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  const terminal = await page.locator(".ui-window").first().locator(".terminal-host").boundingBox();
  await page.mouse.move(terminal!.x + 200, terminal!.y + 200);
  for (let index = 0; index < 10; index++) await page.mouse.wheel(48, 0);
  await expect.poll(async () => (await offset(page)).moving).toBe(false);
  const rest = await offset(page);
  expect(rest.x).toBeLessThan(-200);
  expect(rest.x).toBeGreaterThanOrEqual(rest.minX);
  // Whole device pixels at rest: crisp text (TASTE §5).
  const dpr = await page.evaluate(() => devicePixelRatio);
  expect(Math.abs(rest.x * dpr - Math.round(rest.x * dpr))).toBeLessThan(1e-6);
  expect(rest.transform).toMatch(/^translate3d\(-?\d+(\.\d+)?px, 0px, 0px\)$/);
  // Vertical scrolling over the terminal stays with the terminal, not the canvas.
  const before = (await offset(page)).x;
  await page.mouse.wheel(0, 120);
  expect((await offset(page)).x).toBe(before);
});

test("desktop: a click on an inactive window activates it without moving focus into it", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  const second = page.locator(".ui-window").nth(1);
  await second.locator(".ui-window-body").click();
  await expect(second).toHaveAttribute("aria-current", "true");
  // Focus neither moves into the clicked window nor stays in the live terminal behind it.
  expect(await page.evaluate(() => document.activeElement?.closest(".ui-window")?.getAttribute("data-window-id") ?? null)).toBeNull();
  await expect(page.locator("#capsule-host")).toHaveText(/build-01/);
  // No focus ring after a pointer action (TASTE §1).
  expect(await page.evaluate(() => document.documentElement.dataset.focusRing ?? "off")).toBe("off");
});

test("touch: a tap activates without the keyboard, two fingers pan the canvas", async ({ browser }) => {
  const context = await browser.newContext({ hasTouch: true, isMobile: true, deviceScaleFactor: 3, viewport: { width: 393, height: 852 } });
  const page = await touchContext(context);
  await openCanvas(page);
  const cdp = await context.newCDPSession(page);
  const touch = (type: "touchStart" | "touchMove" | "touchEnd", points: Array<{ x: number; y: number; id: number }>) =>
    cdp.send("Input.dispatchTouchEvent", { type, touchPoints: points });
  const box = (await page.locator(".canvas-viewport").boundingBox())!;
  const y = box.y + box.height / 2;
  // Two-finger pan to the left by 240 px.
  await touch("touchStart", [{ x: 260, y, id: 1 }, { x: 320, y, id: 2 }]);
  for (let step = 1; step <= 12; step++) {
    await touch("touchMove", [{ x: 260 - step * 20, y, id: 1 }, { x: 320 - step * 20, y, id: 2 }]);
  }
  await touch("touchEnd", []);
  await expect.poll(async () => (await offset(page)).moving, { timeout: 4_000 }).toBe(false);
  expect((await offset(page)).x).toBeLessThan(-150);
  // A tap on the now visible second window activates it and opens no keyboard.
  const second = page.locator(".ui-window").nth(1).locator(".ui-window-body");
  await second.tap();
  await expect.poll(() => activeWindow(page)).toMatch(/^build-01:/);
  expect(await page.evaluate(() => document.activeElement?.tagName ?? "")).not.toBe("TEXTAREA");
  await context.close();
});

test("details popover: keys left, values right, each cell copies with a tick", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.locator(".ui-window").first().locator(".ui-window-pill").click();
  const popover = page.locator(".canvas-popover");
  await expect(popover).toBeVisible();
  const row = popover.locator(".ui-kv-row").first();
  const [key, value] = await Promise.all([row.locator(".ui-kv-key").boundingBox(), row.locator(".ui-kv-value").boundingBox()]);
  const rowBox = (await row.boundingBox())!;
  expect(key!.x).toBeLessThan(rowBox.x + 8);
  expect(Math.abs(value!.x + value!.width - (rowBox.x + rowBox.width))).toBeLessThan(8);
  await row.locator(".ui-kv-value").click();
  await expect(row.locator(".ui-kv-value")).toHaveAttribute("data-copied", "");
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("6.8.0-58-generic");
  await row.locator(".ui-kv-key").click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("Kernel");
  // No ellipsis anywhere in the popover.
  expect(await popover.evaluate((node) => [...node.querySelectorAll("*")].some((element) => getComputedStyle(element).textOverflow === "ellipsis"))).toBe(false);
  await page.keyboard.press("Escape");
  await expect(popover).toHaveCount(0);
});

test("live terminal: the cursor stays on its text inside the window card", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await openCanvas(page);
  await page.locator(".ui-window").first().locator(".terminal-host").click();
  const text = "echo abcdefghijklmnopqrstuvwxyz0123456789";
  await page.keyboard.type(text);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorX)).toBe(text.length);
  const metrics = await page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()!);
  // UI tracking must not reach the renderer: the measured advance equals the cell width.
  expect(Math.abs(metrics.naturalCellWidth - metrics.cellWidth)).toBeLessThan(0.51);
});

for (const dpr of [1, 2]) {
  test(`live terminal: an 86-character line puts the cursor at column 86 with 8 px cells at DPR ${dpr} (a window wide enough for 87 columns)`, async ({ browser }) => {
    const context = await browser.newContext({ viewport: { width: 1920, height: 900 }, deviceScaleFactor: dpr });
    const page = await context.newPage();
    try {
      await openCanvas(page);
      await page.locator(".ui-window").first().locator(".terminal-host").click();
      const text = "x".repeat(86);
      await page.keyboard.type(text);
      await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorX)).toBe(86);
      const metrics = await page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()!);
      expect(metrics.cellWidth).toBe(8);
    } finally {
      await context.close();
    }
  });
}
