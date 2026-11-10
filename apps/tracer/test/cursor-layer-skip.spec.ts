/**
 * The cursor layer follows the cursor although render passes skip its sync when no input changed (#447; written by
 * the J468 review). Each test changes one thing the layer depends on. In every frame after a renderer pass, and again
 * once the renderer has parked, the layer must sit on the terminal's own cursor cell, or be hidden exactly when the
 * cursor is hidden or scrolled away.
 */
import { expect, test, type Page } from "playwright/test";
import { THEMES } from "../../../packages/ui/src/themes";

/** The cursor-layer state the test double reports. */
type LayerState = NonNullable<ReturnType<NonNullable<Window["__tracerTestDouble"]>["cursorLayerState"]>>;

/** Opens the test-double terminal in `theme` and waits until it is attached and its renderer has parked. */
async function open(page: Page, theme: "ink" | "paper" = "ink"): Promise<void> {
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  await page.goto(`/?mock=1&theme=${theme}&bg=none`);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await settle(page);
}

/** The page's cursor-layer state (layer box, render passes, typing state). */
const state = (page: Page): Promise<LayerState> => page.evaluate(() => window.__tracerTestDouble!.cursorLayerState()!);

/** Waits until the renderer has parked (no pass for a full settling window). */
async function settle(page: Page): Promise<void> {
  let last = -1;
  await expect.poll(async () => {
    const now = (await state(page)).renderPasses;
    const stable = now === last;
    last = now;
    return stable;
  }, { timeout: 15_000, intervals: [900] }).toBe(true);
}

/** What the layer should show, computed from the terminal itself, and what it shows. */
async function truth(page: Page) {
  return page.evaluate(() => {
    const m = window.__tracerTestDouble!.rendererMetrics()!;
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas")!;
    const layer = window.__tracerTestDouble!.cursorLayerState()!.layer!;
    return {
      want: { visible: m.cursorVisible && m.viewportY === 0, x: canvas.offsetLeft + m.cursorX * m.cellWidth, y: canvas.offsetTop + m.cursorY * m.cellHeight },
      got: { visible: layer.visible, x: layer.x, y: layer.y, color: layer.color },
      cursor: { x: m.cursorX, y: m.cursorY, viewportY: m.viewportY, cols: m.cols, rows: m.rows, cellWidth: m.cellWidth },
    };
  });
}

/** After the renderer parks, the layer is exactly where the terminal's cursor is (or hidden when it is). */
async function expectLayerOnCursor(page: Page, what: string): Promise<void> {
  await settle(page);
  const t = await truth(page);
  expect(t.got.visible, `${what}: visible (${JSON.stringify(t)})`).toBe(t.want.visible);
  if (t.want.visible) {
    expect(t.got.x, `${what}: x (${JSON.stringify(t)})`).toBe(t.want.x);
    expect(t.got.y, `${what}: y (${JSON.stringify(t)})`).toBe(t.want.y);
  }
}


/**
 * Starts a per-frame check in the page: in every animation frame that follows a renderer pass, the layer must already sit
 * on the terminal's cursor (or be hidden exactly when it should be). A stale layer that only the parked renderer's
 * final sync repairs (`pauseTerminal`) is caught here, which `expectLayerOnCursor` (checked after parking) cannot see.
 */
async function watchFrames(page: Page): Promise<void> {
  await page.evaluate(() => {
    const w = window as unknown as { __watch: { running: boolean; frames: number; passFrames: number; stale: unknown[] } };
    w.__watch = { running: true, frames: 0, passFrames: 0, stale: [] };
    let lastPasses = -1;
    let prevStale = false;
    const tick = (): void => {
      const watch = w.__watch;
      const double = window.__tracerTestDouble!;
      const s = double.cursorLayerState()!;
      const m = double.rendererMetrics()!;
      watch.frames += 1;
      if (s.renderPasses !== lastPasses && lastPasses !== -1 && s.layer) {
        watch.passFrames += 1;
        const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas")!;
        const wantVisible = m.cursorVisible && m.viewportY === 0;
        const x = canvas.offsetLeft + m.cursorX * m.cellWidth, y = canvas.offsetTop + m.cursorY * m.cellHeight;
        const stale = s.layer.visible !== wantVisible || (wantVisible && (s.layer.x !== x || s.layer.y !== y));
        // Two stale pass-frames in a row: one can be output that arrived between two frames and is placed by the pass
        // that is about to run in this same frame (this check may run before the renderer's own frame callback).
        const persistent = stale && prevStale;
        prevStale = stale;
        if (persistent) {
          watch.stale.push({ frame: watch.frames, visible: s.layer.visible, wantVisible, x: s.layer.x, y: s.layer.y, wantX: x, wantY: y, cursor: [m.cursorX, m.cursorY], viewportY: m.viewportY });
        }
      }
      lastPasses = s.renderPasses;
      if (watch.running) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
}

/** Stops the frame check and fails if any frame after a renderer pass showed a stale layer; also proves passes were watched. */
async function expectNoStaleFrames(page: Page, what: string): Promise<void> {
  const result = await page.evaluate(() => {
    const w = window as unknown as { __watch: { running: boolean; frames: number; passFrames: number; stale: unknown[] } };
    w.__watch.running = false;
    return w.__watch;
  });
  expect(result.passFrames, `${what}: renderer passes were watched`).toBeGreaterThan(0);
  expect(result.stale, `${what}: frames after a renderer pass where the layer was stale (of ${result.passFrames})`).toEqual([]);
}

/** Sends `text` as live terminal output over the test double's socket and waits until the terminal has taken it. */
async function wire(page: Page, text: string): Promise<void> {
  const before = await page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()!.outputSequence);
  // live-query-output appends live Output frames and can be called repeatedly (text-output is one shot per session).
  expect((await page.context().request.post("/__mock/live-query-output", { data: { text } })).ok()).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()!.outputSequence), { timeout: 15_000 }).not.toBe(before);
}

/** Runs one change with the frame check on, then checks the layer both frame by frame and once the renderer has parked. */
async function step(page: Page, what: string, action: () => Promise<unknown>): Promise<void> {
  await watchFrames(page);
  await action();
  await settle(page);
  await expectNoStaleFrames(page, what);
  await expectLayerOnCursor(page, what);
}

test.beforeEach(async ({ page }) => { await page.setViewportSize({ width: 1440, height: 900 }); });

test("output over the wire moves the layer, including hiding and showing the cursor", async ({ page }) => {
  await open(page);
  await step(page, "after output", () => wire(page, "hello\r\nworld\r\n$ "));
  await step(page, "cursor hidden by the program", () => wire(page, "\x1b[?25l"));
  expect((await truth(page)).got.visible).toBe(false);
  await step(page, "cursor shown and moved", () => wire(page, "\x1b[?25h\x1b[5;9H"));
  expect((await truth(page)).got.visible).toBe(true);
  await step(page, "alternate screen", () => wire(page, "\x1b[?1049h\x1b[2J\x1b[3;4Hfull screen"));
  await step(page, "back from the alternate screen", () => wire(page, "\x1b[?1049l"));
});

test("a local write (mock helper, no wire sequence) moves the layer", async ({ page }) => {
  await open(page);
  await step(page, "after writeText", () => page.evaluate(() => window.__tracerTestDouble!.writeText("local one\r\nlocal two")));
});

test("scrolling the view back hides the layer and returning shows it where the cursor is", async ({ page }) => {
  await open(page);
  const text = Array.from({ length: 200 }, (_, i) => `line ${i}`).join("\r\n") + "\r\n$ ";
  await step(page, "after long output", () => wire(page, text));
  const box = (await page.locator("#terminal-host").boundingBox())!;
  await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
  await step(page, "scrolled back", async () => {
    await page.mouse.wheel(0, -600);
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()!.viewportY)).toBeGreaterThan(0);
  });
  expect((await truth(page)).got.visible).toBe(false);
  await step(page, "scrolled back to the bottom", async () => {
    await page.mouse.wheel(0, 5000);
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()!.viewportY)).toBe(0);
  });
  expect((await truth(page)).got.visible).toBe(true);
});

test("a font size change and a window resize move the layer", async ({ page }) => {
  await open(page);
  await step(page, "start", () => wire(page, "abc\r\ndef $ "));
  const startSize = (await truth(page)).cursor.cellWidth;
  await page.locator("#terminal-host").click({ position: { x: 100, y: 100 } });
  await step(page, "after larger text", async () => {
    for (let i = 0; i < 3; i += 1) await page.keyboard.press("Control+Equal");
    await expect.poll(async () => (await truth(page)).cursor.cellWidth).not.toBe(startSize);
  });
  await step(page, "after resize", () => page.setViewportSize({ width: 1000, height: 640 }));
  await step(page, "after a second resize", () => page.setViewportSize({ width: 1301, height: 777 }));
});

test("a theme change recolours the layer", async ({ page }) => {
  await open(page);
  for (const [id, name] of [["paper", "Paper"], ["ink", "Ink"]] as const) {
    await step(page, `theme ${id}`, async () => {
      await page.keyboard.press("Control+Shift+K");
      await page.locator("#palette-input").fill(name);
      const option = page.locator(`[role="option"][data-action="theme:${id}"]`);
      await expect(option).toBeVisible();
      await option.click();
      await expect(page.locator("#terminal-screen")).toHaveAttribute("data-theme", id);
    });
    expect((await truth(page)).got.color.toLowerCase(), `layer colour in ${id}`).toBe(THEMES[id].accent.toLowerCase());
  }
});

test("typing with prediction on keeps the layer on the real cursor", async ({ page }) => {
  await open(page);
  await page.locator("#terminal-host").click({ position: { x: 100, y: 100 } });
  await step(page, "after typing", async () => { await page.keyboard.type("echo hello"); });
});

test("selecting text does not move or hide the layer", async ({ page }) => {
  await open(page);
  await step(page, "before selection", () => wire(page, "alpha beta gamma $ "));
  const before = (await truth(page)).got;
  await step(page, "after selection", () => page.locator("#terminal-host").dblclick({ position: { x: 40, y: 20 } }));
  expect((await truth(page)).got.x).toBe(before.x);
});
