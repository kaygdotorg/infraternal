/**
 * D249: the cursor blinks while you can type, from a layer of its own, with the renderer asleep.
 *
 * Proves: the layer exists only when typing can reach the terminal; it sits exactly on the cursor cell (also at the end
 * of a long line and after wrapping, at DPR 1 and 2, against the pixels the renderer itself draws); the blink is a
 * compositor animation that ends by itself, stops on blur and on a hidden page, and restarts on input; no renderer
 * pass and no page timer or frame runs while it blinks; reduced motion keeps it steady; a phone shows the steady
 * underline until a tap brings the keyboard.
 */
import { expect, test, type Page } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const baseURL = `http://localhost:${port}`;

type LayerState = NonNullable<ReturnType<NonNullable<Window["__tracerTestDouble"]>["cursorLayerState"]>>;

async function open(page: Page, theme: "ink" | "paper" = "ink"): Promise<void> {
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  await page.goto(`/?mock=1&theme=${theme}&bg=none`);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await settle(page);
}

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

const state = (page: Page): Promise<LayerState> => page.evaluate(() => window.__tracerTestDouble!.cursorLayerState()!);

/** The cell the cursor is on, from the terminal itself, and the layer's box against it. */
async function geometry(page: Page) {
  return page.evaluate(() => {
    const metrics = window.__tracerTestDouble!.rendererMetrics()!;
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas")!;
    const layer = window.__tracerTestDouble!.cursorLayerState()!.layer!;
    return {
      column: metrics.cursorX, row: metrics.cursorY, cols: metrics.cols, cellWidth: metrics.cellWidth, cellHeight: metrics.cellHeight,
      offsetLeft: canvas.offsetLeft, offsetTop: canvas.offsetTop, layer,
    };
  });
}

test("the layer sits on the cursor cell, blinks on the compositor, and the renderer stays asleep", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page);
  const s = await state(page);
  expect(s.typing).toBe("ready");
  expect(s.layer?.visible).toBe(true);
  expect(s.layer?.blinking).toBe(true);
  expect(s.rendererCursorHidden, "exactly one cursor: the renderer skips its own").toBe(true);
  const g = await geometry(page);
  expect(g.layer.x).toBe(g.offsetLeft + g.column * g.cellWidth);
  expect(g.layer.y).toBe(g.offsetTop + g.row * g.cellHeight);
  expect(g.layer.width).toBe(Math.max(2, Math.floor(g.cellWidth * 0.15)));
  expect(g.layer.height).toBe(g.cellHeight);
  // The animation is opacity only, finite, about 30 seconds.
  const anim = await page.evaluate(() => {
    const a = document.querySelector(".terminal-cursor-layer")!.getAnimations()[0]!;
    const t = a.effect!.getTiming();
    return { total: Number(t.duration) * Number(t.iterations), props: Object.keys((a.effect as KeyframeEffect).getKeyframes()[0]!).filter((k) => !["offset", "easing", "composite", "computedOffset"].includes(k)) };
  });
  expect(anim.props).toEqual(["opacity"]);
  expect(anim.total).toBeGreaterThan(29_000);
  expect(anim.total).toBeLessThan(31_000);

  // No renderer pass, timer or animation frame while it blinks.
  await page.evaluate(() => {
    const w = window as unknown as { __calls: { timers: number; frames: number } };
    w.__calls = { timers: 0, frames: 0 };
    const st = window.setTimeout.bind(window), raf = window.requestAnimationFrame.bind(window);
    window.setTimeout = ((...a: Parameters<typeof setTimeout>) => { w.__calls.timers += 1; return st(...a); }) as typeof setTimeout;
    window.requestAnimationFrame = ((cb: FrameRequestCallback) => { w.__calls.frames += 1; return raf(cb); }) as typeof requestAnimationFrame;
  });
  const before = (await state(page)).renderPasses;
  await page.waitForTimeout(3_500);
  expect((await state(page)).renderPasses).toBe(before);
  expect(await page.evaluate(() => (window as unknown as { __calls: unknown }).__calls)).toEqual({ timers: 0, frames: 0 });
});

test("the blink ends by itself, stops on blur and a hidden page, and any input restarts it", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await open(page);
  // Fast-forward to the end of the budget: steady, still there.
  await page.evaluate(() => { const a = document.querySelector(".terminal-cursor-layer")!.getAnimations()[0]!; a.finish(); });
  let s = await state(page);
  expect(s.layer).toMatchObject({ visible: true, blinking: false });
  await page.keyboard.type("x");
  await expect.poll(async () => (await state(page)).layer?.blinking).toBe(true);

  // Focus leaves: steady bar. Focus back: blinking.
  await page.evaluate(() => (document.activeElement as HTMLElement).blur());
  await expect.poll(async () => (await state(page)).layer?.blinking).toBe(false);
  expect((await state(page)).layer?.visible).toBe(true);
  await page.evaluate(() => document.querySelector<HTMLElement>("#terminal-host textarea")!.focus());
  await expect.poll(async () => (await state(page)).layer?.blinking).toBe(true);

  // A hidden page: steady; input after it is visible again restarts.
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect.poll(async () => (await state(page)).layer?.blinking).toBe(false);
  await page.evaluate(() => {
    Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect.poll(async () => (await state(page)).layer?.blinking).toBe(true);
});

test("reduced motion keeps the cursor steady", async ({ browser }) => {
  const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 }, reducedMotion: "reduce" });
  try {
    const page = await context.newPage();
    await open(page);
    const s = await state(page);
    expect(s.layer).toMatchObject({ visible: true, blinking: false });
    expect(s.rendererCursorHidden).toBe(true);
  } finally { await context.close(); }
});

for (const dpr of [1, 2]) {
  test(`the layer lines up with the renderer's own cursor at the end of a long line and after wrapping, DPR ${dpr}`, async ({ browser }) => {
    const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 }, deviceScaleFactor: dpr });
    try {
      const page = await context.newPage();
      await open(page, "paper");
      const cols = (await geometry(page)).cols;
      for (const [name, length] of [["end of a long line", 85], ["after wrapping", cols + 11]] as const) {
        await open(page, "paper");
        const text = "Mx0123456789 ".repeat(40).slice(0, length - 1) + "M";
        const response = await context.request.post("/__mock/text-output", { data: { text } });
        const { bytes } = await response.json() as { bytes: number };
        await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence), { timeout: 15_000 }).toBeTruthy();
        await page.waitForTimeout(300);
        await settle(page);
        void bytes;
        const g = await geometry(page);
        expect(g.column, name).toBe(length % cols === 0 ? cols - 1 : length % cols);
        expect(g.layer.x, name).toBe(g.offsetLeft + g.column * g.cellWidth);
        expect(g.layer.y, name).toBe(g.offsetTop + g.row * g.cellHeight);
        // The renderer's own pixels (layer off) put the same bar on the same device pixels.
        const layerBox = g.layer;
        await page.evaluate(() => window.__tracerTestDouble!.freezeCursorForTest());
        const bar = await page.evaluate(({ x, y, width, height, dpr: ratio, ox, oy }) => {
          const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas")!;
          const ctx = canvas.getContext("2d", { willReadFrequently: true })!;
          const left = Math.round((x - ox) * ratio), top = Math.round((y - oy) * ratio);
          const w = Math.round(width * ratio), h = Math.round(height * ratio);
          const px = (cx: number, cy: number) => Array.from(ctx.getImageData(cx, cy, 1, 1).data);
          return { inside: [px(left, top + (h >> 1)), px(left + w - 1, top + (h >> 1)), px(left + (w >> 1), top), px(left + (w >> 1), top + h - 1)], outside: [px(left - 1, top + (h >> 1)), px(left + w, top + (h >> 1))], cursor: window.__tracerTestDouble!.cursorLayerState()!.layer?.color };
        }, { ...layerBox, dpr, ox: g.offsetLeft, oy: g.offsetTop });
        const first = bar.inside[0]!;
        for (const p of bar.inside) expect(p, `${name}: bar pixels agree`).toEqual(first);
        for (const p of bar.outside) expect(p, `${name}: pixels outside the bar differ`).not.toEqual(first);
      }
    } finally { await context.close(); }
  });
}

test("a phone shows the steady underline until a tap brings the keyboard", async ({ browser }) => {
  const context = await browser.newContext({ baseURL, viewport: { width: 393, height: 852 }, deviceScaleFactor: 3, hasTouch: true, isMobile: true });
  try {
    const page = await context.newPage();
    await open(page);
    let s = await state(page);
    expect(s.typing).toBe("waiting");
    expect(s.layer?.visible, "no live cursor while a tap is needed").toBe(false);
    expect(s.rendererCursorHidden, "the renderer draws the steady underline").toBe(false);
    await page.touchscreen.tap(200, 300);
    await expect.poll(async () => (await state(page)).layer?.visible).toBe(true);
    s = await state(page);
    expect(s.typing).toBe("ready");
    expect(s.layer?.blinking).toBe(true);
    await page.evaluate(() => (document.activeElement as HTMLElement).blur());
    await expect.poll(async () => (await state(page)).layer?.visible).toBe(false);
    expect((await state(page)).rendererCursorHidden).toBe(false);
  } finally { await context.close(); }
});
