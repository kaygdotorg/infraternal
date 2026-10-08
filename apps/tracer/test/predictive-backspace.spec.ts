/**
 * Backspace under predictive local echo [#50, D128]: the predicted cursor must
 * stay on exact cells and follow the host, however typing, backspacing and the
 * host's `\b \b` echoes interleave.
 *
 * A page-side model of the host line (cells, cursor, wrap-pending) replays the
 * same keys the mock host echoes. After every key, while the prediction is
 * still unconfirmed, the drawn cursor and glyphs are compared with that model;
 * after the echoes land, the renderer's own cursor and screen are.
 */
import { expect, test, type Page } from "playwright/test";

const dpr = Number(process.env.TRACER_TEST_DPR ?? "1");

/** Calls `window.__afterMessage` right after the app's own socket handler, in the same task and before any frame. */
function hookSocketMessages(): void {
  const Original = window.WebSocket;
  const descriptor = Object.getOwnPropertyDescriptor(Original.prototype, "onmessage")!;
  window.WebSocket = new Proxy(Original, {
    construct(target, args: [string | URL, (string | string[])?]) {
      const socket = new target(...args);
      Object.defineProperty(socket, "onmessage", {
        configurable: true,
        get: () => descriptor.get!.call(socket),
        set: (handler: ((event: MessageEvent) => void) | null) => {
          descriptor.set!.call(socket, handler === null ? null : (event: MessageEvent) => {
            handler.call(socket, event);
            (window as unknown as { __afterMessage?: () => void }).__afterMessage?.();
          });
        },
      });
      return socket;
    },
  });
}

async function openPredictingTerminal(
  page: Page,
  context: import("playwright/test").BrowserContext,
  options: { hookSockets?: boolean } = {},
): Promise<void> {
  await page.setViewportSize({ width: 720, height: 900 });
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.addInitScript(() => sessionStorage.clear());
  if (options.hookSockets) await page.addInitScript(hookSocketMessages);
  await page.goto("/?mock=1&predict=1&theme=paper&bg=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0), { timeout: 30_000 })
    .toBeGreaterThan(60);
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  expect(await page.evaluate(() => window.devicePixelRatio)).toBe(dpr);
  // A person's first key comes well after the idle warm-up of the prediction path.
  await page.waitForTimeout(500);
}

interface RunResult {
  violations: string[];
  predictedSamples: number;
  samples: number;
  hostCursor: { x: number; y: number };
  model: { x: number; y: number; text: string[] };
  fallbacks: number;
  mispredictions: number;
  /** Work per key, worst key: the budget holds for every key, the first one included. */
  maxInputCostMs: number;
  settled: boolean;
}

/** Sends `keys` with `gapMs` between them, checking the drawn prediction against the host-line model after each. */
function runKeys(page: Page, keys: string[], gapMs: number): Promise<RunResult> {
  return page.evaluate(async ({ keys, gapMs }) => {
    const d = window.__tracerTestDouble!;
    const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));
    const m0 = d.rendererMetrics()!;
    const { cols, rows } = m0;
    // Cells of the host screen as the mock host leaves them (it echoes input bytes; DEL echoes `\b \b`).
    const cells: string[][] = Array.from({ length: rows }, () => Array.from({ length: cols }, () => " "));
    const screen = d.screenText().split("\n");
    for (let y = 0; y < Math.min(rows, screen.length); y += 1) {
      for (let x = 0; x < Math.min(cols, screen[y]!.length); x += 1) cells[y]![x] = screen[y]![x]!;
    }
    let x = m0.cursorX;
    let y = m0.cursorY;
    let wrapPending = false;
    const apply = (key: string): void => {
      if (key === "\x7f") {
        wrapPending = false;
        if (x > 0) x -= 1;
        cells[y]![x] = " ";
        return;
      }
      for (const ch of key) {
        if (wrapPending) { x = 0; y += 1; wrapPending = false; }
        cells[y]![x] = ch;
        if (x === cols - 1) wrapPending = true; else x += 1;
      }
    };

    const violations: string[] = [];
    let samples = 0;
    let predictedSamples = 0;
    const near = (value: number) => Math.abs(value - Math.round(value)) < 1e-6;
    const check = (label: string): void => {
      samples += 1;
      const state = d.predictiveEcho()!;
      const metrics = d.rendererMetrics()!;
      const overlay = state.overlay;
      if (!overlay?.visible) return;
      predictedSamples += 1;
      const cw = metrics.cellWidth;
      const ch = metrics.cellHeight;
      const cursor = overlay.cursor;
      if (!cursor) { violations.push(`${label}: overlay visible without a cursor`); return; }
      if (!near(cursor.x / cw)) violations.push(`${label}: cursor x ${cursor.x} is not a whole number of ${cw}px cells`);
      if (!near(cursor.y / ch)) violations.push(`${label}: cursor y ${cursor.y} is not a whole number of ${ch}px rows`);
      const column = Math.round(cursor.x / cw);
      const row = Math.round(cursor.y / ch);
      if (column !== x || row !== y) violations.push(`${label}: predicted cursor ${column},${row} but the host line is at ${x},${y}`);
      for (const glyph of overlay.glyphs) {
        if (!near(glyph.x / cw) || !near(glyph.y / ch)) { violations.push(`${label}: glyph ${glyph.text} off the cell grid`); continue; }
        const gx = Math.round(glyph.x / cw);
        const gy = Math.round(glyph.y / ch);
        if (cells[gy]?.[gx] !== glyph.text) {
          violations.push(`${label}: glyph ${JSON.stringify(glyph.text)} drawn at ${gx},${gy} where the host line has ${JSON.stringify(cells[gy]?.[gx])}`);
        }
      }
    };

    for (const [index, key] of keys.entries()) {
      d.injectInput(key);
      apply(key);
      check(`after key ${index} ${JSON.stringify(key)}`);
      if (gapMs > 0) await sleep(gapMs);
      check(`gap ${index}`);
    }

    // Let every echo land: the host output stops advancing for longer than a round trip (300 ms + jitter).
    let settled = false;
    let lastOutput = d.rendererMetrics()!.outputSequence;
    let quietSince = performance.now();
    for (let attempt = 0; attempt < 200 && !settled; attempt += 1) {
      await sleep(50);
      const output = d.rendererMetrics()!.outputSequence;
      if (output !== lastOutput) { lastOutput = output; quietSince = performance.now(); }
      const state = d.predictiveEcho()!;
      settled = performance.now() - quietSince > 900 && state.pendingText === "" && state.overlay?.visible !== true;
    }
    const metrics = d.rendererMetrics()!;
    const state = d.predictiveEcho()!;
    return {
      violations,
      predictedSamples,
      samples,
      hostCursor: { x: metrics.cursorX, y: metrics.cursorY },
      model: { x, y, text: cells.map((row) => row.join("").trimEnd()).slice(0, y + 1) },
      fallbacks: Object.values(state.fallbacks).reduce((total, count) => total + count, 0),
      mispredictions: state.mispredictions,
      maxInputCostMs: Math.max(0, ...state.inputCostMs),
      settled,
    };
  }, { keys, gapMs });
}

const BS = "\x7f";
/** The per-key prediction budget (keystroke_prediction_cpu). */
const KEY_COST_BUDGET_MS = 2;

test(`backspace mixed with typing keeps the predicted cursor on exact cells at DPR ${dpr}`, async ({ page, context }) => {
  test.setTimeout(120_000);
  await openPredictingTerminal(page, context);
  // Settle a confirmed line first so backspaces also erase text that is no longer a prediction.
  const first = await runKeys(page, [..."hello world"], 20);
  expect(first.violations).toEqual([]);
  expect(first.settled).toBe(true);
  expect(first.hostCursor).toEqual({ x: first.model.x, y: first.model.y });

  // Quick backspaces over confirmed text, typing in between, backspacing over typed-but-unconfirmed text,
  // and a final run past what was typed.
  const keys = [BS, BS, BS, "x", "y", BS, BS, BS, "p", "q", "r", BS, "s", BS, BS, BS, BS, "t"];
  const second = await runKeys(page, keys, 15);
  expect(second.violations).toEqual([]);
  expect(second.settled).toBe(true);
  expect(second.mispredictions).toBe(0);
  expect(second.fallbacks).toBe(0);
  expect(second.predictedSamples).toBeGreaterThan(keys.length);
  expect(second.hostCursor).toEqual({ x: second.model.x, y: second.model.y });
  const screen = await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "");
  expect(screen.split("\n").slice(0, second.model.text.length).map((row) => row.trimEnd())).toEqual(second.model.text);
  expect(second.maxInputCostMs).toBeLessThan(KEY_COST_BUDGET_MS);
});

test(`rapid backspaces with no gap land on the host cursor at DPR ${dpr}`, async ({ page, context }) => {
  test.setTimeout(120_000);
  await openPredictingTerminal(page, context);
  const typed = await runKeys(page, [..."abcdefghij"], 0);
  expect(typed.violations).toEqual([]);
  const burst = await runKeys(page, [BS, BS, BS, "k", BS, BS, "l", "m", BS, BS, BS, BS, BS], 0);
  expect(burst.violations).toEqual([]);
  expect(burst.settled).toBe(true);
  expect(burst.hostCursor).toEqual({ x: burst.model.x, y: burst.model.y });
});

test(`backspacing across a wrapped line and past its start stays on cells at DPR ${dpr}`, async ({ page, context }) => {
  test.setTimeout(120_000);
  await openPredictingTerminal(page, context);
  const columns = await page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()!.cols);
  const line = [..."W".repeat(columns + 6)];
  const typed = await runKeys(page, line, 5);
  expect(typed.violations).toEqual([]);
  expect(typed.settled).toBe(true);
  expect(typed.hostCursor.y).toBe(typed.model.y);
  expect(typed.model.y).toBeGreaterThan(0);
  // Back to the start of the wrapped row and beyond it, then type again.
  const back = await runKeys(page, [...Array.from({ length: 12 }, () => BS), "a", "b"], 10);
  expect(back.violations).toEqual([]);
  expect(back.settled).toBe(true);
  expect(back.hostCursor).toEqual({ x: back.model.x, y: back.model.y });
});

test(`a key typed in the frame an echo is written is placed from the host cursor at DPR ${dpr}`, async ({ page, context }) => {
  test.setTimeout(120_000);
  await openPredictingTerminal(page, context, { hookSockets: true });
  // The host's echo is written to the renderer at once but reconciled one frame later. A key that arrives in
  // between must not count the already echoed glyphs a second time.
  const result = await page.evaluate(async () => {
    const d = window.__tracerTestDouble!;
    const w = window as unknown as { __afterMessage?: () => void };
    const start = d.rendererMetrics()!.cursorX;
    for (const ch of "abc") d.injectInput(ch);
    let report: { overlayColumn: number; hostColumn: number; pending: string } | undefined;
    w.__afterMessage = () => {
      // Armed until the renderer has taken the echo (its cursor moved) while the prediction is still unreconciled.
      if (report || d.rendererMetrics()!.cursorX === start) return;
      d.injectInput("d");
      const cw = d.rendererMetrics()!.cellWidth;
      report = {
        overlayColumn: (d.predictiveEcho()!.overlay?.cursor?.x ?? Number.NaN) / cw,
        hostColumn: d.rendererMetrics()!.cursorX,
        pending: d.predictiveEcho()!.pendingText,
      };
    };
    for (let attempt = 0; attempt < 100 && !report; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 20));
    return { start, report };
  });
  expect(result.report).toBeDefined();
  expect(result.report!.hostColumn).toBeGreaterThan(result.start);
  // Part of the echo of "abc" is in the renderer and "d" was just typed: four keys are on the line in all.
  expect(result.report!.overlayColumn).toBe(result.start + 4);
});

test(`a backspace typed in the frame a backspace echo is written is placed from the host cursor at DPR ${dpr}`, async ({ page, context }) => {
  test.setTimeout(120_000);
  await openPredictingTerminal(page, context, { hookSockets: true });
  const typed = await runKeys(page, [..."abcdefgh"], 10);
  expect(typed.settled).toBe(true);
  const result = await page.evaluate(async () => {
    const d = window.__tracerTestDouble!;
    const w = window as unknown as { __afterMessage?: () => void };
    const start = d.rendererMetrics()!.cursorX;
    d.injectInput("\x7f");
    let report: { overlayColumn: number; hostColumn: number } | undefined;
    w.__afterMessage = () => {
      // Armed until the renderer's cursor has moved for the first erase, while the prediction is unreconciled.
      if (report || d.rendererMetrics()!.cursorX === start) return;
      d.injectInput("\x7f");
      const cw = d.rendererMetrics()!.cellWidth;
      report = {
        overlayColumn: (d.predictiveEcho()!.overlay?.cursor?.x ?? Number.NaN) / cw,
        hostColumn: d.rendererMetrics()!.cursorX,
      };
    };
    for (let attempt = 0; attempt < 100 && !report; attempt += 1) await new Promise((resolve) => setTimeout(resolve, 20));
    return { start, report };
  });
  expect(result.report).toBeDefined();
  expect(result.report!.hostColumn).toBeLessThan(result.start);
  // Two erases are on the line in all, whatever part of the first one's echo the renderer already has.
  expect(result.report!.overlayColumn).toBe(result.start - 2);
});

test(`predicted cursor pixels sit on the cell edge after backspace at DPR ${dpr}`, async ({ page, context }) => {
  test.setTimeout(120_000);
  await openPredictingTerminal(page, context);
  await runKeys(page, [..."pixel check"], 10);
  await page.evaluate(() => {
    const d = window.__tracerTestDouble!;
    for (const key of ["\x7f", "\x7f", "\x7f"]) d.injectInput(key);
  });
  const geometry = await page.evaluate(() => {
    const d = window.__tracerTestDouble!;
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas")!;
    const box = canvas.getBoundingClientRect();
    const cursor = d.predictiveEcho()!.overlay!.cursor!;
    return { left: box.x + cursor.x, top: box.y + cursor.y, width: cursor.width, height: cursor.height, cw: d.rendererMetrics()!.cellWidth };
  });
  const png = await page.screenshot({ scale: "device" });
  const edges = await page.evaluate(async ({ base64, geometry, dpr }) => {
    const image = new Image();
    image.src = `data:image/png;base64,${base64}`;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    const context = canvas.getContext("2d", { willReadFrequently: true })!;
    context.drawImage(image, 0, 0);
    const y = Math.round((geometry.top + geometry.height / 2) * dpr);
    const read = (px: number) => Array.from(context.getImageData(px, y, 1, 1).data.slice(0, 3));
    const left = Math.round(geometry.left * dpr);
    const barPixels = Math.round(geometry.width * dpr);
    return { left: read(left), beforeLeft: read(left - 1), lastInside: read(left + barPixels - 1), afterRight: read(left + barPixels) };
  }, { base64: png.toString("base64"), geometry, dpr });
  const distance = (a: number[], b: number[]) => Math.abs(a[0]! - b[0]!) + Math.abs(a[1]! - b[1]!) + Math.abs(a[2]! - b[2]!);
  // The bar's first and last device pixel carry the cursor colour; the pixels just outside do not.
  expect(distance(edges.left, edges.lastInside)).toBeLessThan(30);
  expect(distance(edges.left, edges.beforeLeft)).toBeGreaterThan(80);
  expect(distance(edges.left, edges.afterRight)).toBeGreaterThan(80);
});

test(`the first predicted key stays within the per-key budget at DPR ${dpr}`, async ({ page, context }) => {
  test.setTimeout(120_000);
  await openPredictingTerminal(page, context);
  const costs = await page.evaluate(async () => {
    const d = window.__tracerTestDouble!;
    for (const ch of "firstkeys") {
      d.injectInput(ch);
      await new Promise((resolve) => setTimeout(resolve, 60));
    }
    return d.predictiveEcho()!.inputCostMs;
  });
  console.log(`first-key cost ${costs[0]!.toFixed(2)} ms; rest max ${Math.max(...costs.slice(1)).toFixed(2)} ms`);
  expect(costs.length).toBe(9);
  expect(Math.max(...costs)).toBeLessThan(KEY_COST_BUDGET_MS);
});
