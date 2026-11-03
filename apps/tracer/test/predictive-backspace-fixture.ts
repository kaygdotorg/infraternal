/**
 * Backspace under predictive local echo [#50, D128]: the predicted cursor must
 * stay on exact cells and follow the host, however typing, backspacing and the
 * host's `\b \b` echoes interleave.
 *
 * A page-side model of the host line (cells, cursor, wrap-pending) replays the
 * same keys the mock host echoes. After every key, while the prediction is
 * still unconfirmed, the drawn cursor and glyphs are compared with that model;
 * after the echoes land, the renderer's own cursor and screen are. Shared screenshot
 * probes preserve those production bitmaps before encoding can outlive the prediction.
 */
import { expect, type Page } from "playwright/test";

export const dpr = Number(process.env.TRACER_TEST_DPR ?? "1");

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

export async function openPredictingTerminal(
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
export function runKeys(page: Page, keys: string[], gapMs: number): Promise<RunResult> {
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

/**
 * Preserves the actual pending renderer frame before transport or PNG encoding can advance it.
 * The copy contains the original renderer and prediction bitmaps at their existing shared origin;
 * it neither redraws glyphs nor invents cursor pixels. Live confirmation continues underneath it.
 */
export async function freezePredictionFrame(page: Page, keys: string[]) {
  await page.evaluate(() => document.fonts.ready);
  const handle = await page.waitForFunction((keys) => {
    const terminal = window.__tracerTestDouble;
    if (!terminal?.isConnected() || terminal.predictiveEcho()?.enabled !== true) return null;
    for (const key of keys) terminal.injectInput(key);
    const prediction = terminal.predictiveEcho()!;
    const snapshot = prediction.overlay;
    const source = document.querySelector<HTMLCanvasElement>("#terminal-host canvas")!;
    const overlay = document.querySelector<HTMLCanvasElement>("#terminal-host .terminal-text-overlay")!;
    if (!snapshot?.visible || !snapshot.cursor || getComputedStyle(overlay).visibility !== "visible") {
      throw new Error(`Ready input did not produce a visible prediction: ${prediction.reason}`);
    }
    const sourceBox = source.getBoundingClientRect();
    const overlayBox = overlay.getBoundingClientRect();
    if (Math.abs(sourceBox.x - overlayBox.x) > 0.005 || Math.abs(sourceBox.y - overlayBox.y) > 0.005
      || source.width !== overlay.width || source.height !== overlay.height) {
      throw new Error("Renderer and prediction raster origins or backing sizes differ");
    }
    const frame = overlay.cloneNode(false) as HTMLCanvasElement;
    frame.dataset.frozenPrediction = "";
    frame.dataset.cursor = JSON.stringify(snapshot.cursor);
    const context = frame.getContext("2d")!;
    context.drawImage(source, 0, 0);
    context.drawImage(overlay, 0, 0);
    overlay.after(frame);
    return {
      text: snapshot.text,
      geometry: { left: sourceBox.x + snapshot.cursor.x, top: sourceBox.y + snapshot.cursor.y,
        width: snapshot.cursor.width, height: snapshot.cursor.height },
      origins: { sourceLeft: sourceBox.x, sourceTop: sourceBox.y, overlayLeft: overlayBox.x, overlayTop: overlayBox.y },
    };
  }, keys, { timeout: 30_000 });
  const frame = await handle.jsonValue();
  await handle.dispose();
  if (!frame) throw new Error("Prediction frame was not captured");
  return frame;
}

/** Reveals the live renderer again before checking the independently confirmed output. */
export async function releasePredictionFrame(page: Page): Promise<void> {
  await page.evaluate(() => document.querySelectorAll("[data-frozen-prediction]").forEach((node) => node.remove()));
}
