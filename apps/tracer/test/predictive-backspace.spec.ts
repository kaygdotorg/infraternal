/** Functional backspace and cursor regressions; CPU budgets run on the perf VM (#314). */
import { expect, test } from "playwright/test";
import { dpr, openPredictingTerminal, runKeys } from "./predictive-backspace-fixture";

const BS = "\x7f";

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

test(`predicted cursor pixels sit on the cell edge after backspace at DPR ${dpr}`, async ({ page, context }, info) => {
  test.setTimeout(120_000);
  await openPredictingTerminal(page, context);
  const typed = await runKeys(page, [..."pixel check"], 10);
  expect(typed.violations).toEqual([]);
  expect(typed.settled).toBe(true);
  // Font loading must finish before the prediction: screenshot waits for fonts.
  await page.evaluate(() => document.fonts.ready);
  // Keep the echo behind the screenshot so this oracle reads speculative pixels.
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal", delay_ms: 300 } });
  const geometryHandle = await page.waitForFunction(() => {
    const d = window.__tracerTestDouble;
    if (!d?.isConnected() || d.predictiveEcho()?.enabled !== true) return null;
    // Capture the pending cursor in the same task as the keys, before an echo
    // or a route change can clear this particular prediction.
    for (const key of ["\x7f", "\x7f", "\x7f"]) d.injectInput(key);
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas")!;
    const box = canvas.getBoundingClientRect();
    const cursor = d.predictiveEcho()!.overlay?.cursor;
    if (!cursor) throw new Error(`Backspace did not predict: ${d.predictiveEcho()!.reason}`);
    return { left: box.x + cursor.x, top: box.y + cursor.y, width: cursor.width, height: cursor.height, cw: d.rendererMetrics()!.cellWidth };
  }, undefined, { timeout: 30_000 });
  const geometry = await geometryHandle.jsonValue();
  await geometryHandle.dispose();
  if (!geometry) throw new Error("Prediction geometry was not captured");
  const geometryEvidence = await page.evaluate(() => {
    const source = document.querySelector<HTMLCanvasElement>("#terminal-host canvas")!;
    const overlay = document.querySelector<HTMLCanvasElement>("#terminal-host .terminal-text-overlay")!;
    return { sourceLeft: source.getBoundingClientRect().x, sourceTop: source.getBoundingClientRect().y,
      overlayLeft: overlay.getBoundingClientRect().x, overlayTop: overlay.getBoundingClientRect().y,
      sourceOffsetLeft: source.offsetLeft, sourceOffsetTop: source.offsetTop };
  });
  console.log("PREDICTED_CURSOR_GEOMETRY", JSON.stringify({ ...geometryEvidence, ...geometry }));
  const screenshotPath = info.outputPath("predicted-backspace-cursor.png");
  const png = await page.screenshot({ path: screenshotPath, scale: "device" });
  const capturedCursor = await page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.overlay?.cursor);
  expect(capturedCursor).toBeDefined();
  await info.attach("predicted-backspace-cursor", { path: screenshotPath, contentType: "image/png" });
  expect(geometryEvidence.overlayLeft).toBeCloseTo(geometryEvidence.sourceLeft, 2);
  expect(geometryEvidence.overlayTop).toBeCloseTo(geometryEvidence.sourceTop, 2);
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
    // Chromium rasterises the canvas from the containing device pixel. Rounding
    // its fractional origin up moves the oracle one pixel right at DPR 3.
    const left = Math.floor(geometry.left * dpr);
    const barPixels = Math.round(geometry.width * dpr);
    return { left: read(left), beforeLeft: read(left - 1), lastInside: read(left + barPixels - 1), afterRight: read(left + barPixels) };
  }, { base64: png.toString("base64"), geometry, dpr });
  console.log("PREDICTED_CURSOR_EDGES", JSON.stringify(edges));
  const distance = (a: number[], b: number[]) => Math.abs(a[0]! - b[0]!) + Math.abs(a[1]! - b[1]!) + Math.abs(a[2]! - b[2]!);
  // The bar's first and last device pixel carry the cursor colour; the pixels just outside do not.
  expect(distance(edges.left, edges.lastInside)).toBeLessThan(30);
  expect(distance(edges.left, edges.beforeLeft)).toBeGreaterThan(80);
  expect(distance(edges.left, edges.afterRight)).toBeGreaterThan(80);
});

test(`typing through a layout change keeps predicting without mispredictions at DPR ${dpr}`, async ({ page, context }) => {
  test.setTimeout(120_000);
  await openPredictingTerminal(page, context);
  const start = await page.evaluate(() => window.__tracerTestDouble!.rendererMetrics()!.cursorX);
  // The worst misprediction streak seen while typing: it resets to 0 once an echo matches again.
  const type = (text: string, gapMs: number) => page.evaluate(async ({ text, gapMs }) => {
    let worst = 0;
    let muted = false;
    for (const ch of text) {
      const d = window.__tracerTestDouble!;
      d.injectInput(ch);
      await new Promise((resolve) => setTimeout(resolve, gapMs));
      const p = d.predictiveEcho()!;
      worst = Math.max(worst, p.mispredictions);
      muted ||= p.muted;
    }
    return { worst, muted };
  }, { text, gapMs });
  // Keys are in flight (300 ms round trip) when the viewport, and with it the terminal grid, changes.
  const early = await type("abcdef", 20);
  await page.setViewportSize({ width: 660, height: 900 });
  // The echoes of the early keys arrive while later keys are typed. They must not release the wait early and
  // let a newer key be placed from a cursor that lacks them, which shows as repeated mispredictions and a mute.
  const late = await type("ghijklmnopqrstuvwxyz", 80);
  await page.waitForTimeout(1500);
  const state = await page.evaluate(() => {
    const d = window.__tracerTestDouble!;
    const p = d.predictiveEcho()!;
    return { mispredictions: p.mispredictions, muted: p.muted, reason: p.reason, cursorX: d.rendererMetrics()!.cursorX };
  });
  expect(state.cursorX).toBe(start + 26);
  expect(state.reason).not.toBe("repeated-mispredictions");
  expect(state.muted).toBe(false);
  expect(Math.max(early.worst, late.worst)).toBe(0);
  expect(early.muted || late.muted).toBe(false);
});
