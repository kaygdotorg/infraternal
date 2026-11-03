/** Functional backspace and cursor regressions; CPU budgets run on the perf VM (#314). */
import { expect, test } from "playwright/test";
import { dpr, freezePredictionFrame, openPredictingTerminal, releasePredictionFrame, resizeWithInflightInput, runKeys } from "./predictive-backspace-fixture";

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
  const frame = await freezePredictionFrame(page, ["\x7f", "\x7f", "\x7f"]);
  const geometry = frame.geometry;
  const geometryEvidence = frame.origins;
  console.log("PREDICTED_CURSOR_GEOMETRY", JSON.stringify({ ...geometryEvidence, ...geometry }));
  const screenshotPath = info.outputPath("predicted-backspace-cursor.png");
  const png = await page.screenshot({ path: screenshotPath, scale: "device" });
  await releasePredictionFrame(page);
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

test(`layout changes preserve the host cursor and recover prediction after late echo at DPR ${dpr}`, async ({ page, context }) => {
  test.setTimeout(120_000);
  const { start, early, late, state, recoveredState } = await resizeWithInflightInput(page, context, 500);
  expect(state.cursorX).toBe(start + 26);
  expect(state.reason).not.toBe("repeated-mispredictions");
  expect(Math.max(early.worst, late.worst)).toBe(0);
  expect(recoveredState.muted).toBe(false);
  expect(recoveredState.mispredictions).toBe(0);
  expect(recoveredState.cursorX).toBe(start + 27);
});
