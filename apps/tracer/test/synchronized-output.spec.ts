/** Checks that split PTY messages stay off the canvas until synchronized output releases them. */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

const testDoublePort = Number(process.env.TRACER_BACKEND_PORT ?? String(Number(process.env.TRACER_TEST_PORT ?? "4621") + 1));
const testDoubleOrigin = `http://localhost:${testDoublePort}`;

async function sendOutput(page: Page, text: string): Promise<string> {
  const response = await page.request.post(`${testDoubleOrigin}/__mock/live-query-output`, { data: { text } });
  expect(response.ok()).toBe(true);
  return (await response.json() as { output_sequence: string }).output_sequence;
}

async function sendSynchronizedOutput(page: Page, parts: string[]): Promise<string[]> {
  const response = await page.request.post(`${testDoubleOrigin}/__mock/synchronized-output`, { data: { parts } });
  expect(response.ok()).toBe(true);
  return (await response.json() as { output_sequences: string[] }).output_sequences;
}

async function waitForSequence(page: Page, sequence: string): Promise<void> {
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0"), {
    timeout: 15_000,
  }).toBe(sequence);
}

async function waitForReceivedSequence(page: Page, sequence: string): Promise<void> {
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.receivedSequence ?? "0"), {
    timeout: 15_000,
    intervals: [2],
  }).toBe(sequence);
}

async function canvasPixels(page: Page): Promise<string> {
  return page.evaluate(() => {
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
    if (!canvas) throw new Error("terminal canvas is missing");
    const pixels = canvas.getContext("2d")?.getImageData(0, 0, canvas.width, canvas.height).data;
    if (!pixels) throw new Error("terminal canvas pixels are unavailable");
    let hash = 0x811c9dc5;
    for (const pixel of pixels) hash = Math.imul(hash ^ pixel, 0x01000193);
    return `${canvas.width}x${canvas.height}:${hash >>> 0}`;
  });
}

test("synchronized output holds split frame paints and releases within its timeout", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.context().request.post(`${testDoubleOrigin}/__mock/reset`);
  await page.context().request.post(`${testDoubleOrigin}/__mock/open-terminal`);
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);

  const baseSequence = await sendOutput(page, "BASE_FRAME");
  await waitForSequence(page, baseSequence);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("BASE_FRAME");
  await page.evaluate(() => window.__tracerTestDouble?.freezeCursorForTest());
  await page.waitForTimeout(800);
  const originalPixels = await canvasPixels(page);
  const originalPasses = await page.evaluate(() => window.__tracerTestDouble?.cursorLayerState()?.renderPasses ?? -1);
  await page.screenshot({ path: tracerEvidencePath("synchronized-output", "before-frame.png") });

  const frameParts = [
    "\u001b[?2026h\u001b[2J\u001b[Hframe-one",
    "\r\nframe-two",
    "\r\nframe-three",
  ];
  const synchronizedStart = await page.evaluate(() => performance.now());
  const frameSequences = await sendSynchronizedOutput(page, frameParts);
  expect(frameSequences).toHaveLength(frameParts.length);
  const finalFrameSequence = frameSequences.at(-1);
  if (!finalFrameSequence) throw new Error("synchronized output produced no frames");
  await waitForReceivedSequence(page, finalFrameSequence);
  const heldFrameState = await page.evaluate(() => ({
    at: performance.now(),
    holdsPaint: window.__tracerTestDouble?.rendererMetrics()?.synchronizedOutputHoldsPaint ?? false,
    renderPasses: window.__tracerTestDouble?.cursorLayerState()?.renderPasses ?? -1,
  }));
  console.log(`synchronized_output_frames=${frameSequences.length} elapsed_ms=${(heldFrameState.at - synchronizedStart).toFixed(1)} held=${heldFrameState.holdsPaint}`);
  expect(heldFrameState.holdsPaint).toBe(true);
  expect(heldFrameState.renderPasses).toBe(originalPasses);
  expect(await canvasPixels(page), "no part of a held frame reaches the canvas").toBe(originalPixels);

  const releasedSequence = await sendOutput(page, "\u001b[?2026l");
  await waitForSequence(page, releasedSequence);
  expect(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.synchronizedOutputHoldsPaint ?? true))
    .toBe(false);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""))
    .toContain("frame-one\nframe-two\nframe-three");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.cursorLayerState()?.renderPasses ?? -1))
    .toBeGreaterThan(originalPasses);
  await page.screenshot({ path: tracerEvidencePath("synchronized-output", "complete-frame.png") });

  const completePixels = await canvasPixels(page);
  const timeoutStarted = await page.evaluate(() => performance.now());
  const timeoutSequence = await sendOutput(page, "\u001b[?2026h\u001b[2J\u001b[HTIMEOUT_FRAME");
  await waitForReceivedSequence(page, timeoutSequence);
  expect(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.synchronizedOutputHoldsPaint ?? false))
    .toBe(true);
  expect(await canvasPixels(page), "the timeout case is held before its deadline").toBe(completePixels);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.synchronizedOutputHoldsPaint ?? true), {
    timeout: 1_000,
    intervals: [10],
  }).toBe(false);
  const timeoutReleaseMs = await page.evaluate((started) => performance.now() - started, timeoutStarted);
  expect(timeoutReleaseMs).toBeLessThan(500);
  console.log(`synchronized_output_timeout_release_ms=${timeoutReleaseMs.toFixed(1)}`);
  await waitForSequence(page, timeoutSequence);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.cursorLayerState()?.renderPasses ?? -1), {
    timeout: 1_000,
  }).toBeGreaterThan(originalPasses + 1);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("TIMEOUT_FRAME");
  expect(await canvasPixels(page)).not.toBe(completePixels);
});
