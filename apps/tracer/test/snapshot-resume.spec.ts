/** Regresses ring-wrap Snapshot repaint and post-resume echo on the production page. */
import { expect, test } from "playwright/test";

const RING_CAPACITY = 8 * 1024 * 1024;
const OUTPUT_BYTES = RING_CAPACITY + 64;
const SNAPSHOT_MARKER = "__TRACER_SNAPSHOT_READY__";

test("a wrapped-ring Snapshot paints echoes and keeps resize, scrollback, and theme state", async ({ page }) => {
  test.setTimeout(60_000);
  const context = page.context();
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect(page.getByText("TEST DOUBLE")).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);

  // Take the same authenticated terminal offline while the mock PTY advances
  // past the shim's production ring size. The mock then resumes with a
  // contract-valid Snapshot frame at the absolute output cursor.
  await context.setOffline(true);
  await page.evaluate(() => window.__tracerTestDouble?.dropConnection());
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === false)).toBe(true);
  let wrapped: { bytes: number; ring_capacity: number; ring_start_sequence: string; output_sequence: string } | undefined;
  for (let attempt = 0; attempt < 40 && !wrapped; attempt += 1) {
    const response = await context.request.post("/__mock/wrapped-ring");
    if (response.status() === 200) wrapped = await response.json() as typeof wrapped;
    else expect(response.status(), "the previous WebSocket must detach before the PTY advances").toBe(409);
    if (!wrapped) await page.waitForTimeout(50);
  }
  expect(wrapped).toEqual({
    bytes: OUTPUT_BYTES,
    ring_capacity: RING_CAPACITY,
    ring_start_sequence: "64",
    output_sequence: String(OUTPUT_BYTES),
  });
  // This keystroke is buffered by the browser while detached. Its normal
  // echoed Output follows the resume Snapshots over the wire.
  await page.keyboard.press("x");

  await context.setOffline(false);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
  await expect.poll(async () => {
    const metrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
    return metrics !== undefined && BigInt(metrics.outputSequence) >= BigInt(OUTPUT_BYTES);
  }, { timeout: 15_000 }).toBe(true);
  const wrappedState = await (await context.request.get("/__mock/state")).json() as { snapshot_count: number; echoed_text: string };
  expect(wrappedState.snapshot_count).toBe(2);
  expect(wrappedState.echoed_text).toBe("x");
  expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain(SNAPSHOT_MARKER);

  await expect.poll(async () => {
    const metrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
    return metrics?.receivedSequence;
  }).toBe(String(OUTPUT_BYTES + 1));
  await expect.poll(async () => {
    const metrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
    return metrics?.outputSequence;
  }).toBe(String(OUTPUT_BYTES + 1));
  expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("x");
  const postResumePixels = await canvasFingerprint(page);
  await page.keyboard.press("y");
  await expect.poll(async () => {
    const state = await (await context.request.get("/__mock/state")).json() as { echoed_text: string };
    return state.echoed_text;
  }).toBe("xy");
  await expect.poll(async () => {
    const metrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
    return metrics?.outputSequence;
  }).toBe(String(OUTPUT_BYTES + 2));
  expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("xy");
  expect(await canvasFingerprint(page), "a keystroke after Snapshot must paint on the terminal canvas").not.toBe(postResumePixels);

  // Snapshot scrollback remains readable after a real grid resize and theme change.
  const beforeResize = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
  await page.setViewportSize({ width: 1040, height: 600 });
  await expect.poll(() => page.evaluate(() => {
    const metrics = window.__tracerTestDouble?.rendererMetrics();
    return metrics ? `${metrics.cols}x${metrics.rows}` : "";
  })).not.toBe(`${beforeResize?.cols}x${beforeResize?.rows}`);
  expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain(SNAPSHOT_MARKER);
  await page.locator("#terminal-host").hover();
  await page.mouse.wheel(0, -1200);
  await expect.poll(() => page.locator("#terminal-host").getAttribute("data-scrolled")).toBe("true");
  expect(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.scrollbackRows ?? 0)).toBeGreaterThan(0);
  expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain(SNAPSHOT_MARKER);

  // Like the theme regression, compare a settled scroll position. data-scrolled
  // becomes true while the wheel animation is still approaching its target.
  let previousViewportY = (await readTerminalState(page)).viewportY;
  let stableViewportSamples = 0;
  await expect.poll(async () => {
    const viewportY = (await readTerminalState(page)).viewportY;
    stableViewportSamples = Math.abs(viewportY - previousViewportY) < 0.001 ? stableViewportSamples + 1 : 0;
    previousViewportY = viewportY;
    return stableViewportSamples >= 2;
  }, { timeout: 5_000, intervals: [50] }).toBe(true);
  const beforeThemeState = await readTerminalState(page);
  const beforeThemePixels = await canvasFingerprint(page);
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("dracula");
  await page.keyboard.press("Enter");
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-theme", "dracula");
  await expect.poll(() => canvasFingerprint(page)).not.toBe(beforeThemePixels);
  // Theme changes reconnect and replay a fresh Snapshot before restoring the
  // viewport; wait for its painted terminal state instead of the early UI swap.
  await expect.poll(() => readTerminalState(page), { timeout: 15_000 }).toEqual(beforeThemeState);
  expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain(SNAPSHOT_MARKER);
  await page.locator("#terminal-host").click();
  await page.mouse.wheel(0, 10_000);
  await expect.poll(() => page.locator("#terminal-host").getAttribute("data-scrolled")).toBe("false");
  const resizedPixels = await canvasFingerprint(page);
  await page.keyboard.press("z");
  await expect.poll(async () => {
    const metrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
    return metrics?.outputSequence;
  }).toBe(String(OUTPUT_BYTES + 3));
  expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("xyz");
  expect(await canvasFingerprint(page), "echo must remain visible after resize, scrollback, and theme changes").not.toBe(resizedPixels);
});

/** Hashes the rendered canvas pixels without depending on cursor timing or DOM text. */
async function canvasFingerprint(page: import("playwright/test").Page): Promise<string> {
  return page.evaluate(() => {
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
    const context = canvas?.getContext("2d", { willReadFrequently: true });
    if (!canvas || !context) throw new Error("terminal canvas is unavailable");
    const pixels = context.getImageData(0, 0, canvas.width, canvas.height).data;
    let hash = 2_166_136_261;
    for (const pixel of pixels) hash = Math.imul(hash ^ pixel, 16_777_619);
    return `${canvas.width}x${canvas.height}:${hash >>> 0}`;
  });
}

async function readTerminalState(page: import("playwright/test").Page) {
  return page.evaluate(() => {
    const terminal = window.__tracerTestDouble;
    const metrics = terminal?.rendererMetrics();
    if (!metrics) throw new Error("terminal renderer metrics are unavailable");
    return {
      cursorX: metrics.cursorX,
      cursorRow: metrics.cursorY + metrics.scrollbackRows,
      viewportY: Math.round(metrics.viewportY * 100) / 100,
      screenText: terminal?.screenText() ?? "",
    };
  });
}
