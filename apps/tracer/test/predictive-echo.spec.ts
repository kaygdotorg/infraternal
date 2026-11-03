/** Exercises opt-in local echo directly against the production Ghostty renderer build. */
import { expect, test } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const baseURL = `http://localhost:${port}`;

interface CellPoint {
  x: number;
  y: number;
}

interface CursorPoint extends CellPoint {
  wrapPending: boolean;
}

function advanceAscii(start: CellPoint, columns: number, count: number): { cells: CellPoint[]; cursor: CursorPoint } {
  const cells: CellPoint[] = [];
  let x = start.x;
  let y = start.y;
  let wrapPending = false;
  for (let index = 0; index < count; index += 1) {
    if (wrapPending) {
      x = 0;
      y += 1;
      wrapPending = false;
    }
    cells.push({ x, y });
    if (x + 1 === columns) {
      x = columns - 1;
      wrapPending = true;
    } else {
      x += 1;
    }
  }
  return { cells, cursor: { x, y, wrapPending } };
}

function stepBack(cursor: CursorPoint, count: number): CursorPoint {
  let { x, y, wrapPending } = cursor;
  for (let index = 0; index < count; index += 1) {
    if (x === 0) throw new Error("test cursor cannot backspace across an unverified row edge");
    wrapPending = false;
    x -= 1;
  }
  return { x, y, wrapPending };
}

async function inspectPixels(
  page: import("playwright/test").Page,
  screenshot: Buffer,
  cursorBox: { x: number; y: number; width: number; height: number },
  cellBoxes: Array<{ x: number; y: number; width: number; height: number }>,
): Promise<{
  scaleX: number;
  scaleY: number;
  cursorChanged: { minX: number; maxX: number; minY: number; maxY: number; count: number };
  glyphPixels: number[];
}> {
  return page.evaluate(async ({ base64, cursorArea, glyphAreas }) => {
    const image = new Image();
    image.src = `data:image/png;base64,${base64}`;
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("pixel-check canvas context is unavailable");
    context.drawImage(image, 0, 0);
    const scaleX = image.naturalWidth / window.innerWidth;
    const scaleY = image.naturalHeight / window.innerHeight;
    const scan = (box: { x: number; y: number; width: number; height: number }, predicate: (rgba: Uint8ClampedArray, offset: number) => boolean) => {
      const left = Math.max(0, Math.floor(box.x * scaleX));
      const top = Math.max(0, Math.floor(box.y * scaleY));
      const right = Math.min(canvas.width, Math.ceil((box.x + box.width) * scaleX));
      const bottom = Math.min(canvas.height, Math.ceil((box.y + box.height) * scaleY));
      const width = right - left;
      const height = bottom - top;
      const data = context.getImageData(left, top, width, height).data;
      let minX = Number.POSITIVE_INFINITY;
      let maxX = -1;
      let minY = Number.POSITIVE_INFINITY;
      let maxY = -1;
      let count = 0;
      for (let y = 0; y < height; y += 1) {
        for (let x = 0; x < width; x += 1) {
          const offset = (y * width + x) * 4;
          if (!predicate(data, offset)) continue;
          minX = Math.min(minX, left + x);
          maxX = Math.max(maxX, left + x);
          minY = Math.min(minY, top + y);
          maxY = Math.max(maxY, top + y);
          count += 1;
        }
      }
      return { minX, maxX, minY, maxY, count };
    };
    const centerY = Math.min(canvas.height - 1, Math.max(0, Math.floor((cursorArea.y + cursorArea.height / 2) * scaleY)));
    const outsideX = Math.min(canvas.width - 1, Math.max(0, Math.ceil((cursorArea.x + cursorArea.width + 1) * scaleX)));
    const outside = context.getImageData(outsideX, centerY, 1, 1).data;
    const cursorChanged = scan(cursorArea, (pixels, offset) =>
      Math.abs(pixels[offset]! - outside[0]!) + Math.abs(pixels[offset + 1]! - outside[1]!)
        + Math.abs(pixels[offset + 2]! - outside[2]!) > 70);
    const glyphPixels = glyphAreas.map((box) => scan(box, (pixels, offset) => {
      const luma = pixels[offset]! * 0.2126 + pixels[offset + 1]! * 0.7152 + pixels[offset + 2]! * 0.0722;
      return luma < 160;
    }).count);
    return { scaleX, scaleY, cursorChanged, glyphPixels };
  }, {
    base64: screenshot.toString("base64"),
    cursorArea: cursorBox,
    glyphAreas: cellBoxes,
  });
}

function expectCursorPixelBounds(
  pixels: Awaited<ReturnType<typeof inspectPixels>>,
  box: { x: number; y: number; width: number; height: number },
  dpr: number,
): void {
  const expected = {
    left: Math.round(box.x * dpr),
    right: Math.round((box.x + box.width) * dpr) - 1,
  };
  expect(pixels.cursorChanged.count).toBeGreaterThan(dpr * dpr * box.width * box.height * 0.5);
  expect(Math.abs(pixels.cursorChanged.minX - expected.left)).toBeLessThanOrEqual(1);
  expect(Math.abs(pixels.cursorChanged.maxX - expected.right)).toBeLessThanOrEqual(1);
}

test("predictive echo draws only when Ghostty reports a visible normal-screen cursor", async ({ page }) => {
  const context = page.context();
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.setViewportSize({ width: 1440, height: 900 });
  await context.addInitScript(() => sessionStorage.clear());
  await page.goto("/?mock=1&predict=1");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0), { timeout: 30_000 })
    .toBeGreaterThan(60);

  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("$");
  const cursor = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
  expect(Boolean(cursor?.cursorVisible)).toBe(true);

  await page.keyboard.press("a");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("a");
  await expect.poll(async () => ((await (await context.request.get("/__mock/state")).json()) as { echoed_text: string }).echoed_text)
    .toBe("a");
  await context.request.post("/__mock/drop-next-ack");
  await page.evaluate(() => window.__tracerTestDouble?.injectInput("b"));
  await expect.poll(async () => ((await (await context.request.get("/__mock/state")).json()) as { echoed_text: string }).echoed_text)
    .toBe("ab");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ab");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("");

  const inject = (data: string) => page.evaluate((value) => window.__tracerTestDouble?.injectInput(value), data);
  const outputSequence = () => page.evaluate(() => Number(window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0"));
  const resetScreen = async (): Promise<void> => {
    const response = await context.request.post("/__mock/screen-reset");
    const state = await response.json() as { output_sequence: string };
    await expect.poll(async () => BigInt(await page.evaluate(
      () => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0",
    ))).toBeGreaterThanOrEqual(BigInt(state.output_sequence));
  };
  const waitForOutputBytes = async (previous: number, count: number): Promise<void> => {
    await expect.poll(outputSequence).toBeGreaterThanOrEqual(previous + count);
  };
  await context.request.post("/__mock/alternate-screen", { data: { active: true } });
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.reason ?? ""))
    .toBe("unsafe-screen");
  await inject("u");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("");
  await context.request.post("/__mock/alternate-screen", { data: { active: false } });
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.enabled ?? false))
    .toBe(true);

  await context.request.post("/__mock/echo-mode", { data: { mode: "wrong" } });
  for (const [index, key] of ["m", "n", "o"].entries()) {
    await inject(key);
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.mispredictions ?? 0))
      .toBe(index + 1);
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
      .toBe("");
  }
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.muted ?? false)).toBe(true);
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal" } });
  await inject("r");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.muted ?? true)).toBe(false);

  await resetScreen();
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  let previousOutput = await outputSequence();
  await inject("ABC");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ABC");
  await waitForOutputBytes(previousOutput, 3);
  previousOutput = await outputSequence();
  const cursorBeforeMove = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorX ?? 0));
  await inject("\u001b[D");
  await waitForOutputBytes(previousOutput, 3);
  const cursorAfterMove = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.cursorX ?? 0));
  expect(cursorAfterMove).toBe(cursorBeforeMove - 1);
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal", delay_ms: 500 } });
  await inject("Z");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("Z");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.overlay?.text ?? "")).toBe("Z");
  const movedCursor = await page.evaluate(() => ({
    x: window.__tracerTestDouble?.predictiveEcho()?.overlay?.glyphs[0]?.x ?? Number.NaN,
    cellWidth: window.__tracerTestDouble?.rendererMetrics()?.cellWidth ?? 0,
    cursorX: window.__tracerTestDouble?.rendererMetrics()?.cursorX ?? 0,
  }));
  expect(movedCursor.cursorX).toBe(cursorAfterMove);
  expect(movedCursor.x).toBeCloseTo(movedCursor.cellWidth * cursorAfterMove, 1);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("Z");
  await context.request.post("/__mock/echo-mode", { data: { mode: "normal" } });

  await resetScreen();
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  previousOutput = await outputSequence();
  await inject("ABCZ");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ABCZ");
  await waitForOutputBytes(previousOutput, 4);
  previousOutput = await outputSequence();
  await inject("\u007f");
  await waitForOutputBytes(previousOutput, 3);
  const afterBackspace = await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "");
  expect(afterBackspace).toContain("ABC");
  expect(afterBackspace).not.toContain("ABCZ");

  previousOutput = await outputSequence();
  await inject("pasted words");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""))
    .toContain("pasted words");
  await waitForOutputBytes(previousOutput, 12);
  await inject("ok");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("ok");

  await page.setViewportSize({ width: 393, height: 852 });
  await page.evaluate(() => sessionStorage.clear());
  await page.goto("/?mock=1&predict=1&theme=ink");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await resetScreen();
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  // This is a fresh client: attachment precedes the RTT proof that enables prediction.
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.enabled ?? false))
    .toBe(true);
  await inject("x");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("x");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""))
    .toContain("x");
});

test("mutes when the host stops echoing, then resumes after an echo proof", async ({ page, context }) => {
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.addInitScript(() => sessionStorage.clear());
  await page.goto("/?mock=1&predict=1");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0), { timeout: 30_000 })
    .toBeGreaterThan(60);
  await context.request.post("/__mock/echo-mode", { data: { mode: "none" } });
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  // Fixture control can overlap a route recovery; begin this prediction test
  // only once the current terminal is attached and has its RTT proof.
  await expect.poll(() => page.evaluate(() =>
    window.__tracerTestDouble?.isConnected() === true
      && window.__tracerTestDouble.predictiveEcho()?.enabled === true,
  ), { timeout: 30_000 }).toBe(true);

  const noEchoPrediction = await page.evaluate(() => {
    window.__tracerTestDouble?.injectInput("p");
    return {
      state: window.__tracerTestDouble?.predictiveEcho(),
      overlayText: window.__tracerTestDouble?.predictiveEcho()?.overlay?.text ?? "",
    };
  });
  expect(noEchoPrediction.state?.pendingText).toBe("p");
  expect(noEchoPrediction.overlayText).toBe("p");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.muted ?? false), { timeout: 3000 })
    .toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("");

  await context.request.post("/__mock/echo-mode", { data: { mode: "normal" } });
  await page.evaluate(() => window.__tracerTestDouble?.injectInput("s"));
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.muted ?? true))
    .toBe(false);
});

test("predicted cursor advances across a pending multi-character line", async ({ page, context }) => {
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.addInitScript(() => sessionStorage.clear());
  await page.goto("/?mock=1&predict=1");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0), { timeout: 30_000 })
    .toBeGreaterThan(60);
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());

  const predicted = "abcdefghijklmnopqrstuvwx";
  const hostCursor = await page.evaluate(() => ({
    x: Number(window.__tracerTestDouble?.rendererMetrics()?.cursorX ?? 0),
    y: Number(window.__tracerTestDouble?.rendererMetrics()?.cursorY ?? 0),
  }));
  await page.evaluate((value) => {
    for (const character of value) window.__tracerTestDouble?.injectInput(character);
  }, predicted);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe(predicted);

  const overlayCursor = await page.evaluate(() => {
    const cursor = window.__tracerTestDouble?.predictiveEcho()?.overlay?.cursor;
    if (!cursor) throw new Error("the predicted cursor is not drawn");
    return { x: cursor.x, y: cursor.y, width: cursor.width };
  });
  const cell = await page.evaluate(() => ({
    width: window.__tracerTestDouble?.rendererMetrics()?.cellWidth ?? 0,
    height: window.__tracerTestDouble?.rendererMetrics()?.cellHeight ?? 0,
  }));
  expect(overlayCursor.x).toBeCloseTo((hostCursor.x + predicted.length) * cell.width, 2);
  expect(overlayCursor.y).toBeCloseTo(hostCursor.y * cell.height, 2);
  expect(overlayCursor.width).toBeGreaterThan(0);
});

const pixelTestDpr = Number(process.env.TRACER_TEST_DPR ?? "1");
if (![1, 2, 3].includes(pixelTestDpr)) throw new Error("TRACER_TEST_DPR must be 1, 2, or 3");

test(`predicted glyph and cursor pixels match confirmed cells at DPR ${pixelTestDpr}`, async ({ page, context }, testInfo) => {
  const dpr = pixelTestDpr;
  test.setTimeout(180_000);
  await page.setViewportSize({ width: 720, height: 900 });
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.addInitScript(() => sessionStorage.clear());
  await page.goto("/?mock=1&predict=1&theme=paper&bg=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0), { timeout: 30_000 })
    .toBeGreaterThan(60);
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());

  const readGeometry = () => page.evaluate(() => {
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
    const drawnCursor = window.__tracerTestDouble?.predictiveEcho()?.overlay?.cursor;
    const metrics = window.__tracerTestDouble?.rendererMetrics();
    if (!canvas || !metrics) throw new Error("renderer canvas or metrics are unavailable");
    const canvasContext = canvas.getContext("2d", { willReadFrequently: true });
    const scaleX = canvas.width / (metrics.cols * metrics.cellWidth);
    const scaleY = canvas.height / (metrics.rows * metrics.cellHeight);
    const canvasPixel = canvasContext
      ? Array.from(canvasContext.getImageData(
        Math.max(0, Math.min(canvas.width - 1, Math.floor((metrics.cursorX * metrics.cellWidth + Math.max(1, metrics.cellWidth * 0.1)) * scaleX))),
        Math.max(0, Math.min(canvas.height - 1, Math.floor((metrics.cursorY * metrics.cellHeight + metrics.cellHeight / 2) * scaleY))),
        1,
        1,
      ).data.slice(0, 4))
      : [];
    const toBox = (rect: DOMRect) => ({ x: rect.x, y: rect.y, width: rect.width, height: rect.height });
    return {
      canvas: toBox(canvas.getBoundingClientRect()),
      backing: { width: canvas.width, height: canvas.height },
      cursor: drawnCursor ? (() => {
        const canvasBox = canvas.getBoundingClientRect();
        return { x: canvasBox.x + drawnCursor.x, y: canvasBox.y + drawnCursor.y, width: drawnCursor.width, height: drawnCursor.height };
      })() : undefined,
      canvasPixel,
      cellWidth: metrics.cellWidth,
      cellHeight: metrics.cellHeight,
      columns: metrics.cols,
      rows: metrics.rows,
      cursorX: metrics.cursorX,
      cursorY: metrics.cursorY,
      dpr: window.devicePixelRatio,
    };
  });
  const original = await readGeometry();
  expect(original.dpr).toBe(dpr);
  const start = { x: original.cursorX, y: original.cursorY };
  const shortLine = "MMMMMMMMMMMMMMMMMMMMMMMM";
  const shortExpected = advanceAscii(start, original.columns, shortLine.length);
  await page.evaluate((value) => {
    for (const character of value) window.__tracerTestDouble?.injectInput(character);
  }, shortLine);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe(shortLine);

  const pendingGeometry = await readGeometry();
  expect(pendingGeometry.cursor).toBeDefined();
  const pendingCursorBox = pendingGeometry.cursor!;
  expect(pendingCursorBox.x).toBeCloseTo(pendingGeometry.canvas.x + shortExpected.cursor.x * pendingGeometry.cellWidth, 2);
  expect(pendingCursorBox.y).toBeCloseTo(pendingGeometry.canvas.y + shortExpected.cursor.y * pendingGeometry.cellHeight, 2);
  const shortCellBoxes = shortExpected.cells.map((cell) => ({
    x: pendingGeometry.canvas.x + cell.x * pendingGeometry.cellWidth,
    y: pendingGeometry.canvas.y + cell.y * pendingGeometry.cellHeight,
    width: pendingGeometry.cellWidth,
    height: pendingGeometry.cellHeight,
  }));
  const pendingShortPng = await page.screenshot({ scale: "device" });
  const pendingShortPixels = await inspectPixels(
    page,
    pendingShortPng,
    pendingCursorBox,
    shortCellBoxes,
  );
  expect(pendingShortPixels.scaleX).toBe(dpr);
  expect(pendingShortPixels.scaleY).toBe(dpr);
  expect(pendingShortPixels.glyphPixels.every((count) => count > 0)).toBe(true);
  expectCursorPixelBounds(pendingShortPixels, pendingCursorBox, dpr);
  await testInfo.attach(`predictive-dpr${dpr}-short-pending.png`, {
    body: pendingShortPng,
    contentType: "image/png",
  });

  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain(shortLine);
  await page.evaluate(() => window.__tracerTestDouble?.freezeCursorForTest());
  const confirmedGeometry = await readGeometry();
  expect(confirmedGeometry.cursorX).toBe(shortExpected.cursor.x);
  expect(confirmedGeometry.cursorY).toBe(shortExpected.cursor.y);
  const confirmedCursorBox = {
    x: confirmedGeometry.canvas.x + shortExpected.cursor.x * confirmedGeometry.cellWidth,
    y: confirmedGeometry.canvas.y + shortExpected.cursor.y * confirmedGeometry.cellHeight,
    width: Math.max(2, Math.floor(confirmedGeometry.cellWidth * 0.15)),
    height: confirmedGeometry.cellHeight,
  };
  const confirmedShortPng = await page.screenshot({ scale: "device" });
  const confirmedShortPixels = await inspectPixels(
    page,
    confirmedShortPng,
    confirmedCursorBox,
    shortCellBoxes,
  );
  expect(confirmedShortPixels.glyphPixels.every((count) => count > 0)).toBe(true);
  expect(confirmedGeometry.canvasPixel.slice(0, 3)).toEqual([0x3d, 0x63, 0xdd]);
  await testInfo.attach(`predictive-dpr${dpr}-short-confirmed.png`, {
    body: confirmedShortPng,
    contentType: "image/png",
  });

  const beforeBackspace = Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0"));
  const backspaceExpected = stepBack(shortExpected.cursor, 1);
  await page.evaluate(() => window.__tracerTestDouble?.injectInput("\u007f"));
  await expect.poll(() => page.evaluate(() => Boolean(window.__tracerTestDouble?.predictiveEcho()?.overlay?.cursor)))
    .toBe(true);
  const pendingBackspaceGeometry = await readGeometry();
  const pendingBackspaceBox = pendingBackspaceGeometry.cursor!;
  expect(pendingBackspaceBox.x).toBeCloseTo(pendingBackspaceGeometry.canvas.x + backspaceExpected.x * pendingBackspaceGeometry.cellWidth, 2);
  const pendingBackspacePng = await page.screenshot({ scale: "device" });
  const pendingBackspacePixels = await inspectPixels(
    page,
    pendingBackspacePng,
    pendingBackspaceBox,
    [],
  );
  expectCursorPixelBounds(pendingBackspacePixels, pendingBackspaceBox, dpr);
  await expect.poll(async () => Number(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0")))
    .toBeGreaterThanOrEqual(beforeBackspace + 3);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""))
    .toContain("M".repeat(shortLine.length - 1));
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""))
    .not.toContain(shortLine);
  await expect.poll(() => page.locator(".terminal-text-overlay").evaluate((node) => getComputedStyle(node).visibility))
    .toBe("hidden");
  await page.evaluate(() => window.__tracerTestDouble?.freezeCursorForTest());
  const confirmedBackspaceGeometry = await readGeometry();
  expect(confirmedBackspaceGeometry.cursorX).toBe(backspaceExpected.x);
  expect(confirmedBackspaceGeometry.cursorY).toBe(backspaceExpected.y);
  expect(confirmedBackspaceGeometry.canvasPixel.slice(0, 3)).toEqual([0x3d, 0x63, 0xdd]);

  const resetState = await page.evaluate(async () => {
    const response = await fetch("/__mock/screen-reset", { method: "POST", cache: "no-store" });
    if (!response.ok) throw new Error(`screen reset returned HTTP ${response.status}`);
    return await response.json() as { output_sequence: string };
  });
  await expect.poll(async () => BigInt(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? "0")))
    .toBeGreaterThanOrEqual(BigInt(resetState.output_sequence));
  await page.evaluate(() => window.__tracerTestDouble?.seedPrompt());
  const wrapStartGeometry = await readGeometry();
  const wrapStart = { x: wrapStartGeometry.cursorX, y: wrapStartGeometry.cursorY };
  const longLength = Math.min(124, Math.max(90, wrapStartGeometry.columns - wrapStart.x + 12));
  expect(wrapStart.x + longLength).toBeGreaterThan(wrapStartGeometry.columns);
  const longLine = "M".repeat(longLength);
  const longExpected = advanceAscii(wrapStart, wrapStartGeometry.columns, longLength);
  await page.evaluate((value) => {
    for (const character of value) window.__tracerTestDouble?.injectInput(character);
  }, longLine);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe(longLine);
  const pendingLongGeometry = await readGeometry();
  expect(pendingLongGeometry.cursor).toBeDefined();
  expect(pendingLongGeometry.cursor!.x).toBeCloseTo(pendingLongGeometry.canvas.x + longExpected.cursor.x * pendingLongGeometry.cellWidth, 2);
  expect(pendingLongGeometry.cursor!.y).toBeCloseTo(pendingLongGeometry.canvas.y + longExpected.cursor.y * pendingLongGeometry.cellHeight, 2);
  const longCellBoxes = longExpected.cells.map((cell) => ({
    x: pendingLongGeometry.canvas.x + cell.x * pendingLongGeometry.cellWidth,
    y: pendingLongGeometry.canvas.y + cell.y * pendingLongGeometry.cellHeight,
    width: pendingLongGeometry.cellWidth,
    height: pendingLongGeometry.cellHeight,
  }));
  const pendingLongPng = await page.screenshot({ scale: "device" });
  const pendingLongPixels = await inspectPixels(page, pendingLongPng, pendingLongGeometry.cursor!, longCellBoxes);
  expect(pendingLongPixels.glyphPixels.every((count) => count > 0)).toBe(true);
  expectCursorPixelBounds(pendingLongPixels, pendingLongGeometry.cursor!, dpr);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
    .toBe("");
  await page.evaluate(() => window.__tracerTestDouble?.freezeCursorForTest());
  const confirmedLongGeometry = await readGeometry();
  expect(confirmedLongGeometry.cursorX).toBe(longExpected.cursor.x);
  expect(confirmedLongGeometry.cursorY).toBe(longExpected.cursor.y);
  const confirmedLongCursorBox = {
    x: confirmedLongGeometry.canvas.x + longExpected.cursor.x * confirmedLongGeometry.cellWidth,
    y: confirmedLongGeometry.canvas.y + longExpected.cursor.y * confirmedLongGeometry.cellHeight,
    width: Math.max(2, Math.floor(confirmedLongGeometry.cellWidth * 0.15)),
    height: confirmedLongGeometry.cellHeight,
  };
  const confirmedLongPng = await page.screenshot({ scale: "device" });
  const confirmedLongPixels = await inspectPixels(page, confirmedLongPng, confirmedLongCursorBox, longCellBoxes);
  expect(confirmedLongPixels.glyphPixels.every((count) => count > 0)).toBe(true);
  expect(confirmedLongGeometry.canvasPixel.slice(0, 3)).toEqual([0x3d, 0x63, 0xdd]);
});

test("predictive echo captures pending and confirmed glyphs across production viewports and themes", async ({ context }, testInfo) => {
  const captureText = "PredictiveEchoIsNowImmediate";
  const captures = [
    { name: "mobile", width: 393, height: 852, theme: "ink" },
    { name: "mobile", width: 393, height: 852, theme: "paper" },
    { name: "desktop", width: 1440, height: 900, theme: "ink" },
    { name: "desktop", width: 1440, height: 900, theme: "paper" },
  ] as const;

  for (const capture of captures) {
    await context.request.post("/__mock/reset");
    await context.request.post("/__mock/open-terminal");
    const capturePage = await context.newPage();
    try {
      await capturePage.setViewportSize({ width: capture.width, height: capture.height });
      await capturePage.goto(`/?mock=1&predict=1&theme=${capture.theme}`);
      await expect.poll(() => capturePage.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
      await expect.poll(() => capturePage.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.roundTripMs ?? 0), { timeout: 30_000 })
        .toBeGreaterThan(60);
      await expect.poll(() => capturePage.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.enabled ?? false))
        .toBe(true);

      await capturePage.evaluate(() => window.__tracerTestDouble?.seedPrompt());
      await expect.poll(() => capturePage.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""))
        .toContain("$");
      // Prepare the screenshot before input; font loading must not consume the pending frame.
      await capturePage.evaluate(() => document.fonts.ready);
      await context.request.post("/__mock/echo-mode", { data: { mode: "normal", delay_ms: 300 } });
      const injected = await capturePage.waitForFunction((value) => {
        const terminal = window.__tracerTestDouble;
        if (!terminal?.isConnected() || terminal.predictiveEcho()?.enabled !== true) return false;
        for (const character of value) terminal.injectInput(character);
        return true;
      }, captureText, { timeout: 30_000 });
      await injected.dispose();
      await expect.poll(() => capturePage.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
        .toBe(captureText);

      const pendingPath = testInfo.outputPath(`predictive-${capture.name}-${capture.theme}-pending.png`);
      await capturePage.screenshot({ path: pendingPath });
      await testInfo.attach(`predictive-${capture.name}-${capture.theme}-pending`, {
        path: pendingPath,
        contentType: "image/png",
      });
      // The canvas draws predicted text at the theme's prediction alpha; the cursor stays opaque.
      expect(await capturePage.locator(".terminal-text-overlay").evaluate((node) => getComputedStyle(node).visibility))
        .toBe("visible");

      await expect.poll(async () => {
        const state = await (await context.request.get("/__mock/state")).json() as { echoed_text: string };
        return state.echoed_text;
      }).toBe(captureText);
      await expect.poll(() => capturePage.evaluate(() => window.__tracerTestDouble?.screenText() ?? ""))
        .toContain(captureText);
      await expect.poll(() => capturePage.evaluate(() => window.__tracerTestDouble?.predictiveEcho()?.pendingText ?? ""))
        .toBe("");
      const confirmedPath = testInfo.outputPath(`predictive-${capture.name}-${capture.theme}-confirmed.png`);
      await capturePage.screenshot({ path: confirmedPath });
      await testInfo.attach(`predictive-${capture.name}-${capture.theme}-confirmed`, {
        path: confirmedPath,
        contentType: "image/png",
      });
    } finally {
      await capturePage.close();
    }
  }
});
