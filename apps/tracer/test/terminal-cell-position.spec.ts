/** Checks painted terminal glyphs and cursor edges against their device-pixel cells. */
import { cpus, hostname, loadavg, release, totalmem } from "node:os";
import { expect, test } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const baseURL = `http://localhost:${port}`;
const textPattern = "abcdefghijklmnopqrstuvwxyz0123456789";
const mixedLine = `${textPattern.repeat(5)}${textPattern.slice(0, 18)}MM`;
const unicodeLine = `${"a".repeat(195)}漢🙂e\u0301`;
const barRows = Array.from({ length: 50 }, () => `${"a".repeat(199)}|`);
const output = [mixedLine, "M", "|", ...barRows, unicodeLine, "e\u0301", "\u001b[?25h\u001b[54;201H"].join("\r\n");

for (const dpr of [1, 2, 3]) {
  test(`painted glyph cells and cursor align at DPR ${dpr}`, async ({ browser }, testInfo) => {
    test.setTimeout(180_000);
    console.log(`RENDER_ENV ${JSON.stringify({
      host: hostname(),
      kernel: release(),
      cpu: cpus()[0]?.model ?? "unknown",
      logicalCpus: cpus().length,
      totalRamBytes: totalmem(),
      loadAverage: loadavg(),
      dpr,
    })}`);

    const context = await browser.newContext({
      baseURL,
      viewport: { width: 2500, height: 1400 },
      deviceScaleFactor: dpr,
    });
    try {
      await context.request.post(`${baseURL}/__mock/reset`);
      await context.request.post(`${baseURL}/__mock/open-terminal`);
      const page = await context.newPage();
      const pageErrors: string[] = [];
      page.on("pageerror", (error) => pageErrors.push(error.message));
      await page.goto(`${baseURL}/?mock=1&theme=paper&bg=none`);
      await expect(page.getByText("TEST DOUBLE")).toBeVisible();
      await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 })
        .toBe(true)
        .catch(async (error: unknown) => {
          throw new Error(`${String(error)}; page errors=${pageErrors.join(" | ")}`);
        });

      const response = await context.request.post(`${baseURL}/__mock/text-output`, { data: { text: output } });
      expect(response.status()).toBe(200);
      const { bytes } = await response.json() as { bytes: number };
      await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence))
        .toBe(String(bytes));
      await page.evaluate(() => window.__tracerTestDouble?.freezeCursorForTest());
      await page.waitForTimeout(50);
      const screenshotPath = testInfo.outputPath(`terminal-cell-position-dpr${dpr}.png`);
      await page.screenshot({ path: screenshotPath });
      await testInfo.attach(`terminal-cell-position-dpr${dpr}`, { path: screenshotPath, contentType: "image/png" });

      const pixels = await page.evaluate(() => {
        const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
        const context = canvas?.getContext("2d", { willReadFrequently: true });
        const metrics = window.__tracerTestDouble?.rendererMetrics();
        if (!canvas || !context || !metrics) throw new Error("terminal canvas or renderer metrics are unavailable");

        const scaleX = canvas.width / (metrics.cols * metrics.cellWidth);
        const scaleY = canvas.height / (metrics.rows * metrics.cellHeight);
        const cellWidth = metrics.cellWidth * scaleX;
        const cellHeight = metrics.cellHeight * scaleY;
        const pixelAt = (x: number, y: number): readonly [number, number, number] => {
          const pixel = context.getImageData(Math.round(x), Math.round(y), 1, 1).data;
          return [pixel[0]!, pixel[1]!, pixel[2]!];
        };
        const background = pixelAt(3.5 * cellWidth, 1.5 * cellHeight);
        const backgroundLuma = (background[0] * 0.2126) + (background[1] * 0.7152) + (background[2] * 0.0722);
        const isInk = (red: number, green: number, blue: number): boolean =>
          (red * 0.2126) + (green * 0.7152) + (blue * 0.0722) < backgroundLuma - 80;
        const scan = (row: number, startColumn: number, endColumn: number, painted = false) => {
          const left = Math.max(0, Math.floor(startColumn * cellWidth));
          const right = Math.min(canvas.width, Math.ceil(endColumn * cellWidth));
          const top = Math.max(0, Math.floor(row * cellHeight));
          const bottom = Math.min(canvas.height, Math.ceil((row + 1) * cellHeight));
          const width = right - left;
          const height = bottom - top;
          const pixels = context.getImageData(left, top, width, height).data;
          let minX = Number.POSITIVE_INFINITY;
          let maxX = -1;
          let count = 0;
          for (let y = 0; y < height; y += 1) {
            for (let x = 0; x < width; x += 1) {
              const offset = (y * width + x) * 4;
              const red = pixels[offset]!;
              const green = pixels[offset + 1]!;
              const blue = pixels[offset + 2]!;
              const ink = painted
                ? Math.abs(red - background[0]) + Math.abs(green - background[1]) + Math.abs(blue - background[2]) > 45
                : isInk(red, green, blue);
              if (!ink) continue;
              minX = Math.min(minX, left + x);
              maxX = Math.max(maxX, left + x);
              count += 1;
            }
          }
          return { minX, maxX, count };
        };

        const expectedCursorLeft = Math.round(metrics.renderCursorX * cellWidth);
        const cursorTop = Math.floor(metrics.renderCursorY * cellHeight);
        const cursorHeight = Math.min(canvas.height - cursorTop, Math.ceil(cellHeight));
        const cursorWidth = Math.ceil(cellWidth);
        const cursorPixels = context.getImageData(expectedCursorLeft, cursorTop, cursorWidth, cursorHeight).data;
        const accent = [0x3d, 0x63, 0xdd];
        let cursorAccentMinX = Number.POSITIVE_INFINITY;
        let cursorAccentMaxX = -1;
        let cursorAccentPixels = 0;
        for (let y = 0; y < cursorHeight; y += 1) {
          for (let x = 0; x < cursorWidth; x += 1) {
            const offset = (y * cursorWidth + x) * 4;
            if (cursorPixels[offset] !== accent[0] || cursorPixels[offset + 1] !== accent[1] || cursorPixels[offset + 2] !== accent[2]) continue;
            cursorAccentPixels += 1;
            cursorAccentMinX = Math.min(cursorAccentMinX, expectedCursorLeft + x);
            cursorAccentMaxX = Math.max(cursorAccentMaxX, expectedCursorLeft + x);
          }
        }

        context.font = `400 ${metrics.fontSize}px "Geist Mono"`;
        const advance = context.measureText("M").width;
        return {
          dpr: window.devicePixelRatio,
          cols: metrics.cols,
          rows: metrics.rows,
          cursorX: metrics.cursorX,
          cursorY: metrics.cursorY,
          renderCursorX: metrics.renderCursorX,
          renderCursorY: metrics.renderCursorY,
          cellWidth: metrics.cellWidth,
          cellHeight: metrics.cellHeight,
          fontSize: metrics.fontSize,
          fontLoaded: document.fonts.check('14px "Geist Mono"'),
          letterSpacingSupported: typeof context.letterSpacing === "string",
          canvasWidth: canvas.width,
          canvasHeight: canvas.height,
          expectedCursorLeft,
          cursorAccentPixels,
          cursorAccentMinX,
          cursorAccentMaxX,
          expectedCursorAccentPixels: 2 * window.devicePixelRatio * metrics.cellHeight * scaleY,
          referenceM: scan(1, 0, 1),
          lastMixedM: scan(0, 199, 200),
          cjk: scan(53, 195, 197, true),
          emoji: scan(53, 197, 199, true),
          combiningMark: scan(53, 199, 200),
          unicodePresent: (window.__tracerTestDouble?.graphemeText() ?? "").includes("漢🙂e\u0301"),
          barRightEdges: Array.from({ length: 50 }, (_, index) => scan(index + 3, 199, 200).maxX),
          advance,
          expectedCellWidth: Math.round(advance * window.devicePixelRatio) / window.devicePixelRatio,
        };
      });
      console.log(`CELL_POSITION ${JSON.stringify(pixels)}`);

      if (dpr === 2) {
        const redraw = await page.evaluate(() => window.__tracerTestDouble?.benchmarkFullRedraw(30));
        expect(redraw).toHaveLength(30);
        const sortedRedraw = redraw!.slice().sort((left, right) => left - right);
        const outputBench = await page.evaluate(() => window.__tracerTestDouble?.benchmarkOutputAt10MBps());
        expect(outputBench).toBeDefined();
        console.log(`CELL_POSITION_BENCH ${JSON.stringify({
          redrawP50Ms: sortedRedraw[Math.floor((sortedRedraw.length - 1) * 0.5)],
          redrawP95Ms: sortedRedraw[Math.floor((sortedRedraw.length - 1) * 0.95)],
          ...outputBench,
          effectiveMegabytesPerSecond: outputBench!.bytes / outputBench!.elapsedMs / 1000,
        })}`);
      }

      expect(pixels.fontLoaded).toBe(true);
      expect(pixels.cols).toBeGreaterThanOrEqual(201);
      expect(pixels.rows).toBeGreaterThan(54);
      expect(pixels.cursorX).toBe(200);
      expect(pixels.cursorY).toBe(53);
      expect(pixels.renderCursorX).toBe(200);
      expect(pixels.renderCursorY).toBe(53);
      expect(pixels.letterSpacingSupported).toBe(true);
      expect(pixels.unicodePresent).toBe(true);
      expect(Math.abs(pixels.cellWidth - pixels.expectedCellWidth)).toBeLessThanOrEqual(1 / dpr + 0.001);
      expect(pixels.cursorAccentPixels).toBe(pixels.expectedCursorAccentPixels);
      expect(pixels.cursorAccentMinX).toBe(pixels.expectedCursorLeft);
      expect(pixels.cursorAccentMaxX).toBe(pixels.expectedCursorLeft + 2 * dpr - 1);
      expect(pixels.lastMixedM.count).toBeGreaterThan(0);
      expect(pixels.lastMixedM.maxX).toBe(pixels.expectedCursorLeft - 1);
      expect(pixels.cjk.count).toBeGreaterThan(0);
      expect(pixels.emoji.count).toBeGreaterThan(0);
      expect(pixels.combiningMark.count).toBeGreaterThan(0);
      expect(pixels.combiningMark.maxX).toBeLessThan(pixels.expectedCursorLeft);
      expect(pixels.barRightEdges.every((edge) => edge === pixels.expectedCursorLeft - 1)).toBe(true);
      expect(Math.max(...pixels.barRightEdges) - Math.min(...pixels.barRightEdges)).toBeLessThanOrEqual(0.5);
    } finally {
      await context.close();
    }
  });
}
