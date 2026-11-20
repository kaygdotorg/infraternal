/**
 * Proves every curated font keeps the terminal exact (D87, D175, #90): the cursor sits on its cell
 * after an 86-cell line at DPR 1 and 2 (3 for the default), prompt glyphs draw from the shared
 * symbols face, redraw time is measured, and terminal ligatures stay off for every font.
 */
import { cpus, loadavg } from "node:os";
import { expect, test } from "playwright/test";
import { DEFAULT_FONT_ID, FONTS } from "../../../packages/ui/src/fonts";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const baseURL = `http://localhost:${port}`;
// 86 cells: ligature-prone operators, then prompt-like text of mixed glyph widths (letters with wide
// tails, digits, punctuation), then a final wide "M" so the cursor must sit right after it. A font
// whose real advance differs from the measured cell advance would drift along this line.
const line86 = `${"=> -> != === <= >= dev@host:~/infraternal$ 0123456789 ".repeat(3)}`.slice(0, 85) + "M";

for (const font of FONTS) for (const dpr of font.id === DEFAULT_FONT_ID ? [1, 2, 3] : [1, 2]) {
  test(`${font.label}: 86-character line keeps the cursor on its cell at DPR ${dpr}`, async ({ browser }, testInfo) => {
    test.setTimeout(120_000);
    expect(line86).toHaveLength(86);
    const context = await browser.newContext({ baseURL, viewport: { width: 1920, height: 1080 }, deviceScaleFactor: dpr });
    try {
      await context.request.post("/__mock/reset");
      await context.request.post("/__mock/open-terminal");
      const page = await context.newPage();
      await page.goto(`/?mock=1&theme=paper&bg=none&font=${font.id}`);
      await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
      const response = await context.request.post("/__mock/text-output", { data: { text: line86 } });
      const { bytes } = await response.json() as { bytes: number };
      await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence)).toBe(String(bytes));
      await page.evaluate(() => window.__tracerTestDouble?.freezeCursorForTest());
      await page.waitForTimeout(50);
      await page.screenshot({ path: testInfo.outputPath(`line86-${font.id}-dpr${dpr}.png`) });

      const result = await page.evaluate((family) => {
        const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas")!;
        const context = canvas.getContext("2d", { willReadFrequently: true })!;
        const metrics = window.__tracerTestDouble!.rendererMetrics()!;
        const scaleX = canvas.width / (metrics.cols * metrics.cellWidth);
        const cellWidth = metrics.cellWidth * scaleX;
        const cellHeight = metrics.cellHeight * (canvas.height / (metrics.rows * metrics.cellHeight));
        const cursorLeft = Math.round(metrics.renderCursorX * cellWidth);
        // Rightmost glyph ink on row 0 (the cursor bar is the product's accent colour, not text ink).
        const row = context.getImageData(0, 0, Math.ceil(cursorLeft), Math.ceil(cellHeight)).data;
        const accent = [0x3d, 0x63, 0xdd];
        let lastInk = -1;
        for (let x = 0; x < cursorLeft; x += 1) for (let y = 0; y < Math.ceil(cellHeight); y += 1) {
          const o = (y * cursorLeft + x) * 4;
          if (row[o]! + row[o + 1]! + row[o + 2]! < 3 * 255 - 240) lastInk = Math.max(lastInk, x);
        }
        // Nothing but the bar may be inked at or after the cursor: a font whose glyphs advance by more
        // than its cells (browser rounding per glyph) pushes the end of the line past the cursor, which
        // the scan above cannot see because it stops at the cursor.
        const afterStart = cursorLeft + Math.ceil(2 * devicePixelRatio);
        const after = context.getImageData(afterStart, 0, Math.ceil(cellWidth * 3), Math.ceil(cellHeight)).data;
        let inkAfter = 0;
        for (let i = 0; i < after.length; i += 4) {
          const accentPixel = after[i] === accent[0] && after[i + 1] === accent[1] && after[i + 2] === accent[2];
          if (!accentPixel && after[i]! + after[i + 1]! + after[i + 2]! < 3 * 255 - 240) inkAfter += 1;
        }
        const bar = context.getImageData(cursorLeft, 2, Math.ceil(cellWidth), Math.ceil(cellHeight) - 4).data;
        let barMin = Infinity;
        for (let i = 0; i < bar.length; i += 4) {
          if (bar[i] === accent[0] && bar[i + 1] === accent[1] && bar[i + 2] === accent[2]) barMin = Math.min(barMin, (i / 4) % Math.ceil(cellWidth));
        }
        // The measurements are only meaningful if Maple itself (not a fallback) painted the canvas.
        // The product writes every family quoted (`fontStack`), but the browser serializes a computed `font-family` without quotes when the name is
        // a plain identifier (`Iosevka, "Nerd Symbols"`, but `"Victor Mono"`), so the quotes are dropped before comparing.
        const first = (stack: string): string => stack.split(",")[0]!.trim().replaceAll('"', "");
        const mapleLoaded = [...document.fonts].some((face) => face.family.replaceAll('"', "") === family && face.status === "loaded" && face.style === "normal")
          && first(window.__tracerTestDouble!.rendererMetrics()!.fontFamily) === family
          && first(getComputedStyle(document.documentElement).fontFamily) === family;
        return { mapleLoaded, cursorX: metrics.cursorX, renderCursorX: metrics.renderCursorX, cellWidth: metrics.cellWidth, natural: metrics.naturalCellWidth, cursorLeft, lastInk, inkAfter, barMin, dpr: devicePixelRatio, cellWidthPx: cellWidth };
      }, font.family);
      const bench = await page.evaluate(() => window.__tracerTestDouble?.benchmarkFullRedraw(30));
      const sorted = bench!.slice().sort((a, b) => a - b);
      console.log(`FONT_BENCH ${JSON.stringify({ font: font.id, dpr, redrawP50Ms: sorted[14], redrawP95Ms: sorted[28], load: loadavg().map((n) => +n.toFixed(2)), cores: cpus().length })}`);
      console.log(`LINE86 ${JSON.stringify({ font: font.id, ...result })}`);
      expect(result.mapleLoaded).toBe(true);
      expect(result.cursorX).toBe(86);
      expect(result.renderCursorX).toBe(86);
      // The cursor bar starts exactly at the cell edge, and the last glyph's ink ends inside the cell before it.
      expect(result.inkAfter).toBe(0);
      expect(result.barMin).toBe(0);
      expect(result.lastInk).toBeLessThan(result.cursorLeft);
      expect(result.lastInk).toBeGreaterThanOrEqual(result.cursorLeft - Math.ceil(result.cellWidthPx));
    } finally {
      await context.close();
    }
  });
}

test("powerline and icon glyphs draw as real glyphs, not missing-glyph boxes", async ({ browser }, testInfo) => {
  test.setTimeout(120_000);
  const context = await browser.newContext({ baseURL, viewport: { width: 1200, height: 700 }, deviceScaleFactor: 2 });
  try {
    await context.request.post("/__mock/reset");
    await context.request.post("/__mock/open-terminal");
    const page = await context.newPage();
    await page.goto("/?mock=1&theme=ink&bg=none");
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
    // Cell 0 is the powerline arrow, which fills the cell height; a missing-glyph box is far smaller.
    const text = "\u001b[30;44m\u001b[0m    main\r\n";
    const { bytes } = await (await context.request.post("/__mock/text-output", { data: { text } })).json() as { bytes: number };
    await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence)).toBe(String(bytes));
    // The symbol face loads on demand after the first private-use code point arrives.
    await expect.poll(() => page.evaluate(() => document.fonts.check('14px "Maple Mono NF"', "")), { timeout: 10_000 }).toBe(true);
    await page.waitForTimeout(400);
    await page.screenshot({ path: testInfo.outputPath("powerline.png") });
    const ink = await page.evaluate(() => {
      const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas")!;
      const context = canvas.getContext("2d", { willReadFrequently: true })!;
      const metrics = window.__tracerTestDouble!.rendererMetrics()!;
      const scale = canvas.width / (metrics.cols * metrics.cellWidth);
      const cellWidth = metrics.cellWidth * scale;
      const cellHeight = metrics.cellHeight * scale;
      const background = context.getImageData(Math.round(cellWidth * 20), 2, 1, 1).data;
      const heightOf = (column: number): number => {
        const left = Math.round(column * cellWidth);
        const data = context.getImageData(left, 0, Math.ceil(cellWidth), Math.ceil(cellHeight)).data;
        let top = Infinity;
        let bottom = -1;
        for (let y = 0; y < Math.ceil(cellHeight); y += 1) for (let x = 0; x < Math.ceil(cellWidth); x += 1) {
          const o = (y * Math.ceil(cellWidth) + x) * 4;
          if (Math.abs(data[o]! - background[0]!) + Math.abs(data[o + 1]! - background[1]!) + Math.abs(data[o + 2]! - background[2]!) > 60) { top = Math.min(top, y); bottom = Math.max(bottom, y); }
        }
        return bottom < 0 ? 0 : (bottom - top + 1) / cellHeight;
      };
      return { arrow: heightOf(0), branch: heightOf(2), house: heightOf(4), node: heightOf(6) };
    });
    console.log(`POWERLINE ${JSON.stringify(ink)}`);
    expect(ink.arrow).toBeGreaterThan(0.85);
    expect(ink.branch).toBeGreaterThan(0.4);
    expect(ink.house).toBeGreaterThan(0.4);
    expect(ink.node).toBeGreaterThan(0.4);
  } finally {
    await context.close();
  }
});

for (const font of FONTS) {
  test(`${font.label}: terminal ligatures stay off, optimizeSpeed makes that deterministic`, async ({ page }) => {
    const file = font.faces[0]!.file;
    await page.goto(`${baseURL}/health`);
    await page.setContent(`<style>@font-face{font-family:Probe;font-weight:400 700;src:url(${baseURL}/fonts/${file})}</style><canvas id=c></canvas>`);
    await page.evaluate(() => document.fonts.load("14px Probe"));
    const diffs = await page.evaluate(() => {
      const canvas = document.getElementById("c") as HTMLCanvasElement;
      canvas.width = 400; canvas.height = 40;
      const context = canvas.getContext("2d", { willReadFrequently: true })!;
      context.font = "14px Probe";
      const text = "=> -> != === <= >= www";
      const draw = (rendering: CanvasTextRendering, spacing: string): Uint8ClampedArray => {
        context.clearRect(0, 0, 400, 40);
        context.textRendering = rendering;
        context.letterSpacing = spacing;
        context.fillText(text, 0, 20);
        return context.getImageData(0, 0, 400, 40).data.slice();
      };
      const differs = (a: Uint8ClampedArray, b: Uint8ClampedArray): number => { let n = 0; for (let i = 3; i < a.length; i += 4) if (Math.abs(a[i]! - b[i]!) > 40) n += 1; return n; };
      const natural = draw("auto", "0px");
      const spaced = draw("auto", "0.001px");
      const speed = draw("optimizeSpeed", "0px");
      return { autoVsSpaced: differs(natural, spaced), speedVsSpaced: differs(speed, spaced) };
    });
    console.log(`LIGATURE_PROBE ${JSON.stringify({ font: font.id, ...diffs })}`);
    // optimizeSpeed draws exactly what spaced text draws for every font, so no display can show a
    // ligature the next one does not. (Fonts without code ligatures show no difference at all.)
    expect(diffs.speedVsSpaced).toBe(0);
  });
}
