/**
 * Proves each font's registry weights reach the screen (D175, #90): the UI body, label and
 * title roles read the weight tokens, the terminal canvas draws regular text at the font's
 * terminal weight, and bold stays clearly heavier than regular.
 */
import { expect, test } from "playwright/test";
import { FONTS, uiWeights } from "../../../packages/ui/src/fonts";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const baseURL = `http://localhost:${port}`;
const row = "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH";

for (const font of FONTS) {
  for (const dpr of [1, 2]) {
    test(`${font.label} draws terminal and UI text at its registry weights at DPR ${dpr}`, async ({ browser }) => {
      test.setTimeout(120_000);
      const context = await browser.newContext({ baseURL, viewport: { width: 1280, height: 800 }, deviceScaleFactor: dpr });
      try {
        await context.request.post("/__mock/reset");
        await context.request.post("/__mock/open-terminal");
        const page = await context.newPage();
        await page.goto(`/?mock=1&theme=paper&bg=none&font=${font.id}`);
        await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
        // Regular row, then the same row in bold, so the two ink totals compare like for like.
        const text = `${row}\r\n\u001b[1m${row}\u001b[0m\r\n`;
        const { bytes } = await (await context.request.post("/__mock/text-output", { data: { text } })).json() as { bytes: number };
        await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence)).toBe(String(bytes));
        await page.evaluate(() => window.__tracerTestDouble?.freezeCursorForTest());
        await page.waitForTimeout(100);
        const result = await page.evaluate(({ family }) => {
          const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas")!;
          const context = canvas.getContext("2d", { willReadFrequently: true })!;
          const metrics = window.__tracerTestDouble!.rendererMetrics()!;
          const scale = canvas.height / (metrics.rows * metrics.cellHeight);
          const cellHeight = metrics.cellHeight * scale;
          const cellWidth = metrics.cellWidth * scale;
          const width = Math.round(40 * cellWidth);
          const background = context.getImageData(Math.round(60 * cellWidth), 2, 1, 1).data;
          const ink = (rowIndex: number): number => {
            const data = context.getImageData(0, Math.round(rowIndex * cellHeight), width, Math.round(cellHeight)).data;
            let sum = 0;
            for (let i = 0; i < data.length; i += 4) sum += Math.abs(data[i]! - background[0]!) + Math.abs(data[i + 1]! - background[1]!) + Math.abs(data[i + 2]! - background[2]!);
            return sum / 3 / 255;
          };
          const regularInk = ink(0);
          const boldInk = ink(1);
          const loaded = [...document.fonts].some((face) => face.family === family && face.status === "loaded");
          return {
            loaded,
            canvasFont: context.font,
            regularInk,
            boldInk,
            ratio: boldInk / regularInk,
            rendererFamily: window.__tracerTestDouble!.rendererMetrics()!.fontFamily,
            rootFont: getComputedStyle(document.documentElement).fontFamily,
            tokens: ["--fw-secondary", "--fw-body", "--fw-label", "--fw-title"].map((name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim()),
          };
        }, { family: font.family });
        console.log(`FONT_WEIGHT ${JSON.stringify({ font: font.id, dpr, ...result })}`);
        const weights = uiWeights(font);
        expect(result.loaded).toBe(true);
        expect(result.rootFont).toContain(font.family);
        expect(result.rendererFamily).toContain(font.family);
        expect(result.tokens).toEqual([weights.secondary, weights.body, weights.label, weights.title].map(String));
        // The canvas context holds the normalised font string of the last text it drew.
        expect(result.canvasFont).toContain(`${font.terminalWeight}`);
        expect(result.regularInk).toBeGreaterThan(0);
        // Bold is clearly bolder than regular: at least 12 % more ink on the same glyphs.
        expect(result.ratio).toBeGreaterThan(1.12);
      } finally {
        await context.close();
      }
    });
  }
}
