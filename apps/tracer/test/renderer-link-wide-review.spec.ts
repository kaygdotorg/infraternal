/** Verifies link underlines cover the occupied cells of wide terminal glyphs. */
import { expect, test } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const baseURL = `http://localhost:${port}`;
const target = `https://unicode.example.test/${"a".repeat(150)}漢`;
type UnderlinePixels = { dpr: number; endpoint: { x: number; y: number }; cellPixelWidth: number; minCoveredPixels: number; leadAccentPixels: number; continuationAccentPixels: number };

test("revealed underline covers both cells of a wide final URL glyph at DPR 1, 2, and 3", async ({ browser }) => {
  const results: UnderlinePixels[] = [];
  for (const dpr of [1, 2, 3]) {
    const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 }, deviceScaleFactor: dpr });
    try {
      const page = await context.newPage();
      const reset = await context.request.post(`${baseURL}/__mock/reset`);
      const opened = await context.request.post(`${baseURL}/__mock/open-terminal`);
      expect([reset.status(), opened.status()]).toEqual([200, 200]);
      await page.goto(`${baseURL}/?mock=1&proto=product&bg=none&fixture=none&theme=ink`);
      await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
      const output = await context.request.post(`${baseURL}/__mock/live-query-output`, {
        data: { text: `\u001b[2J\u001b[H${target}\r\n\u001b[?25l` },
      });
      expect(output.ok()).toBe(true);
      await expect.poll(() => page.evaluate((expected) => window.__tracerProductTestDouble?.terminalLinks().some((link) => link.target === expected) ?? false, target), { timeout: 30_000 }).toBe(true);
      await page.evaluate(() => document.fonts.ready);
      const point = await page.evaluate(() => {
        const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
        const metrics = window.__tracerProductTestDouble?.rendererMetrics();
        if (!canvas || !metrics) throw new Error("terminal canvas is unavailable");
        const rect = canvas.getBoundingClientRect();
        return { x: rect.left + metrics.cellWidth * 2, y: rect.top + metrics.cellHeight / 2 };
      });
      await page.mouse.move(point.x, point.y);
      await page.waitForTimeout(100);
      const pixels = await page.evaluate((expected) => {
        type Link = { target: string; range: { start: { x: number; y: number }; end: { x: number; y: number } } };
        const links = window.__tracerProductTestDouble?.terminalLinks() as unknown as readonly Link[] | undefined;
        const link = links?.find((candidate) => candidate.target === expected);
        const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
        const metrics = window.__tracerProductTestDouble?.rendererMetrics();
        const context = canvas?.getContext("2d");
        const accent = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim();
        const color = /^#([\da-f]{6})$/i.exec(accent)?.[1];
        const background = metrics?.terminalColors?.background;
        if (!link || !canvas || !metrics || !context || !color || !background) throw new Error("wide link pixels are unavailable");
        const rect = canvas.getBoundingClientRect();
        const scaleX = canvas.width / rect.width;
        const scaleY = canvas.height / rect.height;
        const row = link.range.end.y - metrics.scrollbackRows;
        const leadColumn = link.range.end.x;
        const columns = [leadColumn, leadColumn + 1];
        const red = Number.parseInt(color.slice(0, 2), 16);
        const green = Number.parseInt(color.slice(2, 4), 16);
        const blue = Number.parseInt(color.slice(4, 6), 16);
        const accentVector = [red - background.r, green - background.g, blue - background.b];
        const vectorLength = accentVector.reduce((sum, channel) => sum + channel * channel, 0);
        const countAccentPixels = (column: number): number => {
          const left = Math.max(0, Math.floor(column * metrics.cellWidth * scaleX));
          const right = Math.min(canvas.width, Math.ceil((column + 1) * metrics.cellWidth * scaleX));
          const top = Math.max(0, Math.floor(row * metrics.cellHeight * scaleY));
          const bottom = Math.min(canvas.height, Math.ceil((row + 1) * metrics.cellHeight * scaleY));
          const underlineTop = Math.max(top, bottom - Math.ceil(4 * scaleY));
          const image = context.getImageData(left, underlineTop, right - left, bottom - underlineTop).data;
          let count = 0;
          for (let offset = 0; offset < image.length; offset += 4) {
            if (image[offset + 3]! === 0) continue;
            const pixelVector = [image[offset]! - background.r, image[offset + 1]! - background.g, image[offset + 2]! - background.b];
            const coverage = pixelVector.reduce((sum, channel, index) => sum + channel * accentVector[index]!, 0) / vectorLength;
          const residual = Math.sqrt(pixelVector.reduce((sum, channel, index) => sum + (channel - coverage * accentVector[index]!) ** 2, 0));
            if (coverage >= 0.25 && coverage <= 1.05 && residual <= 4) count += 1;
          }
          return count;
        };
        return {
          dpr: window.devicePixelRatio,
          endpoint: link.range.end,
          cellPixelWidth: metrics.cellWidth * scaleX,
          minCoveredPixels: Math.ceil(metrics.cellWidth * scaleX * 0.5),
          leadAccentPixels: countAccentPixels(columns[0]!),
          continuationAccentPixels: countAccentPixels(columns[1]!),
        };
      }, target);
      results.push(pixels);
    } finally {
      await context.close();
    }
  }
  console.log(`WIDE_LINK_UNDERLINE ${JSON.stringify(results)}`);
  for (const pixels of results) {
    expect(pixels.leadAccentPixels).toBeGreaterThanOrEqual(pixels.minCoveredPixels);
    expect(pixels.continuationAccentPixels).toBeGreaterThanOrEqual(pixels.minCoveredPixels);
  }
});
