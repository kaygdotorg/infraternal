/** Captures the terminal cell geometry and box-drawing joins at real browser DPRs. */
import { cpus, hostname, loadavg, release, totalmem } from "node:os";
import { expect, test } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const baseURL = `http://localhost:${port}`;
const output = [
  "kayg@debian:~$ sudo apt update",
  "Hit:1 http://deb.debian.org/debian bookworm InRelease",
  "Get:2 http://security.debian.org/debian-security bookworm-security InRelease [48.0 kB]",
  "Get:3 http://deb.debian.org/debian bookworm-updates InRelease [55.4 kB]",
  "Fetched 103 kB in 1s (118 kB/s)",
  "Reading package lists... Done",
  "Building dependency tree... Done",
  "Reading state information... Done",
  "All packages are up to date.",
  "kayg@debian:~$ htop",
  "  1 [██████████░░░░░░░░░░░░] 38.4%   5 [███░░░░░░░░░░░░░░░░░] 14.0%",
  "  2 [█████░░░░░░░░░░░░░░░] 18.1%   6 [██░░░░░░░░░░░░░░░░░░]  9.4%",
  "Mem[██████████████░░░░░░░░░░░░░░] 6.81G/31.3G",
  "Swp[░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 0K/0K",
  "  PID USER     PRI  NI    VIRT    RES    S  CPU% MEM%   TIME+  Command",
  " 1337 kayg      20   0  1840M   92M    S   2.4  0.3   0:03.12 zsh",
  " 2048 kayg      20   0  2136M  128M    S   1.1  0.4   0:01.08 infraternal",
  "┌──────────┬─────────┐",
  "│vim split │ apt log │",
  "│M g p q   │ Get: 1.2│",
  "│left pane │ right   │",
  "├──────────┼─────────┤",
  "│box rows  │progress │",
  "│join here │░░░███░░░│",
  "└──────────┴─────────┘",
  "kayg@monitor01  ~/Developer/infraternal  fix-cell-metrics ",
  "",
].join("\r\n");
const boxStartRow = 17;

for (const scenario of [
  { name: "desktop-dpr2", width: 1440, height: 900, dpr: 2 },
  { name: "mobile-dpr3", width: 393, height: 852, dpr: 3 },
  { name: "desktop-dpr1", width: 1440, height: 900, dpr: 1 },
]) {
  test(`Geist cell metrics and box joins at DPR ${scenario.dpr}`, async ({ browser }, testInfo) => {
    test.setTimeout(180_000);
    console.log(`RENDER_ENV ${JSON.stringify({
      host: hostname(),
      kernel: release(),
      cpu: cpus()[0]?.model ?? "unknown",
      logicalCpus: cpus().length,
      totalRamBytes: totalmem(),
      loadAverage: loadavg(),
      scenario: scenario.name,
    })}`);
    const context = await browser.newContext({
      viewport: { width: scenario.width, height: scenario.height },
      deviceScaleFactor: scenario.dpr,
      ...(scenario.name === "mobile-dpr3" ? { isMobile: true, hasTouch: true } : {}),
    });
    try {
      await context.request.post(`${baseURL}/__mock/reset`);
      await context.request.post(`${baseURL}/__mock/open-terminal`);
      const page = await context.newPage();
      const pageErrors: string[] = [];
      page.on("pageerror", (error) => pageErrors.push(error.message));
      await page.goto(`${baseURL}/?mock=1`);
      await expect(page.getByText("TEST DOUBLE")).toBeVisible();
      await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 15_000 })
        .toBe(true)
        .catch(async (error: unknown) => {
          const state = await page.evaluate(() => ({
            status: document.querySelector<HTMLElement>("#connection-status")?.textContent,
            connected: window.__tracerTestDouble?.isConnected(),
          }));
          throw new Error(`${String(error)}; renderer state=${JSON.stringify(state)}; page errors=${pageErrors.join(" | ")}`);
        });
      const fixture = await context.request.post(`${baseURL}/__mock/text-output`, { data: { text: output } });
      expect(fixture.status()).toBe(200);
      const { bytes } = await fixture.json() as { bytes: number };
      await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.outputSequence))
        .toBe(String(bytes));
      await page.waitForTimeout(100);

      const screenshotPath = testInfo.outputPath(`terminal-${scenario.name}.png`);
      await page.screenshot({ path: screenshotPath });
      await testInfo.attach(`terminal-${scenario.name}`, { path: screenshotPath, contentType: "image/png" });

      const measured = await page.evaluate((startRow) => {
        const metrics = window.__tracerTestDouble?.rendererMetrics();
        const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
        const context = canvas?.getContext("2d");
        if (!metrics || !canvas || !context) throw new Error("terminal renderer canvas or metrics are unavailable");
        const measurementCanvas = document.createElement("canvas");
        const measurementContext = measurementCanvas.getContext("2d");
        if (!measurementContext) throw new Error("font metric measurement canvas is unavailable");
        const fontContext = measurementContext as CanvasRenderingContext2D & { letterSpacing?: string };
        if (typeof fontContext.letterSpacing === "string") fontContext.letterSpacing = "0px";
        measurementContext.font = `400 ${metrics.fontSize}px "Geist Mono"`;
        const font = measurementContext.measureText("M");
        const dpr = window.devicePixelRatio;
        const x = Math.round(metrics.cellWidth * 0.5 * dpr);
        const seams = [startRow + 2, startRow + 3, startRow + 6].map((row) => {
          const boundary = Math.round(row * metrics.cellHeight * dpr);
          const pixels = context.getImageData(Math.max(0, x - 1), Math.max(0, boundary - 1), 3, 3).data;
          let ink = 0;
          for (let offset = 0; offset < pixels.length; offset += 4) {
            if (pixels[offset]! + pixels[offset + 1]! + pixels[offset + 2]! > 100) ink += 1;
          }
          return ink;
        });
        return {
          dpr,
          cols: metrics.cols,
          rows: metrics.rows,
          fontSize: metrics.fontSize,
          cellWidth: metrics.cellWidth,
          cellHeight: metrics.cellHeight,
          rendererNaturalAdvance: metrics.naturalCellWidth,
          widthAdvance: font.width,
          fontAscent: font.fontBoundingBoxAscent,
          fontDescent: font.fontBoundingBoxDescent,
          expectedCellWidth: Math.round(metrics.naturalCellWidth * dpr) / dpr,
          expectedCellHeight: Math.round((font.fontBoundingBoxAscent + font.fontBoundingBoxDescent) * dpr) / dpr,
          heightRatio: metrics.cellHeight / metrics.fontSize,
          canvasWidth: canvas.width,
          canvasHeight: canvas.height,
          expectedCanvasWidth: Math.round(metrics.cols * metrics.cellWidth * dpr),
          expectedCanvasHeight: Math.round(metrics.rows * metrics.cellHeight * dpr),
          boxSeamInk: seams,
          fontLoaded: document.fonts.check(`14px "Geist Mono"`),
        };
      }, boxStartRow);
      console.log(`CELL_METRICS ${JSON.stringify(measured)}`);

      const screenText = await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "");
      if (scenario.dpr !== 1) {
        const redraw = await page.evaluate(() => window.__tracerTestDouble?.benchmarkFullRedraw(30));
        expect(redraw).toHaveLength(30);
        const sortedRedraw = redraw!.slice().sort((left, right) => left - right);
        const output = await page.evaluate(() => window.__tracerTestDouble?.benchmarkOutputAt10MBps());
        expect(output).toBeDefined();
        console.log(`RENDER_BENCH ${scenario.name} ${JSON.stringify({
          redrawP50Ms: sortedRedraw[Math.floor((sortedRedraw.length - 1) * 0.5)],
          redrawP95Ms: sortedRedraw[Math.floor((sortedRedraw.length - 1) * 0.95)],
          ...output,
          effectiveMegabytesPerSecond: output!.bytes / output!.elapsedMs / 1000,
        })}`);
      }

      expect(screenText).toContain("┌──────────┬─────────┐");
      expect(screenText).toContain("fix-cell-metrics");
      expect(measured.fontLoaded).toBe(true);
      expect(measured.heightRatio).toBeGreaterThanOrEqual(1.15);
      // Chromium reports an integer 13px ascent + 4px descent on touch devices: 17/13 is 1.308.
      expect(measured.heightRatio).toBeLessThanOrEqual(scenario.name === "mobile-dpr3" ? 1.31 : 1.3);
      expect(Math.abs(measured.cellWidth - measured.expectedCellWidth)).toBeLessThan(0.000001);
      expect(Math.abs(measured.cellHeight - measured.expectedCellHeight)).toBeLessThan(0.000001);
      expect(Math.abs(measured.cellWidth - measured.rendererNaturalAdvance)).toBeLessThanOrEqual(1 / scenario.dpr + 0.001);
      expect(measured.canvasWidth).toBe(measured.expectedCanvasWidth);
      expect(measured.canvasHeight).toBe(measured.expectedCanvasHeight);
      expect(measured.boxSeamInk.every((pixels) => pixels > 0), `box-drawing seam pixels: ${measured.boxSeamInk}`).toBe(true);
    } finally {
      await context.close();
    }
  });
}
