/** Checks every curated terminal palette from painted pixels on the production build. */
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test, type Page, type TestInfo } from "playwright/test";
import { THEMES, type Theme } from "../../../packages/ui/src/themes";

type TerminalPixels = {
  background: string;
  foreground: string;
  ansi: string[];
};

const THEME_IDS = Object.keys(THEMES);

async function waitForTerminal(page: Page): Promise<void> {
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
}

function expectedPixels(theme: Theme): TerminalPixels {
  return {
    background: theme.bg.toLowerCase(),
    foreground: theme.fg.toLowerCase(),
    ansi: [...theme.ansi, ...theme.bright].map((color) => color.toLowerCase()),
  };
}

async function readTerminalPixels(page: Page, theme: Theme): Promise<TerminalPixels> {
  return page.evaluate(({ ansi: themeAnsi, background: themeBackground }) => {
    const host = document.querySelector<HTMLElement>("#terminal-host");
    const canvas = host?.querySelector<HTMLCanvasElement>("canvas");
    const metrics = window.__tracerTestDouble?.rendererMetrics();
    const context = canvas?.getContext("2d", { willReadFrequently: true });
    if (!canvas || !context || !metrics) throw new Error("terminal canvas or renderer metrics are unavailable");

    const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
    const toHex = (r: number, g: number, b: number): string => `#${[r, g, b].map((value) => value.toString(16).padStart(2, "0")).join("")}`;
    const pixelAt = (x: number, y: number): string => {
      const offset = (Math.min(canvas.height - 1, Math.max(0, y)) * canvas.width + Math.min(canvas.width - 1, Math.max(0, x))) * 4;
      return toHex(pixels.data[offset]!, pixels.data[offset + 1]!, pixels.data[offset + 2]!);
    };
    const scaleX = canvas.width / (metrics.cols * metrics.cellWidth);
    const scaleY = canvas.height / (metrics.rows * metrics.cellHeight);
    const glyphColor = (column: number, row: number, background: string): string => {
      const left = Math.floor(column * metrics.cellWidth * scaleX);
      const right = Math.min(canvas.width, Math.ceil((column + 1) * metrics.cellWidth * scaleX));
      const top = Math.floor(row * metrics.cellHeight * scaleY);
      const bottom = Math.min(canvas.height, Math.ceil((row + 1) * metrics.cellHeight * scaleY));
      const colors = new Map<string, number>();
      for (let y = top; y < bottom; y += 1) {
        for (let x = left; x < right; x += 1) {
          const color = pixelAt(x, y);
          if (color !== background) colors.set(color, (colors.get(color) ?? 0) + 1);
        }
      }
      const dominant = [...colors].sort((leftColor, rightColor) => rightColor[1] - leftColor[1])[0];
      // When an ANSI entry equals the background (Gruvbox black), the glyph is
      // correctly invisible; background is also the retry value for an empty cell.
      if (!dominant || dominant[1] < 2) return background;
      return dominant[0];
    };

    const background = pixelAt(canvas.width - 1, canvas.height - 1);
    const defaultRow = metrics.rows - 3;
    const regularRow = metrics.rows - 2;
    const brightRow = metrics.rows - 1;
    return {
      background,
      foreground: glyphColor(9, defaultRow, background),
      ansi: [
        ...Array.from({ length: 8 }, (_, index) => glyphColor(index * 2, regularRow, background)),
        ...Array.from({ length: 8 }, (_, index) => glyphColor(index * 2, brightRow, background)),
      ].map((color, index) => themeAnsi[index] === themeBackground ? background : color),
    };
  }, {
    ansi: [...theme.ansi, ...theme.bright].map((color) => color.toLowerCase()),
    background: theme.bg.toLowerCase(),
  });
}

async function readTerminalState(page: Page) {
  return page.evaluate(() => {
    const metrics = window.__tracerTestDouble?.rendererMetrics();
    if (!metrics) throw new Error("terminal renderer metrics are unavailable");
    return {
      cursorX: metrics.cursorX,
      // The active screen can gain or lose rows when the palette closes; the
      // absolute cursor row stays stable across that grid reflow.
      cursorRow: metrics.cursorY + metrics.scrollbackRows,
      // Ghostty stores scroll offsets as fractional rows while wheel motion is
      // in flight; rebuilding can settle a subpixel remainder to the nearest
      // row without moving the user's readable terminal position.
      viewportY: Math.round(metrics.viewportY * 100) / 100,
      screenText: window.__tracerTestDouble?.screenText() ?? "",
    };
  });
}

async function readHeldCanvas(page: Page): Promise<{ background: string; zIndex: string }> {
  return page.locator('#terminal-host canvas[data-theme-hold]').evaluate((canvas) => {
    const terminalCanvas = canvas as HTMLCanvasElement;
    const context = terminalCanvas.getContext("2d");
    if (!context) throw new Error("held terminal canvas has no 2D context");
    const pixel = context.getImageData(terminalCanvas.width - 1, terminalCanvas.height - 1, 1, 1).data;
    return {
      background: `#${[pixel[0]!, pixel[1]!, pixel[2]!].map((value) => value.toString(16).padStart(2, "0")).join("")}`,
      zIndex: getComputedStyle(terminalCanvas).zIndex,
    };
  });
}

async function saveThemeScreenshot(page: Page, testInfo: TestInfo, themeId: string, width: number, height: number): Promise<void> {
  const name = `terminal-theme-${themeId}-${width}x${height}`;
  const path = resolve(process.cwd(), "test-results", "terminal-themes", `${name}.png`);
  await mkdir(resolve(path, ".."), { recursive: true });
  await page.screenshot({ path, animations: "disabled" });
  await testInfo.attach(name, { path, contentType: "image/png" });
}

async function chooseTheme(page: Page, id: string, name: string): Promise<void> {
  await page.keyboard.press("Control+k");
  await page.locator("#palette-input").fill(name);
  const option = page.locator(`[role="option"][data-action="theme:${id}"]`);
  await expect(option).toBeVisible();
  await option.click();
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-theme", id);
}

test("every curated theme recolors the initial terminal and its existing ANSI text", async ({ page }, testInfo) => {
  test.setTimeout(120_000);
  await page.addInitScript(() => {
    const webAssembly = WebAssembly as unknown as { compile: (source: unknown) => Promise<WebAssembly.Module> };
    const compile = webAssembly.compile.bind(WebAssembly);
    let releaseCompile: (() => void) | undefined;
    Object.defineProperty(window, "__releaseGhosttyInitialization", {
      configurable: true,
      value: () => releaseCompile?.(),
    });
    webAssembly.compile = async (source: unknown): Promise<WebAssembly.Module> => {
      await new Promise<void>((resolve) => { releaseCompile = resolve; });
      return compile(source);
    };
  });
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/theme-palette-fixture");
  await page.context().request.post("/__mock/open-terminal");
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&theme=paper&bg=none");
  await expect(page.locator("#terminal-screen")).toHaveCount(1, { timeout: 30_000 });
  await expect(page.locator("#terminal-host canvas")).toHaveCount(0);
  await page.keyboard.press("Control+k");
  await page.locator("#palette-input").fill("Ink");
  await page.keyboard.press("Enter");
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-theme", "ink");
  await page.evaluate(() => {
    const release = (window as unknown as { __releaseGhosttyInitialization?: () => void }).__releaseGhosttyInitialization;
    release?.();
  });
  await waitForTerminal(page);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.scrollbackRows ?? 0)).toBeGreaterThan(0);
  await expect.poll(() => readTerminalPixels(page, THEMES.ink!), { timeout: 15_000 }).toEqual(expectedPixels(THEMES.ink!));

  for (const [width, height] of [[1440, 900], [393, 852]] as const) {
    await page.setViewportSize({ width, height });
    for (const id of THEME_IDS) {
      const active = THEMES[id]!;
      const needsRebuild = (await page.locator("#terminal-screen").getAttribute("data-theme")) !== id;
      const before = needsRebuild ? await readTerminalState(page) : undefined;
      if (needsRebuild) await chooseTheme(page, id, active.name);
      if (width === 1440 && id === "paper") {
        const heldCanvas = page.locator('#terminal-host canvas[data-theme-hold]');
        await expect(heldCanvas).toHaveCount(1);
        expect(await readHeldCanvas(page)).toEqual({ background: THEMES.ink!.bg.toLowerCase(), zIndex: "2" });
      }
      await expect.poll(() => readTerminalPixels(page, active), { timeout: 15_000 }).toEqual(expectedPixels(active));
      if (before) await expect.poll(() => readTerminalState(page)).toEqual(before);
      expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("theme-history-000");
      expect(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.scrollbackRows ?? 0)).toBeGreaterThan(0);
      await saveThemeScreenshot(page, testInfo, id, width, height);
    }
  }

  // Keep a non-bottom viewport as well as the full history while Ghostty is rebuilt.
  const host = page.locator("#terminal-host");
  await host.hover();
  await page.mouse.wheel(0, -600);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.viewportY ?? 0)).toBeGreaterThan(0);
  const scrolled = await readTerminalState(page);
  await chooseTheme(page, "ink", "Ink");
  await expect.poll(() => readTerminalState(page)).toEqual(scrolled);
  await expect.poll(() => readTerminalPixels(page, THEMES.ink!)).toMatchObject({ background: THEMES.ink!.bg.toLowerCase() });
});
