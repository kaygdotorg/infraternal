/** Checks every curated terminal palette from painted pixels on the production build. */
import { tracerEvidencePath } from "./evidence-path";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test, type Page, type TestInfo } from "playwright/test";
import { selectionColors, THEMES, type Theme } from "../../../packages/ui/src/themes";

type TerminalPixels = {
  background: string;
  foreground: string;
  cursor: string;
  ansi: string[];
  truecolor: string;
};

type ThemeHistoryColors = { rows: number; indexed: number[]; truecolor: number[] };

const THEME_IDS = Object.keys(THEMES);

async function waitForTerminal(page: Page): Promise<void> {
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
}

function expectedPixels(theme: Theme): TerminalPixels {
  return {
    background: theme.bg.toLowerCase(),
    foreground: theme.fg.toLowerCase(),
    cursor: theme.accent.toLowerCase(),
    ansi: [...theme.ansi, ...theme.bright].map((color) => color.toLowerCase()),
    truecolor: "#18a6c4",
  };
}

async function readSocketCounts(page: Page): Promise<{ opened: number; closed: number; active: number }> {
  return page.evaluate(async () => {
    const response = await fetch("/__mock/state");
    const state = await response.json() as {
      socket_open_count: number;
      socket_close_count: number;
      active_socket_count: number;
    };
    return {
      opened: state.socket_open_count,
      closed: state.socket_close_count,
      active: state.active_socket_count,
    };
  });
}

async function readTerminalPixels(page: Page, theme: Theme): Promise<TerminalPixels> {
  return page.evaluate(({ ansi: themeAnsi, background: themeBackground }) => {
    // Cursor blink is an active-session behavior; freeze it so the color probe is deterministic.
    window.__tracerTestDouble?.freezeCursorForTest();
    const host = document.querySelector<HTMLElement>("#terminal-host");
    const canvas = host?.querySelector<HTMLCanvasElement>("canvas");
    const metrics = window.__tracerTestDouble?.rendererMetrics();
    const context = canvas?.getContext("2d", { willReadFrequently: true });
    if (!canvas || !context || !metrics) throw new Error("terminal canvas or renderer metrics are unavailable");

    const toHex = (r: number, g: number, b: number): string => `#${[r, g, b].map((value) => value.toString(16).padStart(2, "0")).join("")}`;
    const pixelAt = (x: number, y: number): string => {
      const data = context.getImageData(
        Math.min(canvas.width - 1, Math.max(0, x)),
        Math.min(canvas.height - 1, Math.max(0, y)),
        1,
        1,
      ).data;
      return toHex(data[0]!, data[1]!, data[2]!);
    };
    const scaleX = canvas.width / (metrics.cols * metrics.cellWidth);
    const scaleY = canvas.height / (metrics.rows * metrics.cellHeight);
    const cursorX = Math.floor((metrics.cursorX * metrics.cellWidth + 1) * scaleX);
    const cursorY = Math.floor((metrics.cursorY * metrics.cellHeight + 1) * scaleY);
    const background = pixelAt(canvas.width - 1, canvas.height - 1);
    const glyphColor = (column: number, row: number, background: string): string => {
      const left = Math.floor(column * metrics.cellWidth * scaleX);
      const right = Math.min(canvas.width, Math.ceil((column + 1) * metrics.cellWidth * scaleX));
      const top = Math.floor(row * metrics.cellHeight * scaleY);
      const bottom = Math.min(canvas.height, Math.ceil((row + 1) * metrics.cellHeight * scaleY));
      const data = context.getImageData(left, top, right - left, bottom - top).data;
      const backgroundColor = Number.parseInt(background.slice(1), 16);
      const colors = new Map<number, number>();
      let dominantColor = backgroundColor;
      let dominantCount = 0;
      for (let offset = 0; offset < data.length; offset += 4) {
        const color = (data[offset]! << 16) | (data[offset + 1]! << 8) | data[offset + 2]!;
        if (color === backgroundColor) continue;
        const count = (colors.get(color) ?? 0) + 1;
        colors.set(color, count);
        if (count > dominantCount) {
          dominantColor = color;
          dominantCount = count;
        }
      }
      // When an ANSI entry equals the background (Gruvbox black), the glyph is
      // correctly invisible; background is also the retry value for an empty cell.
      if (dominantCount < 2) return background;
      return toHex((dominantColor >> 16) & 0xff, (dominantColor >> 8) & 0xff, dominantColor & 0xff);
    };

    const defaultRow = metrics.rows - 3;
    const regularRow = metrics.rows - 2;
    const brightRow = metrics.rows - 1;
    return {
      background,
      foreground: glyphColor(9, defaultRow, background),
      cursor: pixelAt(cursorX, cursorY),
      truecolor: glyphColor(20, defaultRow, background),
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

async function readSelectionBackground(page: Page): Promise<string> {
  return page.evaluate(() => {
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
    const metrics = window.__tracerTestDouble?.rendererMetrics();
    const context = canvas?.getContext("2d", { willReadFrequently: true });
    if (!canvas || !metrics || !context) throw new Error("terminal canvas or renderer metrics are unavailable");
    const scaleX = canvas.width / (metrics.cols * metrics.cellWidth);
    const scaleY = canvas.height / (metrics.rows * metrics.cellHeight);
    // This point is inside selected plain text and above the glyph ink.
    const x = Math.floor((2 * metrics.cellWidth + 1) * scaleX);
    const y = Math.floor(((metrics.rows - 3) * metrics.cellHeight + 1) * scaleY);
    const pixel = context.getImageData(x, y, 1, 1).data;
    return `#${[pixel[0], pixel[1], pixel[2]].map((value) => value!.toString(16).padStart(2, "0")).join("")}`;
  });
}

async function selectDefaultRowText(page: Page): Promise<void> {
  const metrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
  const canvasBox = await page.locator("#terminal-host canvas").boundingBox();
  if (!metrics || !canvasBox) throw new Error("terminal selection geometry is unavailable");
  const rowY = canvasBox.y + (metrics.rows - 3) * metrics.cellHeight + metrics.cellHeight / 2;
  await page.mouse.move(canvasBox.x + metrics.cellWidth / 2, rowY);
  await page.mouse.down();
  await page.mouse.move(canvasBox.x + metrics.cellWidth * 7.5, rowY);
  await page.mouse.up();
}

/**
 * The highlight the terminal must paint behind selected text: the theme's selection pair (D365, D380), which adapts to the theme so
 * the selected text reads on it. Its contrast rules are unit-tested in `packages/ui/src/selection-colors.test.ts`; this check is that
 * the terminal paints exactly that colour. (It used to be a fixed mix of accent and background, which only the light themes still are.)
 */
function expectedSelectionBackground(theme: Theme): string {
  return selectionColors(theme).background.toLowerCase();
}

function colorDistance(left: string, right: string): number {
  const channels = (hex: string) => [1, 3, 5].map((offset) => Number.parseInt(hex.slice(offset, offset + 2), 16));
  const leftRgb = channels(left);
  const rightRgb = channels(right);
  return leftRgb.reduce((total, channel, index) => total + Math.abs(channel - rightRgb[index]!), 0);
}

async function readTerminalState(page: Page) {
  return page.evaluate(() => {
    const metrics = window.__tracerTestDouble?.rendererMetrics();
    if (!metrics) throw new Error("terminal renderer metrics are unavailable");
    return {
      cursorX: metrics.cursorX,
      // The absolute cursor row is stable when the viewport is resized.
      cursorRow: metrics.cursorY + metrics.scrollbackRows,
      viewportY: Math.round(metrics.viewportY * 100) / 100,
    };
  });
}

async function readThemeHistoryColors(page: Page): Promise<ThemeHistoryColors> {
  return page.evaluate(() => window.__tracerTestDouble?.themeHistoryColors() ?? { rows: 0, indexed: [], truecolor: [] });
}

function rgbNumber(hex: string): number {
  return Number.parseInt(hex.slice(1), 16);
}

function expectThemeHistoryColors(history: ThemeHistoryColors, theme: Theme): void {
  const palette = theme.ansi.map(rgbNumber);
  const indexedMismatches = history.indexed.reduce((count, color, row) => count + Number(color !== palette[row % palette.length]), 0);
  const truecolorMismatches = history.truecolor.reduce((count, color) => count + Number(color !== 0x18a6c4), 0);
  expect({ rows: history.rows, indexedMismatches, truecolorMismatches }).toEqual({ rows: 10_000, indexedMismatches: 0, truecolorMismatches: 0 });
}

async function saveThemeScreenshot(page: Page, testInfo: TestInfo, themeId: string, width: number, height: number): Promise<void> {
  const name = `terminal-theme-${themeId}-${width}x${height}`;
  const path = tracerEvidencePath("playwright", "terminal-themes", `${name}.png`);
  await mkdir(resolve(path, ".."), { recursive: true });
  await page.screenshot({ path, animations: "disabled" });
  await testInfo.attach(name, { path, contentType: "image/png" });
}

async function chooseTheme(page: Page, id: string, name: string): Promise<void> {
  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill(name);
  const option = page.locator(`[role="option"][data-action="theme:${id}"]`);
  await expect(option).toBeVisible();
  await option.click();
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-theme", id);
}

test("every curated theme recolors the initial terminal and its existing ANSI text", async ({ page }, testInfo) => {
  test.setTimeout(180_000);
  await page.addInitScript(() => {
    const longTasks: number[] = [];
    (window as typeof window & { __terminalThemeLongTasks?: number[] }).__terminalThemeLongTasks = longTasks;
    if ("PerformanceObserver" in window) {
      const observer = new PerformanceObserver((entries) => {
        for (const entry of entries.getEntries()) longTasks.push(entry.duration);
      });
      observer.observe({ type: "longtask", buffered: false });
    }
  });
  await page.context().request.post("/__mock/reset");
  const fixtureResponse = await page.context().request.post("/__mock/theme-palette-fixture");
  const fixtureInfo = await fixtureResponse.json() as { bytes: number };
  await page.context().request.post("/__mock/open-terminal");
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&theme=paper&bg=none&scrollback=40000000");
  await expect(page.locator("#terminal-screen")).toHaveCount(1, { timeout: 30_000 });
  await waitForTerminal(page);
  // Attach precedes the frame-by-frame WASM writes; wait until every fixture byte
  // has reached the post-render callback before measuring retained history.
  await expect.poll(() => page.evaluate(() => Number(window.__tracerTestDouble?.rendererMetrics()?.outputSequence ?? 0)), { timeout: 60_000 }).toBe(fixtureInfo.bytes);
  const initialMetrics = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics());
  console.log(`theme fixture bytes=${fixtureInfo.bytes} metrics=${JSON.stringify(initialMetrics)}`);
  expect(initialMetrics?.scrollbackRows ?? 0).toBeGreaterThanOrEqual(10_000);
  await expect.poll(() => readTerminalPixels(page, THEMES.paper!), { timeout: 15_000 }).toEqual(expectedPixels(THEMES.paper!));
  const socketCounts = await readSocketCounts(page);
  expect(socketCounts).toEqual({ opened: 1, closed: 0, active: 1 });

  const scrollbackRowsBefore = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.scrollbackRows ?? 0);
  const historyText = await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "");
  const historyMarkers = [...historyText.matchAll(/theme-history-(\d{5})/g)].map((match) => match[1]);
  expect(historyMarkers).toHaveLength(10_000);
  expect(historyMarkers.every((marker, index) => marker === String(index).padStart(5, "0"))).toBe(true);
  expectThemeHistoryColors(await readThemeHistoryColors(page), THEMES.paper!);

  const switchDurations: number[] = [];
  const colorUpdateDurations: number[] = [];
  const renderDurations: number[] = [];
  const pixelCheckedThemes = new Set<string>(["paper"]);
  await page.evaluate(() => { (window as typeof window & { __terminalThemeLongTasks?: number[] }).__terminalThemeLongTasks?.splice(0); });
  for (let index = 0; index < 50; index += 1) {
    const id = THEME_IDS[(index + 1) % THEME_IDS.length]!;
    const active = THEMES[id]!;
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette-input").fill(active.name);
    const option = page.locator(`[role="option"][data-action="theme:${id}"]`);
    await expect(option).toBeVisible();
    const elapsed = await option.evaluate((element) => {
      const startedAt = performance.now();
      (element as HTMLElement).click();
      return performance.now() - startedAt;
    });
    switchDurations.push(elapsed);
    await expect(page.locator("#terminal-screen")).toHaveAttribute("data-theme", id);
    const themeWork = await page.evaluate(() => {
      const metrics = window.__tracerTestDouble?.rendererMetrics();
      return { colors: metrics?.themeColorsMs ?? 0, render: metrics?.themeRenderMs ?? 0 };
    });
    colorUpdateDurations.push(themeWork.colors);
    renderDurations.push(themeWork.render);
    if (!pixelCheckedThemes.has(id)) {
      await expect.poll(() => readTerminalPixels(page, active), { timeout: 2_000 }).toEqual(expectedPixels(active));
      pixelCheckedThemes.add(id);
    }
  }
  const sortedDurations = [...switchDurations].sort((left, right) => left - right);
  const p50 = sortedDurations[Math.floor(sortedDurations.length * 0.50)]!;
  const p99 = sortedDurations[Math.ceil(sortedDurations.length * 0.99) - 1]!;
  const slowestSamples = switchDurations
    .map((click, index) => ({ sample: index + 1, click, colors: colorUpdateDurations[index]!, render: renderDurations[index]! }))
    .sort((left, right) => right.click - left.click)
    .slice(0, 5);
  const colorP50 = [...colorUpdateDurations].sort((left, right) => left - right)[Math.floor(colorUpdateDurations.length * 0.5)]!;
  const renderP50 = [...renderDurations].sort((left, right) => left - right)[Math.floor(renderDurations.length * 0.5)]!;
  const longTasks = await page.evaluate(() => (window as typeof window & { __terminalThemeLongTasks?: number[] }).__terminalThemeLongTasks ?? []);
  console.log(`theme-switch click-to-full-paint JS ms: n=${switchDurations.length} p50=${p50.toFixed(3)} p99=${p99.toFixed(3)} max=${Math.max(...switchDurations).toFixed(3)} long_tasks_gt_50ms=${longTasks.filter((duration) => duration > 50).length}`);
  console.log(`slowest theme samples: ${JSON.stringify(slowestSamples)}`);
  console.log(`theme work JS ms: color_setters_p50=${colorP50.toFixed(3)} repaint_p50=${renderP50.toFixed(3)}`);
  await testInfo.attach("theme-switch-measurements", {
    body: JSON.stringify({ samples: switchDurations, p50, p99, colorUpdateDurations, renderDurations, longTasks }),
    contentType: "application/json",
  });
  expect(p99).toBeLessThan(16.67);
  expect(longTasks.filter((duration) => duration > 50)).toEqual([]);
  expect(await readSocketCounts(page)).toEqual(socketCounts);
  expect(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.scrollbackRows ?? 0)).toBe(scrollbackRowsBefore);
  expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toBe(historyText);
  const activeThemeId = await page.locator("#terminal-screen").getAttribute("data-theme");
  expect(activeThemeId).not.toBeNull();
  expectThemeHistoryColors(await readThemeHistoryColors(page), THEMES[activeThemeId!]!);

  for (const [width, height] of [[1440, 900], [393, 852]] as const) {
    await page.setViewportSize({ width, height });
    for (const id of THEME_IDS) {
      const active = THEMES[id]!;
      const needsThemeChange = (await page.locator("#terminal-screen").getAttribute("data-theme")) !== id;
      if (needsThemeChange) await chooseTheme(page, id, active.name);
      await expect.poll(() => readTerminalPixels(page, active), { timeout: 15_000 }).toEqual(expectedPixels(active));
      expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("theme-history-00000");
      expect(await page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("theme-history-09999");
      expect(await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.scrollbackRows ?? 0)).toBeGreaterThanOrEqual(10_000);
      if (width === 1440) expectThemeHistoryColors(await readThemeHistoryColors(page), active);
      await saveThemeScreenshot(page, testInfo, id, width, height);
    }
  }

  // Keep a non-bottom viewport while palette entries change inside the same terminal.
  await page.setViewportSize({ width: 1440, height: 900 });
  await chooseTheme(page, "paper", "Paper");
  await selectDefaultRowText(page);
  await expect.poll(async () => colorDistance(await readSelectionBackground(page), expectedSelectionBackground(THEMES.paper!))).toBeLessThanOrEqual(3);
  await chooseTheme(page, "ink", "Ink");
  await selectDefaultRowText(page);
  await expect.poll(async () => colorDistance(await readSelectionBackground(page), expectedSelectionBackground(THEMES.ink!))).toBeLessThanOrEqual(3);
  await chooseTheme(page, "paper", "Paper");

  const host = page.locator("#terminal-host");
  await host.hover();
  await page.mouse.wheel(0, -600);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.viewportY ?? 0)).toBeGreaterThan(0);
  let previousViewportY = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.viewportY ?? 0);
  let stableViewportSamples = 0;
  await expect.poll(async () => {
    const viewportY = await page.evaluate(() => window.__tracerTestDouble?.rendererMetrics()?.viewportY ?? 0);
    stableViewportSamples = Math.abs(viewportY - previousViewportY) < 0.001 ? stableViewportSamples + 1 : 0;
    previousViewportY = viewportY;
    return stableViewportSamples >= 2;
  }, { timeout: 5_000, intervals: [50] }).toBe(true);
  const scrolled = await readTerminalState(page);
  await chooseTheme(page, "ink", "Ink");
  await expect.poll(() => readTerminalState(page)).toEqual(scrolled);
  await expect.poll(() => readTerminalPixels(page, THEMES.ink!)).toMatchObject({ background: THEMES.ink!.bg.toLowerCase() });
  expect(await readSocketCounts(page)).toEqual(socketCounts);
});
