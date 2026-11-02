/** Exercises terminal links through the production tracer and its real VT renderer. */
import { expect, test } from "playwright/test";
import type { TerminalLink } from "../src/terminal-links.on-demand";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const baseURL = `http://localhost:${port}`;
const target = `https://links.example.test/oauth/authorize?client_id=web&state=${"s".repeat(420)}&redirect_uri=https%3A%2F%2Flinks.example.test%2Fcallback&response_type=code`;
const osc8Target = "https://links.example.test/actual-destination";

async function openTerminal(
  page: import("playwright/test").Page,
  theme = "ink",
  viewport = { width: 390, height: 844 },
): Promise<void> {
  await page.setViewportSize(viewport);
  const reset = await page.context().request.post("/__mock/reset");
  const opened = await page.context().request.post("/__mock/open-terminal");
  expect([reset.status(), opened.status()]).toEqual([200, 200]);
  await page.goto(`/?mock=1&proto=product&bg=none&fixture=none&theme=${theme}`);
  await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
}

function evidencePath(testInfo: import("playwright/test").TestInfo, name: string): string {
  const directory = process.env.LINK_TOOLTIP_EVIDENCE_DIR;
  return directory ? `${directory}/${name}` : testInfo.outputPath(name);
}

async function linkAccentPixels(page: import("playwright/test").Page, needle: string): Promise<number> {
  return page.evaluate((text) => {
    const screen = window.__tracerProductTestDouble?.screenText() ?? "";
    const lines = screen.split("\n");
    const row = lines.findIndex((line) => line.includes(text));
    const col = row < 0 ? -1 : lines[row]!.indexOf(text);
    const metrics = window.__tracerProductTestDouble?.rendererMetrics();
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
    const context = canvas?.getContext("2d");
    const accent = getComputedStyle(document.documentElement).getPropertyValue("--accent").trim();
    const color = /^#([\da-f]{6})$/i.exec(accent)?.[1];
    const background = metrics?.terminalColors?.background;
    if (row < 0 || col < 0 || !metrics || !canvas || !context || !color || !background) throw new Error("link underline pixels are unavailable");
    if (metrics.rendererAccentColor.toLowerCase() !== accent.toLowerCase()) throw new Error("renderer accent does not match the theme token");
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    const left = Math.max(0, Math.floor(col * metrics.cellWidth * scaleX));
    const right = Math.min(canvas.width, Math.ceil((col + text.length) * metrics.cellWidth * scaleX));
    const top = Math.max(0, Math.floor(row * metrics.cellHeight * scaleY));
    const bottom = Math.min(canvas.height, Math.ceil((row + 1) * metrics.cellHeight * scaleY));
    // A one-pixel canvas stroke may cover adjacent backing pixels partially; check its accent-to-background blend.
    const underlineTop = Math.max(top, bottom - Math.ceil(4 * scaleY));
    const image = context.getImageData(left, underlineTop, right - left, bottom - underlineTop).data;
    const red = Number.parseInt(color.slice(0, 2), 16);
    const green = Number.parseInt(color.slice(2, 4), 16);
    const blue = Number.parseInt(color.slice(4, 6), 16);
    const accentVector = [red - background.r, green - background.g, blue - background.b];
    const vectorLength = accentVector.reduce((sum, channel) => sum + channel * channel, 0);
    let count = 0;
    for (let offset = 0; offset < image.length; offset += 4) {
      if (image[offset + 3]! === 0) continue;
      const pixelVector = [image[offset]! - background.r, image[offset + 1]! - background.g, image[offset + 2]! - background.b];
      const coverage = pixelVector.reduce((sum, channel, index) => sum + channel * accentVector[index]!, 0) / vectorLength;
      const residual = Math.sqrt(pixelVector.reduce((sum, channel, index) => sum + (channel - coverage * accentVector[index]!) ** 2, 0));
      if (coverage >= 0.25 && coverage <= 1.05 && residual <= 4) count += 1;
    }
    return count;
  }, needle);
}

async function linkTextPixels(page: import("playwright/test").Page, needle: string): Promise<number[]> {
  return page.evaluate((text) => {
    const lines = (window.__tracerProductTestDouble?.screenText() ?? "").split("\n");
    const row = lines.findIndex((line) => line.includes(text));
    const col = row < 0 ? -1 : lines[row]!.indexOf(text);
    const metrics = window.__tracerProductTestDouble?.rendererMetrics();
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
    const context = canvas?.getContext("2d");
    if (row < 0 || col < 0 || !metrics || !canvas || !context) throw new Error("link text pixels are unavailable");
    const scaleX = canvas.width / canvas.getBoundingClientRect().width;
    const scaleY = canvas.height / canvas.getBoundingClientRect().height;
    const left = Math.floor(col * metrics.cellWidth * scaleX);
    const right = Math.ceil((col + text.length) * metrics.cellWidth * scaleX);
    const top = Math.floor(row * metrics.cellHeight * scaleY);
    const bottom = Math.max(top, Math.ceil((row + 1) * metrics.cellHeight * scaleY) - Math.ceil(3 * scaleY));
    return Array.from(context.getImageData(left, top, right - left, bottom - top).data);
  }, needle);
}

async function terminalLinkPoint(page: import("playwright/test").Page, prefix: string): Promise<{ x: number; y: number; cols: number }> {
  return page.evaluate((needle) => {
    const text = window.__tracerProductTestDouble?.screenText() ?? "";
    const lines = text.split("\n");
    const row = lines.findIndex((line) => line.includes(needle));
    const col = row < 0 ? -1 : lines[row]!.indexOf(needle);
    const metrics = window.__tracerProductTestDouble?.rendererMetrics();
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
    if (row < 0 || col < 0 || !metrics || !canvas) throw new Error("wrapped terminal URL is not painted");
    const rect = canvas.getBoundingClientRect();
    return { x: rect.left + (col + 2) * metrics.cellWidth, y: rect.top + (row + 0.5) * metrics.cellHeight, cols: metrics.cols };
  }, prefix);
}

async function linkTooltipLayout(
  page: import("playwright/test").Page,
  target: string,
  point: { x: number; y: number },
): Promise<{
  target: string;
  text: string;
  rows: number;
  labelWidth: number;
  labelClientWidth: number;
  labelScrollWidth: number;
  labelHeight: number;
  labelScrollHeight: number;
  lineHeight: number;
  tooltipRect: { x: number; y: number; width: number; height: number };
  linkRowsRect: { top: number; bottom: number };
  labelInsideTooltip: boolean;
  tooltipIntersectsLinkRows: boolean;
  tooltipIntersectsPointer: boolean;
  tooltipArrowAligned: boolean;
}> {
  return page.evaluate(({ expected, pointer }) => {
    const link = window.__tracerProductTestDouble?.terminalLinks().find((item) => item.target === expected) as TerminalLink | undefined;
    const metrics = window.__tracerProductTestDouble?.rendererMetrics();
    const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
    const tooltip = document.querySelector<HTMLElement>(".tip");
    const label = document.querySelector<HTMLElement>(".tip-label:not(.is-leaving)");
    const position = document.querySelector<HTMLElement>(".tip-pos");
    const arrow = position?.querySelector<HTMLElement>(".tip-arrow");
    if (!link || !metrics || !canvas || !tooltip || !label || !position || !arrow) throw new Error("link tooltip layout is unavailable");

    const text = window.__tracerProductTestDouble?.screenText() ?? "";
    const firstRow = text.split("\n").findIndex((line) => line.includes(link.visibleText.slice(0, 24)));
    if (firstRow < 0) throw new Error("terminal link rows are not painted");
    const canvasRect = canvas.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    const labelRect = label.getBoundingClientRect();
    const rowCount = link.range.end.y - link.range.start.y + 1;
    const linkRows = {
      left: canvasRect.left,
      right: canvasRect.right,
      top: canvasRect.top + firstRow * metrics.cellHeight,
      bottom: canvasRect.top + (firstRow + rowCount) * metrics.cellHeight,
    };
    const pointerRect = { left: pointer.x - 0.5, right: pointer.x + 0.5, top: pointer.y - 0.5, bottom: pointer.y + 0.5 };
    const intersects = (rect: DOMRect, other: { left: number; right: number; top: number; bottom: number }): boolean =>
      rect.left < other.right && rect.right > other.left && rect.top < other.bottom && rect.bottom > other.top;
    const style = getComputedStyle(label);
    const lineHeight = Number.parseFloat(style.lineHeight);

    return {
      target: link.target,
      text: label.textContent ?? "",
      rows: rowCount,
      labelWidth: labelRect.width,
      labelClientWidth: label.clientWidth,
      labelScrollWidth: label.scrollWidth,
      labelHeight: labelRect.height,
      labelScrollHeight: label.scrollHeight,
      lineHeight,
      tooltipRect: { x: tooltipRect.x, y: tooltipRect.y, width: tooltipRect.width, height: tooltipRect.height },
      linkRowsRect: { top: linkRows.top, bottom: linkRows.bottom },
      labelInsideTooltip: labelRect.left >= tooltipRect.left && labelRect.right <= tooltipRect.right &&
        labelRect.top >= tooltipRect.top && labelRect.bottom <= tooltipRect.bottom,
      tooltipIntersectsLinkRows: intersects(tooltipRect, linkRows),
      tooltipIntersectsPointer: intersects(tooltipRect, pointerRect),
      // The arrow's centre sits on the surface's edge facing the anchor (read from the boxes, not from a pixel constant in its style).
      tooltipArrowAligned: Math.abs((arrow.getBoundingClientRect().top + arrow.getBoundingClientRect().height / 2) - (position.dataset.side === "top" ? tooltipRect.bottom : tooltipRect.top)) < 0.75,
    };
  }, { expected: target, pointer: point });
}

test("a long link tooltip stays short, readable, and clear of its wrapped rows", async ({ browser }, testInfo) => {
  test.setTimeout(90_000);
  const capture = process.env.LINK_TOOLTIP_CAPTURE ?? "check";
  const videoDirectory = process.env.LINK_TOOLTIP_VIDEO_DIR;
  const context = await browser.newContext({
    baseURL,
    viewport: { width: 390, height: 844 },
    ...(videoDirectory ? { recordVideo: { dir: videoDirectory, size: { width: 390, height: 844 } } } : {}),
  });
  await context.route("https://login.example.test/**", (route) => route.fulfill({ status: 200, body: "opened" }));
  await context.addInitScript(() => {
    const calls: string[][] = [];
    (window as unknown as { __openCalls: string[][] }).__openCalls = calls;
    const nativeOpen = window.open.bind(window);
    window.open = ((...args: Parameters<typeof window.open>) => {
      calls.push(args.map(String));
      return nativeOpen(...args);
    }) as typeof window.open;
  });

  const page = await context.newPage();
  const video = page.video();
  try {
    await openTerminal(page);
    const cols = await page.evaluate(() => window.__tracerProductTestDouble?.rendererMetrics()?.cols ?? 0);
    const visiblePrefix = "https://login.example.test/oauth/authorize?client_id=agy&state=";
    const visibleUrl = `${visiblePrefix}${"s".repeat(Math.max(1, cols * 8 - visiblePrefix.length))}`;
    const longTarget = `${visibleUrl}&redirect_uri=https%3A%2F%2Flogin.example.test%2Fcallback&response_type=code`;
    expect(longTarget.length).toBeGreaterThan(400);
    expect(longTarget.length).toBeLessThan(550);

    const longResponse = await context.request.post("/__mock/live-query-output", {
      data: { text: `\u001b[2J\u001b[H\u001b]8;;${longTarget}\u0007${visibleUrl}\u001b]8;;\u0007` },
    });
    expect(longResponse.ok()).toBe(true);
    await expect.poll(() => page.evaluate((expected) => window.__tracerProductTestDouble?.terminalLinks().some((link) => link.target === expected) ?? false, longTarget), { timeout: 30_000 }).toBe(true);
    const longPoint = await terminalLinkPoint(page, visibleUrl.slice(0, 36));
    await page.mouse.move(longPoint.x, longPoint.y);
    await expect(page.locator(".tip")).toBeVisible();
    await expect(page.locator(".tip-label.is-leaving")).toHaveCount(0);
    await page.screenshot({ path: evidencePath(testInfo, `${capture}-link-tooltip-phone.png`) });
    const longLayout = await linkTooltipLayout(page, longTarget, longPoint);
    // The product's coarse-pointer type scale raises secondary labels to 15 px.
    const mobileTypeScale = await page.addStyleTag({ content: ":root { --text-secondary: 15px; }" });
    await page.mouse.move(0, 0);
    await page.mouse.move(longPoint.x, longPoint.y);
    await expect(page.locator(".tip-label:not(.is-leaving)")).toBeVisible();
    const mobileLongLayout = await linkTooltipLayout(page, longTarget, longPoint);
    await mobileTypeScale.evaluate((style) => style.parentElement?.removeChild(style));

    await page.setViewportSize({ width: 1440, height: 900 });
    await expect.poll(() => page.evaluate(() => window.innerWidth)).toBe(1440);
    await page.mouse.move(0, 0);
    const desktopPoint = await terminalLinkPoint(page, visibleUrl.slice(0, 36));
    await page.mouse.move(desktopPoint.x, desktopPoint.y);
    await expect(page.locator(".tip")).toBeVisible();
    await expect(page.locator(".tip-label.is-leaving")).toHaveCount(0);
    await page.screenshot({ path: evidencePath(testInfo, `${capture}-link-tooltip-desktop.png`) });
    const desktopLongLayout = await linkTooltipLayout(page, longTarget, desktopPoint);

    await page.mouse.click(desktopPoint.x, desktopPoint.y);
    expect(await page.evaluate(() => (window as unknown as { __openCalls: string[][] }).__openCalls.at(-1))).toEqual([longTarget, "_blank", "noopener,noreferrer"]);
    const popup = context.pages().find((candidate) => candidate !== page);
    if (popup) await popup.close();
    await page.bringToFront();

    await page.mouse.move(0, 0);
    const shortTarget = "https://login.example.test/sign-in";
    const shortResponse = await context.request.post("/__mock/live-query-output", {
      data: { text: `\u001b[2J\u001b[H\u001b]8;;${shortTarget}\u0007Sign in\u001b]8;;\u0007` },
    });
    expect(shortResponse.ok()).toBe(true);
    await expect.poll(() => page.evaluate((expected) => window.__tracerProductTestDouble?.terminalLinks().some((link) => link.target === expected) ?? false, shortTarget), { timeout: 30_000 }).toBe(true);
    const shortPoint = await terminalLinkPoint(page, "Sign in");
    await page.mouse.move(shortPoint.x, shortPoint.y);
    await expect(page.locator(".tip")).toBeVisible();
    await expect(page.locator(".tip-label.is-leaving")).toHaveCount(0);
    await page.screenshot({ path: evidencePath(testInfo, `${capture}-link-tooltip-short.png`) });
    const shortLayout = await linkTooltipLayout(page, shortTarget, shortPoint);

    console.log(`LINK_TOOLTIP_LAYOUT ${JSON.stringify({ long: longLayout, short: shortLayout, mobileLong: mobileLongLayout, desktopLong: desktopLongLayout, columns: cols })}`);
    expect.soft(longLayout.rows).toBe(8);
    expect.soft(longLayout.text.startsWith("https://login.example.test")).toBe(true);
    expect.soft(longLayout.text).toContain("…");
    expect.soft(longLayout.text.endsWith("&response_type=code")).toBe(true);
    expect.soft(longLayout.text).not.toBe(longTarget);
    expect.soft(longLayout.labelScrollWidth).toBeLessThanOrEqual(longLayout.labelClientWidth);
    expect.soft(longLayout.labelScrollHeight).toBeLessThanOrEqual(2 * longLayout.lineHeight + 1);
    expect.soft(longLayout.labelInsideTooltip).toBe(true);
    expect.soft(longLayout.tooltipIntersectsLinkRows).toBe(false);
    expect.soft(longLayout.tooltipIntersectsPointer).toBe(false);
    expect.soft(longLayout.tooltipArrowAligned).toBe(true);
    expect.soft(shortLayout.text).toBe(shortTarget);
    expect.soft(shortLayout.labelScrollWidth).toBeLessThanOrEqual(shortLayout.labelClientWidth);
    expect.soft(shortLayout.labelScrollHeight).toBeLessThanOrEqual(2 * shortLayout.lineHeight + 1);
    expect.soft(shortLayout.labelInsideTooltip).toBe(true);
    expect.soft(shortLayout.tooltipIntersectsLinkRows).toBe(false);
    expect.soft(shortLayout.tooltipIntersectsPointer).toBe(false);
    expect.soft(shortLayout.tooltipArrowAligned).toBe(true);
    expect.soft(mobileLongLayout.text.startsWith("https://login.example.test")).toBe(true);
    expect.soft(mobileLongLayout.text).toContain("…");
    expect.soft(mobileLongLayout.text.endsWith("&response_type=code")).toBe(true);
    expect.soft(mobileLongLayout.labelScrollWidth).toBeLessThanOrEqual(mobileLongLayout.labelClientWidth);
    expect.soft(mobileLongLayout.labelScrollHeight).toBeLessThanOrEqual(2 * mobileLongLayout.lineHeight + 1);
    expect.soft(mobileLongLayout.labelInsideTooltip).toBe(true);
    expect.soft(mobileLongLayout.tooltipIntersectsLinkRows).toBe(false);
    expect.soft(mobileLongLayout.tooltipIntersectsPointer).toBe(false);
    expect.soft(mobileLongLayout.tooltipArrowAligned).toBe(true);
    expect.soft(desktopLongLayout.text.startsWith("https://login.example.test")).toBe(true);
    expect.soft(desktopLongLayout.text).toContain("…");
    expect.soft(desktopLongLayout.text.endsWith("&response_type=code")).toBe(true);
    expect.soft(desktopLongLayout.labelScrollWidth).toBeLessThanOrEqual(desktopLongLayout.labelClientWidth);
    expect.soft(desktopLongLayout.labelScrollHeight).toBeLessThanOrEqual(2 * desktopLongLayout.lineHeight + 1);
    expect.soft(desktopLongLayout.labelInsideTooltip).toBe(true);
    expect.soft(desktopLongLayout.tooltipIntersectsLinkRows).toBe(false);
    expect.soft(desktopLongLayout.tooltipIntersectsPointer).toBe(false);
    expect.soft(desktopLongLayout.tooltipArrowAligned).toBe(true);
  } finally {
    await context.close();
    if (video && videoDirectory) await video.saveAs(`${videoDirectory}/link-tooltip.webm`);
  }
});

test("wrapped and OSC 8 links open from the terminal and palette", async ({ browser }, testInfo) => {
  test.setTimeout(90_000);
  const context = await browser.newContext({ baseURL, viewport: { width: 390, height: 844 } });
  await context.route("https://links.example.test/**", (route) => route.fulfill({ status: 200, body: "opened" }));
  await context.addInitScript(() => {
    const calls: string[][] = [];
    (window as unknown as { __openCalls: string[][] }).__openCalls = calls;
    const nativeOpen = window.open.bind(window);
    window.open = ((...args: Parameters<typeof window.open>) => {
      calls.push(args.map(String));
      return nativeOpen(...args);
    }) as typeof window.open;
  });
  try {
    const page = await context.newPage();
    await openTerminal(page);
    const response = await context.request.post("/__mock/live-query-output", { data: { text: `\u001b[2J\u001b[H${target}` } });
    expect(response.ok()).toBe(true);
    await expect.poll(() => page.evaluate((expected) => window.__tracerProductTestDouble?.screenText().replaceAll("\n", "").includes(expected) ?? false, target), { timeout: 30_000 }).toBe(true);
    await expect.poll(() => page.evaluate((expected) => window.__tracerProductTestDouble?.terminalLinks().some((link) => link.target === expected) ?? false, target), { timeout: 30_000 }).toBe(true);

    const point = await terminalLinkPoint(page, "https://links.example.test/oauth");
    expect(point.cols).toBeGreaterThan(1);
    await page.mouse.move(point.x, point.y);
    await page.mouse.down();
    await page.mouse.move(point.x + 120, point.y, { steps: 4 });
    await page.mouse.up();
    expect(await page.evaluate(() => (window as unknown as { __openCalls: string[][] }).__openCalls.length)).toBe(0);
    expect(context.pages()).toHaveLength(1);
    await page.mouse.move(point.x, point.y);
    await expect(page.locator("#terminal-host canvas")).toHaveCSS("cursor", "pointer");
    await page.screenshot({ path: evidencePath(testInfo, "terminal-wrapped-link-hover.png") });
    const pageCount = context.pages().length;
    await page.mouse.click(point.x, point.y);
    expect(await page.evaluate(() => (window as unknown as { __openCalls: string[][] }).__openCalls.at(-1))).toEqual([target, "_blank", "noopener,noreferrer"]);
    await expect.poll(() => context.pages().length).toBe(pageCount + 1);
    const popup = context.pages().find((candidate) => candidate !== page)!;
    await expect(popup).toHaveURL(target);
    await popup.close();

    await page.keyboard.press("Control+Shift+K");
    const paletteInput = page.locator("#palette-input");
    const linkRow = page.locator(".result").filter({ hasText: "Open link: links.example.test…" });
    await paletteInput.fill("Open link: links.example.test");
    await expect(linkRow).toBeVisible();
    const palettePageCount = context.pages().length;
    await paletteInput.press("Enter");
    expect(await page.evaluate(() => (window as unknown as { __openCalls: string[][] }).__openCalls.at(-1))).toEqual([target, "_blank", "noopener,noreferrer"]);
    await expect.poll(() => context.pages().length).toBe(palettePageCount + 1);
    const paletteOpenedPage = context.pages().find((candidate) => candidate !== page)!;
    await expect(paletteOpenedPage).toHaveURL(target);
    await paletteOpenedPage.close();
    await page.bringToFront();

    const osc8Response = await context.request.post("/__mock/live-query-output", {
      data: { text: `\u001b[2J\u001b[H\u001b]8;;${osc8Target}\u0007Sign in\u001b]8;;\u0007` },
    });
    expect(osc8Response.ok()).toBe(true);
    await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.screenText().includes("Sign in") ?? false)).toBe(true);
    await page.waitForTimeout(250);
    await expect.poll(() => page.evaluate((expected) => window.__tracerProductTestDouble?.terminalLinks().some((link) => link.target === expected) ?? false, osc8Target), { timeout: 5_000 }).toBe(true);
    const osc8Point = await terminalLinkPoint(page, "Sign in");
    await page.mouse.move(osc8Point.x, osc8Point.y);
    await expect(page.locator(".tip-label:not(.is-leaving)")).toHaveText(osc8Target, { timeout: 3_000 });
    await page.screenshot({ path: evidencePath(testInfo, "terminal-osc8-target-hover.png") });
    const osc8PageCount = context.pages().length;
    await page.mouse.click(osc8Point.x, osc8Point.y);
    expect(await page.evaluate(() => (window as unknown as { __openCalls: string[][] }).__openCalls.at(-1))).toEqual([osc8Target, "_blank", "noopener,noreferrer"]);
    await expect.poll(() => context.pages().length).toBe(osc8PageCount + 1);
    const osc8Popup = context.pages().find((candidate) => candidate !== page)!;
    await expect(osc8Popup).toHaveURL(osc8Target);
    await osc8Popup.close();
  } finally {
    await context.close();
  }
});

test("link underlines use the theme accent on hover and while the open modifier is held", async ({ browser }, testInfo) => {
  for (const theme of ["ink", "paper"] as const) {
    const context = await browser.newContext({ baseURL, viewport: { width: 390, height: 844 } });
    if (theme === "paper") {
      await context.addInitScript(() => Object.defineProperty(navigator, "platform", { configurable: true, get: () => "MacIntel" }));
    }
    try {
      const page = await context.newPage();
      await openTerminal(page, theme, { width: 393, height: 852 });
      const first = "https://links.example.test/first";
      const second = "https://links.example.test/second";
      const response = await context.request.post("/__mock/live-query-output", {
        data: { text: `\u001b[2J\u001b[H${first}\r\n${second}\r\n\u001b[?25l` },
      });
      expect(response.ok()).toBe(true);
      await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.screenText().includes("/second") ?? false)).toBe(true);
      await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.terminalLinks().length ?? 0)).toBe(2);
      const textBeforeHover = await linkTextPixels(page, first);
      expect(await linkAccentPixels(page, first)).toBe(0);
      expect(await linkAccentPixels(page, second)).toBe(0);

      const point = await terminalLinkPoint(page, first);
      await page.mouse.move(point.x, point.y);
      await expect.poll(() => linkAccentPixels(page, first)).toBeGreaterThan(0);
      expect(await linkAccentPixels(page, second)).toBe(0);
      expect(await linkTextPixels(page, first)).toEqual(textBeforeHover);
      await page.screenshot({ path: evidencePath(testInfo, `terminal-link-underline-${theme}.png`) });

      const blank = await page.evaluate(() => {
        const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
        const metrics = window.__tracerProductTestDouble?.rendererMetrics();
        if (!canvas || !metrics) throw new Error("terminal blank cell is unavailable");
        const rect = canvas.getBoundingClientRect();
        return { x: rect.left + metrics.cellWidth * 2, y: rect.top + metrics.cellHeight * 8 };
      });
      await page.mouse.move(blank.x, blank.y);
      await expect.poll(async () => (await linkAccentPixels(page, first)) + (await linkAccentPixels(page, second))).toBe(0);

      const modifier = theme === "ink" ? "Control" : "Meta";
      await page.keyboard.down(modifier);
      await expect.poll(() => linkAccentPixels(page, first)).toBeGreaterThan(0);
      await expect.poll(() => linkAccentPixels(page, second)).toBeGreaterThan(0);
      await page.keyboard.up(modifier);
      await expect.poll(async () => (await linkAccentPixels(page, first)) + (await linkAccentPixels(page, second))).toBe(0);

      for (const viewport of [{ width: 375, height: 667 }, { width: 1440, height: 900 }]) {
        await page.setViewportSize(viewport);
        const blankAtViewport = await page.evaluate(() => {
          const canvas = document.querySelector<HTMLCanvasElement>("#terminal-host canvas");
          const metrics = window.__tracerProductTestDouble?.rendererMetrics();
          if (!canvas || !metrics) throw new Error("terminal blank cell is unavailable");
          const rect = canvas.getBoundingClientRect();
          return { x: rect.left + metrics.cellWidth * 2, y: rect.top + metrics.cellHeight * 8 };
        });
        await page.mouse.move(blankAtViewport.x, blankAtViewport.y);
        await expect.poll(() => linkAccentPixels(page, first)).toBe(0);
        const textAtViewport = await linkTextPixels(page, first);
        const viewportPoint = await terminalLinkPoint(page, first);
        await page.mouse.move(viewportPoint.x, viewportPoint.y);
        await expect.poll(() => linkAccentPixels(page, first)).toBeGreaterThan(0);
        expect(await linkTextPixels(page, first)).toEqual(textAtViewport);
        await page.screenshot({ path: evidencePath(testInfo, `terminal-link-underline-${theme}-${viewport.width}.png`) });
      }
    } finally {
      await context.close();
    }
  }
});

test("touch tap opens a recognized terminal link", async ({ browser }) => {
  test.setTimeout(90_000);
  const context = await browser.newContext({ baseURL, viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
  await context.route("http://touch.example.test/**", (route) => route.fulfill({ status: 200, body: "opened" }));
  await context.addInitScript(() => {
    const calls: string[][] = [];
    (window as unknown as { __openCalls: string[][] }).__openCalls = calls;
    const nativeOpen = window.open.bind(window);
    window.open = ((...args: Parameters<typeof window.open>) => {
      calls.push(args.map(String));
      return nativeOpen(...args);
    }) as typeof window.open;
  });
  try {
    const page = await context.newPage();
    await openTerminal(page);
    const target = "http://touch.example.test/landing";
    const response = await context.request.post("/__mock/live-query-output", { data: { text: `\u001b[2J\u001b[H${target}` } });
    expect(response.ok()).toBe(true);
    await expect.poll(() => page.evaluate((expected) => window.__tracerProductTestDouble?.terminalLinks().some((link) => link.target === expected) ?? false, target)).toBe(true);
    const point = await terminalLinkPoint(page, target);
    const pageCount = context.pages().length;
    await page.touchscreen.tap(point.x, point.y);
    expect(await page.evaluate(() => (window as unknown as { __openCalls: string[][] }).__openCalls.at(-1))).toEqual([target, "_blank", "noopener,noreferrer"]);
    await expect.poll(() => context.pages().length).toBe(pageCount + 1);
    const popup = context.pages().find((candidate) => candidate !== page)!;
    await expect(popup).toHaveURL(target);
    await popup.close();
  } finally {
    await context.close();
  }
});

test("a plain tooltip keeps its wrapped layout after a link tooltip", async ({ browser }) => {
  test.setTimeout(90_000);
  const context = await browser.newContext({ baseURL, viewport: { width: 390, height: 844 } });
  try {
    const page = await context.newPage();
    await openTerminal(page);
    await page.evaluate(() => {
      const trigger = document.createElement("button");
      trigger.type = "button";
      trigger.id = "plain-tooltip-regression-trigger";
      trigger.dataset.tip = `https://plain.example.test/${"x".repeat(420)}`;
      trigger.style.cssText = "position:fixed;left:20px;top:32px;width:24px;height:24px;opacity:0;";
      document.body.append(trigger);
    });
    const trigger = page.locator("#plain-tooltip-regression-trigger");
    const measurePlainTooltip = () => page.evaluate(() => {
      const tip = document.querySelector<HTMLElement>(".tip");
      const label = document.querySelector<HTMLElement>(".tip-label:not(.is-leaving)");
      if (!tip || !label) throw new Error("plain tooltip is unavailable");
      const tipRect = tip.getBoundingClientRect();
      const labelRect = label.getBoundingClientRect();
      const style = getComputedStyle(label);
      return {
        width: tipRect.width,
        height: tipRect.height,
        labelWidth: labelRect.width,
        labelHeight: labelRect.height,
        lineHeight: Number.parseFloat(style.lineHeight),
        whiteSpace: style.whiteSpace,
        overflowWrap: style.overflowWrap,
        textOverflow: style.textOverflow,
        scrollWidth: label.scrollWidth,
        clientWidth: label.clientWidth,
      };
    });

    await trigger.hover();
    await expect(page.locator(".tip")).toBeVisible();
    const beforeLink = await measurePlainTooltip();
    await page.mouse.move(0, 0);

    const target = "https://login.example.test/sign-in";
    const response = await context.request.post("/__mock/live-query-output", {
      data: { text: `\u001b[2J\u001b[H\u001b]8;;${target}\u0007Sign in\u001b]8;;\u0007` },
    });
    expect(response.ok()).toBe(true);
    await expect.poll(() => page.evaluate((expected) => window.__tracerProductTestDouble?.terminalLinks().some((link) => link.target === expected) ?? false, target)).toBe(true);
    const point = await terminalLinkPoint(page, "Sign in");
    await page.mouse.move(point.x, point.y);
    await expect(page.locator(".tip-label:not(.is-leaving)")).toHaveText(target);
    await trigger.hover();
    await expect(page.locator(".tip-label:not(.is-leaving)")).toHaveText(`https://plain.example.test/${"x".repeat(420)}`);
    const afterLink = await measurePlainTooltip();

    // The link preview's two-line clamp must not leak: a plain label is laid out the same as before it, and (#310, TASTE "A tooltip
    // is as wide as its text") it wraps at the cap and shows all of its text instead of ending in an ellipsis.
    expect(afterLink).toEqual(beforeLink);
    expect(afterLink.whiteSpace).toBe("normal");
    expect(afterLink.overflowWrap).toBe("anywhere");
    expect(afterLink.textOverflow).not.toBe("ellipsis");
    expect(afterLink.labelHeight).toBeGreaterThan(afterLink.lineHeight * 2);
    expect(afterLink.scrollWidth).toBeLessThanOrEqual(afterLink.clientWidth + 1);
  } finally {
    await context.close();
  }
});
