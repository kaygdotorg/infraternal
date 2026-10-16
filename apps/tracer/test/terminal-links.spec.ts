/** Exercises terminal links through the production tracer and its real VT renderer. */
import { expect, test } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const baseURL = `http://localhost:${port}`;
const target = `https://links.example.test/oauth/authorize?client_id=web&state=${"s".repeat(420)}&redirect_uri=https%3A%2F%2Flinks.example.test%2Fcallback&response_type=code`;
const osc8Target = "https://links.example.test/actual-destination";

async function openTerminal(page: import("playwright/test").Page): Promise<void> {
  await page.setViewportSize({ width: 390, height: 844 });
  const reset = await page.context().request.post("/__mock/reset");
  const opened = await page.context().request.post("/__mock/open-terminal");
  expect([reset.status(), opened.status()]).toEqual([200, 200]);
  await page.goto("/?mock=1&proto=product&bg=none&fixture=none");
  await expect.poll(() => page.evaluate(() => window.__tracerProductTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
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
    await page.screenshot({ path: testInfo.outputPath("terminal-wrapped-link-hover.png") });
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
    await page.screenshot({ path: testInfo.outputPath("terminal-osc8-target-hover.png") });
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
