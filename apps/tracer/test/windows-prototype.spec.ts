/** Exercises the gated windows prototype in the production build and saves core comparisons. */
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test, type Browser, type BrowserContext, type Page, type TestInfo } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4173");
const origin = `http://localhost:${port}`;
const outputDirectory = resolve(process.cwd(), "test-results", "windows-prototype");

async function waitForAttached(page: Page): Promise<void> {
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-connected", "true", { timeout: 30_000 });
  await expect(page.locator("#rtt")).toHaveText(/^\d+ ms$/, { timeout: 10_000 });
}

async function openTerminal(context: BrowserContext, page: Page, query: string): Promise<void> {
  await context.request.post("/__mock/open-terminal");
  await page.goto(`${origin}/${query}`);
  await waitForAttached(page);
}

async function saveComparison(
  browser: Browser,
  testInfo: TestInfo,
  page: Page,
  width: number,
  height: number,
  theme: string,
  state: string,
  basePath: string,
): Promise<string> {
  const prototypePath = resolve(outputDirectory, `${width}x${height}-${theme}-${state}-prototype.png`);
  await mkdir(outputDirectory, { recursive: true });
  await page.screenshot({ path: prototypePath, animations: "disabled" });
  const [base, prototype] = await Promise.all([readFile(basePath), readFile(prototypePath)]);
  const compositeContext = await browser.newContext({ viewport: { width: width * 2, height: height + 32 }, deviceScaleFactor: 1 });
  try {
    const composite = await compositeContext.newPage();
    await composite.setContent(`<!doctype html><html><head><style>
      *{box-sizing:border-box}html,body{margin:0;width:${width * 2}px;height:${height + 32}px;background:#101113;color:#e6e7e9;font:500 11px/32px ui-monospace,monospace}
      header{display:grid;grid-template-columns:${width}px ${width}px;height:32px;background:#191a1d}
      header span{padding:0 12px}main{display:grid;grid-template-columns:${width}px ${width}px;width:${width * 2}px;height:${height}px}
      img{display:block;width:${width}px;height:${height}px}
    </style></head><body><header><span>Deployed core · ${theme} · ${width}×${height}</span><span>Windows prototype · ${state}</span></header>
    <main><img alt="Deployed core" src="data:image/png;base64,${base.toString("base64")}"><img alt="Windows prototype" src="data:image/png;base64,${prototype.toString("base64")}"></main></body></html>`);
    await composite.locator("img").evaluateAll((images) => Promise.all(images.map((image) => (image as HTMLImageElement).decode())));
    const comparisonPath = resolve(outputDirectory, `${width}x${height}-${theme}-${state}-comparison.png`);
    await composite.screenshot({ path: comparisonPath, animations: "disabled" });
    await testInfo.attach(`${width}x${height}-${theme}-${state}`, { path: comparisonPath, contentType: "image/png" });
    return comparisonPath;
  } finally {
    await compositeContext.close();
  }
}

test("gated windows, header, popovers, session manager, and phone controls", async ({ browser }, testInfo) => {
  test.setTimeout(600_000);
  await mkdir(outputDirectory, { recursive: true });
  const combinations = [
    { width: 1440, height: 900, theme: "ink", mobile: false },
    { width: 1440, height: 900, theme: "paper", mobile: false },
    { width: 393, height: 852, theme: "ink", mobile: true },
    { width: 393, height: 852, theme: "paper", mobile: true },
  ] as const;
  const screenshotPaths: string[] = [];

  for (const combo of combinations) {
    const context = await browser.newContext({
      baseURL: origin,
      viewport: { width: combo.width, height: combo.height },
      deviceScaleFactor: 1,
      ...(combo.mobile ? { isMobile: true, hasTouch: true } : {}),
    });
    try {
      await context.grantPermissions(["clipboard-read", "clipboard-write"]);
      const page = await context.newPage();
      await openTerminal(context, page, `?mock=1&theme=${combo.theme}&bg=mesh&ui=sans`);
      await expect(page.locator(".window-header")).toHaveCount(0);
      await expect(page.locator(".pane-card")).toHaveCount(1);
      const basePath = resolve(outputDirectory, `${combo.width}x${combo.height}-${combo.theme}-deployed-core.png`);
      await page.screenshot({ path: basePath, animations: "disabled" });

      await openTerminal(context, page, `?mock=1&proto=windows&theme=${combo.theme}&bg=mesh&ui=sans`);
      await expect(page.locator(".window-group")).toHaveCount(4);
      await expect(page.locator(".window-card")).toHaveCount(4);
      await expect(page.locator(".window-card[data-host-id='build-01'] .window-fake-output")).toBeVisible();
      await expect(page.locator(".window-card[data-host-id='build-01'] .window-fake-output")).toContainText("systemctl --failed");
      await expect(page.locator("#terminal-host")).toBeHidden();
      await expect(page.locator(".window-card[data-host-id='edge-arm'] .window-fake-output")).toContainText("apt-get upgrade");
      await expect(page.locator("#tree .bm-sec")).toHaveCount(4);
      await expect(page.locator("#tree .bm-icon svg")).toHaveCount(4);
      await expect(page.locator(".window-card[aria-current='true']")).toHaveCount(1);
      await expect(page.locator(".window-header-action")).toHaveCount(12);
      await expect(page.locator("#keybar [data-proto-control]")).toHaveCount(3);
      if (combo.mobile) {
        await expect(page.locator(".tabs")).toBeHidden();
        await expect(page.locator("#keybar")).toBeVisible();
        const columns = await page.locator(".window-group").evaluateAll((groups) => groups.map((group) => (group as HTMLElement).getBoundingClientRect().width));
        expect(columns.every((column) => column >= combo.width - 30)).toBe(true);
      } else {
        await expect(page.locator(".tabs")).toBeVisible();
        await expect(page.locator("#keybar")).toBeHidden();
      }
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "canvas", basePath));

      await page.keyboard.press("Control+k");
      await expect(page.locator("#palette")).toBeVisible();
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "palette", basePath));
      await page.keyboard.press("Escape");

      await page.locator("#sidebar-toggle").click();
      await expect(page.locator("#sidebar")).toBeVisible();
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "host-tree", basePath));
      await page.locator("#sidebar-toggle").click();

      const firstPill = page.locator(".window-card[aria-current='true'] .window-host-pill");
      await firstPill.click();
      const details = page.getByRole("dialog", { name: "Window details" });
      await expect(details).toBeVisible();
      await expect(details.locator(".machine-os-mark")).toBeVisible();
      const machineColumns = await details.locator(".machine-card-layout").evaluate((layout) => getComputedStyle(layout).gridTemplateColumns.split(" ").length);
      expect(machineColumns).toBe(combo.mobile ? 1 : 2);
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "machine", basePath));

      await details.getByRole("button", { name: "More" }).click();
      await expect(details.locator(".machine-fact")).toHaveCount(14);
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "machine-more", basePath));
      await details.getByRole("tab", { name: "Connection" }).click();
      await expect(details.locator(".connection-facts")).toContainText("WebSocket · TLS 1.3");
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "connection", basePath));
      await details.getByRole("tab", { name: "Session" }).click();
      await expect(details.locator(".session-info-facts")).toContainText("1,842 lines");
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "session-info", basePath));
      await page.keyboard.press("Escape");

      await page.locator(".window-card[aria-current='true'] [data-window-action='sessions']").click();
      const manager = page.getByRole("dialog", { name: "Window details" });
      await expect(manager.locator(".window-session-row")).toHaveCount(2);
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "session-manager", basePath));
      await manager.locator(".window-session-row-actions [data-manager-action='end']").first().click({ timeout: 5_000 });
      const ending = page.getByRole("dialog", { name: "End session?" });
      await expect(ending).toContainText("vim is running in 'deploy'. End it?");
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "end-confirmation", basePath));
      const cancelEnd = ending.getByRole("button", { name: "Keep session" });
      await cancelEnd.click({ timeout: 5_000 });

      if (combo.mobile) {
        await page.evaluate(() => {
          const row = document.querySelector<HTMLElement>(".window-session-row[data-session-id='deploy']")!;
          Object.defineProperty(row, "setPointerCapture", { value: () => undefined, configurable: true });
          const pointer = (type: string, x: number): PointerEvent => new PointerEvent(type, { bubbles: true, cancelable: true, pointerId: 91, pointerType: "touch", clientX: x, clientY: row.getBoundingClientRect().top + 20 });
          const startX = row.getBoundingClientRect().right - 20;
          row.dispatchEvent(pointer("pointerdown", startX));
          row.dispatchEvent(pointer("pointermove", startX - 92));
          row.dispatchEvent(pointer("pointerup", startX - 104));
        });
        await expect(page.getByRole("dialog", { name: "End session?" })).toContainText("vim is running in 'deploy'. End it?");
        await page.getByRole("dialog", { name: "End session?" }).getByRole("button", { name: "Keep session" }).click();
      }
      await manager.getByRole("button", { name: "Close session manager" }).click();

      await page.locator(".window-card[aria-current='true'] .window-host-pill").click();
      await page.getByRole("button", { name: "Share" }).click();
      await expect(page.getByRole("dialog", { name: "Share machine details" })).toBeVisible();
      await expect(page.locator("[data-share-ips]")).not.toBeChecked();
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "share-card", basePath));
      await page.locator("[data-share-ips]").check();
      await expect(page.locator(".window-share-card")).toBeVisible();
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "share-card-with-ips", basePath));
      await page.keyboard.press("Escape");
      await page.keyboard.press("Escape");

      await page.locator(".window-card[aria-current='true'] [data-window-action='split-vertical']").click();
      await expect(page.locator(".window-card")).toHaveCount(5);
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "split-vertical", basePath));
      await page.locator(".window-card[aria-current='true'] [data-window-action='split-horizontal']").click();
      await expect(page.locator(".window-card")).toHaveCount(6);
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "split-horizontal", basePath));

      if (combo.mobile) {
        await page.locator("#keybar [data-proto-control='overview']").click();
      } else {
        await page.keyboard.press("Control+k");
        await page.locator("#palette-input").fill("Window overview");
        await page.keyboard.press("Enter");
      }
      await expect(page.locator(".panes")).toHaveAttribute("data-overview", "true");
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "overview", basePath));
      if (combo.mobile) {
        await page.locator("#keybar [data-proto-control='overview']").click();
      } else {
        await page.keyboard.press("Control+k");
        await page.locator("#palette-input").fill("Window overview");
        await page.keyboard.press("Enter");
      }

      await page.keyboard.press("Control+k");
      await page.locator("#palette-input").fill("Simulate root promotion");
      await page.keyboard.press("Enter");
      const promotionMark = page.locator(".window-header[data-host-id='edge-arm'] .window-promotion-mark[data-state='running']");
      await expect(promotionMark).toBeVisible();
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "promotion-running", basePath));
      if (combo.mobile) {
        const markRect = await promotionMark.boundingBox();
        if (!markRect) throw new Error("The promotion mark has no touch target");
        const pointer = { pointerId: 64, pointerType: "touch", button: 0, clientX: markRect.x + markRect.width / 2, clientY: markRect.y + markRect.height / 2 };
        await promotionMark.dispatchEvent("pointerdown", pointer);
        await expect(page.locator(".tip-pos")).toHaveCSS("visibility", "visible", { timeout: 1_500 });
        await expect(page.locator(".tip-label:not(.is-leaving)")).toContainText("Upgrading to a root infraternal agent");
        screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "promotion-tooltip", basePath));
        await promotionMark.dispatchEvent("pointerup", pointer);
        await promotionMark.dispatchEvent("click", { detail: 1, button: 0 });
      } else {
        await promotionMark.hover();
        await expect(page.locator(".tip-pos")).toHaveCSS("visibility", "visible", { timeout: 1_500 });
        await expect(page.locator(".tip-label:not(.is-leaving)")).toContainText("Upgrading to a root infraternal agent");
        screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "promotion-tooltip", basePath));
      }
      await expect(page.locator(".window-header[data-host-id='edge-arm'] .window-promotion-mark[data-state='done']")).toBeVisible({ timeout: 5_000 });
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "promotion-done", basePath));

      await page.locator("#sidebar-toggle").click();
      await page.locator("#tree .bm-sec[data-id='edge-arm'] .bm-leaf").first().click();
      await page.locator("#sidebar-toggle").click();
      await page.locator(".window-card[aria-current='true'] .window-host-pill").click();
      await page.getByRole("tab", { name: "Session" }).click();
      await expect(page.locator(".session-activity")).toContainText("moved 2 sessions");
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "promotion-session-activity", basePath));

      await page.keyboard.press("Escape");
      await page.keyboard.press("Escape");
      await page.locator(".window-card[aria-current='true'] [data-window-action='sessions']").click();
      await page.locator(".window-new-session").click();
      await expect(page.locator(".capsule-session")).toHaveText("shell-3");
      await expect(page.locator(".window-card[aria-current='true']")).toHaveAttribute("data-session-id", /edge-arm-shell-3/);
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "new-shell", basePath));
      await page.locator(".window-card[aria-current='true'] [data-window-action='sessions']").click();
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "session-manager-new-shell", basePath));
      const newShellRow = page.locator(".window-session-row[data-session-id='edge-arm-shell-3']");
      await newShellRow.locator("[data-manager-action='rename']").click();
      const renameInput = newShellRow.locator(".window-rename-input");
      await renameInput.fill("scratch");
      await renameInput.press("Enter");
      await expect(page.locator(".tabs")).toContainText("scratch");
      await page.locator(".window-session-row[data-session-id='edge-arm-shell-3'] [data-manager-action='beside']").click();
      await expect(page.locator(".window-card")).toHaveCount(7);
      await expect(page.locator(".window-card[aria-current='true']")).toHaveAttribute("data-session-id", "edge-arm-shell-3");

      await page.goto(`${origin}/?mock=1&theme=${combo.theme}&bg=mesh&ui=sans`);
      await waitForAttached(page);
      await expect(page.locator(".window-header")).toHaveCount(0);
      await expect(page.locator(".pane-card")).toHaveCount(1);
    } finally {
      await context.close();
    }
  }

  expect(screenshotPaths).toHaveLength(80);
  console.log(`Windows prototype side-by-side screenshots (production build):\n${screenshotPaths.join("\n")}`);
});

test("prototype has zero idle intervals at four-host, eight-session fixture scale", async ({ browser }) => {
  const context = await browser.newContext({ baseURL: origin, viewport: { width: 1440, height: 900 } });
  try {
    const page = await context.newPage();
    await page.addInitScript(() => {
      const active = new Set<number>();
      const originalSet = window.setInterval;
      const originalClear = window.clearInterval;
      window.setInterval = function (handler: TimerHandler, timeout?: number, ...args: unknown[]) {
        const id = Reflect.apply(originalSet, window, [handler, timeout, ...args]) as number;
        active.add(id);
        return id;
      } as typeof window.setInterval;
      window.clearInterval = function (id) {
        active.delete(id as number);
        return Reflect.apply(originalClear, window, [id]);
      } as typeof window.clearInterval;
      Object.defineProperty(window, "__prototypeIntervalCount", { get: () => active.size });
    });
    await context.request.post("/__mock/open-terminal");
    await page.goto(`${origin}/?mock=1&proto=windows&theme=ink&bg=none&ui=sans`);
    await waitForAttached(page);
    // The terminal renderer parks after its existing 700 ms settling window [D112].
    await page.waitForTimeout(800);
    const idle = await page.evaluate(() => ({
      intervals: (window as Window & { __prototypeIntervalCount?: number }).__prototypeIntervalCount ?? -1,
      hosts: document.querySelectorAll(".window-group").length,
      sessions: document.querySelectorAll("#tree .bm-leaf").length,
      windows: document.querySelectorAll(".window-card").length,
      nodes: document.querySelectorAll("*").length,
      heapBytes: (performance as Performance & { memory?: { usedJSHeapSize: number } }).memory?.usedJSHeapSize ?? -1,
    }));
    expect(idle).toMatchObject({ intervals: 0, hosts: 4, sessions: 8, windows: 4 });
    await page.locator(".window-card[aria-current='true'] .window-host-pill").click();
    await expect.poll(() => page.evaluate(() => (window as Window & { __prototypeIntervalCount?: number }).__prototypeIntervalCount)).toBe(1);
    await page.keyboard.press("Escape");
    await expect.poll(() => page.evaluate(() => (window as Window & { __prototypeIntervalCount?: number }).__prototypeIntervalCount)).toBe(0);
    console.log(`Prototype UI scale: 4 hosts × 2 sessions, 4 windows, ${idle.nodes} DOM nodes, JS heap ${idle.heapBytes} bytes; active metric intervals 0 idle / 1 while machine details are open.`);
  } finally {
    await context.close();
  }
});
