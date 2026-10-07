/** Exercises the gated windows prototype in the production build and saves core comparisons. */
import { mkdir, readFile, writeFile } from "node:fs/promises";
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

/** Saves a close crop that keeps the popover's anchor tail inside the review artifact. */
async function savePopoverCrop(testInfo: TestInfo, page: Page, width: number, height: number, theme: string, state: string, selector = ".window-popover"): Promise<string> {
  const target = page.locator(selector);
  const box = await target.boundingBox();
  if (!box) throw new Error(`Popover crop target is missing: ${selector}`);
  const side = selector === ".window-popover" ? await target.getAttribute("data-side") : null;
  const viewport = page.viewportSize();
  if (!viewport) throw new Error("Popover crop requires a fixed viewport");
  const left = Math.max(0, Math.floor(box.x - 10));
  const top = Math.max(0, Math.floor(box.y - (side === "bottom" ? 18 : 10)));
  const right = Math.min(viewport.width, Math.ceil(box.x + box.width + 10));
  const bottom = Math.min(viewport.height, Math.ceil(box.y + box.height + (side === "top" ? 18 : 10)));
  const path = resolve(outputDirectory, "popover-crops", `${width}x${height}-${theme}-${state}.png`);
  await mkdir(resolve(outputDirectory, "popover-crops"), { recursive: true });
  await page.screenshot({ path, clip: { x: left, y: top, width: right - left, height: bottom - top }, animations: "disabled" });
  await testInfo.attach(`${width}x${height}-${theme}-${state}-popover-crop`, { path, contentType: "image/png" });
  return path;
}

test("window popovers use the shared controls, fastfetch rows, and anchored tabs", async ({ browser }) => {
  const context = await browser.newContext({ baseURL: origin, viewport: { width: 1440, height: 900 } });
  try {
    const page = await context.newPage();
    await context.request.post("/__mock/open-terminal");
    await page.goto(`${origin}/?mock=1&proto=windows&theme=ink&bg=none&ui=sans`);
    await waitForAttached(page);
    await page.locator(".window-card[aria-current='true'] .window-host-pill").click();
    const details = page.getByRole("dialog", { name: "Window details" });
    await expect(details).toBeVisible();
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    const machineStyles = await details.evaluate((popover) => {
      const tablist = popover.querySelector<HTMLElement>(".window-info-tabs")!;
      const tabs = [...tablist.querySelectorAll<HTMLButtonElement>("[role='tab']")];
      const tabStyle = tabs.map((tab) => getComputedStyle(tab));
      const row = popover.querySelector<HTMLButtonElement>(".machine-fact")!;
      const rowStyle = getComputedStyle(row);
      const mark = popover.querySelector<SVGElement>(".machine-os-mark")!;
      const markStyle = getComputedStyle(mark);
      const tail = getComputedStyle(popover, "::before");
      const popoverStyle = getComputedStyle(popover);
      const accentProbe = document.createElement("span");
      accentProbe.style.color = "var(--accent)";
      popover.append(accentProbe);
      const accentColor = getComputedStyle(accentProbe).color;
      accentProbe.remove();
      const tabRect = tablist.getBoundingClientRect();
      const popoverRect = popover.getBoundingClientRect();
      const anchorRect = document.querySelector<HTMLElement>(".window-card[aria-current='true'] .window-host-pill")!.getBoundingClientRect();
      const tailX = Number.parseFloat(popoverStyle.getPropertyValue("--tail-x"));
      const capsule = tablist.querySelector<HTMLElement>(".segmented-capsule")!;
      const capsuleStyle = getComputedStyle(capsule);
      const capsuleWidth = capsuleStyle.width;
      const factRows = [...popover.querySelectorAll<HTMLButtonElement>(".machine-fact")];
      const metricCopies = [...popover.querySelectorAll<HTMLButtonElement>(".machine-metric-copy")];
      return {
        allButtonsReset: [...popover.querySelectorAll<HTMLButtonElement>("button")].every((button) => getComputedStyle(button).appearance === "none"),
        allFactsNoChrome: factRows.every((fact) => getComputedStyle(fact).borderTopWidth === "0px" && getComputedStyle(fact).backgroundColor === "rgba(0, 0, 0, 0)"),
        tabAppearance: tabStyle.map((style) => style.appearance),
        tabBorder: tabStyle.map((style) => style.borderTopWidth),
        tabWidths: tabStyle.map((style) => style.width),
        tabHeights: tabStyle.map((style) => style.height),
        selectedCapsuleWidth: capsuleWidth,
        selectedCapsuleBorder: capsuleStyle.borderTopWidth,
        tabTrayRadius: getComputedStyle(tablist).borderRadius,
        tabsCentered: Math.abs((tabRect.left + tabRect.right) / 2 - (popoverRect.left + popoverRect.right) / 2) < 1,
        tailAlignment: Math.abs(popoverRect.left + tailX - (anchorRect.left + anchorRect.right) / 2),
        factAppearance: rowStyle.appearance,
        factBorder: rowStyle.borderTopWidth,
        factBackground: rowStyle.backgroundColor,
        factSwapAtEnd: factRows.every((fact) => fact.lastElementChild?.matches(".swap") === true && Boolean(fact.querySelector(".swap .is-done"))),
        metricCopyTicks: metricCopies.every((button) => button.lastElementChild?.matches(".swap") === true),
        metricHeight: getComputedStyle(popover.querySelector<HTMLElement>(".machine-metric-track")!).height,
        markFill: markStyle.fill,
        markStroke: markStyle.stroke,
        markColor: markStyle.color,
        accentColor,
        tailContent: tail.content,
        tailMatchesSurface: tail.backgroundColor === popoverStyle.backgroundColor,
        tailZIndex: tail.zIndex,
        originY: popoverStyle.transformOrigin.split(" ")[1],
        side: popover.dataset.side,
      };
    });
    expect(machineStyles).toMatchObject({
      tabAppearance: ["none", "none", "none"],
      tabBorder: ["0px", "0px", "0px"],
      tabWidths: ["56px", "56px", "56px"],
      tabHeights: ["44px", "44px", "44px"],
      selectedCapsuleWidth: "56px",
      selectedCapsuleBorder: "0px",
      tabTrayRadius: "999px",
      tabsCentered: true,
      allButtonsReset: true,
      allFactsNoChrome: true,
      factAppearance: "none",
      factBorder: "0px",
      factBackground: "rgba(0, 0, 0, 0)",
      factSwapAtEnd: true,
      metricCopyTicks: true,
      metricHeight: "3px",
      markStroke: "none",
      tailContent: "\"\"",
      tailMatchesSurface: true,
      tailZIndex: "0",
      side: "bottom",
      originY: "0px",
    });
    expect(machineStyles.tailAlignment).toBeLessThanOrEqual(1);
    expect(machineStyles.markFill).toBe(machineStyles.markColor);
    expect(machineStyles.markColor).toBe(machineStyles.accentColor);
    const copiedFact = details.locator(".machine-fact").first();
    const copiedValue = await copiedFact.locator(".machine-value").textContent();
    await copiedFact.click();
    await expect(copiedFact).toHaveAttribute("data-done", "");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(copiedValue);

    await page.keyboard.press("Escape");
    await page.locator(".window-card[aria-current='true'] [data-window-action='sessions']").click();
    const manager = page.getByRole("dialog", { name: "Window details" });
    const managerStyles = await manager.evaluate((popover) => {
      const row = getComputedStyle(popover.querySelector<HTMLElement>(".window-session-row")!);
      const main = getComputedStyle(popover.querySelector<HTMLElement>(".window-session-main")!);
      const action = getComputedStyle(popover.querySelector<HTMLElement>(".window-session-row-actions button")!);
      return {
        allButtonsReset: [...popover.querySelectorAll<HTMLButtonElement>("button")].every((button) => getComputedStyle(button).appearance === "none"),
        rowBorder: row.borderTopWidth,
        rowBackground: row.backgroundColor,
        mainAppearance: main.appearance,
        mainBorder: main.borderTopWidth,
        mainBackground: main.backgroundColor,
        actionAppearance: action.appearance,
        actionBackground: action.backgroundColor,
      };
    });
    expect(managerStyles).toEqual({
      allButtonsReset: true,
      rowBorder: "0px",
      rowBackground: "rgba(0, 0, 0, 0)",
      mainAppearance: "none",
      mainBorder: "0px",
      mainBackground: "rgba(0, 0, 0, 0)",
      actionAppearance: "none",
      actionBackground: "rgba(0, 0, 0, 0)",
    });
  } finally {
    await context.close();
  }
});

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
  const popoverCropPaths: string[] = [];

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
      const iconTint = await details.locator(".machine-os-mark").evaluate((mark) => {
        const style = getComputedStyle(mark);
        return { color: style.color, fill: style.fill, stroke: style.stroke, logoColor: getComputedStyle(mark.parentElement!).color };
      });
      expect(iconTint.fill).toBe(iconTint.color);
      expect(iconTint.stroke).toBe("none");
      expect(iconTint.color).toBe(iconTint.logoColor);
      expect(iconTint.color).not.toBe("rgb(0, 0, 0)");
      const tailGeometry = await details.evaluate((popover) => {
        const panel = popover.getBoundingClientRect();
        const anchor = document.querySelector<HTMLElement>(".window-card[aria-current='true'] .window-host-pill")!.getBoundingClientRect();
        const style = getComputedStyle(popover);
        const tail = getComputedStyle(popover, "::before");
        const tailX = Number.parseFloat(style.getPropertyValue("--tail-x"));
        const originY = Number.parseFloat(style.transformOrigin.split(" ")[1] ?? "NaN");
        return {
          alignment: Math.abs(panel.left + tailX - (anchor.left + anchor.right) / 2),
          growsFromTail: Math.abs(originY - (popover.dataset.side === "top" ? panel.height : 0)) <= 1,
          visibleTail: tail.content !== "none" && tail.zIndex === "0" && tail.backgroundColor === style.backgroundColor,
        };
      });
      expect(tailGeometry.growsFromTail).toBe(true);
      expect(tailGeometry.visibleTail).toBe(true);
      expect(tailGeometry.alignment).toBeLessThanOrEqual(1);
      const machineColumns = await details.locator(".machine-card-layout").evaluate((layout) => getComputedStyle(layout).gridTemplateColumns.split(" ").length);
      expect(machineColumns).toBe(combo.mobile ? 1 : 2);
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "machine", basePath));
      popoverCropPaths.push(await savePopoverCrop(testInfo, page, combo.width, combo.height, combo.theme, "machine"));

      await details.getByRole("button", { name: "More" }).click();
      await expect(details.locator(".machine-fact")).toHaveCount(14);
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "machine-more", basePath));
      popoverCropPaths.push(await savePopoverCrop(testInfo, page, combo.width, combo.height, combo.theme, "machine-more"));
      await details.getByRole("tab", { name: "Connection" }).click();
      await expect(details.locator(".connection-facts")).toContainText("WebSocket · TLS 1.3");
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "connection", basePath));
      popoverCropPaths.push(await savePopoverCrop(testInfo, page, combo.width, combo.height, combo.theme, "connection"));
      await details.getByRole("tab", { name: "Session" }).click();
      await expect(details.locator(".session-info-facts")).toContainText("1,842 lines");
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "session-info", basePath));
      popoverCropPaths.push(await savePopoverCrop(testInfo, page, combo.width, combo.height, combo.theme, "session-info"));
      await page.keyboard.press("Escape");

      await page.locator(".window-card[aria-current='true'] [data-window-action='sessions']").click();
      const manager = page.getByRole("dialog", { name: "Window details" });
      await expect(manager.locator(".window-session-row")).toHaveCount(2);
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "session-manager", basePath));
      popoverCropPaths.push(await savePopoverCrop(testInfo, page, combo.width, combo.height, combo.theme, "session-manager"));
      const endAction = manager.locator(".window-session-row-actions [data-manager-action='end']").first();
      await endAction.hover();
      await endAction.click({ timeout: 5_000 });
      const ending = page.getByRole("dialog", { name: "End session?" });
      await expect(ending).toContainText("vim is running in 'deploy'. End it?");
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "end-confirmation", basePath));
      popoverCropPaths.push(await savePopoverCrop(testInfo, page, combo.width, combo.height, combo.theme, "end-confirmation", ".window-end-card"));
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
      popoverCropPaths.push(await savePopoverCrop(testInfo, page, combo.width, combo.height, combo.theme, "share-card", ".window-share-sheet"));
      await page.locator("[data-share-ips]").check();
      await expect(page.locator(".window-share-card")).toBeVisible();
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "share-card-with-ips", basePath));
      popoverCropPaths.push(await savePopoverCrop(testInfo, page, combo.width, combo.height, combo.theme, "share-card-with-ips", ".window-share-sheet"));
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
      popoverCropPaths.push(await savePopoverCrop(testInfo, page, combo.width, combo.height, combo.theme, "promotion-session-activity"));

      await page.keyboard.press("Escape");
      await page.keyboard.press("Escape");
      await page.locator(".window-card[aria-current='true'] [data-window-action='sessions']").click();
      await page.locator(".window-new-session").click();
      await expect(page.locator(".capsule-session")).toHaveText("shell-3");
      await expect(page.locator(".window-card[aria-current='true']")).toHaveAttribute("data-session-id", /edge-arm-shell-3/);
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "new-shell", basePath));
      await page.locator(".window-card[aria-current='true'] [data-window-action='sessions']").click();
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "session-manager-new-shell", basePath));
      popoverCropPaths.push(await savePopoverCrop(testInfo, page, combo.width, combo.height, combo.theme, "session-manager-new-shell"));
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
  expect(popoverCropPaths).toHaveLength(40);
  await writeFile(resolve(outputDirectory, "manifest.txt"), [...screenshotPaths, ...popoverCropPaths].join("\n") + "\n");
  console.log(`Windows prototype side-by-side screenshots (production build):\n${screenshotPaths.join("\n")}`);
  console.log(`Windows prototype popover close crops:\n${popoverCropPaths.join("\n")}`);
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
