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

test("mock windows deep link opens with an authenticated fake owner", async ({ browser }) => {
  const context = await browser.newContext({ baseURL: origin, viewport: { width: 393, height: 852 } });
  try {
    const page = await context.newPage();
    await page.goto(`${origin}/?mock=1&proto=windows&theme=ink&bg=none&ui=sans`);
    await expect(page.locator(".window-card")).toHaveCount(4, { timeout: 3_000 });
    await waitForAttached(page);
    const cookie = (await context.cookies(origin)).find((entry) => entry.name === "infraternal-mock-session");
    expect(cookie).toMatchObject({ httpOnly: true, secure: false });
  } finally {
    await context.close();
  }
});

test("window popovers use the shared controls, fastfetch rows, and anchored tabs", async ({ browser }) => {
  const context = await browser.newContext({ baseURL: origin, viewport: { width: 1440, height: 900 } });
  try {
    const page = await context.newPage();
    await openTerminal(context, page, "?mock=1&proto=windows&theme=ink&bg=none&ui=sans");
    await page.locator(".window-card[aria-current='true'] .window-host-pill").click();
    const details = page.getByRole("dialog", { name: "Window details" });
    await expect(details).toBeVisible();
    await context.grantPermissions(["clipboard-read", "clipboard-write"]);
    const machineStyles = await details.evaluate((popover) => {
      const tablist = popover.querySelector<HTMLElement>(".window-info-tabs")!;
      const tabs = [...tablist.querySelectorAll<HTMLButtonElement>("[role='tab']")];
      const tabStyle = tabs.map((tab) => getComputedStyle(tab));
      const row = popover.querySelector<HTMLElement>(".machine-fact")!;
      const key = row.querySelector<HTMLElement>(".machine-key")!;
      const value = row.querySelector<HTMLElement>(".machine-value")!;
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
      const topbarCapsule = document.querySelector<HTMLElement>(".capsule")!;
      const logo = popover.querySelector<HTMLElement>(".machine-logo")!;
      const osTitle = popover.querySelector<HTMLElement>(".machine-os-title");
      const firstFact = popover.querySelector<HTMLElement>(".machine-facts .machine-fact")!;
      const valueCells = [...popover.querySelectorAll<HTMLElement>(".machine-fact .machine-value, .machine-metric .machine-value")];
      const valueXs = valueCells.map((cell) => cell.getBoundingClientRect().left);
      const factRows = [...popover.querySelectorAll<HTMLElement>(".machine-fact, .machine-metric")];
      const factHeights = factRows.map((fact) => {
        const text = fact.querySelector<HTMLElement>(".machine-value-text");
        const lineHeight = Number.parseFloat(getComputedStyle(text ?? fact).lineHeight);
        return { height: fact.getBoundingClientRect().height, textHeight: text?.getBoundingClientRect().height ?? 0, lineHeight };
      });
      return {
        allButtonsReset: [...popover.querySelectorAll<HTMLButtonElement>("button")].every((button) => getComputedStyle(button).appearance === "none"),
        tabAppearance: tabStyle.map((style) => style.appearance),
        tabBorder: tabStyle.map((style) => style.borderTopWidth),
        tabWidths: tabStyle.map((style) => style.width),
        tabHeights: tabStyle.map((style) => style.height),
        selectedCapsuleWidth: capsuleStyle.width,
        selectedCapsuleBorder: capsuleStyle.borderTopWidth,
        tabTrayRadius: getComputedStyle(tablist).borderRadius,
        tabTrayHeight: tablist.getBoundingClientRect().height,
        topbarCapsuleHeight: topbarCapsule.getBoundingClientRect().height,
        headerPillHeight: document.querySelector<HTMLElement>(".window-card[aria-current='true'] .window-host-pill")!.getBoundingClientRect().height,
        tabsCentered: Math.abs((tabRect.left + tabRect.right) / 2 - (popoverRect.left + popoverRect.right) / 2) < 1,
        tailAlignment: Math.abs(popoverRect.left + tailX - (anchorRect.left + anchorRect.right) / 2),
        factAppearance: getComputedStyle(row).appearance,
        factBorder: getComputedStyle(row).borderTopWidth,
        factBackground: getComputedStyle(row).backgroundColor,
        copyIcons: popover.querySelectorAll(".machine-fact .is-idle path, .machine-fact .is-idle rect, .machine-fact .is-idle circle, .machine-fact .is-idle line, .machine-metric .is-idle path, .machine-metric .is-idle rect, .machine-metric .is-idle circle, .machine-metric .is-idle line, .machine-metric-copy").length,
        feedbackTicks: popover.querySelectorAll(".machine-value .swap .is-done").length,
        valueKeyFontSize: getComputedStyle(value).fontSize,
        keyFontSize: getComputedStyle(key).fontSize,
        machineColumns: getComputedStyle(popover.querySelector<HTMLElement>(".machine-card-layout") ?? firstFact.parentElement!).gridTemplateColumns.split(" ").length,
        logoAtTop: logo.getBoundingClientRect().bottom <= firstFact.getBoundingClientRect().top,
        logoCentered: Math.abs((logo.getBoundingClientRect().left + logo.getBoundingClientRect().right) / 2 - (popoverRect.left + popoverRect.right) / 2) < 2,
        osTitle: osTitle?.textContent?.trim() ?? "",
        valueColumnSpread: Math.max(...valueXs) - Math.min(...valueXs),
        factHeights,
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
    console.log(`Machine review layout at 1440x900: ${JSON.stringify(machineStyles)}`);
    expect(machineStyles).toMatchObject({
      tabAppearance: ["none", "none", "none"],
      tabBorder: ["0px", "0px", "0px"],
      tabWidths: ["56px", "56px", "56px"],
      tabHeights: ["30px", "30px", "30px"],
      selectedCapsuleWidth: "56px",
      selectedCapsuleBorder: "0px",
      tabTrayRadius: "999px",
      tabTrayHeight: 38,
      tabsCentered: true,
      allButtonsReset: true,
      headerPillHeight: 36,
      topbarCapsuleHeight: 38,
      factAppearance: "none",
      factBorder: "0px",
      factBackground: "rgba(0, 0, 0, 0)",
      copyIcons: 0,
      feedbackTicks: 11,
      valueKeyFontSize: "16px",
      keyFontSize: "14px",
      machineColumns: 1,
      logoAtTop: true,
      logoCentered: true,
      osTitle: "Ubuntu 24.04.2 LTS",
      valueColumnSpread: 0,
      metricHeight: "3px",
      markStroke: "none",
      tailContent: "\"\"",
      tailMatchesSurface: true,
      tailZIndex: "0",
      side: "bottom",
      originY: "0px",
    });
    expect(machineStyles.factHeights.every(({ height, textHeight, lineHeight }) => height >= 44 && (textHeight > lineHeight + 1 ? height <= textHeight + 18 : height <= 52))).toBe(true);
    expect(machineStyles.tailAlignment).toBeLessThanOrEqual(1);
    expect(machineStyles.markFill).toBe(machineStyles.markColor);
    expect(machineStyles.markColor).toBe(machineStyles.accentColor);
    const copiedValueCell = details.locator(".machine-fact .machine-value").first();
    const copiedValue = await copiedValueCell.locator(".machine-value-text").textContent();
    await copiedValueCell.click();
    await expect(copiedValueCell).toHaveAttribute("data-done", "");
    await expect(copiedValueCell.locator(".swap .is-done")).toHaveCSS("opacity", "1");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(copiedValue);
    await expect(page.locator(".tip-label:not(.is-leaving)")).toHaveText("Copied");

    const layoutSpread = async (selector: string): Promise<number> => details.locator(selector).evaluateAll((cells) => {
      const positions = cells.map((cell) => cell.getBoundingClientRect().left);
      return positions.length ? Math.max(...positions) - Math.min(...positions) : 0;
    });
    expect(await layoutSpread(".machine-fact .machine-value, .machine-metric .machine-value")).toBeLessThanOrEqual(1);
    for (const [tab, facts] of [["Connection", ".connection-facts"], ["Session", ".session-info-facts"]] as const) {
      await details.getByRole("tab", { name: tab }).click();
      expect(await layoutSpread(`${facts} .machine-value`)).toBeLessThanOrEqual(1);
      const sharedGrid = await details.locator(facts).evaluate((root) => {
        const rows = [...root.querySelectorAll<HTMLElement>(".machine-fact")];
        const values = rows.map((row) => row.querySelector<HTMLElement>(".machine-value")!);
        const keys = rows.map((row) => row.querySelector<HTMLElement>(".machine-key")!);
        const valueSizes = values.map((value) => getComputedStyle(value).fontSize);
        const keySizes = keys.map((key) => getComputedStyle(key).fontSize);
        const measures = rows.map((row) => {
          const text = row.querySelector<HTMLElement>(".machine-value-text")!;
          const lineHeight = Number.parseFloat(getComputedStyle(text).lineHeight);
          const textHeight = text.getBoundingClientRect().height;
          return { rowHeight: row.getBoundingClientRect().height, textHeight, lineHeight };
        });
        return { spread: Math.max(...values.map((value) => value.getBoundingClientRect().left)) - Math.min(...values.map((value) => value.getBoundingClientRect().left)), valueSizes, keySizes, measures };
      });
      expect(sharedGrid.spread).toBeLessThanOrEqual(1);
      expect(sharedGrid.valueSizes.every((size) => size === "16px")).toBe(true);
      expect(sharedGrid.keySizes.every((size) => size === "14px")).toBe(true);
      expect(sharedGrid.measures.every(({ rowHeight, textHeight, lineHeight }) => rowHeight >= 44 && (textHeight > lineHeight + 1 ? rowHeight <= textHeight + 18 : rowHeight <= 52))).toBe(true);
    }

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

test("copying a value needs one desktop click or two touch taps", async ({ browser }) => {
  const touch = await browser.newContext({
    baseURL: origin,
    viewport: { width: 393, height: 852 },
    deviceScaleFactor: 1,
    isMobile: true,
    hasTouch: true,
  });
  try {
    await touch.grantPermissions(["clipboard-read", "clipboard-write"]);
    const page = await touch.newPage();
    await openTerminal(touch, page, "?mock=1&proto=windows&theme=ink&bg=none&ui=sans");
    await page.locator(".window-card[aria-current='true'] .window-host-pill").click();
    const value = page.locator(".window-popover .machine-value").first();
    await expect(value).toHaveCSS("touch-action", "manipulation");
    await expect(value).toHaveCSS("user-select", "none");
    const visibleValue = await value.locator(".machine-value-text").textContent();
    const bounds = await value.boundingBox();
    if (!bounds) throw new Error("The machine value has no touch target");
    const x = bounds.x + bounds.width / 2;
    const y = bounds.y + bounds.height / 2;
    await page.evaluate(() => navigator.clipboard.writeText("unchanged until the second tap"));
    await page.touchscreen.tap(x, y);
    await expect(value).not.toHaveAttribute("data-done");
    await page.touchscreen.tap(x, y);
    await expect(value).toHaveAttribute("data-done", "");
    await expect(page.locator(".tip-label:not(.is-leaving)")).toHaveText("Copied");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(visibleValue);
  } finally {
    await touch.close();
  }

  const desktop = await browser.newContext({ baseURL: origin, viewport: { width: 1440, height: 900 } });
  try {
    await desktop.grantPermissions(["clipboard-read", "clipboard-write"]);
    const page = await desktop.newPage();
    await openTerminal(desktop, page, "?mock=1&proto=windows&theme=ink&bg=none&ui=sans");
    await page.locator(".window-card[aria-current='true'] .window-host-pill").click();
    const value = page.locator(".window-popover .machine-value").first();
    const visibleValue = await value.locator(".machine-value-text").textContent();
    await value.click();
    await expect(value).toHaveAttribute("data-done", "");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(visibleValue);
  } finally {
    await desktop.close();
  }
});

test("gated windows, header, popovers, session manager, and phone controls", async ({ browser }, testInfo) => {
  test.setTimeout(600_000);
  await mkdir(outputDirectory, { recursive: true });
  const combinations = [
    { width: 375, height: 667, theme: "ink", mobile: true },
    { width: 375, height: 667, theme: "paper", mobile: true },
    { width: 393, height: 852, theme: "ink", mobile: true },
    { width: 393, height: 852, theme: "paper", mobile: true },
    { width: 1440, height: 900, theme: "ink", mobile: false },
    { width: 1440, height: 900, theme: "paper", mobile: false },
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
      const capturePopover = async (state: string, selector = ".window-popover"): Promise<void> => {
        const coreStates = ["machine", "machine-more", "connection", "session-info", "session-manager", "end-confirmation"];
        if (coreStates.includes(state) || (state === "share-card" && combo.width !== 375)) {
          popoverCropPaths.push(await savePopoverCrop(testInfo, page, combo.width, combo.height, combo.theme, state, selector));
        }
      };
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
      await expect(details.locator(".machine-fact")).toHaveCount(8);
      await expect(details.locator(".machine-fact .is-idle path, .machine-fact .is-idle rect, .machine-fact .is-idle circle, .machine-fact .is-idle line, .machine-metric .is-idle path, .machine-metric .is-idle rect, .machine-metric .is-idle circle, .machine-metric .is-idle line, .machine-metric-copy")).toHaveCount(0);
      await expect(details.locator(".machine-os-title .machine-value-text")).toHaveText("Ubuntu 24.04.2 LTS");
      const machineValues = await details.locator(".machine-facts .machine-value-text").allTextContents();
      expect(machineValues).toContain("ThinkCentre M90q Gen 3");
      expect(machineValues).toContain("i5-12500T · 12 cores");
      expect(machineValues).toContain("root");
      expect(machineValues).toContain("Podman 5.0 · BuildKit 0.16");
      const compactValues = await details.locator(".machine-facts .machine-fact").evaluateAll((rows) => {
        const labels = new Set(["Model", "CPU", "Agent mode", "Engines"]);
        return rows.filter((row) => labels.has(row.querySelector<HTMLElement>(".machine-key")!.textContent ?? ""))
          .map((row) => {
          const text = row.querySelector<HTMLElement>(".machine-value-text")!;
          return {
            key: row.querySelector<HTMLElement>(".machine-key")!.textContent,
            value: text.textContent,
            oneLine: text.getBoundingClientRect().height <= Number.parseFloat(getComputedStyle(text).lineHeight) + 1,
            fitsValueColumn: text.scrollWidth <= text.clientWidth + 1,
          };
        });
      });
      expect(compactValues.map(({ key, value }) => ({ key, value }))).toEqual([
        { key: "Model", value: "ThinkCentre M90q Gen 3" },
        { key: "CPU", value: "i5-12500T · 12 cores" },
        { key: "Agent mode", value: "root" },
        { key: "Engines", value: "Podman 5.0 · BuildKit 0.16" },
      ]);
      expect(compactValues.find(({ key }) => key === "Agent mode")?.oneLine).toBe(true);
      if (combo.width >= 1440) {
        expect(compactValues.filter(({ key }) => key === "Model" || key === "CPU").every(({ oneLine }) => oneLine)).toBe(true);
      }
      expect(compactValues.every(({ fitsValueColumn }) => fitsValueColumn)).toBe(true);
      const assertFactGrid = async (selector: string): Promise<void> => {
        const geometry = await details.locator(selector).evaluate((root) => {
          const values = [...root.querySelectorAll<HTMLElement>(".machine-fact .machine-value, .machine-metric .machine-value")];
          const keys = [...root.querySelectorAll<HTMLElement>(".machine-fact .machine-key, .machine-metric .machine-key")];
          const rows = [...root.querySelectorAll<HTMLElement>(".machine-fact, .machine-metric")];
          const rowsFit = rows.every((row) => {
            const text = row.querySelector<HTMLElement>(".machine-value-text")!;
            const textHeight = text.getBoundingClientRect().height;
            const lineHeight = Number.parseFloat(getComputedStyle(text).lineHeight);
            const rowHeight = row.getBoundingClientRect().height;
            return rowHeight >= 44 && (textHeight > lineHeight + 1 ? rowHeight <= textHeight + 18 : rowHeight <= 52);
          });
          return {
            spread: values.length ? Math.max(...values.map((value) => value.getBoundingClientRect().left)) - Math.min(...values.map((value) => value.getBoundingClientRect().left)) : 0,
            valueSizes: values.map((value) => getComputedStyle(value).fontSize),
            keySizes: keys.map((key) => getComputedStyle(key).fontSize),
            rowsFit,
          };
        });
        expect(geometry.spread).toBeLessThanOrEqual(1);
        expect(geometry.valueSizes.every((size) => size === "16px")).toBe(true);
        expect(geometry.keySizes.every((size) => size === "14px")).toBe(true);
        expect(geometry.rowsFit).toBe(true);
      };
      const assertCapsuleTracksTab = async (): Promise<void> => {
        await expect.poll(() => details.evaluate((popover) => {
          const capsule = popover.querySelector<HTMLElement>(".segmented-capsule")!.getBoundingClientRect();
          const selected = popover.querySelector<HTMLElement>('[role="tab"][aria-selected="true"]')!.getBoundingClientRect();
          return Math.max(Math.abs(capsule.left - selected.left), Math.abs(capsule.right - selected.right));
        })).toBeLessThanOrEqual(1);
      };
      await assertFactGrid(".machine-content");
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
      const capsuleHeights = await details.evaluate((popover) => {
        const base = document.querySelector<HTMLElement>(".capsule")!;
        const hostPill = document.querySelector<HTMLElement>(".window-card[aria-current='true'] .window-host-pill")!;
        const tablist = popover.querySelector<HTMLElement>(".window-info-tabs")!;
        const touchHeight = (element: HTMLElement): number => {
          const rect = element.getBoundingClientRect();
          const before = getComputedStyle(element, "::before");
          const top = Number.parseFloat(before.top);
          const bottom = Number.parseFloat(before.bottom);
          return rect.height - (Number.isFinite(top) ? top : 0) - (Number.isFinite(bottom) ? bottom : 0);
        };
        return {
          base: base.getBoundingClientRect().height,
          host: hostPill.getBoundingClientRect().height,
          tray: tablist.getBoundingClientRect().height,
          hostTouch: touchHeight(hostPill),
          tabTouch: touchHeight(tablist.querySelector<HTMLElement>("[role='tab']")!),
        };
      });
      expect(capsuleHeights.host).toBeLessThanOrEqual(capsuleHeights.base);
      expect(capsuleHeights.tray).toBeLessThanOrEqual(capsuleHeights.base);
      if (combo.mobile) {
        expect(capsuleHeights.hostTouch).toBeGreaterThanOrEqual(44);
        expect(capsuleHeights.tabTouch).toBeGreaterThanOrEqual(44);
      }
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "machine", basePath));
      await capturePopover("machine");

      await details.getByRole("button", { name: "More" }).click();
      await expect(details.locator(".machine-fact")).toHaveCount(13);
      await assertFactGrid(".machine-content");
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "machine-more", basePath));
      await capturePopover("machine-more");
      await details.getByRole("tab", { name: "Connection" }).click();
      await expect(details.locator(".connection-facts")).toContainText("WebSocket · TLS 1.3");
      await assertFactGrid(".connection-facts");
      await assertCapsuleTracksTab();
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "connection", basePath));
      await capturePopover("connection");
      await details.getByRole("tab", { name: "Session" }).click();
      await expect(details.locator(".session-info-facts")).toContainText("1,842 lines");
      await assertFactGrid(".session-info-facts");
      await assertCapsuleTracksTab();
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "session-info", basePath));
      await capturePopover("session-info");
      await page.keyboard.press("Escape");

      await page.locator(".window-card[aria-current='true'] [data-window-action='sessions']").click();
      const manager = page.getByRole("dialog", { name: "Window details" });
      await expect(manager.locator(".window-session-row")).toHaveCount(2);
      await expect(manager.locator(".window-session-output").first()).toHaveCSS("font-size", "16px");
      await expect(manager.locator(".window-session-meta").first()).toHaveCSS("font-size", "14px");
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "session-manager", basePath));
      await capturePopover("session-manager");
      const endAction = manager.locator(".window-session-row-actions [data-manager-action='end']").first();
      await endAction.hover();
      await endAction.click({ timeout: 5_000 });
      const ending = page.getByRole("dialog", { name: "End session?" });
      await expect(ending).toContainText("vim is running in 'deploy'. End it?");
      screenshotPaths.push(await saveComparison(browser, testInfo, page, combo.width, combo.height, combo.theme, "end-confirmation", basePath));
      await capturePopover("end-confirmation", ".window-end-card");
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
      await capturePopover("share-card", ".window-share-sheet");
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

  expect(screenshotPaths).toHaveLength(120);
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
