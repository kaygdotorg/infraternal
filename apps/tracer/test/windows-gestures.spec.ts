/** Covers mobile canvas routing, tap activation, shared glass, and the compact key tray. */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test, type Browser, type BrowserContext, type Page, type TestInfo } from "playwright/test";
import { overlayMaterial, THEMES } from "../../../packages/ui/src/themes";

const port = Number(process.env.TRACER_TEST_PORT ?? "4671");
const origin = `http://localhost:${port}`;
const artifactDirectory = resolve(process.cwd(), "test-results/windows-prototype");

async function openPrototype(context: BrowserContext, page: Page, theme = "ink"): Promise<void> {
  await context.request.post("/__mock/open-terminal");
  await page.goto(`${origin}/?mock=1&proto=windows&theme=${theme}&bg=none&ui=sans`);
  await expect(page.locator(".window-card")).toHaveCount(4);
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-connected", "true");
}

async function putBusyTerminalBehindPopover(page: Page): Promise<void> {
  await page.locator(".window-fake-output").first().evaluate((node) => {
    const rows = Array.from({ length: 100 }, (_, index) =>
      `16:${String(index % 60).padStart(2, "0")}:42 infraternal-agent[991]: relay resumed · packet ${index + 1} · output bytes 1,024 · status connected`,
    );
    rows[50] = `${rows[50]} ${"stdout: " + "x".repeat(180)}`;
    node.textContent = rows.join("\n");
  });
}

type TouchPoint = { id: number; x: number; y: number };
type CDP = Awaited<ReturnType<BrowserContext["newCDPSession"]>>;

async function dispatchTouches(cdp: CDP, type: "touchStart" | "touchMove" | "touchEnd", points: TouchPoint[]): Promise<void> {
  await cdp.send("Input.dispatchTouchEvent", {
    type,
    touchPoints: points.map(({ id, x, y }) => ({ id, x: Math.round(x), y: Math.round(y), radiusX: 3, radiusY: 3, force: 1 })),
  });
}

async function touchTap(cdp: CDP, x: number, y: number, id = 1): Promise<void> {
  await dispatchTouches(cdp, "touchStart", [{ id, x, y }]);
  await dispatchTouches(cdp, "touchEnd", []);
}

async function touchDrag(cdp: CDP, start: TouchPoint[], end: TouchPoint[], frame?: () => Promise<void>): Promise<void> {
  await dispatchTouches(cdp, "touchStart", start);
  await new Promise((resolve) => setTimeout(resolve, 30));
  for (let step = 1; step <= 5; step += 1) {
    const points = start.map((point, index) => ({
      id: point.id,
      x: point.x + (end[index]!.x - point.x) * step / 5,
      y: point.y + (end[index]!.y - point.y) * step / 5,
    }));
    await dispatchTouches(cdp, "touchMove", points);
    if (frame) await frame();
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  await dispatchTouches(cdp, "touchEnd", []);
}

function touchContext(browser: Browser, viewport = { width: 393, height: 852 }): Promise<BrowserContext> {
  return browser.newContext({ baseURL: origin, viewport, deviceScaleFactor: 1, isMobile: true, hasTouch: true });
}

test("a tap activates an inactive window without focusing the terminal input", async ({ browser }) => {
  const context = await touchContext(browser);
  try {
    const page = await context.newPage();
    await openPrototype(context, page);
    await page.locator(".window-card[aria-current='true'] [data-window-action='split-vertical']").click();
    const cards = page.locator(".window-group[data-host-id='build-01'] .window-card");
    await expect(cards).toHaveCount(2);
    const inactive = cards.first();
    await expect(inactive).not.toHaveAttribute("aria-current", "true");
    const box = await inactive.locator(".window-fake-terminal").boundingBox();
    if (!box) throw new Error("The inactive terminal has no touch target");
    const cdp = await context.newCDPSession(page);
    await touchTap(cdp, box.x + box.width * 0.55, box.y + box.height * 0.65);
    await expect(inactive).toHaveAttribute("aria-current", "true");
    expect(await page.locator("#terminal-host").evaluate((node) => document.activeElement === node)).toBe(false);
    expect(await page.evaluate(() => document.scrollingElement?.scrollTop ?? -1)).toBe(0);

    const active = page.locator(".window-card[aria-current='true']");
    const activeBox = await active.locator(".window-fake-terminal").boundingBox();
    if (!activeBox) throw new Error("The active terminal has no touch target");
    await touchTap(cdp, activeBox.x + activeBox.width * 0.55, activeBox.y + activeBox.height * 0.65, 2);
    await expect(page.locator("#terminal-host")).not.toHaveAttribute("hidden", "");
    await expect.poll(() => page.locator("#terminal-host").evaluate((node) => document.activeElement === node)).toBe(true);
  } finally {
    await context.close();
  }
});

test("one finger scrolls and pans the terminal without chaining into the canvas", async ({ browser }) => {
  const context = await touchContext(browser);
  try {
    const page = await context.newPage();
    await openPrototype(context, page);
    await putBusyTerminalBehindPopover(page);
    const panes = page.locator(".panes");
    const terminal = page.locator(".window-card[aria-current='true'] .window-fake-terminal");
    await panes.evaluate((element) => { element.scrollLeft = 0; element.scrollTop = 0; });
    await terminal.evaluate((element) => { element.scrollTop = 0; element.scrollLeft = 0; });
    const box = await terminal.boundingBox();
    if (!box) throw new Error("The terminal has no touch scroll surface");
    const cdp = await context.newCDPSession(page);
    const x = box.x + box.width * 0.7;
    const y = box.y + box.height * 0.7;
    await touchDrag(cdp, [{ id: 1, x, y }], [{ id: 1, x, y: y - 180 }]);
    await expect.poll(() => terminal.evaluate((element) => element.scrollTop)).toBeGreaterThan(40);
    expect(await panes.evaluate((element) => element.scrollTop)).toBe(0);
    expect(await panes.evaluate((element) => element.scrollLeft)).toBe(0);

    const updated = await terminal.boundingBox();
    if (!updated) throw new Error("The terminal lost its touch scroll surface");
    await terminal.evaluate((element) => { element.scrollLeft = 0; });
    await touchDrag(cdp, [{ id: 2, x: updated.x + updated.width - 24, y: updated.y + updated.height * 0.45 }], [{ id: 2, x: updated.x + updated.width - 180, y: updated.y + updated.height * 0.45 }]);
    await expect.poll(() => terminal.evaluate((element) => element.scrollLeft)).toBeGreaterThan(40);
    expect(await panes.evaluate((element) => element.scrollLeft)).toBe(0);

    const end = await terminal.evaluate((element) => ({ top: element.scrollTop, height: element.clientHeight, scrollHeight: element.scrollHeight }));
    await terminal.evaluate((element) => { element.scrollTop = element.scrollHeight; });
    const edgeBox = await terminal.boundingBox();
    if (!edgeBox) throw new Error("The terminal lost its edge scroll surface");
    await touchDrag(cdp, [{ id: 3, x: edgeBox.x + 50, y: edgeBox.y + edgeBox.height * 0.7 }], [{ id: 3, x: edgeBox.x + 50, y: edgeBox.y + edgeBox.height * 0.35 }]);
    expect(await terminal.evaluate((element) => element.scrollTop)).toBeGreaterThanOrEqual(end.scrollHeight - end.height - 1);
    expect(await panes.evaluate((element) => element.scrollTop)).toBe(0);
    expect(await page.evaluate(() => document.scrollingElement?.scrollTop ?? -1)).toBe(0);
  } finally {
    await context.close();
  }
});

test("two fingers pan stacked windows and columns; pinch resizes type without panning", async ({ browser }, testInfo: TestInfo) => {
  const context = await touchContext(browser);
  try {
    const page = await context.newPage();
    await openPrototype(context, page);
    const panes = page.locator(".panes");
    await page.locator(".window-card[aria-current='true'] [data-window-action='split-horizontal']").click();
    const stacked = page.locator(".window-group[data-host-id='build-01'] .window-card");
    await expect(stacked).toHaveCount(2);
    await panes.evaluate((element) => { element.scrollLeft = 0; element.scrollTop = 0; element.style.scrollSnapType = "none"; });
    const firstBox = await stacked.first().boundingBox();
    const viewport = await panes.boundingBox();
    if (!firstBox || !viewport) throw new Error("The stacked canvas has no touch surface");
    const cdp = await context.newCDPSession(page);
    const x1 = firstBox.x + firstBox.width * 0.35;
    const x2 = firstBox.x + firstBox.width * 0.65;
    const y1 = firstBox.y + firstBox.height * 0.56;
    const y2 = firstBox.y + firstBox.height * 0.72;
    await touchDrag(cdp, [{ id: 1, x: x1, y: y1 }, { id: 2, x: x2, y: y2 }], [{ id: 1, x: x1, y: y1 - 230 }, { id: 2, x: x2, y: y2 - 230 }]);
    await expect.poll(() => panes.evaluate((element) => element.scrollTop)).toBeGreaterThan(80);
    const afterRelease = await panes.evaluate((element) => element.scrollTop);
    await page.waitForTimeout(120);
    expect(await panes.evaluate((element) => element.scrollTop)).toBeGreaterThan(afterRelease + 10);
    const lowerBox = await stacked.nth(1).boundingBox();
    if (!lowerBox) throw new Error("The lower window has no canvas position");
    expect(lowerBox.y).toBeLessThan(viewport.y + viewport.height);
    expect(lowerBox.y + lowerBox.height).toBeGreaterThan(viewport.y);
    expect(await page.evaluate(() => document.scrollingElement?.scrollTop ?? -1)).toBe(0);

    await panes.evaluate((element) => { element.scrollLeft = 0; element.scrollTop = 0; });
    const cardBox = await stacked.first().boundingBox();
    if (!cardBox) throw new Error("The visible first window has no touch surface");
    const centerY = cardBox.y + cardBox.height * 0.55;
    const startColumn = [{ id: 3, x: cardBox.x + cardBox.width * 0.65, y: centerY }, { id: 4, x: cardBox.x + cardBox.width * 0.65, y: centerY + 45 }];
    const endColumn = startColumn.map((point) => ({ ...point, x: point.x - 190 }));
    const frameDirectory = resolve(artifactDirectory, "gesture-frames");
    await mkdir(frameDirectory, { recursive: true });
    const framePaths: string[] = [];
    await touchDrag(cdp, startColumn, endColumn, async () => {
      const framePath = resolve(frameDirectory, `393x852-ink-two-finger-pan-${framePaths.length + 1}.png`);
      await page.screenshot({ path: framePath, animations: "disabled" });
      framePaths.push(framePath);
    });
    const frames = await Promise.all(framePaths.map((path) => readFile(path)));
    const stripData = await page.evaluate(async (sources) => {
      const images = await Promise.all(sources.map(async (source) => {
        const image = new Image();
        image.src = source;
        await image.decode();
        return image;
      }));
      const width = 393;
      const height = 852;
      const canvas = document.createElement("canvas");
      canvas.width = width * images.length;
      canvas.height = height;
      const context = canvas.getContext("2d");
      if (!context) throw new Error("A canvas is required to assemble the gesture frame strip");
      images.forEach((image, index) => context.drawImage(image, index * width, 0, width, height));
      return canvas.toDataURL("image/png");
    }, frames.map((frame) => `data:image/png;base64,${frame.toString("base64")}`));
    const stripPath = resolve(frameDirectory, "393x852-ink-two-finger-pan-strip.png");
    await writeFile(stripPath, Buffer.from(stripData.slice(stripData.indexOf(",") + 1), "base64"));
    await writeFile(resolve(frameDirectory, "manifest.txt"), [...framePaths, stripPath].join("\n") + "\n");
    await testInfo.attach("393x852-ink-two-finger-pan-strip", { path: stripPath, contentType: "image/png" });
    await expect.poll(() => panes.evaluate((element) => element.scrollLeft)).toBeGreaterThan(80);
    const nextGroup = await page.locator(".window-group[data-host-id='edge-arm']").boundingBox();
    if (!nextGroup) throw new Error("The next column has no canvas position");
    expect(nextGroup.x).toBeLessThan(viewport.x + viewport.width);
    expect(await page.evaluate(() => document.scrollingElement?.scrollTop ?? -1)).toBe(0);
  } finally {
    await context.close();
  }
});

test("pinch changes terminal font size without moving the canvas", async ({ browser }) => {
  const context = await touchContext(browser);
  try {
    const page = await context.newPage();
    await openPrototype(context, page);
    const panes = page.locator(".panes");
    const terminal = page.locator(".window-card[aria-current='true'] .window-fake-terminal");
    const before = Number.parseFloat(await terminal.evaluate((element) => getComputedStyle(element).fontSize));
    const box = await terminal.boundingBox();
    if (!box) throw new Error("The active terminal has no pinch surface");
    const cdp = await context.newCDPSession(page);
    const centerX = box.x + box.width * 0.55;
    const centerY = box.y + box.height * 0.55;
    await touchDrag(cdp,
      [{ id: 1, x: centerX - 20, y: centerY }, { id: 2, x: centerX + 20, y: centerY }],
      [{ id: 1, x: centerX - 70, y: centerY }, { id: 2, x: centerX + 70, y: centerY }],
    );
    const after = Number.parseFloat(await terminal.evaluate((element) => getComputedStyle(element).fontSize));
    expect(after).toBeGreaterThan(before + 1);
    expect(await panes.evaluate((element) => ({ left: element.scrollLeft, top: element.scrollTop }))).toEqual({ left: 0, top: 0 });
    expect(await page.evaluate(() => document.scrollingElement?.scrollTop ?? -1)).toBe(0);
  } finally {
    await context.close();
  }
});

test("desktop click activates, middle-drag pans the canvas, and Shift-wheel moves columns", async ({ browser }) => {
  const context = await browser.newContext({ baseURL: origin, viewport: { width: 1440, height: 900 } });
  try {
    const page = await context.newPage();
    await openPrototype(context, page);
    await page.locator(".window-card[aria-current='true'] [data-window-action='split-vertical']").click();
    const initialWindow = page.locator(".window-group[data-host-id='build-01'] .window-card").first();
    await expect(initialWindow).not.toHaveAttribute("aria-current", "true");
    await page.locator("#sidebar-toggle").focus();
    await initialWindow.locator(".window-fake-terminal").click({ position: { x: 140, y: 180 } });
    await expect(initialWindow).toHaveAttribute("aria-current", "true");
    expect(await page.locator("#terminal-host").evaluate((node) => document.activeElement === node)).toBe(false);
    await initialWindow.locator(".window-fake-terminal").click({ position: { x: 140, y: 180 } });
    await expect.poll(() => page.locator("#terminal-host").evaluate((node) => document.activeElement === node)).toBe(true);

    const panes = page.locator(".panes");
    const box = await panes.boundingBox();
    if (!box) throw new Error("The desktop canvas has no pointer surface");
    const x = box.x + box.width * 0.7;
    const y = box.y + box.height * 0.5;
    await page.mouse.move(x, y);
    await page.keyboard.down("Shift");
    await page.mouse.wheel(0, 700);
    await page.keyboard.up("Shift");
    await expect.poll(() => panes.evaluate((element) => element.scrollLeft)).toBeGreaterThan(60);

    await page.locator(".window-card[aria-current='true'] [data-window-action='split-horizontal']").click();
    const before = await panes.evaluate((element) => ({ left: element.scrollLeft, top: element.scrollTop }));
    await page.mouse.move(x, y);
    await page.mouse.down({ button: "middle" });
    await page.mouse.move(x - 700, y - 80, { steps: 5 });
    await page.mouse.up({ button: "middle" });
    await expect.poll(() => panes.evaluate((element) => element.scrollTop)).toBeGreaterThan(before.top + 30);
    await expect.poll(() => panes.evaluate((element) => element.scrollLeft)).toBeGreaterThan(before.left + 30);
    expect(await page.evaluate(() => document.scrollingElement?.scrollTop ?? -1)).toBe(0);
  } finally {
    await context.close();
  }
});

test("compact toolbar clears both canvas layouts and keeps 44px targets", async ({ browser }) => {
  const context = await touchContext(browser);
  try {
    const page = await context.newPage();
    const measure = async (prototype: boolean): Promise<{ gap: number; pillHeight: number; keyHeight: number; documentScroll: number }> => {
      await openPrototype(context, page);
      if (!prototype) {
        await context.request.post("/__mock/open-terminal");
        await page.goto(`${origin}/?mock=1&theme=ink&bg=none&ui=sans`);
        await expect(page.locator("#terminal-screen")).toHaveAttribute("data-connected", "true");
      }
      const card = page.locator(prototype ? ".window-card[aria-current='true']" : ".pane-card");
      await expect(card).toBeVisible();
      return page.evaluate((selector) => {
        const card = document.querySelector<HTMLElement>(selector)!;
        const tray = document.querySelector<HTMLElement>("#keybar .keytray")!;
        const key = document.querySelector<HTMLElement>("#keybar button:not([hidden])")!;
        return {
          gap: tray.getBoundingClientRect().top - card.getBoundingClientRect().bottom,
          pillHeight: tray.getBoundingClientRect().height,
          keyHeight: key.getBoundingClientRect().height,
          documentScroll: document.scrollingElement?.scrollTop ?? -1,
        };
      }, prototype ? ".window-card[aria-current='true']" : ".pane-card");
    };
    const prototype = await measure(true);
    expect(prototype.gap).toBeGreaterThanOrEqual(16);
    expect(prototype.pillHeight).toBe(48);
    expect(prototype.keyHeight).toBeGreaterThanOrEqual(44);
    expect(prototype.documentScroll).toBe(0);
    const core = await measure(false);
    expect(core.gap).toBeGreaterThanOrEqual(16);
    expect(core.pillHeight).toBe(48);
    expect(core.keyHeight).toBeGreaterThanOrEqual(44);
    expect(core.documentScroll).toBe(0);
  } finally {
    await context.close();
  }
});

test("shared glass, HIG typography, row targets, contrast and accessibility respond in both themes", async ({ browser }, testInfo: TestInfo) => {
  const channels = (hex: string): number[] => [1, 3, 5].map((index) => Number.parseInt(hex.slice(index, index + 2), 16));
  for (const [id, theme] of Object.entries(THEMES)) {
    const { surface } = overlayMaterial(theme);
    const foreground = theme.fg2;
    const luminance = (hex: string): number => channels(hex).map((channel) => channel / 255)
      .map((channel) => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4)
      .reduce((total, channel, index) => total + channel * [0.2126, 0.7152, 0.0722][index]!, 0);
    const pair = [luminance(foreground), luminance(surface)].sort((left, right) => right - left);
    expect((pair[0]! + 0.05) / (pair[1]! + 0.05), `${id} secondary label contrast`).toBeGreaterThanOrEqual(4.5);
  }

  const outputPaths: string[] = [];
  for (const theme of ["ink", "paper"]) {
    const context = await touchContext(browser);
    try {
      const page = await context.newPage();
      await openPrototype(context, page, theme);
      await putBusyTerminalBehindPopover(page);
      await page.locator(".window-card[aria-current='true'] .window-host-pill").click();
      const popover = page.locator(".window-popover");
      await expect(popover).toBeVisible();
      await expect(popover).toHaveAttribute("data-open", "true");
      await page.waitForTimeout(240);
      await expect.poll(async () => Number.parseFloat(/blur\(([\d.]+)px\)/.exec(
        await popover.evaluate((element) => getComputedStyle(element).backdropFilter),
      )?.[1] ?? "NaN")).toBeGreaterThan(19.5);
      const material = await popover.evaluate((element) => {
        const style = getComputedStyle(element);
        const value = element.querySelector<HTMLElement>(".machine-value")!;
        const key = element.querySelector<HTMLElement>(".machine-key")!;
        const tab = element.querySelector<HTMLElement>("[role='tab']")!;
        const tabTarget = tab.getBoundingClientRect();
        const tabHit = getComputedStyle(tab, "::before");
        const row = element.querySelector<HTMLElement>(".machine-fact")!;
        const target = value.getBoundingClientRect();
        return {
          shared: element.classList.contains("ui-overlay-surface"),
          overlaySize: element.dataset.overlaySize,
          shadow: style.boxShadow,
          backdrop: style.backdropFilter,
          background: style.backgroundColor,
          blurAlpha: Number(style.backgroundColor.match(/,\s*([\d.]+)\)$/)?.[1] ?? 0),
          valueSize: getComputedStyle(value).fontSize,
          keySize: getComputedStyle(key).fontSize,
          keyWeight: getComputedStyle(key).fontWeight,
          keySpacing: getComputedStyle(key).letterSpacing,
          keyColor: getComputedStyle(key).color,
          contrastToken: getComputedStyle(element).getPropertyValue("--fg-2").trim(),
          rowHeight: row.getBoundingClientRect().height,
          valueHeight: target.height,
          valueHitHeight: target.height,
          tabHeight: tabTarget.height,
          tabHitHeight: tabTarget.height - Number.parseFloat(tabHit.top) - Number.parseFloat(tabHit.bottom),
          iconStroke: getComputedStyle(tab.querySelector("svg")!).strokeWidth,
          transition: style.transition,
          transitionDuration: style.transitionDuration,
          easing: style.transitionTimingFunction,
          origin: style.transformOrigin,
          hasTickPrimitive: Boolean(value.querySelector(".swap .is-done")),
        };
      });
      console.log(`${theme} popover material: ${JSON.stringify(material)}`);
      expect(material).toMatchObject({
        shared: true,
        overlaySize: "large",
        valueSize: "16px",
        keySize: "14px",
        tabHitHeight: 44,
        hasTickPrimitive: true,
      });
      const blurRadius = Number.parseFloat(/blur\(([\d.]+)px\)/.exec(material.backdrop)?.[1] ?? "NaN");
      expect(blurRadius).toBeGreaterThanOrEqual(19.5);
      expect(blurRadius).toBeLessThanOrEqual(20.5);
      expect(material.backdrop).toContain("saturate(1.8)");
      expect(material.shadow).toContain("0px 1px 0px 0px inset");
      expect(material.shadow).toMatch(/(24px 56px -10px|20px 48px -8px)/);
      expect(material.rowHeight).toBeGreaterThanOrEqual(44);
      expect(material.valueHitHeight).toBeGreaterThanOrEqual(44);
      expect(material.blurAlpha).toBeGreaterThanOrEqual(0.6);
      expect(material.blurAlpha).toBeLessThanOrEqual(0.7);
      expect(material.keyColor).toBe(`rgb(${channels(THEMES[theme]!.fg2).join(", ")})`);
      expect(Number.parseFloat(material.iconStroke)).toBeGreaterThanOrEqual(1.8);
      expect(material.transition).toContain("backdrop-filter");
      expect(material.transition).toContain("transform");
      expect(material.transition).toContain("opacity");
      const entryDurations = material.transitionDuration.split(",").map((duration) => Number.parseFloat(duration) * 1000);
      expect(entryDurations).toHaveLength(5);
      expect(Math.max(...entryDurations)).toBeLessThanOrEqual(240);
      expect(material.easing.match(/cubic-bezier\([^)]*\)/g)).toEqual(Array(5).fill("cubic-bezier(0.23, 1, 0.32, 1)"));
      const origin = material.origin.split(" ").map((coordinate) => Number.parseFloat(coordinate));
      expect(origin[0]).toBe(Number.parseFloat(await popover.evaluate((element) => getComputedStyle(element).getPropertyValue("--tail-x"))));
      expect(origin[1]).toBe(0);

      await mkdir(resolve(artifactDirectory, "after"), { recursive: true });
      const capture = resolve(artifactDirectory, "after", `393x852-${theme}-machine-busy.png`);
      await page.screenshot({ path: capture, animations: "disabled" });
      await testInfo.attach(`393x852-${theme}-machine-busy`, { path: capture, contentType: "image/png" });
      outputPaths.push(capture);

      await page.evaluate(() => { document.documentElement.style.fontSize = "18px"; });
      expect(await popover.locator(".machine-value").first().evaluate((element) => getComputedStyle(element).fontSize)).toBe("18px");
      expect(await popover.locator(".machine-key").first().evaluate((element) => getComputedStyle(element).fontSize)).toBe("15.75px");
      await page.evaluate(() => { document.documentElement.style.fontSize = ""; });

      await page.keyboard.press("Escape");
      await expect(popover).toHaveAttribute("data-open", "false");
      const exitDurations = await popover.evaluate((element) => getComputedStyle(element).transitionDuration
        .split(",").map((duration) => Number.parseFloat(duration) * 1000));
      expect(Math.max(...exitDurations)).toBeLessThan(Math.max(...entryDurations));
      await page.locator(".window-card[aria-current='true'] [data-window-action='sessions']").click();
      const manager = page.locator(".window-popover");
      await expect(manager).toHaveClass(/ui-overlay-surface/);
      await expect.poll(() => manager.evaluate((element) => new DOMMatrixReadOnly(getComputedStyle(element).transform).a)).toBe(1);
      const rows = await manager.evaluate((element) => {
        const row = element.querySelector<HTMLElement>(".window-session-row")!;
        const main = element.querySelector<HTMLElement>(".window-session-main")!;
        const action = element.querySelector<HTMLElement>(".window-session-row-actions button")!;
        return {
          row: row.getBoundingClientRect().height,
          main: main.getBoundingClientRect().height,
          action: action.getBoundingClientRect().height,
          outputSize: getComputedStyle(element.querySelector<HTMLElement>(".window-session-output")!).fontSize,
          keySize: getComputedStyle(element.querySelector<HTMLElement>(".window-session-meta")!).fontSize,
        };
      });
      expect(rows.row).toBeGreaterThanOrEqual(44);
      expect(rows.main).toBeGreaterThanOrEqual(44);
      expect(rows.action).toBeGreaterThanOrEqual(44);
      expect(rows.outputSize).toBe("16px");
      expect(rows.keySize).toBe("14px");

      const cdp = await context.newCDPSession(page);
      await cdp.send("Emulation.setEmulatedMedia", {
        features: [
          { name: "prefers-reduced-transparency", value: "reduce" },
          { name: "prefers-contrast", value: "more" },
          { name: "prefers-reduced-motion", value: "reduce" },
        ],
      });
      await expect.poll(() => page.evaluate(() => matchMedia("(prefers-reduced-transparency: reduce)").matches)).toBe(true);
      const accessibleMaterial = await manager.evaluate((element) => {
        const style = getComputedStyle(element);
        const rgba = style.backgroundColor.match(/,\s*([\d.]+)\)$/);
        const border = style.borderTopColor.match(/,\s*([\d.]+)\)$/);
        return {
          backdrop: style.backdropFilter,
          alpha: rgba ? Number(rgba[1]) : 1,
          borderAlpha: border ? Number(border[1]) : 1,
          transitionProperty: style.transitionProperty,
        };
      });
      expect(accessibleMaterial.backdrop).toBe("none");
      expect(accessibleMaterial.alpha).toBeGreaterThanOrEqual(0.85);
      expect(accessibleMaterial.borderAlpha).toBeGreaterThanOrEqual(0.5);
      expect(accessibleMaterial.transitionProperty).toBe("opacity");

      await page.keyboard.press("Escape");
      await page.keyboard.press("Control+k");
      await page.locator("#palette-input").fill("Machine information");
      await page.keyboard.press("Enter");
      await expect(page.locator(".window-popover")).toHaveAttribute("data-open", "true");
      const runningAnimations = await page.locator(".window-popover").evaluate((element) => element.getAnimations().filter((animation) => animation.playState === "running").length);
      expect(runningAnimations).toBe(0);
    } finally {
      await context.close();
    }
  }
await writeFile(resolve(artifactDirectory, "after", "manifest.txt"), `${outputPaths.join("\n")}\n`);
});

test("palette, sidebar, and warm tooltip use the shared floating material", async ({ browser }) => {
  const context = await browser.newContext({ baseURL: origin, viewport: { width: 1440, height: 900 } });
  try {
    const page = await context.newPage();
    await openPrototype(context, page);
    await page.locator("#sidebar-toggle").click();
    await expect(page.locator("#sidebar")).toHaveClass(/ui-overlay-surface/);
    await page.locator("#sidebar-toggle").click();
    await page.keyboard.press("Control+k");
    await expect(page.locator("#palette")).toHaveClass(/ui-overlay-surface/);
    await page.keyboard.press("Escape");
    await page.locator(".window-card[aria-current='true'] [data-window-action='split-vertical']").hover();
    await expect(page.locator(".tip-pos")).toHaveCSS("visibility", "visible", { timeout: 2_000 });
    await expect(page.locator(".tip")).toHaveClass(/ui-overlay-surface/);
    expect(await page.locator(".tip").evaluate((element) => getComputedStyle(element).backdropFilter)).toBe("blur(20px) saturate(1.8)");
    await page.locator(".window-card[aria-current='true'] .window-host-pill").click();
    await page.getByRole("button", { name: "Share" }).click();
    await expect(page.locator(".window-share-sheet")).toHaveClass(/ui-overlay-surface/);
    expect(await page.locator(".window-share-sheet").evaluate((element) => getComputedStyle(element).backdropFilter)).toBe("blur(20px) saturate(1.8)");
    await page.keyboard.press("Escape");
    await page.locator(".window-card[aria-current='true'] [data-window-action='sessions']").click();
    await page.locator(".window-session-row-actions [data-manager-action='end']").first().click();
    await expect(page.locator(".window-end-card")).toHaveClass(/ui-overlay-surface/);
    expect(await page.locator(".window-end-card").evaluate((element) => getComputedStyle(element).backdropFilter)).toBe("blur(20px) saturate(1.8)");
  } finally {
    await context.close();
  }
});
