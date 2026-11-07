/** Exercises the authenticated core screen and saves the requested production-build views. */
import { tracerEvidencePath } from "./evidence-path";
import { mkdir } from "node:fs/promises";
import { hostname } from "node:os";
import { resolve } from "node:path";
import { expect, test, type Page, type TestInfo } from "playwright/test";
import { contrastRatio } from "../../../packages/ui/src/color";
import { THEMES, overlayMaterial } from "../../../packages/ui/src/themes";
import { FONTS } from "../../../packages/ui/src/fonts";

async function waitForAttached(page: Page): Promise<void> {
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
  await expect(page.locator("#rtt")).toHaveText(/^\d+ ms$/, { timeout: 10_000 });
}

/** Saves a screen capture outside the checkout and attaches it to the Playwright result. */
async function saveScreenshot(page: Page, testInfo: TestInfo, name: string): Promise<string> {
  const path = tracerEvidencePath("playwright", "core-screen", `${name}.png`);
  await mkdir(resolve(path, ".."), { recursive: true });
  await page.screenshot({ path, animations: "disabled" });
  await testInfo.attach(name, { path, contentType: "image/png" });
  return path;
}

function cssChannels(value: string): [number, number, number, number] {
  const channels = [...value.matchAll(/[\d.]+/g)].map((match) => Number(match[0]));
  if (channels.length < 3) throw new Error(`Expected an RGB color, received ${value}`);
  return [channels[0]!, channels[1]!, channels[2]!, channels[3] ?? 1];
}

function overlaySurface(overlay: string, background: string): string {
  const tint = cssChannels(overlay);
  const base = [1, 3, 5].map((index) => Number.parseInt(background.slice(index, index + 2), 16));
  const channels = base.map((channel, index) => Math.round(tint[index]! * tint[3] + channel * (1 - tint[3])));
  return `#${channels.map((channel) => channel.toString(16).padStart(2, "0")).join("")}`;
}

test("curated overlay materials preserve foreground contrast in every theme", () => {
  for (const theme of Object.values(THEMES)) {
    const surface = overlayMaterial(theme).surface;
    expect(contrastRatio(theme.fg, surface), `${theme.name} fg on overlay`).toBeGreaterThanOrEqual(7);
    expect(contrastRatio(theme.fg2, surface), `${theme.name} fg-2 on overlay`).toBeGreaterThanOrEqual(4.5);
  }
});

async function screenshotMatrix(page: Page, testInfo: TestInfo, width: number, height: number): Promise<string[]> {
  const paths: string[] = [];
  await page.setViewportSize({ width, height });
  for (const theme of ["paper", "ink"] as const) {
    await page.goto(`/?theme=${theme}&bg=mesh`);
    await waitForAttached(page);
    await page.mouse.move(width / 2, height / 2);
    await expect.poll(() => page.evaluate(() => getComputedStyle(document.querySelector(".backdrop")!).getPropertyValue("--mesh-image"))).toContain("blob:");

    const material = await page.evaluate(() => {
      const root = getComputedStyle(document.documentElement);
      const stage = document.querySelector<HTMLElement>("#terminal-screen")!;
      const layers = ["#sidebar-toggle", ".capsule"];
      if (getComputedStyle(document.querySelector<HTMLElement>(".tabs")!).display !== "none") layers.push(".tab-add");
      if (getComputedStyle(document.querySelector<HTMLElement>(".keybar")!).display !== "none") layers.push(".keytray");
      return {
        // The card tint lives on the elements that read it, not on the root (a root token restyles the whole page).
        root: getComputedStyle(document.querySelector<HTMLElement>(".capsule")!).getPropertyValue("--overlay").trim(),
        rootPanel: getComputedStyle(document.querySelector<HTMLElement>("#sidebar")!).getPropertyValue("--overlay").trim(),
        rootLine: root.getPropertyValue("--overlay-line").trim(),
        rootShadow: root.getPropertyValue("--shadow").trim(),
        rootLargeShadow: root.getPropertyValue("--overlay-shadow-large").trim(),
        stage: getComputedStyle(document.querySelector<HTMLElement>("#sidebar-toggle")!).getPropertyValue("--overlay").trim(),
        stageLine: getComputedStyle(stage).getPropertyValue("--overlay-line").trim(),
        stageShadow: getComputedStyle(stage).getPropertyValue("--shadow").trim(),
        layers: layers.map((selector) => {
          const style = getComputedStyle(document.querySelector<HTMLElement>(selector)!);
          return { selector, background: style.backgroundColor, line: style.borderTopColor, shadow: style.boxShadow };
        }),
      };
    });
    const active = THEMES[theme]!;
    expect(material.stage).toBe(material.root);
    expect(material.stageLine).toBe(material.rootLine);
    expect(material.stageShadow).toBe(material.rootShadow);
    for (const layer of material.layers) {
      expect(cssChannels(layer.background), `${theme} ${layer.selector} surface`).toEqual(cssChannels(material.root));
      expect(cssChannels(layer.line), `${theme} ${layer.selector} line`).toEqual(cssChannels(material.rootLine));
      expect(layer.shadow, `${theme} ${layer.selector} shadow`).toBe(material.layers[0]!.shadow);
    }
    const surface = overlaySurface(material.root, active.bg);
    expect(contrastRatio(active.fg, surface), `${active.name} fg on overlay`).toBeGreaterThanOrEqual(7);
    expect(contrastRatio(active.fg2, surface), `${active.name} fg-2 on overlay`).toBeGreaterThanOrEqual(4.5);
    const menuStroke = await page.locator("#sidebar-toggle svg path").evaluate((path) => getComputedStyle(path).stroke);
    expect(menuStroke).not.toBe("none");

    const prefix = `tracer-core-${width}x${height}-${theme}`;
    paths.push(await saveScreenshot(page, testInfo, `${prefix}-sidebar-closed`));
    await page.locator("#sidebar-toggle").click();
    await expect(page.locator("#sidebar")).toBeVisible();
    const sidebarMaterial = await page.locator("#sidebar").evaluate((element) => {
      const style = getComputedStyle(element);
      return { background: style.backgroundColor, line: style.borderTopColor, shadow: style.boxShadow };
    });
    // The sidebar is a large floating surface: the thinner shared panel material, not the pill one.
    expect(cssChannels(sidebarMaterial.background)).toEqual(cssChannels(material.rootPanel));
    expect(cssChannels(sidebarMaterial.line)).toEqual(cssChannels(material.rootLine));
    expect(material.rootLargeShadow).not.toBe("");
    paths.push(await saveScreenshot(page, testInfo, `${prefix}-sidebar-open`));
    await page.locator("#sidebar-toggle").click();
    await expect(page.locator("#sidebar")).toBeHidden();
    await page.keyboard.press("Control+Shift+K");
    await expect(page.getByRole("dialog", { name: "Go to anything" })).toBeVisible();
    const paletteMaterial = await page.locator("#palette").evaluate((element) => {
      const style = getComputedStyle(element);
      return { background: style.backgroundColor, line: style.borderTopColor, shadow: style.boxShadow };
    });
    expect(cssChannels(paletteMaterial.background)).toEqual(cssChannels(material.root));
    expect(cssChannels(paletteMaterial.line)).toEqual(cssChannels(material.rootLine));
    expect(paletteMaterial.shadow).toBe(sidebarMaterial.shadow);
    expect(paletteMaterial.shadow).not.toBe(material.layers[0]!.shadow);
    paths.push(await saveScreenshot(page, testInfo, `${prefix}-palette-open`));
    await page.keyboard.press("Escape");
  }
  return paths;
}

test("core screen themes, tree, RTT, mobile tray, and screenshots", async ({ browser, page }, testInfo) => {
  // This production matrix captures twelve views and can outlast Playwright's 30 s default under load.
  test.setTimeout(120_000);
  const context = page.context();
  const backdropWorkers: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.endsWith("/backdrop.worker.js")) backdropWorkers.push(request.url());
  });
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&theme=paper&bg=mesh");
  await waitForAttached(page);
  await expect(page.locator("#terminal-host").locator("xpath=..")).toHaveClass(/pane-card/);
  await expect(page.locator("#tree .bm-sec[data-id='current-host']")).toHaveAttribute("aria-label", hostname());
  await expect(page.locator("#tree .bm-sec")).toHaveCount(1);
  await expect(page.locator("#tree .bm-leaf:not(:disabled)")).toHaveCount(1);
  await expect(page.locator("#tree .bm-leaf:disabled")).toHaveCount(0);
  await expect(page.locator(".tabs .tab")).toHaveCount(1);
  await expect(page.locator(".tabs .tab-add")).toBeVisible();
  await expect(page.locator("#tree")).not.toContainText(/static example|name unavailable|not available yet|not connected/i);
  await expect(page.locator(".tabs")).toBeVisible();
  expect(await page.locator("#terminal-host").locator("xpath=..").evaluate((element) => getComputedStyle(element).backdropFilter)).toBe("none");
  await expect(page.locator(".terminal-screen")).not.toContainText(/static example|STATIC|name unavailable|not available yet|not connected/i);
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.querySelector(".backdrop")!).getPropertyValue("--mesh-image"))).toContain("blob:");
  await expect.poll(() => backdropWorkers.length).toBe(1);
  await page.waitForTimeout(2100);
  expect(backdropWorkers).toHaveLength(1);

  await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#sidebar")).toBeVisible();
  await page.locator("#tree .bm-leaf:not(:disabled)").click();
  const branchMotion = await page.evaluate(() => ({
    marker: Number.parseFloat(document.querySelector<HTMLElement>("#tree .bm-marker")!.style.transitionDuration),
    draw: document.querySelector<SVGPathElement>("#tree .bm-lit")!.getAnimations()
      .map((animation) => Number(animation.effect?.getTiming().duration)),
  }));
  expect(branchMotion.marker, "the marker glide must stay under the 300 ms motion cap").toBeLessThan(300);
  expect(branchMotion.draw).toContain(300);
  await expect(page.locator("#tree")).not.toContainText(/static example|STATIC|name unavailable|not available yet|not connected/i);
  await page.keyboard.press("Escape");
  await expect(page.locator("#sidebar")).toBeHidden();

  await page.keyboard.press("Control+Shift+K");
  const palette = page.locator("#palette");
  await expect(palette).toBeVisible();
  await expect(palette).not.toContainText(/static example|STATIC|name unavailable|not available yet|not connected/i);
  await expect(palette.locator(".result:disabled")).toHaveCount(0);
  const paletteActions = await palette.locator(".result").evaluateAll((results) =>
    results.map((result) => (result as HTMLButtonElement).dataset.action ?? ""));
  expect(paletteActions.sort()).toEqual([
    "session:current", "host:current", "bg:mesh", "bg:soft", "bg:none", ...[1, 2, 3, 4].flatMap((n) => [`card:${n}`, `windows:${n}`]), ...Object.keys(THEMES).map((id) => `theme:${id}`), ...FONTS.map((font) => `font:${font.id}`),
  ].sort());
  // Superseded (TASTE: animation never gets in the way): a key-triggered open is a short 180 ms fade, never blocking input.
  expect(await palette.evaluate((element) => getComputedStyle(element).transitionDuration)).toBe("0.18s");
  const previousMesh = await page.evaluate(() => getComputedStyle(document.querySelector(".backdrop")!).getPropertyValue("--mesh-image"));
  await page.locator("#palette-input").fill("dracula");
  await expect(page.getByRole("option", { name: /Dracula/ })).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-theme", "dracula");
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.querySelector(".backdrop")!).getPropertyValue("--mesh-image"))).not.toBe(previousMesh);
  expect(backdropWorkers).toHaveLength(1);

  await page.keyboard.press("Control+Shift+K");
  await page.locator("#palette-input").fill("background: plain");
  await page.keyboard.press("Enter");
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-bg", "none");
  await expect.poll(() => page.locator("#rtt").textContent()).toMatch(/^\d+ ms$/);

  const screenshotPaths = await screenshotMatrix(page, testInfo, 1440, 900);
  const mobileContext = await browser.newContext({
    baseURL: new URL(page.url()).origin,
    viewport: { width: 393, height: 852 },
    deviceScaleFactor: 1,
    isMobile: true,
    hasTouch: true,
  });
  try {
    await mobileContext.request.post("/__mock/open-terminal");
    const mobilePage = await mobileContext.newPage();
    await mobilePage.goto("/?theme=paper&bg=mesh");
    await waitForAttached(mobilePage);
    await expect(mobilePage.locator("#keybar")).toBeVisible();
    // The key row exists only while a terminal has input focus (a phone needs a tap for that).
    await mobilePage.locator(".terminal-host").first().tap();
    // The product screen is the canvas: on a phone the top bar keeps only the "+" (a new window) beside the pill.
    await expect(mobilePage.locator(".tabs .tab-add")).toBeVisible();
    for (const desktopOnly of [".tabs .cl-snap"]) await expect(mobilePage.locator(desktopOnly)).toBeHidden();
    const controls = await mobilePage.locator("#sidebar-toggle, #capsule, #keybar button:not([hidden])").evaluateAll((items) => items.map((item) => {
      const rect = item.getBoundingClientRect();
      return { width: rect.width, height: rect.height };
    }));
    expect(controls.every((rect) => rect.width >= 44 && rect.height >= 44)).toBe(true);
    await expect(mobilePage.locator(".dpad[data-tip-off]")).toHaveCount(1);
    screenshotPaths.push(...await screenshotMatrix(mobilePage, testInfo, 393, 852));
  } finally {
    await mobileContext.close();
  }

  expect(screenshotPaths).toHaveLength(12);
  console.log(`Core-screen screenshots (production build):\n${screenshotPaths.join("\n")}`);
});

test("the UI stays monospace and a URL font preview never becomes a preference", async ({ browser, page }, testInfo) => {
  test.setTimeout(180_000);
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");

  const captures = new Map<string, string>();
  const sizes = [
    { width: 1440, height: 900 },
    { width: 393, height: 852 },
  ];

  async function capture(pageToUse: Page, width: number, height: number, state: "sidebar-open" | "palette-open"): Promise<void> {
    await pageToUse.setViewportSize({ width, height });
    await pageToUse.goto("/?mock=1&theme=ink&bg=none&ui=mono");
    await waitForAttached(pageToUse);
    await expect(pageToUse.locator("html")).toHaveAttribute("data-ui-font", "mono");
    const typography = await pageToUse.evaluate(() => {
      const stage = document.querySelector<HTMLElement>("#terminal-screen")!;
      return {
        family: getComputedStyle(stage).fontFamily,
        selectedFaceLoaded: document.fonts.check(document.documentElement.dataset.uiFont === "mono" ? '450 13px "Maple Mono NF"' : '450 14px "Geist Sans"'),
        stored: localStorage.getItem("tracer.ui-font"),
      };
    });
    expect(typography.family).toContain("Maple Mono NF");
    expect(typography.selectedFaceLoaded).toBe(true);
    expect(typography.stored).toBeNull();

    if (width === 393) {
      await expect(pageToUse.locator(".tabs")).toBeHidden();
      const mobileLayout = await pageToUse.evaluate(() => {
        const capsule = document.querySelector<HTMLElement>("#capsule")!;
        const capsuleRect = capsule.getBoundingClientRect();
        const host = document.querySelector<HTMLElement>(".capsule-host")!;
        const children = [...capsule.children].map((child) => {
          const rect = child.getBoundingClientRect();
          return { left: rect.left, right: rect.right, width: rect.width };
        }).filter((rect) => rect.width > 0);
        const controls = [...document.querySelectorAll<HTMLElement>("#sidebar-toggle, #capsule, #keybar button:not([hidden])")]
          .map((element) => {
            const rect = element.getBoundingClientRect();
            return { width: rect.width, height: rect.height };
          });
        return {
          capsule: { left: capsuleRect.left, right: capsuleRect.right, width: capsuleRect.width, height: capsuleRect.height },
          hostOverflowMode: getComputedStyle(host).textOverflow,
          hostWhiteSpace: getComputedStyle(host).whiteSpace,
          children,
          controls,
        };
      });
      expect(mobileLayout.capsule.left).toBeGreaterThanOrEqual(0);
      expect(mobileLayout.capsule.right).toBeLessThanOrEqual(393);
      expect(mobileLayout.capsule.height).toBe(44);
      expect(mobileLayout.children.every((item, index, all) => index === 0 || all[index - 1]!.right <= item.left + 1)).toBe(true);
      expect(mobileLayout.hostOverflowMode).toBe("ellipsis");
      expect(mobileLayout.hostWhiteSpace).toBe("nowrap");
      expect(mobileLayout.controls.every((rect) => rect.width >= 44 && rect.height >= 44)).toBe(true);
    } else {
      const desktopTabs = await pageToUse.locator(".tabs").boundingBox();
      expect(desktopTabs).not.toBeNull();
      expect(desktopTabs!.x + desktopTabs!.width).toBeLessThanOrEqual(width);
    }

    if (state === "sidebar-open") {
      await pageToUse.locator("#sidebar-toggle").click();
      await expect(pageToUse.locator("#sidebar")).toBeVisible();
    } else {
      await pageToUse.keyboard.press("Control+Shift+K");
      await expect(pageToUse.getByRole("dialog", { name: "Go to anything" })).toBeVisible();
    }
    const name = `ui-${width}x${height}-${state}`;
    captures.set(name, await saveScreenshot(pageToUse, testInfo, name));
  }

  for (const size of sizes) {
    if (size.width === 393) {
      const mobileContext = await browser.newContext({
        baseURL: new URL(page.url()).origin,
        viewport: { width: size.width, height: size.height },
        deviceScaleFactor: 1,
        isMobile: true,
        hasTouch: true,
      });
      try {
        await mobileContext.request.post("/__mock/open-terminal");
        const mobilePage = await mobileContext.newPage();
        await capture(mobilePage, size.width, size.height, "sidebar-open");
        await mobilePage.keyboard.press("Escape");
        await capture(mobilePage, size.width, size.height, "palette-open");
        await mobilePage.keyboard.press("Escape");
      } finally {
        await mobileContext.close();
      }
    } else {
      await capture(page, size.width, size.height, "sidebar-open");
      await page.keyboard.press("Escape");
      await capture(page, size.width, size.height, "palette-open");
      await page.keyboard.press("Escape");
    }
  }

  // A query choice is this page's preview only; later visits keep the product's monospace face.
  await page.goto("/?mock=1&theme=ink&bg=none&ui=mono");
  await expect(page.locator("html")).toHaveAttribute("data-ui-font", "mono");
  expect(await page.evaluate(() => localStorage.getItem("tracer.ui-font"))).toBeNull();
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect(page.locator("html")).toHaveAttribute("data-ui-font", "mono");
  expect(await page.evaluate(() => localStorage.getItem("tracer.ui-font"))).toBeNull();
  await page.goto("/?mock=1&theme=ink&bg=none&ui=sans");
  await expect(page.locator("html")).toHaveAttribute("data-ui-font", "sans");
  expect(await page.evaluate(() => localStorage.getItem("tracer.ui-font"))).toBeNull();

  const storedPreferenceContext = await browser.newContext({ baseURL: new URL(page.url()).origin });
  try {
    await storedPreferenceContext.addInitScript(() => localStorage.setItem("tracer.ui-font", "sans"));
    await storedPreferenceContext.request.post("/__mock/open-terminal");
    const storedPreferencePage = await storedPreferenceContext.newPage();
    await storedPreferencePage.goto("/?mock=1&theme=ink&bg=none");
    await waitForAttached(storedPreferencePage);
    await expect(storedPreferencePage.locator("html")).toHaveAttribute("data-ui-font", "mono");
    const storedFamily = await storedPreferencePage.locator("#terminal-screen").evaluate((stage) => getComputedStyle(stage).fontFamily);
    expect(storedFamily).toContain("Maple Mono NF");
  } finally {
    await storedPreferenceContext.close();
  }

  // Blocked storage must not stop a URL-selected face from rendering.
  const blockedStorageContext = await browser.newContext({ baseURL: new URL(page.url()).origin });
  try {
    await blockedStorageContext.addInitScript(() => {
      Object.defineProperty(window, "localStorage", {
        configurable: true,
        get: () => { throw new DOMException("Storage is disabled", "SecurityError"); },
      });
    });
    await blockedStorageContext.request.post("/__mock/open-terminal");
    const blockedStoragePage = await blockedStorageContext.newPage();
    await blockedStoragePage.goto("/?mock=1&theme=ink&bg=none&ui=mono");
    await waitForAttached(blockedStoragePage);
    await expect(blockedStoragePage.locator("html")).toHaveAttribute("data-ui-font", "mono");
    const blockedFamily = await blockedStoragePage.locator("#terminal-screen").evaluate((stage) => getComputedStyle(stage).fontFamily);
    expect(blockedFamily).toContain("Maple Mono NF");
  } finally {
    await blockedStorageContext.close();
  }

  expect(captures.size).toBe(4);
});
