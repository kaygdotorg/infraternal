/** Exercises the authenticated core screen and saves the requested production-build views. */
import { mkdir } from "node:fs/promises";
import { hostname } from "node:os";
import { resolve } from "node:path";
import { expect, test, type Page, type TestInfo } from "playwright/test";
import { contrastRatio } from "../../../packages/ui/src/color";
import { THEMES, overlayMaterial } from "../../../packages/ui/src/themes";

async function waitForAttached(page: Page): Promise<void> {
  await expect.poll(() => page.locator("#terminal-screen").getAttribute("data-connected"), { timeout: 30_000 }).toBe("true");
  await expect(page.locator("#rtt")).toHaveText(/^\d+ ms$/, { timeout: 10_000 });
}

async function saveScreenshot(page: Page, testInfo: TestInfo, name: string): Promise<string> {
  const path = resolve(process.cwd(), "test-results", "core-screen", `${name}.png`);
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
    await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--mesh-image"))).toContain("blob:");

    const material = await page.evaluate(() => {
      const root = getComputedStyle(document.documentElement);
      const stage = document.querySelector<HTMLElement>("#terminal-screen")!;
      const layers = [".icon-btn", ".capsule"];
      if (getComputedStyle(document.querySelector<HTMLElement>(".tabs")!).display !== "none") layers.push(".tab-add");
      if (getComputedStyle(document.querySelector<HTMLElement>(".keybar")!).display !== "none") layers.push(".keytray");
      return {
        root: root.getPropertyValue("--overlay").trim(),
        rootLine: root.getPropertyValue("--overlay-line").trim(),
        rootShadow: root.getPropertyValue("--shadow").trim(),
        stage: getComputedStyle(stage).getPropertyValue("--overlay").trim(),
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
    expect(cssChannels(sidebarMaterial.background)).toEqual(cssChannels(material.root));
    expect(cssChannels(sidebarMaterial.line)).toEqual(cssChannels(material.rootLine));
    expect(sidebarMaterial.shadow).toBe(material.layers[0]!.shadow);
    paths.push(await saveScreenshot(page, testInfo, `${prefix}-sidebar-open`));
    await page.locator("#sidebar-toggle").click();
    await expect(page.locator("#sidebar")).toBeHidden();
    await page.keyboard.press("Control+k");
    await expect(page.getByRole("dialog", { name: "Go to anything" })).toBeVisible();
    const paletteMaterial = await page.locator("#palette").evaluate((element) => {
      const style = getComputedStyle(element);
      return { background: style.backgroundColor, line: style.borderTopColor, shadow: style.boxShadow };
    });
    expect(cssChannels(paletteMaterial.background)).toEqual(cssChannels(material.root));
    expect(cssChannels(paletteMaterial.line)).toEqual(cssChannels(material.rootLine));
    expect(paletteMaterial.shadow).toBe(material.layers[0]!.shadow);
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
  expect(await page.locator(".pane-card").evaluate((element) => getComputedStyle(element).backdropFilter)).toBe("none");
  await expect(page.locator(".terminal-screen")).not.toContainText(/static example|STATIC|name unavailable|not available yet|not connected/i);
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--mesh-image"))).toContain("blob:");
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

  await page.keyboard.press("Control+k");
  const palette = page.locator("#palette");
  await expect(palette).toBeVisible();
  await expect(palette).not.toContainText(/static example|STATIC|name unavailable|not available yet|not connected/i);
  await expect(palette.locator(".result:disabled")).toHaveCount(0);
  const paletteActions = await palette.locator(".result").evaluateAll((results) =>
    results.map((result) => (result as HTMLButtonElement).dataset.action ?? ""));
  expect(paletteActions.sort()).toEqual([
    "session:current", "host:current", "bg:mesh", "bg:none", ...Object.keys(THEMES).map((id) => `theme:${id}`),
  ].sort());
  expect(await palette.evaluate((element) => getComputedStyle(element).transitionDuration)).toBe("0s");
  const previousMesh = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--mesh-image"));
  await page.locator("#palette-input").fill("dracula");
  await expect(page.getByRole("option", { name: /Dracula/ })).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-theme", "dracula");
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--mesh-image"))).not.toBe(previousMesh);
  expect(backdropWorkers).toHaveLength(1);

  await page.keyboard.press("Control+k");
  await page.locator("#palette-input").fill("background none");
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
    await expect(mobilePage.locator(".tabs")).toBeHidden();
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
