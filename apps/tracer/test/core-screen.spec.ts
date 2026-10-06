/** Exercises the authenticated core screen and saves the requested production-build views. */
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { expect, test, type Page, type TestInfo } from "playwright/test";

declare global {
  interface Window {
    __meshProbe?: { events: string[]; draws: number; losses: number; snapshots: number };
  }
}

async function instrumentMesh(page: Page): Promise<void> {
  await page.addInitScript({ content: `
    (() => {
      window.__meshProbe = { events: [], draws: 0, losses: 0, snapshots: 0 };
      const probe = () => window.__meshProbe;
      const getContext = HTMLCanvasElement.prototype.getContext;
      const wrapped = new WeakSet();
      HTMLCanvasElement.prototype.getContext = function(type, ...args) {
        const gl = getContext.call(this, type, ...args);
        if (type !== "webgl2" || !gl || wrapped.has(gl)) return gl;
        wrapped.add(gl);
        const drawArrays = gl.drawArrays.bind(gl);
        gl.drawArrays = (...drawArgs) => {
          probe().draws += 1;
          probe().events.push("draw");
          return drawArrays(...drawArgs);
        };
        const getExtension = gl.getExtension.bind(gl);
        gl.getExtension = (name) => {
          const extension = getExtension(name);
          if (name === "WEBGL_lose_context" && extension && !extension.__meshWrapped) {
            extension.__meshWrapped = true;
            const loseContext = extension.loseContext.bind(extension);
            extension.loseContext = () => {
              probe().losses += 1;
              probe().events.push("lose");
              return loseContext();
            };
          }
          return extension;
        };
        return gl;
      };
      const toBlob = HTMLCanvasElement.prototype.toBlob;
      HTMLCanvasElement.prototype.toBlob = function(...args) {
        probe().snapshots += 1;
        probe().events.push("toBlob");
        return toBlob.apply(this, args);
      };
    })();
  ` });
}

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

async function screenshotMatrix(page: Page, testInfo: TestInfo, width: number, height: number): Promise<string[]> {
  const paths: string[] = [];
  await page.setViewportSize({ width, height });
  for (const theme of ["paper", "ink"] as const) {
    await page.goto(`/?theme=${theme}&bg=mesh`);
    await waitForAttached(page);
    await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--mesh-image"))).toContain("blob:");

    const prefix = `tracer-core-${width}x${height}-${theme}`;
    paths.push(await saveScreenshot(page, testInfo, `${prefix}-sidebar-closed`));
    await page.locator("#sidebar-toggle").click();
    await expect(page.locator("#sidebar")).toBeVisible();
    paths.push(await saveScreenshot(page, testInfo, `${prefix}-sidebar-open`));
    await page.locator("#sidebar-toggle").click();
    await expect(page.locator("#sidebar")).toBeHidden();
    await page.keyboard.press("Control+k");
    await expect(page.getByRole("dialog", { name: "Go to anything" })).toBeVisible();
    paths.push(await saveScreenshot(page, testInfo, `${prefix}-palette-open`));
    await page.keyboard.press("Escape");
  }
  return paths;
}

test("core screen themes, tree, RTT, mobile tray, and screenshots", async ({ browser, page }, testInfo) => {
  const context = page.context();
  await context.request.post("/__mock/reset");
  await context.request.post("/__mock/open-terminal");
  await instrumentMesh(page);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/?mock=1&theme=paper&bg=mesh");
  await waitForAttached(page);
  await expect(page.locator("#terminal-host").locator("xpath=..")).toHaveClass(/pane-card/);
  await expect(page.locator("#tree .bm-sec[data-id='current-host']")).toHaveAttribute("aria-label", "Current host · name unavailable");
  await expect(page.locator("#tree .bm-leaf:disabled")).toHaveCount(3);
  await expect(page.locator(".tab:disabled .sample-tag")).toHaveCount(2);
  await expect(page.locator(".tabs")).toBeVisible();
  expect(await page.locator(".pane-card").evaluate((element) => getComputedStyle(element).backdropFilter)).toBe("none");
  await expect.poll(() => page.evaluate(() => window.__meshProbe?.draws)).toBe(1);
  await expect.poll(() => page.evaluate(() => window.__meshProbe?.losses)).toBe(1);

  const meshEvents = await page.evaluate(() => window.__meshProbe?.events ?? []);
  expect(meshEvents.indexOf("toBlob"), "the still must be captured before the WebGL context is released").toBeLessThan(meshEvents.indexOf("lose"));
  await expect.poll(() => page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--mesh-image"))).toContain("blob:");
  await page.waitForTimeout(2100);
  expect(await page.evaluate(() => window.__meshProbe?.draws)).toBe(1);

  await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#sidebar")).toBeVisible();
  await expect(page.locator("#tree")).toContainText("static example");
  await page.keyboard.press("Escape");
  await expect(page.locator("#sidebar")).toBeHidden();

  await page.keyboard.press("Control+k");
  const palette = page.locator("#palette");
  await expect(palette).toBeVisible();
  expect(await palette.evaluate((element) => getComputedStyle(element).transitionDuration)).toBe("0s");
  await page.locator("#palette-input").fill("dracula");
  await expect(page.getByRole("option", { name: /Dracula/ })).toBeVisible();
  await page.keyboard.press("Enter");
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-theme", "dracula");
  await expect.poll(() => page.evaluate(() => window.__meshProbe?.draws)).toBe(2);

  await page.keyboard.press("Control+k");
  await page.locator("#palette-input").fill("background none");
  await page.keyboard.press("Enter");
  await expect(page.locator("#terminal-screen")).toHaveAttribute("data-bg", "none");
  await expect.poll(() => page.locator("#rtt").textContent()).toMatch(/^\d+ ms$/);

  const screenshotPaths = await screenshotMatrix(page, testInfo, 1440, 900);
  const mobileContext = await browser.newContext({
    baseURL: "http://localhost:4173",
    viewport: { width: 393, height: 852 },
    deviceScaleFactor: 1,
    isMobile: true,
    hasTouch: true,
  });
  try {
    await mobileContext.request.post("/__mock/open-terminal");
    const mobilePage = await mobileContext.newPage();
    await instrumentMesh(mobilePage);
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
