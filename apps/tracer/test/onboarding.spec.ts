/** Production-browser onboarding evidence at the approved phone and desktop viewports. */
import { expect, test, type Page, type TestInfo } from "playwright/test";

const viewports = [
  { id: "iphone-15", width: 393, height: 852 },
  { id: "desktop", width: 1440, height: 900 },
] as const;

test("setup, recovery acknowledgement, welcome and returning sign-in match the browser contract", async ({ page }, testInfo) => {
  test.setTimeout(60_000);
  const context = page.context();
  await context.request.post("/__mock/reset");
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
    },
  });
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "no-preference" });
  await page.goto("/?mock=1");
  await expect(page.locator("#setup-card")).toBeVisible();
  await expect(page.locator("#faulty-field")).toBeVisible();
  await expect(page.locator("#faulty-field")).toHaveAttribute("data-ready", "true");
  expect(await page.locator(".auth-screen").evaluate((element) => getComputedStyle(element).backgroundColor)).toBe("rgba(0, 0, 0, 0)");
  await expect(page.locator("#setup-token")).toBeFocused();

  const screenshots: string[] = [];
  const tokenCenters = await captureState(page, testInfo, "step-1-token", screenshots, "#setup-card");
  await installShiftObserver(page);

  const setupResponse = await context.request.get("/__mock/setup-token");
  const setupBody = await setupResponse.json() as { setup_token: string };
  await page.locator("#setup-token").fill(setupBody.setup_token);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator("#setup-username")).toBeVisible();
  await expectNoLayoutShifts(page);
  const identityCenters = await captureState(page, testInfo, "step-2-identity", screenshots, "#setup-card");
  await page.locator("#setup-username").fill("Ada");
  await expect(page.locator("#setup-username")).toHaveValue("ada");
  await expect(page.locator("#setup-display-name")).toHaveValue("ada");
  await page.locator("#setup-display-name").fill("Ada Lovelace");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Create your passkey" })).toBeVisible();
  await expectNoLayoutShifts(page);
  const passkeyCenters = await captureState(page, testInfo, "step-3-passkey", screenshots, "#setup-card");

  // Hold the real test-double response past the threshold to verify the count-up stays
  // hidden before 400 ms and then shows elapsed time, without inventing progress.
  await page.route("**/auth/setup-start", async (route) => {
    await page.waitForTimeout(900);
    await route.continue();
  });
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.waitForTimeout(180);
  await expect(page.locator("#setup-next .busy-count")).toBeHidden();
  await page.waitForTimeout(350);
  await expect(page.locator("#setup-next .busy-count")).toBeVisible();
  await expect(page.locator("#setup-next .busy-count")).toContainText(/\d+\.\d+s/);
  await expect(page.getByRole("heading", { name: "Save your recovery key" })).toBeVisible();
  await expect(page.locator("#recovery-words li")).toHaveCount(24);
  await expectNoLayoutShifts(page);
  const recoveryCenters = await captureState(page, testInfo, "step-4-recovery", screenshots, "#setup-card");

  const copyButton = page.locator("#copy-recovery");
  await page.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText: async () => { throw new Error("clipboard unavailable"); }, readText: async () => "" },
    });
  });
  await copyButton.click();
  expect(await copyButton.getAttribute("data-done")).toBeNull();
  await expect(page.locator("#recovery-message")).toHaveText("Copy is unavailable here. Select and copy the words.");
  await page.evaluate(() => {
    let copied = "";
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        writeText: async (text: string) => { copied = text; },
        readText: async () => copied,
      },
    });
  });
  await copyButton.click();
  await expect(copyButton).toHaveAttribute("data-done", "");
  const copiedWords = await page.evaluate(() => navigator.clipboard.readText());
  expect(copiedWords.trim().split(/\s+/)).toHaveLength(24);
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download recovery key" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("infraternal-recovery-key.txt");
  await expect(page.locator("#download-recovery")).toHaveAttribute("data-done", "");
  await page.locator(".auth-check").click();
  await expect(page.getByRole("button", { name: "Open infraternal" })).toBeEnabled();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(page.locator("#welcome-title")).toHaveText("Welcome to infraternal");

  const welcomeCenters = await captureState(page, testInfo, "welcome", screenshots, ".welcome-copy");
  for (const center of Object.values(welcomeCenters)) {
    expect(Math.abs(center.x)).toBeLessThanOrEqual(1);
    expect(Math.abs(center.y)).toBeLessThanOrEqual(1);
  }
  await expect.poll(async () => {
    const state = await (await context.request.get("/__mock/state")).json() as { username?: string; display_name?: string };
    return `${state.username}/${state.display_name}`;
  }).toBe("ada/Ada Lovelace");
  await expect(page.getByText("TEST DOUBLE")).toBeVisible({ timeout: 8_000 });
  await expect(page.locator("#faulty-field")).toHaveCount(0);

  // The card hugs each step (owner: no empty gap above the footer) and stays centred:
  // horizontally always, vertically whenever the step fits on screen. Every viewport.
  const stepCenters = [tokenCenters, identityCenters, passkeyCenters, recoveryCenters].flatMap((centers) => Object.values(centers));
  for (const center of stepCenters) {
    expect(Math.abs(center.x)).toBeLessThanOrEqual(1);
    if (center.fits) expect(Math.abs(center.y)).toBeLessThanOrEqual(1);
  }
  const nonInputShifts = await page.evaluate(() => (window as Window & { __layoutShifts?: number[] }).__layoutShifts ?? []);
  expect(nonInputShifts).toEqual([]);

  // A cleared cookie and local storage leave only the authenticator's resident credential.
  await context.clearCookies();
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await expect(page.locator("#login-passkey")).toBeVisible();
  const signInCenters = await captureState(page, testInfo, "returning-sign-in", screenshots, ".auth-signin");
  for (const center of Object.values(signInCenters)) {
    expect(Math.abs(center.x)).toBeLessThanOrEqual(1);
  }
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
  console.log(`ONBOARDING_SCREENSHOTS ${screenshots.join(" ")}`);
});

interface CenterByViewport { x: number; y: number; height: number; fits: boolean }

/** Saves dark production-build screenshots and returns element-center offsets per viewport. */
async function captureState(
  page: Page,
  testInfo: TestInfo,
  name: string,
  screenshots: string[],
  selector: string,
): Promise<Record<string, CenterByViewport>> {
  const centers: Record<string, CenterByViewport> = {};
  await expect(page.locator("#faulty-field")).toHaveAttribute("data-ready", "true");
  for (const viewport of viewports) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    await page.waitForTimeout(300); // let the 240 ms height glide settle after a resize
    const path = testInfo.outputPath(`${name}-${viewport.id}.png`);
    await page.screenshot({ path, fullPage: true, animations: "disabled" });
    await testInfo.attach(`${name}-${viewport.id}`, { path, contentType: "image/png" });
    screenshots.push(path);
    const center = await page.locator(selector).evaluate((element) => {
      const rect = element.getBoundingClientRect();
      return {
        height: rect.height,
        // 24 px is the auth screen's minimum vertical padding on each side.
        fits: rect.height <= window.innerHeight - 48,
        x: (rect.left + rect.right) / 2 - window.innerWidth / 2,
        y: (rect.top + rect.bottom) / 2 - window.innerHeight / 2,
      };
    });
    centers[viewport.id] = center;
  }
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => {
    ((window as Window & { __layoutShifts?: number[] }).__layoutShifts ?? []).length = 0;
    resolve();
  }))));
  return centers;
}

async function expectNoLayoutShifts(page: Page): Promise<void> {
  await page.waitForTimeout(280);
  const values = await page.evaluate(() => (window as Window & { __layoutShifts?: number[] }).__layoutShifts ?? []);
  expect(values).toEqual([]);
}

async function installShiftObserver(page: Page): Promise<void> {
  await page.evaluate(() => {
    const values: number[] = [];
    Object.assign(window, { __layoutShifts: values });
    new PerformanceObserver((list) => {
      // The card glides to each step's height in 240 ms (owner-approved). Shifts inside
      // that window after an "auth-step" mark are the planned glide; anything else fails.
      const steps = () => performance.getEntriesByName("auth-step").map((m) => m.startTime);
      for (const entry of list.getEntries() as Array<PerformanceEntry & { value: number; hadRecentInput: boolean }>) {
        if (entry.hadRecentInput) continue;
        if (steps().some((t) => entry.startTime >= t && entry.startTime <= t + 300)) continue;
        values.push(entry.value);
      }
    }).observe({ type: "layout-shift", buffered: false });
  });
}
