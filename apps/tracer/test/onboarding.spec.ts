/** Production-browser onboarding evidence at the approved phone and desktop viewports. */
import { expect, test, type Page, type Route, type TestInfo } from "playwright/test";

const viewports = [
  { id: "iphone-15", width: 393, height: 852 },
  { id: "desktop", width: 1440, height: 900 },
] as const;

test("invalid setup token stays on step 1 with focused guidance", async ({ page }, testInfo) => {
  test.setTimeout(60_000);
  const context = page.context();
  // Capture the fresh fixture token before screenshots leave the request connection idle.
  const resetResponse = await context.request.post("/__mock/reset", { maxRetries: 1 });
  const setupBody = await resetResponse.json() as { setup_token: string };
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "no-preference" });
  await page.goto("/install?mock=1");
  await expect(page.getByRole("heading", { name: "Make this server yours" })).toBeVisible();
  await expect(page.locator("[data-setup-token-command]")).toHaveText("infraternal server setup-token");
  await expect(page.locator(".auth-hint")).toContainText("Run the command on the server. The token expires after 24 hours.");

  // Hold the validation response long enough to check the 400 ms count-up threshold.
  await page.route("**/auth/setup-check", async (route) => {
    await page.waitForTimeout(900);
    await route.continue();
  });
  await page.locator("#setup-token").fill("definitely-wrong-token");
  await page.getByRole("button", { name: "Continue" }).click();
  await page.waitForTimeout(180);
  await expect(page.getByRole("heading", { name: "Make this server yours" })).toBeVisible();
  await expect(page.locator("#setup-next .busy-count")).toBeHidden();
  await page.waitForTimeout(300);
  await expect(page.locator("#setup-next .busy-count")).toBeVisible();
  await expect(page.locator("#setup-next .busy-count")).toContainText(/\d+\.\d+s/);
  await expect(page.locator("#setup-token-error")).toContainText(
    "That token doesn't match. Run the command shown above on the server.",
  );
  await expect(page.locator("#setup-token")).toBeFocused();
  await expect(page.locator("#setup-username")).toHaveCount(0);

  const screenshots: string[] = [];
  for (const viewport of viewports) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    const path = testInfo.outputPath(`step-1-wrong-token-${viewport.id}.png`);
    await page.screenshot({ path, fullPage: true, animations: "disabled", mask: [page.locator("#setup-token")] });
    await testInfo.attach(`step-1-wrong-token-${viewport.id}`, { path, contentType: "image/png" });
    screenshots.push(path);
  }

  await page.locator("#setup-token").fill(setupBody.setup_token);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Who are you?" })).toBeVisible();
  console.log(`SETUP_TOKEN_ERROR_SCREENSHOTS ${screenshots.join(" ")}`);
});

test("system-service setup shows and copies its sudo command", async ({ page }, testInfo) => {
  const context = page.context();
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.route("**/auth/status", (route) => route.fulfill({
    status: 200,
    json: {
      setup_required: true,
      setup_token_command: "sudo infraternal server setup-token",
    },
  }));

  await page.goto("/install?mock=1");
  const command = "sudo infraternal server setup-token";
  await expect(page.locator("[data-setup-token-command]")).toHaveText(command);
  await page.setViewportSize({ width: 393, height: 852 });
  const screenshot = testInfo.outputPath("system-service-setup-token-command.png");
  await page.screenshot({ path: screenshot, fullPage: true, animations: "disabled" });
  await testInfo.attach("system-service-setup-token-command", {
    path: screenshot,
    contentType: "image/png",
  });
  await page.getByRole("button", { name: "Copy setup token command" }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(command);
});

test("setup, recovery acknowledgement, welcome and returning sign-in match the browser contract", async ({ page }, testInfo) => {
  test.setTimeout(90_000);
  const context = page.context();
  // Capture the fresh fixture token before screenshots leave the request connection idle.
  const resetResponse = await context.request.post("/__mock/reset", { maxRetries: 1 });
  const setupBody = await resetResponse.json() as { setup_token: string };
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

  await page.locator("#setup-token").fill(setupBody.setup_token);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator("#setup-username")).toBeVisible();
  await expectNoLayoutShifts(page);
  const identityCenters = await captureState(page, testInfo, "step-2-identity", screenshots, "#setup-card");
  // The username rule is on screen before any wrong key, and the display-name input stops at the validated limit.
  await expect(page.locator("#username-hint")).toHaveText("Use 2–32 lowercase letters, digits, _ or -.");
  await expect(page.locator("#setup-display-name")).toHaveAttribute("maxlength", "64");
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
    // The shared copy helper falls back to execCommand; both paths must fail for "unavailable".
    document.execCommand = () => false;
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
  // The tick is the only confirmation: no "Copied" line, and the earlier failure line is gone.
  await expect(page.locator("#recovery-message")).toHaveText("");
  await expect(page.getByText("Store the words somewhere private")).toHaveCount(0);
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
  await expect(page.locator(".auth-signin .auth-mark")).toBeVisible();
  await expect(page.locator(".auth-signin #signin-title")).toHaveText("Welcome back");
  await expect(page.locator(".auth-signin .auth-lede")).toHaveText("Your passkey is all you need.");
  await expect(page.locator(".auth-signin button")).toHaveCount(1);
  await expect(page.locator("#use-recovery")).toHaveCount(0);
  await expect(page.locator("#login-other")).toHaveCount(0);
  await page.evaluate(() => {
    const transitions: string[] = [];
    Object.assign(window, { __signinTransitions: transitions });
    document.addEventListener("transitionrun", (event) => {
      if (event.target instanceof Element) {
        const element = event.target;
        const selector = element.id ? `#${element.id}` : element.matches(".auth-primary") ? ".auth-primary" : "";
        if (selector) transitions.push(`${selector}:${(event as TransitionEvent).propertyName}`);
      }
    });
  });
  const signInCenters = await captureState(page, testInfo, "returning-sign-in", screenshots, ".auth-signin");
  for (const center of Object.values(signInCenters)) {
    expect(Math.abs(center.x)).toBeLessThanOrEqual(1);
  }
  await page.getByRole("button", { name: "Continue with passkey" }).focus();
  await page.keyboard.press("Enter");
  const signInTransitions = await page.evaluate(() => (window as Window & { __signinTransitions?: string[] }).__signinTransitions ?? []);
  expect(signInTransitions).toEqual([]);
  await expect.poll(
    () => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true),
    { timeout: 30_000 },
  ).toBe(true);
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
    await page.waitForTimeout(300); // let the 240 ms approved height glide settle after a resize
    const path = testInfo.outputPath(`${name}-${viewport.id}.png`);
    // Recovery words are generated by real browser crypto even against the
    // test double. Preserve card/layout evidence while masking capabilities.
    await page.screenshot({ path, fullPage: true, animations: "disabled",
      mask: [page.locator("#recovery-words"), page.locator("#setup-token")],
    });
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
      // Only the deliberate pointer step glide is allowed to shift layout without recent input.
      const steps = () => performance.getEntriesByName("auth-step").map((mark) => mark.startTime);
      for (const entry of list.getEntries() as Array<PerformanceEntry & { value: number; hadRecentInput: boolean }>) {
        if (entry.hadRecentInput) continue;
        if (steps().some((start) => entry.startTime >= start && entry.startTime <= start + 300)) continue;
        // Sub-pixel rounding (observed 3e-6) is not a visible shift. 0.001 is 1% of the
        // CLS "good" threshold (0.1), so any shift a person could see still fails.
        if (entry.value >= 0.001) values.push(entry.value);
      }
    }).observe({ type: "layout-shift", buffered: false });
  });
}

test("a setup chunk that fails to load shows a retry card, never a blank screen (#247)", async ({ page }, testInfo) => {
  test.setTimeout(60_000);
  await page.context().request.post("/__mock/reset", { maxRetries: 1 });
  // Fail only the setup chunk: the one whose text holds the first step's lede.
  const blocked = async (route: Route) => {
    const response = await route.fetch();
    if ((await response.text()).includes("Paste the one-time setup token")) await route.abort(); else await route.fulfill({ response });
  };
  await page.route(/\/chunk-[0-9a-z]{8}\.js$/, blocked);
  for (const viewport of viewports) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.goto("/?mock=1");
    await expect(page.locator("#auth-error")).toHaveText("Could not load setup. Check your connection; it will retry.");
    await page.screenshot({ path: testInfo.outputPath(`setup-load-failed-${viewport.id}.png`) });
    console.log("SETUP_LOAD_FAILED_SCREENSHOT", testInfo.outputPath(`setup-load-failed-${viewport.id}.png`));
  }
  await page.unroute(/\/chunk-[0-9a-z]{8}\.js$/, blocked);
  await page.getByRole("button", { name: "Try again" }).click();
  await expect(page.locator("#setup-token")).toBeVisible();
});

test("system-service setup stays within the phone viewport", async ({ page }) => {
  const viewport = { width: 375, height: 667 };
  await page.setViewportSize(viewport);
  await page.route("**/auth/status", (route) => route.fulfill({
    status: 200,
    json: {
      setup_required: true,
      setup_token_command: "sudo infraternal server setup-token",
    },
  }));
  await page.goto("/install?mock=1");
  await expect(page.locator("[data-setup-token-command]")).toHaveText("sudo infraternal server setup-token");
  await page.evaluate(() => document.fonts.ready);
  const bounds = await page.locator("#setup-card").boundingBox();
  expect(bounds).not.toBeNull();
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(viewport.width);
});
