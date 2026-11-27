/** Functional access, input and resume checks against the production tracer build (#314). */
import { expect, test } from "playwright/test";
import { terminalScenario } from "./terminal-scenario";

test("first run, passkey login, terminal resume, and the latency probe", async ({ page }, info) => {
  // One long scenario (sign-in, resume, predictions with deliberate 1.5 s echo delays, a 20-key probe at 300 ms RTT) that
  // takes 75-95 s even on an idle host, so the config's 90 s default expired mid-run (a disposed request context).
  test.setTimeout(240_000);
  await terminalScenario(page, info);
});

/** A session probe refused at startup shows a countdown and restores the layout without a click. */
test("a throttled layout startup counts down and retries", async ({ page }, info) => {
  await page.setViewportSize({ width: 393, height: 852 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.clock.install();
  await page.clock.pauseAt(Date.now() + 200);
  let sessionRequests = 0;
  await page.route("**/auth/session", async (route) => {
    sessionRequests++;
    if (sessionRequests === 1) {
      await route.fulfill({ status: 429, headers: { "Retry-After": "3" }, json: {} });
    } else {
      await route.continue();
    }
  });
  await page.goto("/?mock=1");
  await expect(page.getByRole("heading", { name: "Connect to load your layout" })).toBeVisible();
  await expect(page.getByText("Your layout will load when the connection is ready.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retrying in 3s" })).toBeDisabled();
  await page.clock.fastForward(1000);
  const countdown = page.getByRole("button", { name: "Retrying in 2s" });
  await expect(countdown).toBeDisabled();
  const left = await page.locator("#unavailable-title, #status-error, #retry-status")
    .evaluateAll((nodes) => nodes.map((node) => node.getBoundingClientRect().left));
  expect(left).toHaveLength(3);
  for (const edge of left) expect(Math.abs(edge - left[0]!)).toBeLessThanOrEqual(0.5);
  const path = info.outputPath("layout-retry-phone.png");
  await page.screenshot({ path, animations: "disabled" });
  await info.attach("layout-retry-phone", { path, contentType: "image/png" });
  expect(sessionRequests).toBe(1);
  await page.clock.fastForward(2000);
  await page.clock.resume();
  await expect(page.locator("#tree")).toBeVisible();
  expect(sessionRequests).toBe(2);
});

/** Access failures must not expose a guessed form or browser exception details. */
test("status failure, invalid setup token, and cancelled passkey have distinct guidance", async ({ page }, info) => {
  await page.context().request.post("/__mock/reset");
  await page.route("**/auth/status", (route) => route.fulfill({ status: 503, json: {} }));
  await page.goto("/");
  await expect(page.getByRole("alert")).toHaveText("The server could not complete the request. Try again.");
  await expect(page.locator("form")).toHaveCount(0);
  // Keep production error-state evidence at the desktop and phone review sizes.
  for (const [width, height] of [[1440, 900], [393, 852], [375, 667]] as const) {
    for (const colorScheme of ["dark", "light"] as const) {
      await page.setViewportSize({ width, height });
      await page.emulateMedia({ colorScheme, reducedMotion: "reduce" });
      await page.goto("/");
      await expect(page.getByRole("alert")).toHaveText("The server could not complete the request. Try again.");
      await page.evaluate(() => document.fonts.ready);
      const leftEdges = await page.locator("#unavailable-title, #status-error, #retry-status")
        .evaluateAll((nodes) => nodes.map((node) => node.getBoundingClientRect().left));
      expect(leftEdges).toHaveLength(3);
      for (const left of leftEdges) expect(Math.abs(left - leftEdges[0]!)).toBeLessThanOrEqual(0.5);
      const path = info.outputPath(`unavailable-${width}-${colorScheme}.png`);
      await page.screenshot({ path, animations: "disabled" });
      await info.attach(`unavailable-${width}-${colorScheme}`, { path, contentType: "image/png" });
    }
  }
  await page.unroute("**/auth/status");
  await page.getByRole("button", { name: "Try again" }).click();
  await page.locator("#setup-token").fill("invalid-input");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.locator("#setup-token-error")).toContainText(
    "That token doesn't match. Run the command shown above on the server.",
  );
  await expect(page.locator("#setup-token")).toBeFocused();
  await expect(page.locator("#setup-username")).toHaveCount(0);
  await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/login-start", (route) => route.fulfill({ json: {
    ceremony: "cancel-test", options: { publicKey: {
      challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", rpId: "localhost",
      allowCredentials: [], userVerification: "required", extensions: {},
    } },
  } }));
  await page.addInitScript(() => {
    Object.defineProperty(navigator.credentials, "get", { value: async () => {
      throw new DOMException("browser internal diagnostic", "NotAllowedError");
    } });
  });
  await page.goto("/?setup=1");
  await expect(page.locator("#login-passkey")).toBeVisible();
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await expect(page.locator("#auth-error")).toHaveText("The passkey prompt was cancelled or timed out. Try again when you are ready.");
});

/** Both access states must finish rendering; elapsed-time budgets run on the perf VM. */
for (const setupRequired of [true, false]) test(`access screen renders (setup required: ${setupRequired})`, async ({ page }) => {
  await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: setupRequired } }));
  await page.goto("/");
  await expect(page.locator(setupRequired ? "#setup-card" : "#login-passkey")).toBeVisible();
});
