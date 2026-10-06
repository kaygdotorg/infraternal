/** Browser contract test: virtual passkey, auth round trip, echo, dedupe, probe and screenshot. */
import { writeFile } from "node:fs/promises";
import { expect, test } from "playwright/test";

test("first run, passkey login, terminal resume, and the latency probe", async ({ page }, testInfo) => {
  const context = page.context();
  await context.request.post("/__mock/reset");
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

  await page.goto("/?mock=1");
  await page.getByRole("button", { name: "Set up the first owner" }).click();
  const setupResponse = await context.request.get("/__mock/setup-token");
  const setupBody = await setupResponse.json() as { setup_token: string };
  await page.locator("#setup-token").fill(setupBody.setup_token);
  await page.locator("#owner-name").fill("Tracer browser test");
  await page.getByRole("button", { name: "Register a passkey" }).click();

  await expect(page.getByRole("heading", { name: "Save your recovery key" })).toBeVisible();
  const recoveryWords = (await page.locator("#recovery-words").textContent())?.trim().split(/\s+/) ?? [];
  expect(recoveryWords).toHaveLength(24);
  const userId = await page.locator("#account-id-value").textContent();
  expect(userId).toMatch(/^[0-9a-f-]{36}$/);
  await page.locator("#recovery-saved").check();
  await page.getByRole("button", { name: "Finish setup" }).click();
  await expect(page.getByText("TEST DOUBLE")).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);

  // Keep the virtual authenticator and account UUID, but remove the session cookie to exercise login.
  await context.clearCookies();
  await page.reload();
  await expect(page.locator("#login-form")).toBeVisible();
  await expect(page.locator("#account-id")).toHaveValue(userId ?? "");
  await page.getByRole("button", { name: "Continue with passkey" }).click();
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);

  await page.keyboard.press("a");
  await expect.poll(async () => {
    const state = await (await context.request.get("/__mock/state")).json() as { echoed_text: string };
    return state.echoed_text;
  }).toBe("a");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("a");

  // The mock writes b once, drops its Ack and Output, then deduplicates b when it is resent.
  await context.request.post("/__mock/drop-next-ack");
  await page.keyboard.press("b");
  await expect.poll(async () => {
    const state = await (await context.request.get("/__mock/state")).json() as { echoed_text: string };
    return state.echoed_text;
  }).toBe("ab");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.screenText() ?? "")).toContain("ab");
  const resumedState = await (await context.request.get("/__mock/state")).json() as {
    echoed_text: string;
    accepted_input_bytes: number;
  };
  expect(resumedState.echoed_text).toBe("ab");
  expect(resumedState.accepted_input_bytes).toBe(2);

  const terminalScreenshot = await page.screenshot({ fullPage: true });
  const terminalScreenshotPath = testInfo.outputPath("tracer-terminal.png");
  await writeFile(terminalScreenshotPath, terminalScreenshot);
  await testInfo.attach("tracer-terminal.png", {
    path: terminalScreenshotPath,
    contentType: "image/png",
  });

  // The phone/headless probe uses the same painted-output callback and adds a real forced-drop round trip.
  await page.goto("/?probe=1&n=36&mock=1");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true)).toBe(true);
  await expect(page.locator("#probe-run")).toBeEnabled();
  await page.locator("#probe-run").click();
  await expect.poll(
    async () => (await page.locator("#probe-results").textContent()) ?? "",
    { timeout: 20_000 },
  ).toContain("p99:");
  const probeState = await (await context.request.get("/__mock/state")).json() as {
    echoed_text: string;
    accepted_input_bytes: number;
    output_sequence: string;
  };
  expect(probeState.echoed_text).toBe("abcdefghijklmnopqrstuvwxyz0123456789");
  expect(probeState.accepted_input_bytes).toBe(36);
  expect(probeState.output_sequence).toBe("36");
  await expect(page.locator("#probe-results")).toContainText("Painted echoes: 36 / 36");
  await page.locator("#probe-drop").click();
  await expect.poll(async () => (await page.locator("#probe-results").textContent()) ?? "")
    .toMatch(/Time to resume: [0-9.]+ ms/);
  const probeReport = (await page.locator("#probe-results").textContent()) ?? "";
  console.log(`S1 probe result (36 keys)\n${probeReport}`);
  await testInfo.attach("tracer-probe-results.txt", {
    body: probeReport,
    contentType: "text/plain",
  });
  const probeScreenshotPath = testInfo.outputPath("tracer-probe.png");
  await page.screenshot({ fullPage: true, path: probeScreenshotPath });
  await testInfo.attach("tracer-probe.png", {
    path: probeScreenshotPath,
    contentType: "image/png",
  });
  console.log(`S1 screenshots: ${terminalScreenshotPath}, ${probeScreenshotPath}`);
  await page.locator("#probe-copy").click();
  await expect(page.locator("#probe-message")).toContainText(/Results copied|Clipboard unavailable/);
});
