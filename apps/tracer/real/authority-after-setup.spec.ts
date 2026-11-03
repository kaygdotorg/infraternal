// SPDX-License-Identifier: AGPL-3.0-only
/**
 * First-run setup on a real server with the remote component (#327): as soon as setup ends, the server reports its
 * host-connection authority as locked, so the palette must offer "Unlock host connections" without a reload. Other
 * real specs used to dispatch `visibilitychange` by hand to force the page to ask again; this one does not.
 */
import { expect, test } from "playwright/test";
import { personName, startRealServer } from "./server";

test("the palette offers Unlock host connections right after first-run setup, without a reload", async ({ browser }) => {
  test.setTimeout(120_000);
  const server = await startRealServer({ latencyMs: Number(process.env.AFTER_SETUP_LATENCY_MS ?? 0), remoteListen: `127.0.0.1:${Number(process.env.TRACER_TEST_PORT ?? 4444) + 1000}` });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  try {
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
    await page.goto(server.origin);
    // Keep the one-time setup value out of a locator action's failure log.
    await page.locator("#setup-token").evaluate((element, token) => {
      (element as HTMLInputElement).value = token;
      element.dispatchEvent(new Event("input", { bubbles: true }));
    }, server.token);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.locator("#setup-username").fill(personName("after_setup"));
    await page.locator("#setup-display-name").fill("After setup");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.getByRole("button", { name: "Create passkey" }).click();
    await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
    await page.locator(".auth-check").click();
    await page.getByRole("button", { name: "Open infraternal" }).click();
    await page.locator(".cl-viewport").waitFor();

    // The server's own answer, asked from the same signed-in page: locked.
    const status = await page.evaluate(async () => (await fetch("/remote/ca/status", { method: "POST" })).json());
    expect(status.locked).toBe(true);

    // Open the palette at once, the way a person does right after setup. The page learns the lock state about a second
    // after its first paint, while the palette is already open, so the row must arrive in the open palette. No reload,
    // no visibility event.
    await page.keyboard.press("Control+Shift+K");
    await expect(page.locator("#palette")).toBeVisible();
    await page.keyboard.type("Unlock host");
    await expect(page.locator("#palette-results .result-label")).toContainText(["Unlock host connections"]);
  } finally {
    try { await context.close(); }
    finally { await server.dispose(); }
  }
});
