/** Production browser/server/PTY regressions for suspension and a refused connection capability (#244, D300). */
import { expect, test } from "playwright/test";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { personName, startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

test("hidden mobile page keeps its terminal and a refused resume attaches afresh once", async ({ browser }) => {
  test.setTimeout(150_000);
  const server = await startRealServer({ latencyMs: Number(process.env.MOBILE_ONE_WAY_MS ?? 75), remoteListen: `127.0.0.1:${Number(process.env.TRACER_TEST_PORT ?? 4444) + 1000}` });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 393, height: 852 }, isMobile: true, hasTouch: true });
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
    await page.locator("#setup-username").fill(personName("mobile_lease"));
    await page.locator("#setup-display-name").fill("Mobile lease");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.getByRole("button", { name: "Create passkey" }).click();
    await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
    await page.locator(".auth-check").click();
    await page.getByRole("button", { name: "Open infraternal" }).click();
    await page.locator(".cl-viewport").waitFor();
    await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
    const unlock = page.getByLabel("Hosts settings").getByRole("button", { name: "Unlock", exact: true, includeHidden: true });
    await expect(unlock).toHaveAttribute("data-shown", "true");
    await unlock.evaluate(button => (button as HTMLButtonElement).click());
    await expect.poll(() => page.evaluate(async () => (await fetch("/remote/ca/status", { method: "POST" })).json())).toEqual({ locked: false, initialized: true });
    const terminal = page.locator('.cl[data-view="console"] .ui-window').first();
    await expect(terminal).toHaveAttribute("data-status", "live");
    console.log("MOBILE_UI terminal ready");
    const before = server.bridges.length;
    for (const suspension of [5000, 30_000]) {
      await page.evaluate(() => {
        Object.defineProperty(document, "hidden", { configurable: true, get: () => true });
        Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" });
        document.dispatchEvent(new Event("visibilitychange"));
      });
      // Let the visibility notice cross the real bridge before the renderer stops.
      await page.waitForTimeout(1000);
      await cdp.send("Page.setWebLifecycleState", { state: "frozen" });
      await new Promise<void>(done => setTimeout(done, suspension));
      await cdp.send("Page.setWebLifecycleState", { state: "active" });
      await page.evaluate(() => {
        Object.defineProperty(document, "hidden", { configurable: true, get: () => false });
        Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "visible" });
        document.dispatchEvent(new Event("visibilitychange"));
      });
      await expect(terminal).toHaveAttribute("data-status", "live");
      expect(server.bridges.length).toBe(before);
      expect(server.bridges.filter(bridge => bridge.closed).length).toBe(0);
    }
    // Delete only fixture connection state, never read or log capability bytes.
    const deleted = spawnSync("python3", ["-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('PRAGMA foreign_keys=ON'); c.execute('DELETE FROM websocket_connections'); c.commit(); c.close()", resolve(server.dataDir, "infraternal.sqlite")]);
    expect(deleted.status).toBe(0);
    await server.restart(async () => {
      await expect(terminal).toHaveAttribute("data-status", "connecting");
      await terminal.locator(".terminal-host textarea").focus();
      await page.keyboard.type("echo retained-typing-$((6*9))\n");
    });
    // Failed upgrades while the process restarts are ordinary retries. Count
    // actual handshake refusals and fresh Hellos rather than TCP attempts.
    const recovered = () => server.bridges.slice(before);
    await expect.poll(() => recovered().filter(bridge => bridge.serverClose === "s0 the server refused to resume the connection").length, { timeout: 30_000 }).toBe(1);
    await expect.poll(() => recovered().filter(bridge => bridge.helloResume === false).length, { timeout: 30_000 }).toBe(1);
    await expect(terminal).toHaveAttribute("data-status", "live", { timeout: 30_000 });
    console.log("MOBILE_UI fresh attach ready");
    const resend = page.getByRole("button", { name: "Send again", exact: true });
    await expect(resend).toBeVisible();
    await expect(page.getByText("New shell. Offline typing may not have arrived.", { exact: false })).toBeVisible();
    const retainedOutput = () => server.bridges.flatMap(bridge => [...bridge.output.values()]).join("");
    expect(retainedOutput().includes("retained-typing-54")).toBe(false);
    for (const theme of ["ink", "paper"]) {
      await page.keyboard.press("Control+Shift+K");
      await page.locator("#palette-input").fill(theme);
      await page.locator(`[data-action="theme:${theme}"]`).click();
      for (const size of [{ width: 1440, height: 900 }, { width: 393, height: 852 }, { width: 375, height: 667 }]) {
        console.log(`MOBILE_UI theme=${theme} width=${size.width} begin`);
        await page.setViewportSize(size);
        await page.keyboard.press("Control+Shift+K");
        await expect(page.locator("#palette")).toBeVisible();
        await page.locator("#palette-input").fill("Go to Console");
        await page.locator('[data-action="canvas:view:console"]').click({ timeout: 5000 });
        await expect(resend).toBeInViewport();
        await resend.click({ trial: true, timeout: 5000 });
        console.log(`MOBILE_UI theme=${theme} width=${size.width} clickable`);
        await page.screenshot({ path: tracerEvidencePath("mobile-lease", `retained-typing-${theme}-${size.width}.png`) });
      }
    }
    await page.setViewportSize({ width: 393, height: 852 });
    expect(retainedOutput().includes("retained-typing-54")).toBe(false);
    await resend.click();
    await expect(resend).toBeHidden();
    await expect.poll(() => retainedOutput().includes("retained-typing-54")).toBe(true);
    expect(retainedOutput().match(/retained-typing-54/g)?.length).toBe(1);
    const attached = server.bridges.length;
    await page.waitForTimeout(2000);
    expect(server.bridges.length).toBe(attached);
    expect(recovered().filter(bridge => bridge.helloResume === false).length).toBe(1);
    await terminal.locator(".terminal-host").click({ position: { x: 40, y: 40 } });
    await terminal.locator(".terminal-host textarea").focus();
    await page.keyboard.type("echo mobile-resumed-$((6*7))\n", { delay: 5 });
    await expect.poll(() => server.bridges.flatMap(bridge => [...bridge.output.values()]).some(output => output.includes("mobile-resumed-42"))).toBe(true);
    await page.screenshot({ path: tracerEvidencePath("mobile-lease", "resumed.png") });
  } finally {
    try { await context.close(); }
    finally { await server.dispose(); }
  }
});
