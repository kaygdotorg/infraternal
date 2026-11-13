// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Add host after a server restart, on a real server and a real SSH host (#510).
 *
 * A restart locks the server's certificate authority again. An Add host card that was opened before the restart has
 * already passed its own check, so the lock reaches the card as the host's failure. The card must offer Unlock (the
 * same ceremony the host-connections toast runs), and after it the same host must carry on instead of failing again
 * with the lock. Nothing here is scripted by a test double: the failure comes from the server's own authority check,
 * the host is a private `sshd` run by this spec as the current user, and the unlock is the real passkey ceremony with
 * a virtual authenticator that supports PRF.
 */
import { mkdirSync } from "node:fs";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "../test/evidence-path";
import { enrolOwner, unlockViaPalette } from "./addhost-flow";
import { startHost } from "./ssh-host";
import { startRealServer } from "./server";

test("a locked server offers Unlock on the Add host card and the host carries on after it (#510)", async ({ browser }) => {
  test.setTimeout(240_000);
  mkdirSync(tracerEvidencePath("addhost-510-real"), { recursive: true });
  const host = await startHost();
  const server = await startRealServer({ remoteListen: `127.0.0.1:${Number(process.env.TRACER_TEST_PORT ?? 4444) + 1000}` });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 393, height: 852 } });
  const page = await context.newPage();
  try {
    await enrolOwner(context, page, server, "locked_card");
    await unlockViaPalette(page);
    const status = async (): Promise<boolean> => (await page.evaluate(async () => (await fetch("/remote/ca/status", { method: "POST" })).json())).locked;
    expect(await status()).toBe(false);

    // Open the card while unlocked; the lock returns later without the card knowing.
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
    await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 30_000 });

    const wizard = page.locator(".ah-float");
    await page.locator(".ui-chip-text").click();
    await page.keyboard.type(`${process.env.USER ?? "claude"}@127.0.0.1:${host.port} `, { delay: 5 });
    await wizard.getByRole("button", { name: "Continue", exact: true }).click();
    // First contact: the host's key is new, so the card asks to trust it.
    await wizard.getByRole("button", { name: "Trust and continue" }).click({ timeout: 60_000 }).catch(async (error: unknown) => {
      // Name the page the card is on, so a changed flow is diagnosed from the log and not from a guess.
      throw new Error(`the card never asked to trust the host key; it shows: ${(await wizard.innerText()).replace(/\s+/g, " ").slice(0, 400)} (${String(error).slice(0, 80)})`);
    });
    // The server's own key is locked and not installed, so the host asks how to sign in. The card has passed its
    // authority check by now and remembers it. The server restarts here, so its authority is locked again.
    await wizard.getByText("Use a key from your computer").click({ timeout: 60_000 });
    await server.restart();
    await expect.poll(async () => { try { return await status(); } catch { return undefined; } }, { timeout: 60_000 }).toBe(true);
    await wizard.locator("[data-secret='key']").fill(host.privateKey);
    await wizard.getByRole("button", { name: "Sign in", exact: true }).click();

    const locked = wizard.locator(".ah-page[data-page='failure']:not(.is-leaving)");
    await expect(locked.getByRole("heading", { name: "Host connections are locked" })).toBeVisible({ timeout: 90_000 });
    await expect(wizard.locator(".ah-page.is-leaving")).toHaveCount(0, { timeout: 10_000 });
    await page.screenshot({ path: tracerEvidencePath("addhost-510-real", "locked-card-real.png") });

    // Unlock on the card itself, then the same host is tried again; the lock must not come back.
    await wizard.locator(".ah-foot").getByRole("button", { name: "Unlock", exact: true }).click();
    await expect.poll(status, { timeout: 60_000 }).toBe(false);
    // The key was used once and is not kept, so the card asks for it again and says why.
    await expect(wizard.locator(".ah-page[data-page='choose']:not(.is-leaving) .ah-lede")).toContainText("was used once and isn't kept", { timeout: 30_000 });
    // The previous page is still fading out under the new one for a moment; shoot only once it has left the DOM.
    await expect(wizard.locator(".ah-page.is-leaving")).toHaveCount(0, { timeout: 10_000 });
    await page.screenshot({ path: tracerEvidencePath("addhost-510-real", "sign-in-again-real.png") });
    await wizard.getByText("Use a key from your computer").click();
    await wizard.locator("[data-secret='key']").fill(host.privateKey);
    await wizard.getByRole("button", { name: "Sign in", exact: true }).click();
    // Past the lock the install goes on: it must not stop on the lock again. (This build carries no host payload, so
    // it may stop for that reason instead; only the lock is under test.)
    await expect(wizard.locator(".ah-page[data-page='progress']:not(.is-leaving)")).toBeVisible({ timeout: 30_000 });
    await expect(wizard.locator(".ah-stage-row[data-stage='detect'] .ah-stage-detail")).toHaveText("Signed in with your key", { timeout: 60_000 });
    await expect(wizard.getByRole("heading", { name: "Host connections are locked" })).toHaveCount(0);
    await page.screenshot({ path: tracerEvidencePath("addhost-510-real", "after-unlock-real.png") });
  } finally {
    try { await context.close(); }
    finally { host.stop(); await server.dispose(); }
  }
});
