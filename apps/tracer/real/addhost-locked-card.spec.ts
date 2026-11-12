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
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "../test/evidence-path";
import { personName, startRealServer } from "./server";

/** A throwaway key-only `sshd` for the current user on a free loopback port; `stop()` removes everything it made. */
async function startHost(): Promise<{ port: number; privateKey: string; stop(): void }> {
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "h"));
  const port = await new Promise<number>((resolve) => { const probe = createServer(); probe.listen(0, "127.0.0.1", () => { const p = (probe.address() as { port: number }).port; probe.close(() => resolve(p)); }); });
  for (const type of ["ed25519"]) spawnSync("ssh-keygen", ["-q", "-t", type, "-N", "", "-f", join(dir, `host_${type}`)], { stdio: "ignore" });
  spawnSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", join(dir, "user")], { stdio: "ignore" });
  writeFileSync(join(dir, "authorized_keys"), readFileSync(join(dir, "user.pub")), { mode: 0o600 });
  writeFileSync(join(dir, "sshd_config"), [
    `Port ${port}`, "ListenAddress 127.0.0.1", `HostKey ${join(dir, "host_ed25519")}`, `AuthorizedKeysFile ${join(dir, "authorized_keys")}`,
    "PasswordAuthentication no", "KbdInteractiveAuthentication no", "UsePAM no", "StrictModes no", `PidFile ${join(dir, "pid")}`, "LogLevel ERROR",
  ].join("\n"));
  // A transient user unit, not a bare process: shells of a bare sshd have no user systemd manager, and the host check
  // then (rightly) calls the host unsupported. The unit's environment carries XDG_RUNTIME_DIR into the sessions.
  const unit = `j510-host-${port}`;
  const child: ChildProcess = spawn("systemd-run", ["--user", "--quiet", "--collect", "--unit", unit, `--setenv=XDG_RUNTIME_DIR=${process.env.XDG_RUNTIME_DIR ?? `/run/user/${process.getuid?.() ?? 1000}`}`, "/usr/sbin/sshd", "-D", "-e", "-f", join(dir, "sshd_config")], { stdio: "ignore" });
  const privateKey = readFileSync(join(dir, "user"), "utf8");
  await new Promise((resolve) => setTimeout(resolve, 500)); // sleep: give sshd time to bind its port before the first connection
  return { port, privateKey, stop: () => { spawnSync("systemctl", ["--user", "stop", unit], { stdio: "ignore", timeout: 10_000 }); child.kill(); rmSync(dir, { recursive: true, force: true }); } };
}

test("a locked server offers Unlock on the Add host card and the host carries on after it (#510)", async ({ browser }) => {
  test.setTimeout(240_000);
  mkdirSync(tracerEvidencePath("addhost-510-real"), { recursive: true });
  const host = await startHost();
  const server = await startRealServer({ remoteListen: `127.0.0.1:${Number(process.env.TRACER_TEST_PORT ?? 4444) + 1000}` });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 393, height: 852 } });
  const page = await context.newPage();
  try {
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
    await page.goto(server.origin);
    await page.locator("#setup-token").evaluate((element, token) => {
      (element as HTMLInputElement).value = token;
      element.dispatchEvent(new Event("input", { bubbles: true }));
    }, server.token);
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.locator("#setup-username").fill(personName("locked_card"));
    await page.locator("#setup-display-name").fill("Locked card");
    await page.getByRole("button", { name: "Continue", exact: true }).click();
    await page.getByRole("button", { name: "Create passkey" }).click();
    await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
    await page.locator(".auth-check").click();
    await page.getByRole("button", { name: "Open infraternal" }).click();
    await page.locator(".cl-viewport").waitFor();

    // Unlock once from the sign-in toast, the way a person does after a restart, so the Add host card's own check passes
    // (the state a long-open card is in).
    const unlockViaToast = async (): Promise<void> => {
      await page.locator(".ui-toast").getByRole("button", { name: "Unlock", exact: true }).click({ timeout: 60_000 });
      await expect(page.locator(".ui-toast").filter({ hasText: "Host connections unlocked" })).toBeVisible({ timeout: 30_000 });
    };
    await unlockViaToast();
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
    await page.screenshot({ path: tracerEvidencePath("addhost-510-real", "locked-card-real.png") });

    // Unlock on the card itself, then the same host is tried again; the lock must not come back.
    await wizard.locator(".ah-foot").getByRole("button", { name: "Unlock", exact: true }).click();
    await expect.poll(status, { timeout: 60_000 }).toBe(false);
    await expect(wizard.locator(".ah-page[data-page='progress']:not(.is-leaving)")).toBeVisible({ timeout: 30_000 });
    // Past the lock the install goes on (or stops for a reason that is not the lock; this build has no host payload).
    await expect(wizard.getByRole("heading", { name: "Host connections are locked" })).toHaveCount(0, { timeout: 30_000 });
    await page.screenshot({ path: tracerEvidencePath("addhost-510-real", "after-unlock-real.png") });
  } finally {
    try { await context.close(); }
    finally { host.stop(); await server.dispose(); }
  }
});
