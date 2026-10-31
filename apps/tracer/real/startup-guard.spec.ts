/** Production D315 flow on real PTYs in an isolated account namespace; no startup files on the VM are changed. */
import { test, expect } from "playwright/test";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

test.describe.configure({ mode: "serial" });
test.skip(process.env.D315_NAMESPACE !== "1", "requires the private account/mount namespace runbook in contracts/terminal-startup.md");

for (const [name, width, height] of [["desktop", 1440, 900], ["phone", 393, 852], ["small-phone", 375, 667]] as const) {
  for (const theme of ["ink", "paper"]) {
    test(`${name} ${theme}: discovery, confirmation, guard and undo`, async ({ browser }) => {
      const tmux = process.env.D315_TMUX!;
      expect(tmux).toBeTruthy();
      const socket = `d315-${process.pid}`;
      const file = join(homedir(), ".zshrc");
      const command = `exec tmux -L ${socket} new-session -s startup`;
      const original = `if [ -z "$TMUX" ]; then\n  ${command}\nfi\n`;
      await writeFile(file, original, { mode: 0o600 });
      const server = await startRealServer({ startupDirectory: homedir() });
      const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width, height } });
      const page = await context.newPage();
      const errors: string[] = [];
      page.on("pageerror", (error) => errors.push(error.message));
      const captures = tracerEvidencePath("startup-guard");
      await mkdir(captures, { recursive: true });
      try {
        const cdp = await context.newCDPSession(page);
        await cdp.send("WebAuthn.enable");
        await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
        await page.goto(`${server.origin}/?theme=${theme}&bg=none`);
        await page.locator("#setup-token").fill(server.token);
        await page.getByRole("button", { name: "Continue", exact: true }).click();
        await page.locator("#setup-username").fill("startup_test");
        await page.locator("#setup-display-name").fill("Startup test");
        await page.getByRole("button", { name: "Continue", exact: true }).click();
        await page.getByRole("button", { name: "Create passkey" }).click();
        await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
        await page.locator(".auth-check").click();
        await page.getByRole("button", { name: "Open infraternal" }).click();
        await page.locator(".cl-viewport").waitFor();
        const add = page.locator(".ui-toast").getByRole("button", { name: "Add guard", exact: true });
        await expect(add).toBeVisible({ timeout: 20_000 });
        expect(await readFile(file, "utf8")).toBe(original);
        await expect(page.getByRole("button", { name: "Copy guard", exact: true })).toBeVisible();
        await page.screenshot({ path: join(captures, `${name}-${theme}-notice.png`) });
        await add.click();
        await expect(page.locator(".ui-confirm-tip")).toBeVisible();
        expect(await readFile(file, "utf8")).toBe(original);
        await page.screenshot({ path: join(captures, `${name}-${theme}-confirm.png`) });
        await page.locator(".ui-confirm-no").click();
        await expect(page.locator(".ui-confirm-tip")).toHaveCount(0);
        await expect(add).toBeVisible();
        expect(await readFile(file, "utf8")).toBe(original);
        await add.click();
        await page.locator(".ui-confirm-yes").click();
        const undo = page.getByRole("button", { name: "Remove guard", exact: true });
        await expect(undo).toBeVisible();
        expect(await readFile(file, "utf8")).toBe(original.replace(command, `[ -n "$INFRATERNAL_SESSION" ] || ${command}`));
        await page.screenshot({ path: join(captures, `${name}-${theme}-added.png`) });
        await undo.click();
        await expect.poll(() => readFile(file, "utf8")).toBe(original);
        await page.reload();
        await page.locator(".cl-viewport").waitFor();
        await expect(add).not.toBeVisible();
        expect(errors).toEqual([]);
      } finally {
        await context.close();
        await server.dispose();
        spawnSync(tmux, ["-L", socket, "kill-server"], { stdio: "ignore" });
      }
    });
  }
}
