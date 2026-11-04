// SPDX-License-Identifier: AGPL-3.0-only
/**
 * A rootless server and a person whose name is no account on it (#327). The first canvas load opens a console shell,
 * the infraternal agent refuses it for want of a login, and the toast must say why and what to do, not "not valid".
 * Runs only as a non-root user: a root host falls back to root for such a person, so there is no refusal to see.
 *
 * The server has no remote component on purpose, so this spec isolates the refusal. With one, a locked authority raises
 * its own "unlock" toast in the same first load; toasts now stack (D336), so the refusal stays beside it
 * (toast-stack.spec.ts covers that rule). The unlock row itself is covered by authority-after-setup.spec.ts.
 */
import { expect, test } from "playwright/test";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

const MESSAGE = "This server runs without root, so it can only open shells as its own user. Add a host to work elsewhere.";

for (const [name, viewport, phone] of [["desktop", { width: 1440, height: 900 }, false], ["phone", { width: 393, height: 852 }, true]] as const) {
  test(`a rootless server says why it cannot open a shell (${name})`, async ({ browser }) => {
    test.skip(process.getuid?.() === 0, "a root host falls back to root, so nothing is refused");
    test.setTimeout(120_000);
    const server = await startRealServer({});
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport, ...(phone ? { isMobile: true, hasTouch: true, deviceScaleFactor: 3 } : {}) });
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
      // Deliberately no account of this name on the host.
      await page.locator("#setup-username").fill("nobody_here_j142");
      await page.locator("#setup-display-name").fill("Nobody here");
      await page.getByRole("button", { name: "Continue", exact: true }).click();
      await page.getByRole("button", { name: "Create passkey" }).click();
      await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
      await page.locator(".auth-check").click();
      await page.getByRole("button", { name: "Open infraternal" }).click();
      await page.locator(".cl-viewport").waitFor();

      const toast = page.locator(".ui-toast").filter({ hasText: "runs without root" });
      await expect(toast).toBeVisible({ timeout: 20_000 });
      await expect(toast).toHaveText(MESSAGE);
      await expect(page.locator(".ui-toast").filter({ hasText: "not valid" })).toHaveCount(0);
      await page.screenshot({ path: tracerEvidencePath("rootless-refusal", `toast-${name}.png`) });
    } finally {
      try { await context.close(); }
      finally { await server.dispose(); }
    }
  });
}
