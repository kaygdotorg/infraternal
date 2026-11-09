// SPDX-License-Identifier: AGPL-3.0-only
/**
 * A rootless server and a person whose name is no account on it (#327). The first canvas load opens a console shell,
 * the infraternal agent refuses it for want of a login, and the window must say why and what to do, not "not valid", and never spin.
 * Runs only as a non-root user: a root host falls back to root for such a person, so there is no refusal to see.
 *
 * The server has no remote component on purpose, so this spec isolates the refusal. With one, a locked authority raises
 * its own "unlock" toast in the same first load; toasts now stack (D336), so the refusal stays beside it
 * (toast-stack.spec.ts covers that rule). The unlock row itself is covered by authority-after-setup.spec.ts.
 *
 * A refused shell has no session and none is coming, so its window is no layout change in waiting: "Not saved — keep
 * this tab open" must go away while the refused window is still open (#395; it used to stay until the window closed).
 */
import { expect, test } from "playwright/test";
import { startRealServer } from "./server";
import { cache, watchLayout } from "./layout-observer";
import { tracerEvidencePath } from "../test/evidence-path";

const MESSAGE = "This server runs without root, so it can only open shells as its own user. Add a host to work elsewhere.";

for (const [name, viewport, phone] of [["desktop", { width: 1440, height: 900 }, false], ["phone", { width: 393, height: 852 }, true]] as const) {
  test(`a rootless server says why it cannot open a shell (${name})`, async ({ browser }) => {
    test.skip(process.getuid?.() === 0, "a root host falls back to root, so nothing is refused");
    test.setTimeout(120_000);
    const server = await startRealServer({});
    const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport, ...(phone ? { isMobile: true, hasTouch: true, deviceScaleFactor: 3 } : {}) });
    const page = watchLayout(await context.newPage());
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

      // The refusal is the console window's own state (#305), with the one action that helps; no toast carries it.
      const strip = page.locator(".ui-window[data-kind='terminal'] .cl-sx-strip");
      await expect(strip.locator(".cl-sx-strip-text")).toHaveText(MESSAGE, { timeout: 20_000 });
      await expect(strip.getByRole("button", { name: "Add host" })).toBeVisible();
      await expect(page.locator(".ui-toast").filter({ hasText: "not valid" })).toHaveCount(0);
      // The refused window stays and says why, but nothing waits to be saved for it (#395). The notice goes away within
      // the store's first retry window, and stays away for longer than the 20 s J299 saw it stuck on a real server.
      await expect.poll(async () => (await cache(page)).initialized, { timeout: 30_000 }).toBe(true);
      const pending = page.getByText("Not saved — keep this tab open", { exact: true });
      await expect(pending).toHaveCount(0, { timeout: 10_000 });
      await expect.poll(async () => (await cache(page)).pending.length, { timeout: 10_000 }).toBe(0);
      for (let i = 0; i < 4; i++) {
        // sleep: the stuck notice was a steady state, so absence is sampled over 20 s rather than awaited once.
        await page.waitForTimeout(5_000);
        await expect(pending).toHaveCount(0);
      }
      await expect(strip.locator(".cl-sx-strip-text")).toHaveText(MESSAGE);
      await page.screenshot({ path: tracerEvidencePath("rootless-refusal", `window-${name}.png`) });
    } finally {
      try { await context.close(); }
      finally { await server.dispose(); }
    }
  });
}
