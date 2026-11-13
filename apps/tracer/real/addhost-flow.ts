// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Steps shared by the real-server Add host specs: making the first-run owner with a virtual passkey that supports PRF,
 * and unlocking host connections from the palette.
 */
import { expect, type BrowserContext, type Page } from "playwright/test";
import { personName, type RealServer } from "./server";

/** Signs up the first-run owner `name` on `server` in `page` (virtual PRF authenticator) and waits for the canvas. */
export async function enrolOwner(context: BrowserContext, page: Page, server: RealServer, name: string): Promise<void> {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin);
  await page.locator("#setup-token").evaluate((element, token) => {
    (element as HTMLInputElement).value = token;
    element.dispatchEvent(new Event("input", { bubbles: true }));
  }, server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName(name));
  await page.locator("#setup-display-name").fill(name);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
}

/**
 * Unlocks host connections from the palette row: a brand-new account has no host yet, so it gets no restart toast (#512),
 * but the first host needs the unlock all the same. The row appears once the page has learned the lock state (about a
 * second after first paint), so the palette is opened again until it is there.
 */
export async function unlockViaPalette(page: Page): Promise<void> {
    await expect.poll(async () => {
      await page.keyboard.press("Control+Shift+K");
      await expect(page.locator("#palette")).toBeVisible();
      await page.keyboard.type("Unlock host");
      const found = (await page.locator("#palette-results .result-label").allTextContents()).includes("Unlock host connections");
      if (!found) { await page.keyboard.press("Escape"); await expect(page.locator("#palette")).toBeHidden(); }
      return found;
    }, { timeout: 30_000 }).toBe(true);
    await page.keyboard.press("Enter");
    await expect(page.locator(".ui-toast").filter({ hasText: "Host connections unlocked" })).toBeVisible({ timeout: 30_000 });
}
