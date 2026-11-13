// SPDX-License-Identifier: AGPL-3.0-only
/**
 * A server restart while the Add host card waits at the host-key step, on a real server and a real SSH host (#510).
 *
 * The restart closes the card's run, and the server forgets the key it showed. The card used to stay on a Trust button that
 * could only answer "Check the host key again before trusting it."; it must ask the host again by itself, show the key check
 * once more, and carry on after Trust.
 */
import { expect, test } from "playwright/test";
import { enrolOwner, unlockViaPalette } from "./addhost-flow";
import { startRealServer } from "./server";
import { startHost } from "./ssh-host";

test("a server restart at the host-key step re-asks the host and Trust carries on (#510)", async ({ browser }) => {
  test.setTimeout(240_000);
  const host = await startHost();
  const server = await startRealServer({ remoteListen: `127.0.0.1:${Number(process.env.TRACER_TEST_PORT ?? 4444) + 1000}` });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 393, height: 852 } });
  const page = await context.newPage();
  try {
    await enrolOwner(context, page, server, "restart_hostkey");
    await unlockViaPalette(page);
    await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
    const wizard = page.locator(".ah-float");
    await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 30_000 });
    await page.locator(".ui-chip-text").click();
    await page.keyboard.type(`${process.env.USER ?? "claude"}@127.0.0.1:${host.port} `, { delay: 5 });
    await wizard.getByRole("button", { name: "Continue", exact: true }).click();
    const trust = wizard.getByRole("button", { name: "Trust and continue" });
    await expect(trust).toBeVisible({ timeout: 60_000 });
    // The server restarts under the open host-key step.
    await server.restart();
    // The card recovers by itself: the check is shown again for the new observation, and Trust is accepted.
    await expect(wizard.getByRole("heading", { name: /Check .*'s key/ })).toBeVisible({ timeout: 60_000 });
    await expect(trust).toBeEnabled({ timeout: 30_000 });
    await trust.click();
    await expect(wizard.locator(".ah-error")).toHaveCount(0);
    await expect(wizard.getByText("Check the host key again before trusting it.")).toHaveCount(0);
    // Past the key check the host asks how to sign in (the server's own key is not on it): the step was left.
    await expect(wizard.getByRole("heading", { name: /Check .*'s key/ })).toHaveCount(0, { timeout: 60_000 });
  } finally {
    try { await context.close(); }
    finally { host.stop(); await server.dispose(); }
  }
});
