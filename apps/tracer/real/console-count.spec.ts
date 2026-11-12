// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The Console label follows the real open windows (#512): after the last window closes the label must not keep
 * counting a window that is gone. Real server, real login shell, no test double.
 */
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "../test/evidence-path";
import { enrol, windows } from "./layout-devices";
import { startRealServer } from "./server";

test("after the last window closes the Console label no longer counts it", async ({ browser }) => {
  test.setTimeout(120_000);
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4673) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  try {
    const page = await context.newPage();
    await enrol(page, server);
    const label = page.locator("#capsule .capsule-session");
    await expect(windows(page)).toHaveCount(1, { timeout: 30_000 });
    await expect(label).toContainText("1");
    const host = page.locator('.cl[data-view="console"] .terminal-host');
    await host.click();
    await host.locator("textarea").focus();
    await page.keyboard.type("exit", { delay: 10 });
    await page.keyboard.press("Enter");
    await expect(windows(page)).toHaveCount(0, { timeout: 15_000 });
    // sleep: the label repaints from the inventory after the window's session ends; give it the same second the exit spec gives a toast.
    await page.waitForTimeout(1_500);
    test.info().annotations.push({ type: "label", description: (await label.innerText()).replace(/\s+/g, " ") });
    await page.screenshot({ path: tracerEvidencePath("console-count-512", "after-exit.png") });
    await expect(label).toContainText("0");
  } finally {
    await context.close();
    await server.dispose();
  }
});
