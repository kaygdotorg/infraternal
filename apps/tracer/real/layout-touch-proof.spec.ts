/** Production-build evidence for shared toolbar touch activation and retained terminal focus (R250-04). */
import { chromium, devices, expect, test } from "playwright/test";
import { enrol, settled, windows } from "./layout-devices";
import { watchLayout } from "./layout-observer";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";
for (const theme of ["ink", "paper"]) test(`toolbar touch preserves terminal focus and activates once (${theme})`, async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4458) });
  const bootstrap = await chromium.launch({ args: ["--ignore-certificate-errors"] });
  const auth = await bootstrap.newContext({ ignoreHTTPSErrors: true });
  const context = await browser.newContext({ ...devices["iPhone 15"], viewport: { width: 393, height: 852 }, ignoreHTTPSErrors: true });
  try {
    const owner = watchLayout(await auth.newPage()); await enrol(owner, server);
    await context.addCookies(await auth.cookies());
    const page = watchLayout(await context.newPage()); await page.goto(`${server.origin}/?theme=${theme}`);
    await expect(windows(page)).toHaveCount(1); await settled(page);
    await windows(page).first().locator(".terminal-host textarea").focus();
    await page.getByRole("button", { name: "Tab", exact: true }).tap();
    await expect.poll(() => page.evaluate(() => !!document.activeElement?.closest(".terminal-host"))).toBe(true);
    // The key row owns focused input; releasing focus reveals the canvas row.
    await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
    await page.getByRole("button", { name: "Split right", exact: true }).tap();
    await expect(windows(page)).toHaveCount(2); await settled(page);
    await page.screenshot({ path: tracerEvidencePath(`touch-${browser.browserType().name()}-${theme}-393.png`) });
    await page.setViewportSize({ width: 375, height: 667 });
    await page.screenshot({ path: tracerEvidencePath(`touch-${browser.browserType().name()}-${theme}-375.png`) });
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.screenshot({ path: tracerEvidencePath(`touch-${browser.browserType().name()}-${theme}-1440.png`) });
  } finally { await context.close(); await auth.close(); await bootstrap.close(); await server.dispose(); }
});
