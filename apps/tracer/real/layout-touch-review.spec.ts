/** Isolate production touch split behavior from network interception and offline emulation (#250). */
import { chromium, devices, expect, test } from "playwright/test";
import { enrol, settled, windows } from "./layout-devices";
import { watchLayout } from "./layout-observer";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

for (const reload of [false, true]) test(`touching Split right creates a second window without network interception (reload=${reload})`, async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4457) });
  const bootstrap = await chromium.launch({ args: ["--ignore-certificate-errors"] });
  const auth = await bootstrap.newContext({ ignoreHTTPSErrors: true });
  const profile = { ...devices["iPhone 15"], ignoreHTTPSErrors: true };
  if (browser.browserType().name() === "firefox") profile.isMobile = false;
  const context = await browser.newContext(profile);
  try {
    const owner = watchLayout(await auth.newPage()); await enrol(owner, server);
    await context.addCookies(await auth.cookies());
    const page = watchLayout(await context.newPage()); await page.goto(server.origin);
    await expect(windows(page)).toHaveCount(1); await settled(page);
    if (reload) { await page.reload(); await expect(windows(page)).toHaveCount(1); await settled(page); }
    await page.evaluate(() => {
      const events: string[] = [];
      (window as unknown as { reviewTouchEvents: string[] }).reviewTouchEvents = events;
      for (const type of ["pointerdown", "pointerup", "touchstart", "touchend", "click"]) document.addEventListener(type, (event) => {
        if ((event.target as Element | null)?.closest('button[aria-label="Split right"]')) events.push(type);
      }, true);
    });
    await page.getByRole("button", { name: "Split right", exact: true }).tap();
    try { await expect(windows(page)).toHaveCount(2); }
    catch (error) {
      const engine = browser.browserType().name();
      console.log(JSON.stringify({ engine, reload, events: await page.evaluate(() => (window as unknown as { reviewTouchEvents: string[] }).reviewTouchEvents) }));
      await page.screenshot({ path: tracerEvidencePath(`touch-${engine}-reload-${reload}.png`) });
      throw error;
    }
    await settled(page);
  } finally { await context.close(); await auth.close(); await bootstrap.close(); await server.dispose(); }
});
