/** Captures for the leftovers and already-running screens (#169), at phone and desktop size in the ink theme. */
import { tracerEvidencePath } from "./evidence-path";
import { expect, test, type Page } from "playwright/test";
import { resolve } from "node:path";

const OUT = tracerEvidencePath("addhost-start-fresh");
const SIZES = [{ name: "desktop", width: 1440, height: 900 }, { name: "phone", width: 393, height: 852 }];
const PORT = process.env.TRACER_TEST_PORT ?? "4621";

async function reach(page: Page, host: string, size: { width: number; height: number }): Promise<void> {
  await page.request.post("/__mock/bootstrap/reset", { maxRetries: 1 });
  await page.setViewportSize(size);
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
  await page.waitForTimeout(400);
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
  await page.locator(".ui-chip-text").click();
  await page.keyboard.type(`${host} `, { delay: 5 });
  await page.locator(".ah-float").getByRole("button", { name: "Continue", exact: true }).click();
}

for (const size of SIZES) {
  test(`captures ${size.name}`, async ({ page }) => {
    test.setTimeout(180_000);
    await reach(page, "stale.lab", size);
    await expect(page.getByRole("heading", { name: "This host has leftovers from an earlier setup" })).toBeVisible({ timeout: 30_000 });
    await page.waitForTimeout(600);
    await page.screenshot({ path: resolve(OUT, `leftovers-${size.name}-ink.png`) });
    await page.locator(".ah-details summary").click();
    await page.waitForTimeout(400);
    await page.screenshot({ path: resolve(OUT, `leftovers-details-${size.name}-ink.png`) });
    await page.locator(".ah-float").getByRole("button", { name: "Start fresh", exact: true }).click();
    await page.waitForTimeout(250);
    await page.screenshot({ path: resolve(OUT, `start-fresh-progress-${size.name}-ink.png`) });
    await reach(page, "running.lab", size);
    await expect(page.getByRole("heading", { name: "Setup is already running on this host" })).toBeVisible({ timeout: 30_000 });
    await page.waitForTimeout(600);
    await page.screenshot({ path: resolve(OUT, `running-${size.name}-ink.png`) });
  });
}

for (const size of SIZES) {
  test(`captures stuck-upgrade replacement at ${size.name} and keeps its label aligned`, async ({ browser }) => {
    test.setTimeout(180_000);
    const context = await browser.newContext({
      baseURL: `http://localhost:${PORT}`,
      viewport: { width: size.width, height: size.height },
      deviceScaleFactor: 2,
      hasTouch: size.name === "phone",
      isMobile: size.name === "phone",
    });
    const page = await context.newPage();
    try {
      await page.request.post("/__mock/bootstrap/reset", { maxRetries: 1 });
      await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
      await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
      await page.waitForTimeout(400);
      await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: "canvas:addhost", source: "keyboard" } })));
      await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible({ timeout: 45_000 });
      await page.locator(".ui-chip-text").click();
      await page.keyboard.type("stuck.lab ", { delay: 5 });
      await page.locator(".ah-float").getByRole("button", { name: "Continue", exact: true }).click();

      await expect(page.getByRole("heading", { name: "A stuck infraternal agent was found on stuck.lab" })).toBeVisible({ timeout: 30_000 });
      await expect(page.locator(".ah-page[data-page='failure'] .ah-lede")).toContainText(/build-node.*process 254.*2026-11-02T04:05:06Z/);
      const replace = page.locator(".ah-float footer").getByRole("button", { name: "Replace the stuck install", exact: true });
      await expect(replace).toBeVisible();
      const alignment = await replace.evaluate((button) => {
        const label = button.querySelector("span");
        if (!label) throw new Error("replacement button has no text label");
        const buttonBounds = button.getBoundingClientRect();
        const labelBounds = label.getBoundingClientRect();
        return {
          horizontal: Math.abs((buttonBounds.left + buttonBounds.right - labelBounds.left - labelBounds.right) / 2),
          vertical: Math.abs((buttonBounds.top + buttonBounds.bottom - labelBounds.top - labelBounds.bottom) / 2),
        };
      });
      expect(alignment.horizontal).toBeLessThanOrEqual(0.5);
      expect(alignment.vertical).toBeLessThanOrEqual(0.5);
      await page.screenshot({ path: resolve(OUT, `stuck-replacement-${size.name}-2x-ink.png`) });

      await replace.click();
      await expect(page.locator(".ah-page[data-page='progress']")).toBeVisible();
      await expect(page.locator(".ah-run[data-state='done']")).toBeVisible({ timeout: 30_000 });
    } finally {
      await context.close();
    }
  });
}
