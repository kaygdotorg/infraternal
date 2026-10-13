/** Independent D255 product-flow regressions: an early prompt still needs retained setup status and retry. */
import { expect, test } from "playwright/test";

test("review published host window subscribes to setup after the wizard closes", async ({ page }) => {
  const subscriptions: string[] = [];
  page.on("websocket", (socket) => {
    if (new URL(socket.url()).pathname === "/v1/bootstrap/setup/ws") {
      socket.on("framesent", ({ payload }) => subscriptions.push(String(payload)));
    }
  });
  await page.request.post("/__mock/bootstrap/reset");
  await page.goto("/?mock=1&proto=clusters&scene=3&theme=ink&bg=none");
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 45_000 });
  await page.evaluate(() => window.dispatchEvent(new CustomEvent("tracer:canvas-action", {
    detail: { action: "canvas:addhost", source: "keyboard" },
  })));
  await expect(page.locator(".ah-page[data-page='discovery']")).toBeVisible();
  await page.locator(".ui-chip-text").click();
  await page.keyboard.insertText("instant-fail.lab ");
  await page.locator(".ah-float").getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.locator(".ah-float")).toHaveCount(0, { timeout: 20_000 });
  // Raw-socket coverage in addhost-instant.spec.ts proves this fixture publishes
  // Join:failed after Done. Here only the product may subscribe; the test does
  // not supply the missing status adapter or drive retry on the person's behalf.
  await page.screenshot({ path: "test-results/addhost-instant-review-after-publication.png" });
  await expect.poll(() => subscriptions.some((text) => {
    const value = JSON.parse(text) as { action?: string; host_id?: string; window_id?: string };
    return value.action === "subscribe" && Boolean(value.host_id && value.window_id);
  })).toBe(true);
});
