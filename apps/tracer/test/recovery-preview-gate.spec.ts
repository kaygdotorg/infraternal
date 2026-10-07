/** Proves preview builds require both mock mode and explicit recovery prototype selection. */
import { expect, test } from "playwright/test";

test.skip(process.env.INFRATERNAL_RECOVERY_UI !== "preview", "Requires the explicit preview build flag");
for (const url of ["/", "/?mock=1", "/?proto=recovery", "/?mock=0&proto=recovery", "/?mock=1&proto=other", "/?mock=1&proto=recovery"]) {
  test(`preview recovery entry is scoped at ${url}`, async ({ page }) => {
    await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
    await page.route("**/auth/session", route => route.fulfill({ status: 401, json: {} }));
    await page.goto(url);
    await expect(page.locator("#login-passkey")).toBeVisible();
    await expect(page.locator("#use-recovery")).toHaveCount(url === "/?mock=1&proto=recovery" ? 1 : 0);
  });
}
