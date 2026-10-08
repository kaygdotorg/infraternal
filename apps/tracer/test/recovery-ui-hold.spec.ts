/** Proves D162 keeps production sign-in identical to dev 9c62448 and preview opt-in scoped. */
import { expect, test } from "playwright/test";

test.skip(Boolean(process.env.INFRATERNAL_RECOVERY_UI && process.env.INFRATERNAL_RECOVERY_UI !== "off"), "Requires the default production artifact");

for (const [name, width, height] of [["mobile", 393, 852], ["desktop", 1440, 900]] as const) {
  test(`production ${name} sign-in matches dev without recovery entry points`, async ({ page }, info) => {
    await page.setViewportSize({ width, height });
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
    await page.route("**/auth/session", route => route.fulfill({ status: 401, json: {} }));
    // Even an explicit prototype URL cannot enable an ordinary production artifact.
    await page.goto("/?mock=1&proto=recovery");
    await expect(page.getByRole("button", { name: "Continue with passkey" })).toBeVisible();
    await expect(page.locator("#use-recovery")).toHaveCount(0);
    await expect(page.locator("#recovery-card")).toHaveCount(0);
    await page.evaluate(() => document.fonts.ready);
    // Exclude the time-dependent shader only; all sign-in pixels and geometry remain.
    await page.addStyleTag({ content: "#faulty-field { visibility: hidden !important; }" });
    await expect(page).toHaveScreenshot(`signin-${name}.png`, { animations: "disabled", maxDiffPixels: 0, threshold: 0 });
    const path = info.outputPath(`production-signin-${name}.png`);
    await page.screenshot({ path, animations: "disabled" });
    await info.attach(`production-signin-${name}`, { path, contentType: "image/png" });
    console.log(`RECOVERY_UI_HOLD viewport=${width}x${height} differing_pixels=0 baseline=9c62448`);
  });
}

test("production account state exposes no recovery controls", async ({ page }) => {
  await page.context().request.post("/__mock/reset");
  await page.route("**/auth/status", route => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", route => route.fulfill({ json: {
    user_id: "11111111-1111-4111-8111-111111111111", username: "fixture_owner",
    display_name: "Fixture owner", hostname: "fixture-host", recovery_words_need_replacing: true,
    recovery_pending: { ready_at: Math.floor(Date.now() / 1000) + 86400 },
  } }));
  await page.goto("/?mock=1&proto=recovery");
  await expect(page.locator("#capsule")).toBeVisible();
  await page.locator("#capsule").click();
  await expect(page.locator('[data-action="account:recovery"]')).toHaveCount(0);
  await expect(page.locator("#recovery-notice")).toBeHidden();
  await expect(page.locator(".ui-toast")).toBeHidden();
  await expect(page.getByText("replace recovery words", { exact: false })).toHaveCount(0);
});
