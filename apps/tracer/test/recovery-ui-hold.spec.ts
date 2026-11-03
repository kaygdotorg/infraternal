/** Proves D162 keeps the recovery entry out of production sign-in and the preview opt-in scoped.
 *
 * The pixel baselines were re-recorded on the owner's request (hug the content, a light scheme, a
 * translucent card), so they no longer match dev 9c62448; what they still pin is that production
 * sign-in has no recovery entry point and does not drift unnoticed, in both schemes. */
import { expect, test } from "playwright/test";

test.skip(Boolean(process.env.INFRATERNAL_RECOVERY_UI && process.env.INFRATERNAL_RECOVERY_UI !== "off"), "Requires the default production artifact");

for (const [name, width, height, scheme] of [
  ["mobile", 393, 852, "dark"], ["desktop", 1440, 900, "dark"], ["mobile-light", 393, 852, "light"], ["desktop-light", 1440, 900, "light"],
] as const) {
  test(`production ${name} sign-in matches its baseline without recovery entry points`, async ({ page }, info) => {
    await page.setViewportSize({ width, height });
    await page.emulateMedia({ reducedMotion: "reduce", colorScheme: scheme });
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
    // Expected pixels are test fixtures; raw captures remain in the evidence directory.
    await expect(page).toHaveScreenshot(["fixtures", `signin-${name}.png`], { animations: "disabled", maxDiffPixels: 0, threshold: 0 });
    const path = info.outputPath(`production-signin-${name}.png`);
    await page.screenshot({ path, animations: "disabled" });
    await info.attach(`production-signin-${name}`, { path, contentType: "image/png" });
    console.log(`RECOVERY_UI_HOLD viewport=${width}x${height} scheme=${scheme} differing_pixels=0`);
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
