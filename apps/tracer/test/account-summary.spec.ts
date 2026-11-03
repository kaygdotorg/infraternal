/** Slice 1 uses the production card and Settings, with only the HTTP summary replaced (#224). */
import { expect, test } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

for (const viewport of [{ width: 1440, height: 900 }, { width: 393, height: 852 }]) for (const theme of ["ink", "paper"]) {
  test(`account summary rows and Settings at ${viewport.width} ${theme}`, async ({ page }) => {
    await page.setViewportSize(viewport);
    let userId = "", requests = 0, passkeys = 1;
    await page.route("**/auth/session", async (route) => {
      const response = await route.fetch();
      const session = await response.json() as { user_id: string };
      userId = session.user_id;
      await route.fulfill({ response });
    });
    await page.route("**/auth/account-summary", async (route) => {
      requests++;
      await route.fulfill({ json: { user_id: userId, session_incarnation: "fixture", passkeys, recovery_set_up: true } });
    });
    await page.goto(`/?mock=1&proto=product&fresh=1&bg=none&theme=${theme}`);
    await expect(page.locator("#sidebar-toggle")).toBeVisible();
    // Wait for idle card preparation as well as the first screen; neither may read account setup facts.
    await expect(page.locator(".ac")).toBeAttached({ timeout: 20_000 });
    expect(requests).toBe(0);
    await page.locator("#sidebar-toggle").click();
    await page.locator(".ui-sidebar-user").click();
    const card = page.locator('.ac[data-open="true"]');
    const row = (name: string) => card.locator(".ui-kv-row").filter({ has: page.locator(".ui-kv-key", { hasText: name }) });
    await expect(row("Passkeys").locator(".ui-kv-value")).toHaveText("Only one, add a second");
    await expect(row("Recovery key").locator(".ui-kv-value")).toHaveText("Set up");
    await expect(row("Recovery key").locator(".ui-kv-value")).toHaveAttribute("data-tip", /verification history unavailable/);
    await expect(card.locator(".ui-kv-row")).toHaveCount(2);
    await expect(page.locator(".ui-sidebar-user")).toHaveAttribute("data-attention", "passkey");
    await page.waitForTimeout(500);
    const geometry = await card.evaluate((root) => {
      const sidebar = root.getBoundingClientRect();
      const keys = [...root.querySelectorAll<HTMLElement>(".ui-kv-key")].map((key) => key.getBoundingClientRect());
      const rows = [...root.querySelectorAll<HTMLElement>(".ui-kv-row")].map((row) => row.getBoundingClientRect());
      return { lefts: keys.map((key) => key.left), contained: rows.every((row) => row.left >= sidebar.left && row.right <= sidebar.right + 0.5) };
    });
    expect(Math.abs(geometry.lefts[0]! - geometry.lefts[1]!)).toBeLessThanOrEqual(0.5);
    expect(geometry.contained).toBe(true);
    await page.screenshot({ path: tracerEvidencePath(`account-summary-${viewport.width}-${theme}.png`) });
    await row("Passkeys").locator(".ui-kv-value").click();
    await expect(page.locator("#sidebar-toggle")).toHaveAttribute("aria-expanded", "false");
    const settings = page.locator('[data-window-id="s-account"]');
    await expect(settings.getByRole("button", { name: "Add a second", exact: true })).toBeVisible();
    await expect(settings.locator('[data-kind="recovery"]')).toContainText("verification history unavailable");
    await page.waitForTimeout(500);
    await page.screenshot({ path: tracerEvidencePath(`account-settings-${viewport.width}-${theme}.png`) });
    const alignment = await settings.locator('[data-kind="passkeys"] .ui-sp-row').evaluate((root) => {
      const label = root.querySelector(".ui-sp-label")!.getBoundingClientRect();
      const button = root.querySelector("button")!.getBoundingClientRect();
      return Math.abs((label.top + label.bottom) / 2 - (button.top + button.bottom) / 2);
    });
    expect(alignment).toBeLessThanOrEqual(0.5);
    let adds = 0;
    await page.route("**/auth/login-start", (route) => { adds++; return route.fulfill({ status: 503, json: { error: "auth unavailable" } }); });
    await settings.getByRole("button", { name: "Add a second", exact: true }).click();
    await expect(page.locator(".ui-toast").filter({ hasText: "The passkey could not be added" })).toBeVisible();
    expect(adds).toBe(1);
    passkeys = 2;
    await page.locator("#sidebar-toggle").click();
    await page.locator(".ui-sidebar-user").click();
    await expect(row("Passkeys").locator(".ui-kv-value")).toHaveText("2");
    await expect(page.locator(".ui-sidebar-user .ac-badge")).toHaveCount(0);
  });
}

test("unavailable summary never invents zero keys or never-verified recovery, and reopen retries", async ({ page }) => {
  let unavailable = true;
  await page.route("**/auth/account-summary", (route) => route.fulfill(unavailable ? { status: 503, json: { error: "auth unavailable" } } : { json: { user_id: "different-account", session_incarnation: "different", passkeys: 0, recovery_set_up: false } }));
  await page.goto("/?mock=1&proto=product&fresh=1&bg=none");
  await expect(page.locator(".ac")).toBeAttached({ timeout: 20_000 });
  await page.locator("#sidebar-toggle").click();
  await page.locator(".ui-sidebar-user").click();
  await expect(page.locator('.ac[data-open="true"]')).toBeVisible();
  await expect(page.locator(".ac .ui-kv-row")).toHaveCount(0);
  unavailable = false;
  await page.locator(".ui-sidebar-user").click();
  await page.locator(".ui-sidebar-user").click();
  await expect(page.locator('.ac[data-open="true"]')).toBeVisible();
  await expect(page.locator(".ac .ui-kv-row")).toHaveCount(0);
});
