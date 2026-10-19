/** Production-build flag and settings checks with real H264 decoding; screenshots are external review receipts [D160,D208,D262]. */
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "./evidence-path";

test.skip(process.env.TRACER_DOUBLE_APPWIN !== "1", "needs the desktop source double and rendered H264 fixtures");
async function open(page: Page) {
  await page.request.post("/__mock/reset");
  await page.request.post("/__mock/appwin/config", { data: { reset: true, controlContract: true } });
  expect((await (await page.request.get("/__mock/appwin/state")).json()).sessions).toHaveLength(0);
  // The server double establishes the test account; the bundle takes its normal signed-in product path.
  await page.goto("/?proto=product&fresh=1&appwin=1&bg=none");
  await expect(page.locator(".ui-window").first()).toBeVisible();
  await expect(async () => {
    await page.keyboard.press("Control+Shift+K");
    await expect(page.getByRole("option", { name: /Settings: Hosts/ })).toBeVisible({ timeout: 1500 });
  }).toPass({ timeout: 25_000 });
  await page.keyboard.press("Escape");
}
async function enable(page: Page) {
  await page.keyboard.press("Control+Shift+K");
  await page.getByRole("option", { name: /Settings: Hosts/ }).click();
  const toggle = page.getByRole("switch", { name: /Stream app windows/ });
  await expect(toggle).not.toBeChecked();
  await toggle.click();
  await expect(toggle).toBeChecked();
  expect(await page.evaluate(() => localStorage.getItem("infraternal.app-windows"))).toBe("1");
  await page.getByRole("button", { name: "New window", exact: true }).click();
  await page.getByRole("option", { name: /Editor, stream\.ts/ }).click();
  await expect(page.locator(".aw-stage")).toHaveAttribute("data-picture", "live", { timeout: 20_000 });
}

test("production ignores the preview URL and keeps New window opening shells", async ({ page }) => {
  await open(page);
  expect(await page.evaluate(() => localStorage.getItem("infraternal.app-windows"))).not.toBe("1");
  await page.getByRole("button", { name: "New window", exact: true }).click();
  await expect(page.locator('.ui-window[data-kind="terminal"]')).toHaveCount(2);
  await expect(page.locator(".aw-pop")).toHaveCount(0);
});

test("the production setting enables viewing, control and releasing its native lease", async ({ page }) => {
  await open(page);
  await enable(page);
  await expect(page.locator(".aw-control")).toHaveCount(0);
  await page.screenshot({ path: tracerEvidencePath("production-app-viewing.png") });
  await page.locator(".aw-stage").click();
  await expect(page.locator(".aw-control")).toContainText("Controlled from infraternal");
  await page.screenshot({ path: tracerEvidencePath("production-app-control.png") });
  await page.locator(".aw-control").click();
  await expect.poll(async () => (await (await page.request.get("/__mock/appwin/state")).json()).sessions[0]?.controller).toBe(false);
  await expect(page.locator(".aw-stage")).toHaveAttribute("data-picture", "live");
});

test.describe("phone production surface", () => {
  test.use({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  test("the same setting and picker open a live window", async ({ page }) => {
    await open(page);
    await enable(page);
    await page.screenshot({ path: tracerEvidencePath("production-app-phone.png") });
  });
});

test("turning the production setting off retires existing windows and source sessions", async ({ page }) => {
  test.setTimeout(60_000);
  await open(page);
  await enable(page);
  await page.keyboard.press("Control+Shift+K");
  await page.getByRole("option", { name: /Settings: Hosts/ }).click();
  await page.getByRole("switch", { name: /Stream app windows/ }).click();
  expect(await page.evaluate(() => localStorage.getItem("infraternal.app-windows"))).toBe("0");
  await expect(page.locator('.ui-window[data-kind="app"], .ui-window[data-kind="screen"]')).toHaveCount(0);
  await expect.poll(async () => (await (await page.request.get("/__mock/appwin/state")).json()).sessions.length).toBe(0);
  // Re-enable must create a fresh binding, rather than focus the disposed one.
  await enable(page);
  await expect(page.locator('.ui-window[data-kind="app"]')).toHaveCount(1);
  await expect.poll(async () => (await (await page.request.get("/__mock/appwin/state")).json()).sessions.length).toBe(1);
});
