/** Recovery from an address that is not a secure context, like a LAN IP over plain http. */
import { expect, test } from "playwright/test";

test.skip(!["preview", "1"].includes(process.env.INFRATERNAL_RECOVERY_UI ?? "off"), "Recovery presentation requires an explicit build flag");

const port = process.env.TRACER_TEST_PORT ?? "4621";
// Not localhost and not https: browsers treat it as insecure, so crypto.subtle and WebAuthn are
// undefined, exactly as on http://<lan address>. The name resolves to the loopback test server.
test.use({ launchOptions: { args: ["--disable-renderer-backgrounding", "--host-resolver-rules=MAP insecure-lan.test 127.0.0.1"] } });

test("recovery from a non-secure origin says it needs https and sends nothing", async ({ page }) => {
  const requests: string[] = [];
  page.on("request", (request) => { if (request.url().includes("/auth/recovery")) requests.push(request.url()); });
  await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", (route) => route.fulfill({ status: 401, json: {} }));
  await page.goto(`http://insecure-lan.test:${port}/?mock=1&proto=recovery`);
  expect(await page.evaluate(() => [window.isSecureContext, typeof crypto.subtle])).toEqual([false, "undefined"]);
  await page.locator("#use-recovery").click();
  await page.locator("#recovery-username").fill("fixture_owner");
  // Fixture words only; they protect nothing. Pasting the whole key fills every field.
  const words = "rifle sketch story tattoo ginger nose define robot kick best nuclear raise museum drum extend purchase myth electric globe group enlist taxi olympic bargain";
  await page.locator(".auth-word-inputs input").first().evaluate((input, text) => {
    const data = new DataTransfer(); data.setData("text/plain", text);
    input.dispatchEvent(new ClipboardEvent("paste", { clipboardData: data, bubbles: true, cancelable: true }));
  }, words);
  await page.locator("#recovery-next").click();
  await expect(page.locator("#auth-error")).toHaveText("Recovery needs a secure connection (https)");
  expect(requests).toEqual([]);
});
