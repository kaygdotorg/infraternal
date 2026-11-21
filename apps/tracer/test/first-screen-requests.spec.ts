/**
 * How a cold visit asks for its first screen (J1069, D375): the page hints the chunks it will need so they download
 * with it, and it asks the server for the first-run state and the session together instead of one after the other.
 * A functional check of the request shape; speed itself is measured by the first-paint audit, never asserted here (#314).
 */
import { expect, test } from "playwright/test";

test("the page hints its first-screen chunks and each hint is served", async ({ page }) => {
  const html = await (await page.request.get("/")).text();
  const hinted = [...html.matchAll(/<link rel="modulepreload" href="\.\/([^"]+)"/g)].map((match) => match[1]!);
  expect(hinted[0]).toBe("main.js");
  expect(hinted.length).toBeGreaterThan(1);
  for (const file of hinted) {
    expect(file === "main.js" || /^chunk-[0-9a-z]{8}\.js$/.test(file)).toBe(true);
    expect((await page.request.get(`/${file}`)).status()).toBe(200);
  }
});

test("the first-run check and the session check are both in flight before either answers", async ({ page }) => {
  await page.context().request.post("/__mock/reset");
  let release!: () => void;
  const answers = new Promise<void>((resolve) => { release = resolve; });
  const asked: string[] = [];
  await page.route("**/auth/status", async (route) => { asked.push("status"); await answers; await route.fulfill({ json: { setup_required: false } }); });
  await page.route("**/auth/session", async (route) => { asked.push("session"); await answers; await route.fulfill({ status: 401, json: {} }); });
  await page.goto("/");
  await expect.poll(() => asked.length).toBe(2);
  expect(asked).toEqual(["status", "session"]);
  release();
  await expect(page.locator("#login-passkey")).toBeVisible();
});

test("a session answer asked for early is dropped when the server needs first-run setup", async ({ page }) => {
  await page.context().request.post("/__mock/reset");
  await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: true } }));
  // A session the page must not use: setup comes first.
  await page.route("**/auth/session", (route) => route.fulfill({ json: { user_id: "stale" } }));
  await page.goto("/");
  await expect(page.locator("#setup-card")).toBeVisible();
  await expect(page.locator("#login-passkey")).toHaveCount(0);
});
