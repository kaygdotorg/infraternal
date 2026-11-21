/**
 * How a cold visit asks for its first screen (J1069, D375): the page hints the chunks it will need so they download
 * with it. A functional check of the request shape; speed itself is measured by the first-paint audit, never asserted here (#314).
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
