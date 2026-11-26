/**
 * How a cold visit asks for its first screen (J1069, D375): the page hints the chunks it will need so they download
 * with it, and it asks the server for the first-run state and the session together instead of one after the other.
 * A functional check of the request shape; speed itself is measured by the first-paint audit, never asserted here (#314).
 */
import { expect, test } from "playwright/test";

test("the page hints its first-screen chunks and each hint is served", async ({ page }) => {
  const html = await (await page.request.get("/")).text();
  const hinted = [...html.matchAll(/<link rel="modulepreload" href="\.\/([^"]+)"/g)].map((match) => match[1]!);
  expect(hinted[0]).toMatch(/^main\.[0-9a-f]{10}\.js$/);
  expect(hinted.length).toBeGreaterThan(1);
  for (const file of hinted) {
    expect(/^main\.[0-9a-f]{10}\.js$/.test(file) || /^chunk-[0-9a-z]{8}\.js$/.test(file)).toBe(true);
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

test("the first-run and session checks start before the entry script finishes loading", async ({ page }) => {
  await page.context().request.post("/__mock/reset");
  let entryReleased = false;
  await page.route(/\/main\.[0-9a-f]{10}\.js$/, async (route) => {
    // sleep: hold main.js so the test proves auth checks left index.html before the entry script arrived.
    await new Promise((resolve) => setTimeout(resolve, 1500));
    entryReleased = true;
    await route.continue();
  });
  const asked: string[] = [];
  await page.route("**/auth/status", async (route) => { asked.push("status"); await route.fulfill({ json: { setup_required: false } }); });
  await page.route("**/auth/session", async (route) => { asked.push("session"); await route.fulfill({ status: 401, json: {} }); });
  await page.goto("/", { waitUntil: "commit" });
  await expect.poll(() => asked.length).toBe(2);
  expect(asked).toEqual(["status", "session"]);
  expect(entryReleased).toBe(false);
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

/** The style sheets only the signed-in canvas needs; the page loads them without blocking the first paint. */
const CANVAS_SHEETS = ["canvas", "clusters", "mesh", "sessions", "addhost"];

test("the page links fingerprinted sheets, and the five canvas sheets are off the render-blocking path", async ({ page }) => {
  const html = await (await page.request.get("/")).text();
  const sheets = [...html.matchAll(/<link rel="stylesheet" href="\.\/([^"]+)"([^>]*)>/g)].map((match) => ({ file: match[1]!, rest: match[2]! }));
  expect(sheets).toHaveLength(8);
  for (const { file, rest } of sheets) {
    expect(file).toMatch(/^[a-z]+\.[0-9a-f]{10}\.css$/);
    const deferred = CANVAS_SHEETS.some((name) => file.startsWith(`${name}.`));
    expect(rest.includes('media="print"') && rest.includes("data-deferred")).toBe(deferred);
    const response = await page.request.get(`/${file}`);
    expect(response.status()).toBe(200);
  }
});

test("the sign-in screen does not wait for the canvas sheets", async ({ page }) => {
  await page.context().request.post("/__mock/reset");
  await page.route("**/auth/status", (route) => route.fulfill({ json: { setup_required: false } }));
  await page.route("**/auth/session", (route) => route.fulfill({ status: 401, json: {} }));
  let released = false;
  await page.route(/\/(?:canvas|clusters|mesh|sessions|addhost)\.[0-9a-f]{10}\.css$/, async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    released = true;
    await route.continue();
  });
  // "commit", not the default "load": the load event waits for every stylesheet, even one that does not block rendering.
  await page.goto("/", { waitUntil: "commit" });
  await expect(page.locator("#login-passkey")).toBeVisible();
  expect(released).toBe(false);
});

test("the canvas is not drawn until its sheets have arrived, and then it is styled", async ({ page }) => {
  await page.context().request.post("/__mock/reset");
  let released = false;
  await page.route(/\/clusters\.[0-9a-f]{10}\.css$/, async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    released = true;
    await route.continue();
  });
  // Looks at the sheets in the same tick as the first window is added to the page. (Checking visibility afterwards would not do:
  // an unstyled window has no size, so it only counts as visible once its sheet is in, whatever the guard does.)
  await page.addInitScript(() => {
    new MutationObserver(() => {
      const w = window as unknown as { __atFirstWindow?: string[] };
      if (w.__atFirstWindow === undefined && document.querySelector(".ui-window")) {
        w.__atFirstWindow = [...document.querySelectorAll("link[data-deferred]")].map((link) => (link as HTMLLinkElement).media);
      }
    }).observe(document, { childList: true, subtree: true });
  });
  await page.goto("/?proto=product&fresh=1&bg=none", { waitUntil: "commit" });
  await expect(page.locator(".ui-window").first()).toBeVisible();
  expect(released).toBe(true);
  // Every deferred sheet was live (not on the print medium) when the first window appeared.
  expect(await page.evaluate(() => (window as unknown as { __atFirstWindow?: string[] }).__atFirstWindow)).toEqual(["all", "all", "all", "all", "all"]);
});
