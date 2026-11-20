/**
 * The glass layer is optional and loads after the first paint (D188, D365, #448): if its chunks never arrive, the app still renders.
 *
 * The contrast rules and the solver (`glass-rules.on-demand.ts`, in a chunk of their own), the adaptive trackers and the watcher
 * (`glass-under.on-demand.ts`) are requested by the first `applyTheme`. Here every such chunk is refused by the network (found by what
 * it contains, never by a file name, which changes with each build) and the page must still come up: no unhandled error, the
 * windows drawn, the theme's own colours on the root, the palette opening, and one warning that says why the layer is missing.
 * The service worker is blocked, or it would answer from its cache and the route would never see a request.
 */
import { expect, test } from "playwright/test";

/** Strings only the glass chunks contain: the attribute their code puts on the root once it has run. */
const GLASS_MARKERS = ["data-glass-rules", "data-glass-watching"];

test("aborting the glass chunks leaves the app rendering with the theme's own colours", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, serviceWorkers: "block" });
  const aborted = new Set<string>();
  await context.route(/\/chunk-[a-z0-9]+\.js(\?.*)?$/, async (route) => {
    const response = await route.fetch();
    const body = await response.text();
    if (GLASS_MARKERS.some((marker) => body.includes(marker))) { aborted.add(route.request().url()); await route.abort("failed"); return; }
    await route.fulfill({ response, body });
  });
  const page = await context.newPage();
  const errors: string[] = [], warnings: string[] = [];
  page.on("pageerror", (error) => { errors.push(error.message); });
  page.on("console", (message) => { if (message.type() === "warning") warnings.push(message.text()); });
  await page.goto("/?mock=1&proto=clusters&scene=1&fps=0&bg=none&theme=ink");
  await expect(page.locator(".ui-window").first()).toBeVisible({ timeout: 30_000 });
  await page.keyboard.press("Control+Shift+K");
  await expect(page.locator("#palette")).toBeVisible({ timeout: 8000 });
  // The check bites: something really was refused, and the layer really is absent.
  expect(aborted.size, "glass chunks refused by the route").toBeGreaterThan(0);
  await expect(page.locator("html")).not.toHaveAttribute("data-glass-rules", "");
  // The theme's own colours are on the root and the palette text uses them.
  const colours = await page.evaluate(() => ({ fg: getComputedStyle(document.documentElement).getPropertyValue("--fg").trim(), text: getComputedStyle(document.querySelector("#palette")!).color }));
  expect(colours.fg).not.toBe("");
  expect(colours.text).not.toBe("");
  expect(errors, "unhandled page errors").toEqual([]);
  expect(warnings.some((w) => w.includes("glass")), `a warning names the missing glass layer (${warnings.join(" | ")})`).toBe(true);
  await context.close();
});
