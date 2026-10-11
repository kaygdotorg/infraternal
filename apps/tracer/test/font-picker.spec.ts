/**
 * The Font group in the command palette (#90, D87): arrowing or hovering onto a row previews
 * the whole font (UI and terminal), Escape reverts, Enter commits and persists, and a font is
 * fetched only when first previewed or picked.
 */
import { expect, test, type Page } from "playwright/test";

const port = Number(process.env.TRACER_TEST_PORT ?? "4621");
const baseURL = `http://localhost:${port}`;

const state = (page: Page) => page.evaluate(() => {
  const metrics = window.__tracerTestDouble!.rendererMetrics()!;
  return {
    dataFont: document.documentElement.dataset.font,
    rootFamily: getComputedStyle(document.documentElement).fontFamily,
    terminalId: metrics.fontId,
    cols: metrics.cols,
    saved: localStorage.getItem("tracer.font"),
    loaded: [...document.fonts].filter((face) => face.status === "loaded").map((face) => face.family.replaceAll('"', "")),
  };
});

async function open(page: Page): Promise<void> {
  await page.context().request.post("/__mock/reset");
  await page.context().request.post("/__mock/open-terminal");
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  await page.keyboard.press("Control+Shift+K");
  await page.fill("#palette-input", "font");
}

test("arrow previews a font, Escape reverts, nothing is saved", async ({ browser }) => {
  const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  await open(page);
  expect((await state(page)).loaded).not.toContain("Geist Mono");
  await page.keyboard.press("ArrowDown");
  await expect.poll(async () => (await state(page)).dataFont).toBe("geist-mono");
  // The terminal follows the interface in its own task (so no single task is long): poll for it.
  await expect.poll(async () => (await state(page)).terminalId).toBe("geist-mono");
  const preview = await state(page);
  expect(preview.rootFamily).toContain("Geist Mono");
  expect(preview.loaded).toContain("Geist Mono");
  expect(preview.saved).toBeNull();
  await page.keyboard.press("Escape");
  await expect.poll(async () => (await state(page)).dataFont).toBe("maple-mono-nf");
  await expect.poll(async () => (await state(page)).terminalId).toBe("maple-mono-nf");
  expect((await state(page)).saved).toBeNull();
  await context.close();
});

test("hover previews, Enter commits and the choice survives a reload", async ({ browser }) => {
  const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  await open(page);
  const row = page.locator('#palette-results .result[data-action="font:ibm-plex-mono"]');
  await row.hover();
  await page.mouse.move((await row.boundingBox())!.x + 40, (await row.boundingBox())!.y + 10);
  await expect.poll(async () => (await state(page)).dataFont).toBe("ibm-plex-mono");
  await page.keyboard.press("Enter");
  await expect(page.locator("#palette")).toBeHidden();
  const committed = await state(page);
  expect(committed.dataFont).toBe("ibm-plex-mono");
  expect(committed.terminalId).toBe("ibm-plex-mono");
  expect(committed.saved).toBe("ibm-plex-mono");
  await page.goto("/?mock=1&theme=ink&bg=none");
  await expect.poll(() => page.evaluate(() => window.__tracerTestDouble?.isConnected() === true), { timeout: 30_000 }).toBe(true);
  const reloaded = await state(page);
  expect(reloaded.dataFont).toBe("ibm-plex-mono");
  expect(reloaded.terminalId).toBe("ibm-plex-mono");
  expect(reloaded.loaded).toContain("IBM Plex Mono");
  await context.close();
});
