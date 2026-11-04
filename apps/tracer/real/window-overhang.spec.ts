/**
 * A framed Console window stays inside the desktop viewport, alone or among oversized columns (owner report, release
 * 9.5: the window was cut off at the gutter lines, 20 px in from each screen edge). The saved width of a hand-resized window is a weight times the
 * default width, so a wider "Window Sizes" option or a narrower browser window made it wider than the screen, and the
 * canvas container clips whatever overhangs it. Production server binary, real sessions (D177), 1690x1000 at 2x.
 */
import { expect, test, type BrowserContext, type Page } from "playwright/test";
import type { CanvasDocument } from "../src/canvas/model/schema";
import { tracerEvidencePath } from "../test/evidence-path";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });
let server: RealServer;
let cookies: Awaited<ReturnType<BrowserContext["cookies"]>>;

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("overhang_real"));
  await page.locator("#setup-display-name").fill("Overhang real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
  await windows(page).first().waitFor();
  cookies = await context.cookies();
  await context.close();
});
test.afterAll(async () => { await server?.dispose(); });

const windows = (page: Page) => page.locator('.cl[data-view="console"] .ui-window');

/** How far the window's box reaches past the canvas viewport on each side, once the camera has come to rest. */
async function overhang(page: Page, index = 0): Promise<{ left: number; right: number; width: number }> {
  let last = "";
  for (let i = 0; i < 60; i++) {
    const m = await page.evaluate((i) => {
      const w = document.querySelectorAll('.cl[data-view="console"] .ui-window')[i]!.getBoundingClientRect();
      const v = document.querySelector(".cl-viewport")!.getBoundingClientRect();
      return { left: Math.max(0, v.left - w.left), right: Math.max(0, w.right - v.right), width: w.width, x: w.x, y: w.y };
    }, index);
    const key = JSON.stringify(m);
    if (key === last) return m;
    last = key;
    await page.waitForTimeout(120);
  }
  throw new Error("the camera never came to rest");
}
const fits = async (page: Page, what: string, index = 0): Promise<void> => {
  const m = await overhang(page, index);
  expect(m.left, `${what}: ${m.left} px past the left edge (window ${m.width} px)`).toBeLessThanOrEqual(1);
  expect(m.right, `${what}: ${m.right} px past the right edge (window ${m.width} px)`).toBeLessThanOrEqual(1);
};
const setSize = (page: Page, size: string) => page.evaluate((v) => { localStorage.setItem("tracer.window-size.desktop", v); window.dispatchEvent(new CustomEvent("tracer:window-size")); }, size);

test("desktop 1690x1000: a hand-resized window stays inside the screen after a size change, a reload and a narrower window", async ({ browser }) => {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1690, height: 1000 }, deviceScaleFactor: 2 });
  await context.addCookies(cookies);
  const page = await context.newPage();
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.evaluate(() => localStorage.removeItem("tracer.window-size.desktop"));
  await page.reload();
  await page.locator(".cl-viewport").waitFor();
  await windows(page).first().waitFor();
  while ((await windows(page).count()) > 1) { await windows(page).last().locator('[data-action="close"]').evaluate((b) => (b as HTMLElement).click()); await page.waitForTimeout(600); }
  await fits(page, "default window");

  // Drag the right edge as far as it goes (it stops at the screen width) to save a wide weight.
  const box = (await windows(page).first().boundingBox())!;
  await page.mouse.move(box.x + box.width - 4, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width + 900, box.y + box.height / 2, { steps: 12 });
  await page.mouse.up();
  await page.waitForTimeout(500);
  const resized = await overhang(page);
  expect(resized.width, "the hand resize took").toBeGreaterThan(box.width + 400);
  await fits(page, "after the hand resize");

  for (const size of ["wide", "full", "comfortable"]) {
    await setSize(page, size);
    await fits(page, `"${size}" applied live`);
    await page.reload();
    await page.locator(".cl-viewport").waitFor();
    await windows(page).first().waitFor();
    await fits(page, `"${size}" after a reload`);
  }
  await setSize(page, "wide");
  await page.reload();
  await page.locator(".cl-viewport").waitFor();
  await windows(page).first().waitFor();
  await page.mouse.move(700, 500);
  for (let i = 0; i < 8; i++) await page.mouse.wheel(60, 0);
  await page.waitForTimeout(600);
  await fits(page, "after panning");
  await page.setViewportSize({ width: 1440, height: 900 });
  await fits(page, "after the browser window gets narrower");
  await context.close();
});

test("three hand-resized columns land fully inside the viewport at every camera stop", async ({ browser }) => {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1690, height: 1000 }, deviceScaleFactor: 2 });
  try {
    await context.addCookies(cookies);
    const page = await context.newPage();
    await page.goto(server.origin + "/?theme=ink&bg=none");
    await windows(page).first().waitFor();
    await setSize(page, "comfortable");
    while ((await windows(page).count()) > 1) {
      await windows(page).last().locator('[data-action="close"]').evaluate((b) => (b as HTMLElement).click());
      await page.waitForTimeout(600);
    }
    for (let i = 0; i < 3; i++) {
      if (i > 0) {
        await page.locator(".tab-add").click();
        await expect(windows(page)).toHaveCount(i + 1);
      }
      await fits(page, `column ${i + 1} before resize`, i);
      const box = (await windows(page).nth(i).boundingBox())!;
      await page.mouse.move(box.x + box.width - 4, box.y + box.height / 2);
      await page.mouse.down();
      await page.mouse.move(box.x + box.width + 900, box.y + box.height / 2, { steps: 12 });
      await page.mouse.up();
      await page.waitForTimeout(500);
      expect((await overhang(page, i)).width, `column ${i + 1} was hand-resized`).toBeGreaterThan(1200);
      await fits(page, `column ${i + 1} after resize`, i);
    }

    const columns = page.locator('.cl[data-view="console"] .cl-col');
    const rawWidths = () => columns.evaluateAll((els) => els.map((el) => Number((el as HTMLElement).dataset.w)));
    // Use the real focus shortcut to reach the first column, then wheel through the camera's stops in both directions.
    // Checking only focusWindow would miss extra or misplaced stops between columns.
    const savedWeights = () => page.evaluate(() => {
      const account = localStorage.getItem("tracer.user-id");
      const cache = JSON.parse(localStorage.getItem(`infraternal.canvas.${account}`) ?? "null") as { canonical?: CanvasDocument; pending?: unknown[] } | null;
      const layout = cache?.canonical?.views.find((view) => view.id === "console")?.layout;
      return cache?.pending?.length === 0 && layout?.type === "tiled" ? layout.columns.map((col) => col.weight) : [];
    });
    const checkStops = async (label: string, oversized: boolean): Promise<void> => {
      await expect(columns).toHaveCount(3);
      const viewportWidth = await page.locator(".cl-viewport").evaluate((el) => el.clientWidth);
      if (oversized) for (const width of await rawWidths()) expect(width, `${label}: saved width exceeds the viewport`).toBeGreaterThan(viewportWidth);
      for (let i = 0; i < 3; i++) await page.keyboard.press("Control+Shift+BracketLeft");
      await fits(page, `${label}: first stop`, 0);
      const viewport = (await page.locator(".cl-viewport").boundingBox())!;
      await page.mouse.move(viewport.x + viewport.width / 2, viewport.y + 8);
      for (const [direction, indices] of [[1, [1, 2, 2]], [-1, [1, 0, 0]]] as const) {
        for (const i of indices) {
          await page.mouse.wheel(direction * 60, 0);
          await page.waitForTimeout(600);
          await fits(page, `${label}: stop for column ${i + 1}`, i);
          if (label === "narrower" && direction === 1) await page.screenshot({ path: tracerEvidencePath(`overhang-${label}-column-${i + 1}.png`) });
        }
      }
      const widths = await windows(page).evaluateAll((els) => els.map((el) => el.getBoundingClientRect().width));
      for (const width of widths) expect(width, `${label}: drawn width is capped`).toBeLessThanOrEqual(viewportWidth);
      await page.screenshot({ path: tracerEvidencePath(`overhang-${label}.png`) });
    };

    await expect.poll(savedWeights, { message: "all three hand-resized weights reached the server" }).toHaveLength(3);
    const saved = await savedWeights();
    await setSize(page, "wide");
    await checkStops("wide-live", false);
    await page.reload();
    await expect(windows(page)).toHaveCount(3);
    await checkStops("wide-reload", true);
    expect(await savedWeights(), "reload preserves saved weights under the display ceiling").toEqual(saved);
    await page.setViewportSize({ width: 1440, height: 900 });
    await checkStops("narrower", true);
    expect(await savedWeights(), "narrowing preserves saved weights").toEqual(saved);
  } finally {
    await context.close();
  }
});
