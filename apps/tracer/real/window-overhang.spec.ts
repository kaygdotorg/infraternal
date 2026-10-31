/**
 * A lone Console window never overhangs the canvas viewport on a desktop (owner report, release 9.5: the window was cut
 * off at the gutter lines, 20 px in from each screen edge). The saved width of a hand-resized window is a weight times the
 * default width, so a wider "Window Sizes" option or a narrower browser window made it wider than the screen, and the
 * canvas viewport clips whatever overhangs it. Production server binary, real sessions (D177), 1690x1000 at 2x.
 */
import { expect, test, type BrowserContext, type Page } from "playwright/test";
import { startRealServer, type RealServer } from "./server";

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
  await page.locator("#setup-username").fill("overhang_real");
  await page.locator("#setup-display-name").fill("Overhang real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
  cookies = await context.cookies();
  await context.close();
});
test.afterAll(async () => { await server?.dispose(); });

const windows = (page: Page) => page.locator('.cl[data-view="console"] .ui-window');

/** How far the window's box reaches past the canvas viewport on each side, once the camera has come to rest. */
async function overhang(page: Page): Promise<{ left: number; right: number; width: number }> {
  let last = "";
  for (let i = 0; i < 60; i++) {
    const m = await page.evaluate(() => {
      const w = document.querySelector('.cl[data-view="console"] .ui-window')!.getBoundingClientRect();
      const v = document.querySelector(".cl-viewport")!.getBoundingClientRect();
      return { left: Math.max(0, v.left - w.left), right: Math.max(0, w.right - v.right), width: w.width };
    });
    const key = JSON.stringify(m);
    if (key === last) return m;
    last = key;
    await page.waitForTimeout(120);
  }
  throw new Error("the camera never came to rest");
}
const fits = async (page: Page, what: string): Promise<void> => {
  const m = await overhang(page);
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
    await fits(page, `"${size}" after a reload`);
  }
  await setSize(page, "wide");
  await page.reload();
  await page.locator(".cl-viewport").waitFor();
  await page.mouse.move(700, 500);
  for (let i = 0; i < 8; i++) await page.mouse.wheel(60, 0);
  await page.waitForTimeout(600);
  await fits(page, "after panning");
  await page.setViewportSize({ width: 1440, height: 900 });
  await fits(page, "after the browser window gets narrower");
  await context.close();
});
