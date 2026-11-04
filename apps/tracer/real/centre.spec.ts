/**
 * One Console window stays centred. (The sidebar is a layer over the canvas and moves nothing: see sidebar.spec.ts, #114.)
 * Production server binary, real sessions (D177). "Centred" is measured against the canvas area (the pane under
 * the top bar and above the key tray), within 1 px, after each event that can move the framing.
 */
import { devices, expect, test, type BrowserContext, type Page } from "playwright/test";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });
let server: RealServer;
let desktop: BrowserContext;
let cookies: Awaited<ReturnType<BrowserContext["cookies"]>>;

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  desktop = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await desktop.newPage();
  const cdp = await desktop.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("centre_real"));
  await page.locator("#setup-display-name").fill("Centre real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
  cookies = await desktop.cookies();
  await page.close();
});
test.afterAll(async () => { await desktop?.close(); await server?.dispose(); });

const windows = (page: Page) => page.locator('.cl[data-view="console"] .ui-window');

/** Offset of the window's centre from the canvas area's centre, once the camera has come to rest. */
async function offset(page: Page): Promise<{ dx: number; dy: number }> {
  let last = "";
  for (let i = 0; i < 60; i++) {
    const m = await page.evaluate(() => {
      const w = document.querySelector('.cl[data-view="console"] .ui-window')!.getBoundingClientRect();
      const v = document.querySelector(".cl-viewport")!.getBoundingClientRect();
      return { dx: (w.left + w.right) / 2 - (v.left + v.right) / 2, dy: (w.top + w.bottom) / 2 - (v.top + v.bottom) / 2 };
    });
    const key = `${m.dx.toFixed(2)},${m.dy.toFixed(2)}`;
    if (key === last) return m;
    last = key;
    await page.waitForTimeout(120);
  }
  throw new Error("the camera never came to rest");
}
const centred = async (page: Page, what: string): Promise<void> => {
  const m = await offset(page);
  expect(Math.abs(m.dx), `${what}: horizontal offset ${m.dx}`).toBeLessThanOrEqual(1);
  expect(Math.abs(m.dy), `${what}: vertical offset ${m.dy}`).toBeLessThanOrEqual(1);
};

async function onlyWindow(page: Page): Promise<void> {
  while ((await windows(page).count()) > 1) {
    await windows(page).last().locator('[data-action="close"]').evaluate((b) => (b as HTMLElement).click());
    await page.waitForTimeout(600);
  }
}

async function scenarios(page: Page, label: string): Promise<void> {
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator(".cl-viewport").waitFor();
  await onlyWindow(page);
  await centred(page, `${label}: after load`);

  // open and close
  await page.locator(".tab-add").click();
  await expect(windows(page)).toHaveCount(2);
  await windows(page).last().locator('[data-action="close"]').evaluate((b) => (b as HTMLElement).click());
  await expect(windows(page)).toHaveCount(1);
  await centred(page, `${label}: after open and close`);

  // reload
  await page.reload();
  await page.locator(".cl-viewport").waitFor();
  await expect(windows(page)).toHaveCount(1);
  await centred(page, `${label}: after reload`);

  // font and theme
  for (const choice of ["Paper", "Geist Mono", "Ink", "Maple Mono"]) {
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette-input").fill(choice);
    await page.locator("#palette-results [role=option]", { hasText: choice }).first().click();
    await page.waitForTimeout(700);
    await expect(page.locator("#palette")).toBeHidden();
    await centred(page, `${label}: after choosing ${choice}`);
  }

  // resize by dragging an edge (desktop only: a phone has no edge handles)
  if (label === "desktop") {
    const box = (await windows(page).first().boundingBox())!;
    await page.mouse.move(box.x + box.width - 1, box.y + box.height / 2);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width + 60, box.y + box.height / 2, { steps: 8 });
    await page.mouse.up();
    await centred(page, `${label}: after a window resize`);
  }

  // viewport resize
  const size = page.viewportSize()!;
  // A phone cannot get narrower than the smallest column (260 px), so it only loses a little.
  await page.setViewportSize(label === "phone" ? { width: size.width - 40, height: size.height - 60 } : { width: size.width - 120, height: size.height - 90 });
  await centred(page, `${label}: after a viewport resize`);
  await page.setViewportSize(size);
  await centred(page, `${label}: after restoring the viewport`);
}

test("desktop 1440x900: one window stays centred after every event", async () => {
  const page = await desktop.newPage();
  await scenarios(page, "desktop");

  // the sidebar is a layer over the canvas: a centred window does not move at all
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator(".cl-viewport").waitFor();
  await onlyWindow(page);
  await centred(page, "before the sidebar");
  const before = await windows(page).first().boundingBox();
  const sizeBefore = await page.locator(".terminal-host").first().evaluate((n) => `${n.clientWidth}x${n.clientHeight}`);
  await page.evaluate(() => { (window as unknown as { __moves: number }).__moves = 0; const w = document.querySelector('.cl[data-view="console"] .ui-window')!; let last = ""; const tick = (): void => { const r = w.getBoundingClientRect(); const k = `${r.left.toFixed(2)}`; if (last && k !== last) (window as unknown as { __moves: number }).__moves++; last = k; requestAnimationFrame(tick); }; tick(); });
  await page.locator("#sidebar-toggle").click();
  await expect(page.locator("#sidebar")).toBeVisible();
  await page.waitForTimeout(1200);
  const after = await windows(page).first().boundingBox();
  expect(Math.abs(after!.x - before!.x)).toBeLessThanOrEqual(0.5);
  expect(await page.evaluate(() => (window as unknown as { __moves: number }).__moves)).toBe(0);
  expect(await page.locator(".terminal-host").first().evaluate((n) => `${n.clientWidth}x${n.clientHeight}`)).toBe(sizeBefore);
  await page.locator("#sidebar-toggle").click();
  await page.waitForTimeout(800);
  await centred(page, "after the sidebar closes");
  await page.close();
});

test("phone 393x852: one window stays centred after every event", async ({ browser }) => {
  const context = await browser.newContext({ ...devices["iPhone 15"], ignoreHTTPSErrors: true });
  await context.addCookies(cookies);
  const page = await context.newPage();
  await scenarios(page, "phone");
  await context.close();
});
