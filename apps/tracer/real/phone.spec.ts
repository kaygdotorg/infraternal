/**
 * The phone (#119, D191): window width, the on-screen keyboard, an honest cursor, the plain default background and
 * Settings -> Window Sizes. Production server binary, real sessions; iPhone contexts at 393x852 and 375x667.
 *
 * The keyboard is emulated by shrinking the viewport's height (the page's meta asks for the layout to resize with
 * the keyboard); only the height may change: the window keeps its width and the terminal its columns.
 */
import { tracerEvidencePath } from "../test/evidence-path";
import { devices, expect, test, type BrowserContext, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });
let server: RealServer;
let cookies: Awaited<ReturnType<BrowserContext["cookies"]>>;
const captures = tracerEvidencePath("window-sizes");

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
  await mkdir(captures, { recursive: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("phone_real"));
  await page.locator("#setup-display-name").fill("Phone real");
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

const win = (page: Page) => page.locator('.cl[data-view="console"] .ui-window').first();
const width = async (page: Page): Promise<number> => (await win(page).boundingBox())!.width;
const grid = (page: Page) => page.locator('.cl[data-view="console"] .terminal-host').first().evaluate((h) => ({ cols: Number((h as HTMLElement).dataset.cols), rows: Number((h as HTMLElement).dataset.rows), typing: (h as HTMLElement).dataset.typing }));
const openSettings = (page: Page, section: string) => page.evaluate((s) => window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: `canvas:settings:${s}`, source: "pointer" } })), section);

for (const [w, h, keyboard] of [[393, 852, 336], [375, 667, 300]] as const) {
  test(`phone ${w}x${h}: full width, plain background, an honest cursor, the keyboard changes only the height`, async ({ browser }) => {
    test.setTimeout(120_000);
    const context = await browser.newContext({ ...devices["iPhone 15"], viewport: { width: w, height: h }, deviceScaleFactor: 3, ignoreHTTPSErrors: true });
    await context.addCookies(cookies);
    const page = await context.newPage();
    await page.goto(server.origin + "/?theme=ink");
    await page.locator(".cl-viewport").waitFor();
    await expect(win(page)).toBeVisible();
    await page.waitForTimeout(2500);

    // A fresh profile shows the Plain background.
    expect(await page.evaluate(() => document.documentElement.dataset.bg)).toBe("none");

    // The default keeps the gutter (TASTE: windows keep the gutter on phones): 99% of the space between the 16 px margins.
    expect(Math.abs((await width(page)) - 0.99 * (w - 32))).toBeLessThanOrEqual(1);

    // The cursor does not pretend: nothing is focused, so it waits; one tap focuses the input in that gesture.
    await expect.poll(() => grid(page).then((g) => g.cols)).toBeGreaterThan(10);
    expect((await grid(page)).typing).toBe("waiting");
    expect(await page.evaluate(() => (document.activeElement?.closest(".terminal-host") ?? null) === null)).toBe(true);
    const box = (await win(page).locator(".terminal-host").boundingBox())!;
    await page.touchscreen.tap(box.x + box.width / 2, box.y + box.height / 2);
    await expect.poll(() => page.evaluate(() => document.activeElement?.tagName)).toBe("TEXTAREA");
    expect((await grid(page)).typing).toBe("ready");
    await page.screenshot({ path: `${captures}/phone-${w}x${h}-keyboard-down.png` });

    // Long lines, then the keyboard: columns and width identical, only the height changes.
    await page.keyboard.type("printf '%0220d\\n' 7; ls -la /usr/bin | head -n 5\n", { delay: 3 });
    await page.waitForTimeout(1500);
    const before = { ...(await grid(page)), width: await width(page) };
    await page.setViewportSize({ width: w, height: h - keyboard });
    await page.waitForTimeout(1500);
    const after = { ...(await grid(page)), width: await width(page) };
    expect(after.cols, "columns with the keyboard up").toBe(before.cols);
    expect(Math.abs(after.width - before.width), "window width with the keyboard up").toBeLessThanOrEqual(0.5);
    expect(after.rows).toBeLessThan(before.rows);
    await page.screenshot({ path: `${captures}/phone-${w}x${h}-keyboard-up.png` });
    await page.setViewportSize({ width: w, height: h });
    await page.waitForTimeout(1000);
    expect((await grid(page)).cols).toBe(before.cols);

    // Settings -> Window Sizes switches the width live.
    await openSettings(page, "windows");
    const row = (group: string, id: string) => page.locator(`.ui-window[data-window-id="s-windows"] [data-kind="window-size-${group}"] .ui-sp-row[data-id="${id}"]`);
    await expect(row("phone", "full")).toBeVisible({ timeout: 10_000 });
    await expect(row("phone", "full")).toHaveAttribute("aria-checked", "true");
    expect(await page.locator('.ui-window[data-window-id="s-windows"] .ui-ts-title').allTextContents()).toEqual(["Phones", "Desktop"]);
    await page.waitForTimeout(800);
    await page.screenshot({ path: `${captures}/phone-${w}x${h}-settings-window-sizes.png` });
    await row("phone", "comfortable").evaluate((b) => (b as HTMLElement).click());
    await expect.poll(async () => Math.round(await width(page)), { timeout: 5000 }).toBe(w - 24 - 28);
    await expect(row("phone", "comfortable")).toHaveAttribute("aria-checked", "true");
    await row("phone", "full").evaluate((b) => (b as HTMLElement).click());
    await expect.poll(async () => Math.abs((await width(page)) - 0.99 * (w - 32)), { timeout: 5000 }).toBeLessThanOrEqual(1);
    // Edge to edge is an explicit choice: 99% of the screen, touching both edges.
    await row("phone", "edge").evaluate((b) => (b as HTMLElement).click());
    await expect.poll(async () => Math.abs((await width(page)) - 0.99 * w), { timeout: 5000 }).toBeLessThanOrEqual(1);
    await row("phone", "full").evaluate((b) => (b as HTMLElement).click());
    await context.close();
  });
}

test("desktop 1440x900: widths are unchanged, and Window Sizes switches them", async ({ browser }) => {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  await context.addCookies(cookies);
  const page = await context.newPage();
  await page.goto(server.origin + "/?theme=ink");
  await page.locator(".cl-viewport").waitFor();
  await expect(win(page)).toBeVisible();
  await page.waitForTimeout(2000);
  expect(Math.round(await width(page))).toBe(459); // one third of the canvas area (1400 px), as before
  await openSettings(page, "windows");
  const row = (group: string, id: string) => page.locator(`.ui-window[data-window-id="s-windows"] [data-kind="window-size-${group}"] .ui-sp-row[data-id="${id}"]`);
  await expect(row("desktop", "comfortable")).toHaveAttribute("aria-checked", "true", { timeout: 10_000 });
  await row("desktop", "wide").evaluate((b) => (b as HTMLElement).click());
  await expect.poll(async () => Math.round(await width(page)), { timeout: 5000 }).toBe(688);
  await row("desktop", "comfortable").evaluate((b) => (b as HTMLElement).click());
  await expect.poll(async () => Math.round(await width(page)), { timeout: 5000 }).toBe(459);
  await context.close();
});
