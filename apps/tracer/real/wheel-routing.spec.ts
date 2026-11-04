// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The wheel scrolls what is under it, for terminals (D275, #308), without the input lock. Three windows stacked in one column,
 * real PTYs, production server binary and build.
 *
 * - The FOCUSED terminal with scrollback: a vertical wheel over it moves its scrollback and the strip (the column's scroll offset
 *   and the canvas transform) does not move by a pixel, also past its top and bottom (a burst like trackpad momentum is swallowed).
 * - The same terminal at the bottom of its scrollback: a FRESH gesture (after a quiet moment) goes to the canvas and steps the column.
 * - A focused terminal with nothing to scroll, and an UNFOCUSED terminal even with scrollback, belong to the canvas (D275).
 * - The wheel over a window's header strip (nothing scrolls there) still pans.
 * Captures at 1440×900 (DPR 2) go to the external evidence directory.
 */
import { mkdirSync } from "node:fs";
import { expect, test, type Page } from "playwright/test";
import { tracerEvidencePath } from "../test/evidence-path";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });
const OUT = tracerEvidencePath("wheel-routing");
let server: RealServer;
let page: Page;

test.beforeAll(async ({ browser }) => {
  mkdirSync(OUT, { recursive: true });
  server = await startRealServer();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2 });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("wheel_real"));
  await page.locator("#setup-display-name").fill("Wheel real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
});
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

const windows = () => page.locator('.cl[data-view="console"] .ui-window');
const strip = () => page.evaluate(() => {
  const col = document.querySelector<HTMLElement>('.cl[data-view="console"] .cl-col')!;
  return `${col.scrollTop}|${col.scrollLeft}|${document.querySelector<HTMLElement>(".cl-world")!.style.transform}`;
});
const scrolled = (index: number) => windows().nth(index).locator(".terminal-host").getAttribute("data-scrolled");
/** A point on the terminal that is on screen (the strip shows only part of a tall window). */
const centre = async (index: number) => {
  const b = (await windows().nth(index).locator(".terminal-host").boundingBox())!;
  const top = Math.max(b.y, 70), bottom = Math.min(b.y + b.height, 880);
  return { x: b.x + b.width / 2, y: (top + bottom) / 2 };
};
const focus = async (index: number) => {
  await windows().nth(index).locator(".terminal-host").click({ position: { x: 60, y: 60 } });
  await expect(windows().nth(index).locator(".terminal-host")).toBeFocused();
};
/** A burst of wheel events 8 ms apart: one gesture, like trackpad momentum. */
const burst = async (dy: number, count: number) => { for (let i = 0; i < count; i++) { await page.mouse.wheel(0, dy); await page.waitForTimeout(8); } };
const quiet = () => page.waitForTimeout(450);

test("three stacked windows; no input lock anywhere", async () => {
  await windows().first().locator('[data-action="split-down"]').evaluate((b) => (b as HTMLElement).click());
  await expect(windows()).toHaveCount(2);
  await windows().nth(1).locator('[data-action="split-down"]').evaluate((b) => (b as HTMLElement).click());
  await expect(windows()).toHaveCount(3);
  await expect.poll(() => server.bridges.filter((bridge) => !bridge.closed).some((bridge) =>
    [...bridge.attached.keys()].filter((id) => (bridge.output.get(id)?.length ?? 0) > 0).length === 3,
  ), { timeout: 45_000 }).toBe(true);
  // Tall windows, so the column is a strip that scrolls (as when the person has stacked and resized them).
  await page.evaluate(() => { for (const w of document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window')) { w.style.height = "560px"; w.style.flex = "none"; } });
  await expect.poll(() => page.evaluate(() => { const c = document.querySelector<HTMLElement>('.cl[data-view="console"] .cl-col')!; return c.scrollHeight - c.clientHeight; }), { timeout: 15_000 }).toBeGreaterThan(200);
  // Scrollback in the middle and the last window: 400 lines each.
  for (const index of [2, 1]) {
    await focus(index);
    await page.keyboard.type("seq 1 400\n", { delay: 5 });
    await page.waitForTimeout(1200);
  }
  expect(await page.locator(".cl-viewport[data-input-lock]").count(), "the input lock is off").toBe(0);
  await page.waitForTimeout(1200);
});

test("focused, unlocked, with scrollback: the wheel scrolls the terminal and the strip never moves", async () => {
  await focus(1);
  await page.waitForTimeout(800);
  const before = await strip();
  await expect.poll(scrolled.bind(null, 1)).toBe("false");
  const mid = await centre(1);
  await page.mouse.move(mid.x, mid.y);
  await page.mouse.wheel(0, -300);
  await expect.poll(scrolled.bind(null, 1), "the scrollback moved").toBe("true");
  expect(await strip(), "the strip did not move").toBe(before);
  await page.screenshot({ path: `${OUT}/terminal-scrolled-back.png` });
  // To the very top and beyond, in one gesture: swallowed, never chained into the strip.
  await burst(-200, 80);
  await page.waitForTimeout(500);
  expect(await strip()).toBe(before);
  // Back to the bottom and beyond, in one gesture.
  await burst(200, 120);
  await page.waitForTimeout(500);
  expect(await scrolled(1)).toBe("false");
  expect(await strip(), "momentum past the bottom did not reach the strip").toBe(before);
});

test("at the bottom of its scrollback a fresh gesture goes to the canvas (D275)", async () => {
  await quiet();
  const before = await strip();
  const mid = await centre(1);
  await page.mouse.move(mid.x, mid.y);
  await page.mouse.wheel(0, 240);
  await expect.poll(strip, { timeout: 5000 }).not.toBe(before);
  await page.screenshot({ path: `${OUT}/handoff-after-bottom.png` });
});

test("an unfocused terminal belongs to the canvas, even with scrollback", async () => {
  await focus(1);
  await page.waitForTimeout(800);
  await quiet();
  const before = await strip();
  const other = await centre(2);
  await page.mouse.move(other.x, other.y);
  await page.mouse.wheel(0, -240);
  await page.waitForTimeout(900);
  expect(await scrolled(2), "the unfocused terminal's scrollback stayed").toBe("false");
  expect(await strip(), "the canvas took the wheel").not.toBe(before);
});

test("a focused terminal with nothing to scroll belongs to the canvas", async () => {
  await focus(0);
  await page.waitForTimeout(800);
  await quiet();
  const before = await strip();
  const first = await centre(0);
  await page.mouse.move(first.x, first.y);
  await page.mouse.wheel(0, 240);
  await page.waitForTimeout(900);
  expect(await scrolled(0)).toBe("false");
  expect(await strip(), "no scrollback: the canvas took the wheel").not.toBe(before);
});

test("the wheel over a window's header strip pans the canvas", async () => {
  await quiet();
  const before = await strip();
  const head = (await windows().nth(1).locator(".ui-window-head").boundingBox())!;
  await page.mouse.move(head.x + head.width - 4, head.y + head.height / 2);
  await page.mouse.wheel(0, 240);
  await page.waitForTimeout(900);
  expect(await strip()).not.toBe(before);
});
