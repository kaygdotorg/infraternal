/** D312 production-browser loss boundary, delayed confirmation, peer revocation and private-storage controls. */
import { expect, test, type Page } from "playwright/test";
import { mkdir } from "node:fs/promises";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { enrol, settled, windows } from "./layout-devices";
import { cache, watchLayout } from "./layout-observer";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

const pending = (page: Page) => page.getByText("Not saved — keep this tab open", { exact: true });
/** Hold only layout applies; all terminal frames and unrelated calls still reach the real server. */
async function holdApplies(page: Page) {
  let holding = false;
  const held: Array<() => void> = [];
  await page.routeWebSocket("**/v1/ws", (route) => {
    const upstream = route.connectToServer();
    route.onMessage((message) => {
      let layout = false;
      if (typeof message !== "string") new WebSocketFrameDecoder().feed(new Uint8Array(message), (_id, frame) => { if (frame.type === "Call" && frame.actionId === "canvas.layout.apply") layout = true; });
      if (layout && holding) held.push(() => upstream.send(message)); else upstream.send(message);
    });
  });
  return { hold() { holding = true; }, release() { holding = false; for (const send of held.splice(0)) send(); }, discard() { holding = false; held.length = 0; } };
}
async function noPrivateStorage(page: Page): Promise<void> {
  expect(await page.evaluate(() => Object.keys(localStorage).filter((key) => /^(infraternal\.canvas|tracer\.(drawing-identity|sessions|session\.|user-id))/.test(key)))).toEqual([]);
  expect(await page.evaluate(() => Object.keys(sessionStorage).filter((key) => key.startsWith("tracer.session.")))).toEqual([]);
}
async function signOut(page: Page): Promise<void> {
  await page.keyboard.press("Control+Shift+K"); await page.locator("#palette-input").fill("sign out");
  await page.locator("#palette-results [role=option]").first().click();
  await page.locator('.ui-confirm-tip[data-open="true"]').getByRole("button", { name: "Sign out", exact: true }).click();
}

test("three tabs keep edits local until confirmation and recover confirmed state after reload", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4450) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  try {
    const a = watchLayout(await context.newPage()), gate = await holdApplies(a); await enrol(a, server); await settled(a);
    const b = watchLayout(await context.newPage()), c = watchLayout(await context.newPage());
    await b.goto(server.origin); await c.goto(server.origin); await expect(windows(b)).toHaveCount(1); await expect(windows(c)).toHaveCount(1);
    gate.hold(); await a.bringToFront(); await a.keyboard.press("Control+Shift+E");
    await expect(windows(a)).toHaveCount(2); await expect(pending(a)).toBeVisible();
    await expect(windows(b)).toHaveCount(1); await expect(windows(c)).toHaveCount(1);
    const evidence = tracerEvidencePath("per-tab"); await mkdir(evidence, { recursive: true });
    for (const theme of ["ink", "paper"]) {
      await a.setViewportSize({ width: 1440, height: 900 });
      await a.keyboard.press("Control+Shift+K"); await a.locator("#palette-input").fill(theme === "ink" ? "Ink" : "Paper");
      await a.locator(`#palette-results [data-action="theme:${theme}"]`).click();
      await expect(a.locator("html")).toHaveAttribute("data-theme", theme);
      await a.setViewportSize({ width: 1440, height: 900 }); await a.screenshot({ path: `${evidence}/desktop-${theme}.png` });
      await a.setViewportSize({ width: 393, height: 852 }); await a.screenshot({ path: `${evidence}/phone-${theme}.png` });
    }
    await noPrivateStorage(a); await noPrivateStorage(b); await noPrivateStorage(c);
    gate.release(); await settled(a); await expect(pending(a)).toBeHidden(); await expect(windows(b)).toHaveCount(2); await expect(windows(c)).toHaveCount(2);
    await a.reload(); await expect(windows(a)).toHaveCount(2); await settled(a); await noPrivateStorage(a);
    expect((await cache(a)).canonical).toEqual((await cache(b)).canonical);
  } finally { await context.close(); await server.dispose(); }
});

test("unconfirmed tab loss restores only server state and warm offline drawing survives until cold reload", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4450) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  try {
    const page = watchLayout(await context.newPage()), gate = await holdApplies(page); await enrol(page, server); await settled(page);
    gate.hold(); await page.keyboard.press("Control+Shift+E"); await expect(windows(page)).toHaveCount(2); await expect(pending(page)).toBeVisible();
    gate.discard(); await page.reload(); await expect(windows(page)).toHaveCount(1); await settled(page);
    await expect.poll(() => page.evaluate(async () => Boolean(await (await caches.open("infraternal-drawing-v1")).match("/"))), { timeout: 30_000 }).toBe(true);
    await context.setOffline(true); await expect(windows(page)).toHaveCount(1);
    await page.reload(); await expect(page.getByRole("heading", { name: "Connect to load your layout" })).toBeVisible(); await expect(windows(page)).toHaveCount(0);
    await context.setOffline(false); await page.getByRole("button", { name: "Try again" }).click(); await expect(windows(page)).toHaveCount(1); await noPrivateStorage(page);
  } finally { await context.close(); await server.dispose(); }
});

test("failed logout preserves the signed-in queue; successful logout invalidates peers and late completions", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4450) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  let resumeLogout = (): void => {};
  try {
    const a = watchLayout(await context.newPage()), gate = await holdApplies(a); await enrol(a, server); await settled(a);
    const b = watchLayout(await context.newPage()); await b.goto(server.origin); await expect(windows(b)).toHaveCount(1);
    gate.hold(); await a.bringToFront(); await a.keyboard.press("Control+Shift+E"); await expect(pending(a)).toBeVisible();
    const logoutWait = new Promise<void>((resolve) => { resumeLogout = resolve; });
    await a.route("**/auth/logout", async (route) => { await logoutWait; await route.fulfill({ status: 503, body: "unavailable" }); });
    await signOut(a);
    await expect(a.locator("#terminal-screen")).toHaveJSProperty("inert", true);
    await a.keyboard.press("Control+Shift+E"); await expect(windows(a)).toHaveCount(2);
    resumeLogout(); await expect(a.getByText("Could not sign out. Check your connection and try again.")).toBeVisible(); await expect(pending(a)).toBeVisible();
    await a.unroute("**/auth/logout"); await signOut(a); await expect(a.locator("#login-passkey")).toBeVisible();
    gate.release(); await b.bringToFront(); await b.evaluate(() => window.dispatchEvent(new Event("online"))); await expect(b.locator("#login-passkey")).toBeVisible();
    await a.locator("#login-passkey").click(); await expect(windows(a)).toHaveCount(1); await settled(a); await noPrivateStorage(a); await noPrivateStorage(b);
  } finally { resumeLogout(); await context.close(); await server.dispose(); }
});
test("throwing storage at cold startup and recovered storage never create a private layout cache", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4450) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  try {
    await context.addInitScript(() => {
      for (const name of ["localStorage", "sessionStorage"]) {
        const descriptor = Object.getOwnPropertyDescriptor(window, name)!;
        Object.defineProperty(window, name, { configurable: true, get() { throw new DOMException("Storage unavailable", "SecurityError"); } });
        window.addEventListener("test:restore-storage", () => Object.defineProperty(window, name, descriptor), { once: true });
      }
    });
    const page = watchLayout(await context.newPage()), gate = await holdApplies(page), errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message)); await enrol(page, server); await settled(page);
    gate.hold(); await page.keyboard.press("Control+Shift+E"); await expect(windows(page)).toHaveCount(2); await expect(pending(page)).toBeVisible();
    await page.evaluate(() => window.dispatchEvent(new Event("test:restore-storage")));
    gate.release(); await settled(page); await noPrivateStorage(page); expect(errors).toEqual([]);
    await page.reload(); await expect(windows(page)).toHaveCount(2); await settled(page);
    await page.evaluate(() => window.dispatchEvent(new Event("test:restore-storage"))); await noPrivateStorage(page);
  } finally { await context.close(); await server.dispose(); }
});
