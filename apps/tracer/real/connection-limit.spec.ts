// SPDX-License-Identifier: AGPL-3.0-only
/**
 * A page that cannot get a connection must say so, never sit on a blank pane (#523).
 *
 * The server allows each account a fixed number of live connections. On QA1 an iPhone kept every old tab open, the
 * account reached that limit, and every fresh load stayed on the core screen's placeholder ("<host> / SSH shell ··"):
 * no toolbar, no host list, no words. These specs hold the account's connections from raw protocol sockets (the same
 * Hello a tab sends), open one more page, and check that it explains itself, offers Try again, and recovers once a
 * connection is free. A second spec covers what J752 first suspected: a cold restart (host CA locked) with a saved
 * own-host shell must still load the canvas with its toolbar and host list. Real server, no test double.
 */
import { expect, test, type BrowserContext, type Page } from "playwright/test";
import { WebSocket } from "ws";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "../test/evidence-path";
import { enrol, windows } from "./layout-devices";
import { watchLayout } from "./layout-observer";
import { startRealServer, type RealServer } from "./server";

/** The per-account cap in crates/infraternal-server/src/websocket.rs (`new_connection`). */
const ACCOUNT_SOCKETS = 16;

/** One welcomed protocol connection of the signed-in account that answers pings until `close` (a tab that stays open). */
async function holdConnection(server: RealServer, context: BrowserContext): Promise<{ close(): void }> {
  const cookie = (await context.cookies()).map((c) => `${c.name}=${c.value}`).join("; ");
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder();
  const send = (frame: Parameters<typeof encodeMuxedFrame>[1]): void => { socket.send(encodeMuxedFrame(0, frame)); };
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(Error("held connection was not welcomed")), 15_000);
    socket.on("error", () => { clearTimeout(timer); reject(Error("held connection failed")); });
    socket.on("close", () => { clearTimeout(timer); reject(Error("held connection closed before its welcome")); });
    socket.on("message", (bytes) => decoder.feed(new Uint8Array(Buffer.from(bytes as Buffer)), (_stream, frame) => {
      if (frame.type === "Hello") send({ type: "Hello", version: 1, caps: 0n, clientInfo: "connection-limit-spec" });
      if (frame.type === "Ping") send({ ...frame, type: "Pong" });
      if (frame.type === "Welcome") { clearTimeout(timer); resolve(); }
    }));
  });
  return { close: () => { socket.close(1000, "spec done"); } };
}

/** Loads the app in a fresh tab of the signed-in context. */
async function openTab(context: BrowserContext, server: RealServer, width: number, height: number): Promise<Page> {
  const page = await context.newPage();
  await page.setViewportSize({ width, height });
  await page.goto(`${server.origin}/?bg=none`);
  return page;
}

/**
 * A second browser of the same account for the light and dark receipts: the session cookie only, no cached look, so
 * the placeholder follows the device scheme. The enrolled tab's cached look pins its own theme over `?theme=`.
 */
async function receiptContext(context: BrowserContext, scheme: "light" | "dark"): Promise<BrowserContext> {
  const cookies = await context.cookies();
  return context.browser()!.newContext({ storageState: { cookies, origins: [] }, colorScheme: scheme, ignoreHTTPSErrors: true });
}

test("a page over the account's connection limit says why and recovers when a connection frees up", async ({ browser }) => {
  // Enrolment, four receipt pages, the unreachable page and the recovery: about 3 minutes on a loaded build host.
  test.setTimeout(300_000);
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4673) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const held: { close(): void }[] = [];
  try {
    const first = watchLayout(await context.newPage());
    await enrol(first, server);
    // The enrolled tab holds one connection; the rest are held like tabs the person forgot.
    for (let i = 1; i < ACCOUNT_SOCKETS; i++) held.push(await holdConnection(server, context));

    for (const scheme of ["light", "dark"] as const) {
      const receipts = await receiptContext(context, scheme);
      try {
        for (const [width, height] of [[1440, 900], [393, 852]] as const) {
          const page = await openTab(receipts, server, width, height);
          const notice = page.locator(".startup-notice");
          await expect(notice).toBeVisible({ timeout: 15_000 });
          await expect(notice).toContainText("too many browser tabs");
          await expect(notice.getByRole("button", { name: "Try again" })).toBeVisible();
          // Never the blank placeholder alone: the sidebar toggle stays reachable beside the notice.
          await expect(page.locator("#sidebar-toggle")).toBeVisible();
          await page.screenshot({ path: tracerEvidencePath("connection-limit-523", `limit-${width}-${scheme}.png`) });
          await page.close();
        }
      } finally { await receipts.close(); }
    }

    // Any other failure (here: every socket closes before its welcome) says so after a short wait, never at once.
    const unreachable = await context.newPage();
    await unreachable.setViewportSize({ width: 393, height: 852 });
    await unreachable.routeWebSocket("**/v1/ws", (socket) => { void socket.close({ code: 1011, reason: "" }); });
    await unreachable.goto(`${server.origin}/?bg=none`);
    const generic = unreachable.locator(".startup-notice");
    await expect(generic).toContainText("Can't reach the server", { timeout: 15_000 });
    await unreachable.screenshot({ path: tracerEvidencePath("connection-limit-523", "unreachable-393.png") });
    await unreachable.close();

    const page = await openTab(context, server, 1440, 900);
    const notice = page.locator(".startup-notice");
    await expect(notice).toBeVisible({ timeout: 15_000 });
    // Closing one forgotten tab frees a connection; Try again connects at once and the canvas takes over.
    held.pop()?.close();
    await notice.getByRole("button", { name: "Try again" }).click();
    await expect(windows(page)).toHaveCount(1, { timeout: 30_000 });
    await expect(notice).toHaveCount(0);
    await page.screenshot({ path: tracerEvidencePath("connection-limit-523", "recovered-1440.png") });
  } finally {
    for (const connection of held) connection.close();
    await context.close();
    await server.dispose();
  }
});

test("a cold restart (host CA locked) still restores the own-host shell with its toolbar and host list", async ({ browser }) => {
  test.setTimeout(150_000);
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4673) });
  const context = await browser.newContext({ viewport: { width: 393, height: 852 }, ignoreHTTPSErrors: true });
  try {
    const page = watchLayout(await context.newPage());
    await enrol(page, server);
    // A server restart is a cold start: the host CA stays locked until an administrator unlocks it (D168).
    await server.restart();
    await page.goto(`${server.origin}/?theme=latte&bg=none`);
    await expect(windows(page)).toHaveCount(1, { timeout: 30_000 });
    await expect(page.locator(".startup-notice")).toHaveCount(0);
    // The canvas row of the key tray (the toolbar) and the host list mount with the canvas.
    await expect(page.locator("#keyrow-canvas")).toHaveCount(1);
    await page.locator("#sidebar-toggle").click();
    await expect(page.locator("#tree")).not.toBeEmpty({ timeout: 15_000 });
    await page.screenshot({ path: tracerEvidencePath("connection-limit-523", "cold-restart-393-latte.png") });
  } finally {
    await context.close();
    await server.dispose();
  }
});
