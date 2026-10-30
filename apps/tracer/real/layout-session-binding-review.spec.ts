/** Original-session ownership must survive suspended tabs and later authentication (D312, #250). */
import { expect, test, type BrowserContext } from "playwright/test";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { enrol, request, settled, windows } from "./layout-devices";
import { cache, watchLayout } from "./layout-observer";
import { startRealServer, type RealServer } from "./server";
import type { CanvasDocument } from "../src/canvas/model/schema";

/** Seed only the owned fixture; the session capability stays in memory and travels over stdin. */
async function secondAccount(server: RealServer, context: BrowserContext): Promise<string> {
  const token = randomBytes(32).toString("base64url"), user = randomUUID();
  const digest = createHash("sha256").update(token).digest("base64url");
  const child = spawn("python3", ["-c", `import json,sqlite3,sys,time
v=json.load(sys.stdin)
with sqlite3.connect(sys.argv[1]) as db:
 db.execute("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'Review peer',0,'unused','review_peer','Review peer')",(v['user'],))
 db.execute("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'review',?,?,1)",(v['digest'],v['user'],int(time.time())+3600,int(time.time())))
`, server.dataDir + "/infraternal.sqlite"], { stdio: ["pipe", "ignore", "ignore"] });
  const ended = once(child, "exit"); child.stdin.end(JSON.stringify({ user, digest }));
  expect((await ended)[0]).toBe(0);
  await context.addCookies([{ name: "__Host-infraternal", value: token, url: server.origin, secure: true, httpOnly: true, sameSite: "Strict" }]);
  return user;
}

test("a suspended original-account import cannot be admitted by a different account session", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4457) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  try {
    const page = watchLayout(await context.newPage());
    // A discarded notification channel models the allowed missed-notice suspension boundary.
    await page.addInitScript(() => { Object.defineProperty(window, "BroadcastChannel", { configurable: true, value: class { close() {} postMessage() {} } }); });
    await enrol(page, server); await settled(page);
    const originalSession = await (await context.request.post(server.origin + "/auth/session", { data: {}, headers: { Origin: server.origin } })).json();
    const legacy: CanvasDocument = { format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Original private drawing", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [{ id: "original-column", weight: 1, windows: [{ id: "original-settings", target: { type: "settings", section: "appearance" } }] }] } }] };
    await page.evaluate(({ account, document }) => localStorage.setItem(`infraternal.canvas.${account}`, JSON.stringify(document)), { account: originalSession.user_id, document: legacy });
    let hold = true, intercepted = 0, disconnect = (): void => {};
    await page.routeWebSocket("**/v1/ws", (route) => {
      const upstream = route.connectToServer();
      disconnect = () => route.close({ code: 1001, reason: "review offline transition" });
      route.onMessage((message) => {
        let initializing = false;
        if (typeof message !== "string") new WebSocketFrameDecoder().feed(new Uint8Array(message), (_stream, frame) => { if (frame.type === "Call" && frame.actionId === "canvas.layout.initialize") initializing = true; });
        if (hold && initializing) intercepted++; else upstream.send(message);
      });
    });
    await page.reload(); await expect.poll(() => intercepted).toBeGreaterThan(0);
    await expect(page.getByText("Not saved — keep this tab open", { exact: true })).toBeVisible();
    const cdp = await context.newCDPSession(page);
    await cdp.send("Network.enable");
    await cdp.send("Network.emulateNetworkConditions", { offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
    disconnect();
    await cdp.send("Page.setWebLifecycleState", { state: "frozen" });
    const logout = await context.request.post(server.origin + "/auth/logout", { data: {}, headers: { Origin: server.origin } });
    expect(logout.ok()).toBe(true);
    const replacement = await secondAccount(server, context); expect(replacement).not.toBe(originalSession.user_id);
    const baseline: CanvasDocument = { format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Replacement drawing", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [{ id: "replacement-column", weight: 1, windows: [{ id: "replacement-settings", target: { type: "settings", section: "shortcuts" } }] }] } }] };
    expect((await request(server, context, "canvas.layout.initialize", { op_id: randomUUID(), document: baseline })).ok).toBe(true);
    const before = (await request(server, context, "", {}, true)).value;
    hold = false;
    await cdp.send("Network.emulateNetworkConditions", { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
    await cdp.send("Page.setWebLifecycleState", { state: "active" });
    await page.evaluate(() => { window.dispatchEvent(new Event("online")); document.dispatchEvent(new Event("visibilitychange")); });
    await expect.poll(async () => (await context.request.post(server.origin + "/auth/session", { data: {}, headers: { Origin: server.origin } })).status()).toBe(200);
    await expect.poll(async () => (await cache(page)).canonical.revision, { timeout: 30_000 }).toBeGreaterThanOrEqual(Number(before.revision));
    // Wait for either safe teardown or completion of the old queue before checking server state.
    await expect(page.getByText("Not saved — keep this tab open", { exact: true })).toBeHidden({ timeout: 30_000 });
    const after = (await request(server, context, "", {}, true)).value;
    expect(after, "replacement account retains its own canonical layout after the old tab resumes").toEqual(before);
    await expect(windows(page)).toHaveCount(0);
  } finally { await context.close(); await server.dispose(); }
});
