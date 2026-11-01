/** Revoked canvas lifetimes must end the old screen and keep layout data inside its authenticated account (D312, #250). */
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { expect, test, type BrowserContext, type Page } from "playwright/test";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { enrol, request, settled, windows } from "./layout-devices";
import { watchLayout } from "./layout-observer";
import { tracerEvidencePath } from "../test/evidence-path";
import { startRealServer, type RealServer } from "./server";
import type { CanvasDocument } from "../src/canvas/model/schema";

const pendingLabel = "Not saved — keep this tab open";
const revokedMessage = "Not saved. Changes waiting to save were lost. Sign in again to continue.";
const changedMessage = "Your sign-in changed. Sign in again to continue.";

interface WireObservations { opened: number; closed: number; welcomes: number; layoutApplies: number }

function observeWire(page: Page, state: WireObservations): void {
  page.on("websocket", (socket) => {
    state.opened++;
    const sent = new WebSocketFrameDecoder(), received = new WebSocketFrameDecoder();
    socket.on("close", () => { state.closed++; });
    socket.on("framesent", ({ payload }) => {
      if (typeof payload === "string") return;
      sent.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type === "Call" && frame.actionId === "canvas.layout.apply") state.layoutApplies++;
      });
    });
    socket.on("framereceived", ({ payload }) => {
      if (typeof payload === "string") return;
      received.feed(new Uint8Array(payload), (_stream, frame) => {
        if (frame.type === "Welcome") state.welcomes++;
      });
    });
  });
}

/** Test-only account/session seeding sends the private session token only to the browser cookie jar. */
async function addSession(server: RealServer, context: BrowserContext, user: string, createUser: boolean): Promise<void> {
  const token = randomBytes(32).toString("base64url");
  const digest = createHash("sha256").update(token).digest("base64url");
  const name = `Switch ${user.slice(0, 8)}`;
  const child = spawn("python3", ["-c", `import json,sqlite3,sys,time
v=json.load(sys.stdin)
with sqlite3.connect(sys.argv[1]) as db:
 if v['create_user']:
  db.execute("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,?,0,'unused',?,?)",(v['user'],v['name'],v['username'],v['name']))
 db.execute("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'review',?,?,1)",(v['digest'],v['user'],int(time.time())+3600,int(time.time())))
`, `${server.dataDir}/infraternal.sqlite`], { stdio: ["pipe", "ignore", "ignore"] });
  const exited = once(child, "exit");
  child.stdin.end(JSON.stringify({ digest, user, create_user: createUser, name, username: `switch_${user.replaceAll("-", "")}` }));
  expect((await exited)[0]).toBe(0);
  await context.addCookies([{ name: "__Host-infraternal", value: token, url: server.origin, secure: true, httpOnly: true, sameSite: "Strict" }]);
}

async function disconnect(cdp: Awaited<ReturnType<BrowserContext["newCDPSession"]>>, wire: WireObservations): Promise<void> {
  const closed = wire.closed;
  await cdp.send("Network.enable");
  await cdp.send("Network.emulateNetworkConditions", { offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
  await expect.poll(() => wire.closed, { timeout: 15_000 }).toBeGreaterThan(closed);
}

async function freeze(cdp: Awaited<ReturnType<BrowserContext["newCDPSession"]>>): Promise<void> {
  await cdp.send("Page.setWebLifecycleState", { state: "frozen" });
}

async function waitForIncrease(read: () => number, before: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (read() <= before && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
  return read() > before;
}

async function resumeWithReplacementCookie(
  page: Page,
  context: BrowserContext,
  cdp: Awaited<ReturnType<BrowserContext["newCDPSession"]>>,
  wire: WireObservations,
  cookies: Awaited<ReturnType<BrowserContext["cookies"]>>,
): Promise<{ opened: boolean; welcomed: boolean }> {
  const opened = wire.opened, welcomes = wire.welcomes;
  await context.clearCookies();
  await context.addCookies(cookies);
  await cdp.send("Network.emulateNetworkConditions", { offline: false, latency: 0, downloadThroughput: -1, uploadThroughput: -1 });
  await cdp.send("Page.setWebLifecycleState", { state: "active" });
  await page.evaluate(() => { window.dispatchEvent(new Event("online")); document.dispatchEvent(new Event("visibilitychange")); });
  const openedAgain = await waitForIncrease(() => wire.opened, opened, 15_000);
  // Wait only for the session boundary, never for a layout event; account reads still run if the page fails to resume.
  const welcomedAgain = openedAgain && await waitForIncrease(() => wire.welcomes, welcomes, 15_000);
  if (welcomedAgain) await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  return { opened: openedAgain, welcomed: welcomedAgain };
}

test("a replaced same-account session ends the canvas after dropping its pending edit", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4457) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const wire: WireObservations = { opened: 0, closed: 0, welcomes: 0, layoutApplies: 0 };
  let cdp: Awaited<ReturnType<BrowserContext["newCDPSession"]>> | undefined;
  try {
    const page = watchLayout(await context.newPage());
    observeWire(page, wire);
    await enrol(page, server);
    await settled(page);
    const identity = await (await context.request.post(server.origin + "/auth/session", { data: {}, headers: { Origin: server.origin } })).json() as { user_id: string };
    cdp = await context.newCDPSession(page);
    await disconnect(cdp, wire);

    // The close is local while offline; the server's last confirmed layout still contains its window.
    const appliesBeforeOfflineClose = wire.layoutApplies;
    await windows(page).first().locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click());
    await expect(windows(page)).toHaveCount(0);
    await expect(page.getByText(pendingLabel, { exact: true })).toBeVisible();
    expect(wire.layoutApplies).toBe(appliesBeforeOfflineClose);
    await freeze(cdp);
    const logout = await context.request.post(server.origin + "/auth/logout", { data: {}, headers: { Origin: server.origin } });
    expect(logout.ok()).toBe(true);
    await addSession(server, context, identity.user_id, false);
    const canonicalBeforeResume = (await request(server, context, "", {}, true)).value;

    const resumed = await resumeWithReplacementCookie(page, context, cdp, wire, await context.cookies());
    const signedOut = await page.locator("#login-passkey").isVisible();
    if (!signedOut && resumed.welcomed) {
      // On the broken build this accepted-looking edit removes the last window only in the old screen.
      if (await windows(page).count() > 0) {
        await windows(page).first().locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click());
      }
    }

    const canonicalAfterResume = (await request(server, context, "", {}, true)).value;
    expect(canonicalAfterResume, "the local close is not a server receipt").toEqual(canonicalBeforeResume);
    await page.screenshot({ path: tracerEvidencePath("revoked-layout-not-saved.png") });
    if (signedOut) {
      await page.setViewportSize({ width: 393, height: 852 });
      const messageBox = await page.locator("#auth-error").boundingBox();
      expect(messageBox).not.toBeNull();
      if (messageBox) expect(messageBox.x >= 0 && messageBox.x + messageBox.width <= 393).toBe(true);
      await page.screenshot({ path: tracerEvidencePath("revoked-layout-not-saved-mobile.png") });
    }
    expect(resumed.opened, "the page must reconnect after the cookie replacement").toBe(true);
    expect(resumed.welcomed, "the page must receive the replacement session boundary").toBe(true);
    expect(signedOut, "a replaced session must end the old editable canvas").toBe(true);
    await expect(page.locator("#auth-error")).toHaveText(revokedMessage);
    await expect(page.locator(".cl .ui-window")).toHaveCount(0);
  } finally {
    await cdp?.detach();
    await context.close();
    await server.dispose();
  }
});

test("a tab whose cookie changes accounts cannot edit either account's layout", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4459) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const wire: WireObservations = { opened: 0, closed: 0, welcomes: 0, layoutApplies: 0 };
  let cdp: Awaited<ReturnType<BrowserContext["newCDPSession"]>> | undefined;
  try {
    const page = watchLayout(await context.newPage());
    observeWire(page, wire);
    await enrol(page, server);
    await settled(page);
    const firstCookies = await context.cookies();
    const firstLayout = (await request(server, context, "", {}, true)).value;

    const secondUser = randomUUID();
    await addSession(server, context, secondUser, true);
    const secondDocument: CanvasDocument = { format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "console", kind: "console", name: "Second account", cell: { x: 0, y: 0 }, layout: { type: "tiled", columns: [{ id: "second-column", weight: 1, windows: [{ id: "second-settings", target: { type: "settings", section: "shortcuts" } }] }] } }] };
    expect((await request(server, context, "canvas.layout.initialize", { op_id: randomUUID(), document: secondDocument })).ok).toBe(true);
    const secondCookies = await context.cookies();
    const secondLayout = (await request(server, context, "", {}, true)).value;
    await context.clearCookies();
    await context.addCookies(firstCookies);

    cdp = await context.newCDPSession(page);
    await disconnect(cdp, wire);
    const resumed = await resumeWithReplacementCookie(page, context, cdp, wire, secondCookies);
    const signedOut = await page.locator("#login-passkey").isVisible();
    let appliesBeforeEdit: number | undefined;
    if (!signedOut && resumed.welcomed) {
      const visibleWindows = page.locator(".cl .ui-window");
      appliesBeforeEdit = wire.layoutApplies;
      if (await visibleWindows.count() > 0) {
        await visibleWindows.first().locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click());
      }
    }

    await context.clearCookies();
    await context.addCookies(secondCookies);
    const secondAfterResume = (await request(server, context, "", {}, true)).value;
    await context.clearCookies();
    await context.addCookies(firstCookies);
    const firstAfterResume = (await request(server, context, "", {}, true)).value;
    expect(secondAfterResume, "the replacement account must keep its canonical layout").toEqual(secondLayout);
    expect(firstAfterResume, "the original account must keep its canonical layout").toEqual(firstLayout);
    if (appliesBeforeEdit !== undefined) expect(wire.layoutApplies).toBe(appliesBeforeEdit);
    if (signedOut) await expect(page.locator("#auth-error")).toHaveText(changedMessage);
    await page.screenshot({ path: tracerEvidencePath("account-switch-sign-in-required.png") });
    expect(resumed.opened, "the page must reconnect after the cookie replacement").toBe(true);
    expect(resumed.welcomed, "the page must receive the replacement session boundary").toBe(true);
    expect(signedOut, "a cookie for another account must end the old account's canvas").toBe(true);
    await expect(page.locator(".cl .ui-window")).toHaveCount(0);
  } finally {
    await cdp?.detach();
    await context.close();
    await server.dispose();
  }
});
