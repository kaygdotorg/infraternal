/** Two independent devices share real production layout state; no browser-local document seeds the phone (#243). */
import { cache } from "./layout-observer";
import { watchLayout } from "./layout-observer";
import { devices, expect, test, type Page } from "playwright/test";
import { mkdir, writeFile } from "node:fs/promises";
import { personName, startRealServer, type RealServer } from "./server";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { tracerEvidencePath } from "../test/evidence-path";

test.setTimeout(240_000);
const windows = (page: Page) => page.locator('.cl[data-view="console"] .ui-window');
const ids = (page: Page) => windows(page).evaluateAll((els) => els.map((el) => (el as HTMLElement).dataset.windowId));
// Group columns use display:contents; their enclosing frame carries the actual scale.
const outerDropX = (page: Page) => page.locator('.cl[data-view="console"] .cl-col').first().evaluate((column) => {
  const frame = column.closest<HTMLElement>(".cl-group") ?? column as HTMLElement;
  const box = frame.getBoundingClientRect();
  return box.left - 20 * box.width / frame.offsetWidth - 1;
});

async function settled(page: Page): Promise<void> {
  await expect.poll(async () => (await cache(page)).initialized, { timeout: 30_000 }).toBe(true);
  await expect(page.getByText("Not saved — keep this tab open", { exact: true })).toBeHidden();
  await expect.poll(async () => (await cache(page) as { pending?: unknown[] } | undefined)?.pending?.length, { timeout: 30_000 }).toBe(0);
}
async function enrol(page: Page, server: RealServer): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("layout_sync"));
  await page.locator("#setup-display-name").fill("Layout sync");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(windows(page)).toHaveCount(1);
}

test("fresh phone restores ten split windows and both devices converge", async ({ browser }) => {
  const perf = process.env.LAYOUT_PERF === "1";
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4563), ...(perf ? { latencyMs: 150, timedControls: true } : {}) });
  const evidence = tracerEvidencePath("layout-sync"); await mkdir(evidence, { recursive: true });
  const desktop = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const phone = await browser.newContext({ ...devices["iPhone 15"], viewport: { width: 393, height: 852 }, ignoreHTTPSErrors: true, recordVideo: { dir: evidence, size: { width: 393, height: 852 } } });
  let peer: Awaited<ReturnType<typeof browser.newContext>> | undefined;
  const errors: string[] = [];
  const failedRequests: string[] = [];
  let offlinePhase = false;
  let receiptAt = 0, phoneEdits = 0;
  let timing: { workMs: number; remotePaintMs: number; receiptMs: number } | undefined;
  let mobileCache: () => Promise<unknown> = async () => undefined;
  const page = watchLayout(await desktop.newPage());
  page.on("requestfailed", (request) => failedRequests.push(new URL(request.url()).pathname));
  page.on("pageerror", (error) => { errors.push(error.message); console.log(`BROWSER_ERROR ${error.stack}`); });
  try {
    await enrol(page, server); await settled(page);
    for (let i = 1; i < 10; i++) {
      await windows(page).evaluateAll((els) => {
        const largest = els.map((el) => el as HTMLElement).sort((a, b) => b.offsetWidth * b.offsetHeight - a.offsetWidth * a.offsetHeight)[0];
        largest?.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true, button: 0 }));
      });
      await page.keyboard.press(i % 2 ? "Control+Shift+E" : "Control+Shift+D");
      await expect(windows(page)).toHaveCount(i + 1);
      await expect.poll(async () => { const value = await cache(page) as { canonical?: { views: Array<{ layout: { type: string; columns?: Array<{ windows: unknown[] }> } }> } }; return value?.canonical?.views.flatMap((v) => v.layout.columns?.flatMap((c) => c.windows) ?? []).length; }, { timeout: 30_000 }).toBe(i + 1);
      await settled(page);
    }
    // A remote paint must retain the model object owned by each live binding: ten edits create ten PTYs.
    expect(server.bridges.flatMap((bridge) => bridge.control).filter((frame) => frame.type === "Call" && frame.detail === "ssh.session.open")).toHaveLength(10);
    const order = await ids(page); expect(new Set(order).size).toBe(10);
    await page.screenshot({ path: `${evidence}/desktop-ten.png` });
    await phone.addCookies(await desktop.cookies());
    const mobile = watchLayout(await phone.newPage());
    mobileCache = () => cache(mobile);
    if (perf) mobile.on("websocket", (socket) => {
      const sent = new WebSocketFrameDecoder(), received = new WebSocketFrameDecoder();
      let layoutCall: number | undefined;
      socket.on("framesent", ({ payload }) => { if (typeof payload !== "string") sent.feed(new Uint8Array(payload), (_stream, frame) => { if (frame.type === "Call" && frame.actionId === "canvas.layout.apply") { layoutCall = frame.callId; phoneEdits++; } }); });
      socket.on("framereceived", ({ payload }) => { if (typeof payload !== "string") received.feed(new Uint8Array(payload), (_stream, frame) => { if (frame.type === "Result" && frame.callId === layoutCall) receiptAt = Date.now(); }); });
    });
    mobile.on("pageerror", (error) => { errors.push(error.message); console.log(`PHONE_ERROR ${error.stack}`); });
    await mobile.goto(server.origin + "/?theme=ink&bg=none");
    await expect(windows(mobile)).toHaveCount(10);
    const phoneOrder = await ids(mobile); expect(phoneOrder).toEqual(order); await settled(mobile);
    await mobile.locator('button[aria-label="Sessions"]').last().evaluate((el) => (el as HTMLElement).click());
    await expect(mobile.locator('.cl-sx-group[aria-label="Open"] li')).toHaveCount(10);
    await expect(mobile.locator('.cl-sx-group[aria-label="Detached"]')).toHaveCount(0);
    await mobile.screenshot({ path: `${evidence}/phone-ten.png` });
    await mobile.locator('button[aria-label="Sessions"]').last().evaluate((el) => (el as HTMLElement).click());
    await expect(mobile.locator(".cl-sx-group")).toHaveCount(0);
    expect(server.bridges.flatMap((bridge) => bridge.control).filter((frame) => frame.type === "Call" && frame.detail === "ssh.session.open")).toHaveLength(10);
    // Expose a reachable outer drop zone before moving a window out of the spanning group.
    await mobile.getByRole("button", { name: "Canvas lock on", exact: true }).click();
    await mobile.mouse.move(196, 426);
    await mobile.keyboard.down("Control");
    await mobile.mouse.wheel(0, 25);
    await mobile.keyboard.up("Control");
    await expect.poll(() => outerDropX(mobile)).toBeGreaterThan(0);
    const beforeMove = await ids(mobile), beforePhoneEdits = phoneEdits;
    const remotePaint = perf ? page.evaluate((before) => new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => { observer.disconnect(); reject(Error("shared move did not paint")); }, 10_000);
      const observer = new MutationObserver(() => {
        const ids = [...document.querySelectorAll<HTMLElement>('.cl[data-view="console"] .ui-window')].map((el) => el.dataset.windowId);
        if (ids.length !== before.length || JSON.stringify(ids) === JSON.stringify(before)) return;
        observer.disconnect(); clearTimeout(timer); requestAnimationFrame(() => resolve(performance.timeOrigin + performance.now()));
      });
      observer.observe(document.querySelector('.cl[data-view="console"]')!, { childList: true, subtree: true });
    }), beforeMove) : undefined;
    if (remotePaint) void remotePaint.catch(() => undefined);
    const movable = await windows(mobile).evaluateAll((els) => els.findIndex((el, index) => {
      const pill = el.querySelector(".ui-window-pill")!, box = pill.getBoundingClientRect();
      const x = box.x + box.width / 2, y = box.y + box.height / 2;
      return index > 0 && x > 30 && x < innerWidth - 30 && y > 100 && y < innerHeight - 160 && document.elementFromPoint(x, y)?.closest(".ui-window-pill") === pill;
    }));
    expect(movable).toBeGreaterThan(0);
    const movingPill = windows(mobile).nth(movable).locator(".ui-window-pill");
    await movingPill.hover();
    await mobile.screenshot({ path: `${evidence}/phone-layout.png` });
    const pill = (await movingPill.boundingBox())!;
    const x = pill.x + pill.width / 2, y = pill.y + pill.height / 2;
    // Cross the actual new-column boundary. A fixed gutter coordinate can keep
    // the same slot, and a partial-width top band cannot be inserted into a spanning group.
    const dropX = await outerDropX(mobile);
    expect(dropX).toBeGreaterThanOrEqual(0);
    const columnsBefore = await mobile.locator('.cl[data-view="console"] .cl-col').evaluateAll((columns) => columns.map((column) => (column as HTMLElement).dataset.id));
    await mobile.mouse.move(x, y); await mobile.mouse.down();
    await mobile.mouse.move(dropX, y + 16, { steps: 12 });
    if (perf) await mobile.evaluate(() => {
      const probe = window as unknown as { __layoutTiming: { start: number; drop: number; work: number; paint: number } };
      probe.__layoutTiming = { start: 0, drop: 0, work: 0, paint: 0 };
      document.addEventListener("pointerup", () => { probe.__layoutTiming.start = performance.now(); probe.__layoutTiming.drop = performance.timeOrigin + performance.now(); }, { capture: true, once: true });
      window.addEventListener("pointerup", () => { queueMicrotask(() => { probe.__layoutTiming.work = performance.now() - probe.__layoutTiming.start; }); requestAnimationFrame(() => { probe.__layoutTiming.paint = performance.now() - probe.__layoutTiming.start; }); }, { once: true });
    });
    await expect(mobile.locator(".is-lifted")).toHaveCount(1);
    const dropColumn = await mobile.locator(".cl-slot").evaluate((slot) => slot.parentElement?.dataset.id);
    expect(columnsBefore).not.toContain(dropColumn);
    await mobile.mouse.up();
    if (remotePaint) void remotePaint.catch(() => undefined);
    await expect.poll(() => ids(page), { timeout: 15_000 }).not.toEqual(beforeMove);
    await settled(mobile); await settled(page);
    expect(await ids(page)).toEqual(await ids(mobile));
    if (remotePaint) {
      expect(phoneEdits - beforePhoneEdits).toBe(1);
      const remote = await remotePaint;
      const local = await mobile.evaluate(() => (window as unknown as { __layoutTiming: { drop: number; work: number; paint: number } }).__layoutTiming);
      const metrics = { semanticIntents: phoneEdits - beforePhoneEdits, receiptMs: receiptAt - local.drop, controls: server.bridges.map((bridge) => bridge.control.slice(-8)), windows: 10, rttMs: 300, workMs: local.work, editToPaintMs: local.paint, remotePaintMs: remote - local.drop };
      await writeFile(`${evidence}/phone-move-timing.json`, JSON.stringify(metrics, null, 2));
      console.log(`LAYOUT_MOVE ${JSON.stringify(metrics)}`);
      expect(metrics.receiptMs).toBeGreaterThan(0); timing = metrics;
    }
    // Closing is also a competing structural edit, and must not resurrect on the other device.
    await Promise.all([
      windows(page).nth(1).locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click()),
      windows(mobile).nth(8).locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click()),
    ]);
    await expect(windows(page)).toHaveCount(8); await expect(windows(mobile)).toHaveCount(8);
    await settled(page); await settled(mobile); expect(await ids(page)).toEqual(await ids(mobile));
    const final = await ids(page);
    await page.reload(); await expect(windows(page)).toHaveCount(8); expect(await ids(page)).toEqual(final);
    await settled(page);
    await phone.close();
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette-input").fill("sign out");
    await page.locator("#palette-results [role=option]").first().click();
    await page.locator('.ui-confirm-tip[data-open="true"]').getByRole("button", { name: "Sign out", exact: true }).click();
    await expect(page.locator("#login-passkey")).toBeVisible();
    expect(await page.evaluate(() => Object.keys(localStorage).filter((key) => key.startsWith("infraternal.canvas.")))).toEqual([]);
    await page.locator("#login-passkey").click();
    await expect(windows(page)).toHaveCount(8); expect(await ids(page)).toEqual(final); await settled(page);
    await expect.poll(() => page.evaluate(async () => Boolean(await (await caches.open("infraternal-drawing-v1")).match("/"))), { timeout: 30_000 }).toBe(true);
    peer = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
    await peer.addCookies(await desktop.cookies());
    const other = watchLayout(await peer.newPage()); await other.goto(server.origin + "/?theme=ink&bg=none");
    await expect(windows(other)).toHaveCount(8); await settled(other);
    offlinePhase = true;
    await desktop.setOffline(true);
    await windows(other).last().locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click());
    await expect(windows(other)).toHaveCount(7); await settled(other);
    await expect(windows(page)).toHaveCount(8);
    await page.reload(); await expect(page.getByRole("heading", { name: "Connect to load your layout" })).toBeVisible();
    await expect(windows(page)).toHaveCount(0);
    await page.screenshot({ path: `${evidence}/offline-connect.png` });
    await desktop.setOffline(false); await page.getByRole("button", { name: "Try again" }).click(); await expect(windows(page)).toHaveCount(7); await settled(page); expect(await ids(page)).toEqual(await ids(other));
    await peer.close(); peer = undefined;
    expect(errors).toEqual([]);
    await writeFile(`${evidence}/functional.json`, JSON.stringify({ desktopOrder: order, freshPhoneOrder: phoneOrder, afterConcurrentClose: final, reconciledOrder: await ids(page), initialDesktop: order.length, freshPhone: order.length, concurrentClose: final.length, equalOrder: true, restoredAfterReload: true, restoredAfterSignIn: true, coldOfflineConnect: true, warmOfflineDrawing: true, reconciledAfterOffline: 7, detachedOnFreshPhone: 0 }, null, 2));
    if (timing) { expect(timing.workMs).toBeLessThanOrEqual(16); expect(timing.remotePaintMs).toBeLessThanOrEqual(timing.receiptMs + 34); }
  } catch (error) {
    if (offlinePhase) await page.screenshot({ path: `${evidence}/offline-failure.png` }).catch(() => undefined);
    const drawingState = offlinePhase ? await page.evaluate(async () => ({ ready: document.readyState, scripts: [...document.scripts].map((s) => s.src ? new URL(s.src).pathname : "inline"), elements: [...document.body.children].map((el) => ({ tag: el.tagName, id: el.id, class: el.className })), cached: await (await caches.open("infraternal-drawing-v1")).keys().then((rs) => rs.map((r) => new URL(r.url).pathname)) })).catch(() => undefined) : undefined;
    await writeFile(`${evidence}/diagnostic.json`, JSON.stringify({ drawingState, failedRequests, errors, error: error instanceof Error ? error.message : String(error), canvas: await cache(page).catch(() => undefined), phone: await mobileCache().catch(() => undefined), control: server.bridges.map((b) => b.control) }, null, 2));
    throw error;
  } finally { await peer?.close(); await phone.close(); await desktop.close(); await server.dispose(); }
});

test("an overlapping legacy cache keeps the canonical view on both devices", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4563) });
  const first = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const second = await browser.newContext({ ...devices["iPhone 15"], viewport: { width: 393, height: 852 }, ignoreHTTPSErrors: true });
  try {
    const page = watchLayout(await first.newPage()); await enrol(page, server); await settled(page);
    // Built-in Mesh registration is independent of the import; finish it before taking the no-op baseline.
    await expect.poll(async () => (await cache(page) as { canonical: { views: Array<{ id: string }> } }).canonical.views.some((view) => view.id === "mesh")).toBe(true);
    await settled(page);
    const before = (await cache(page) as { canonical: import("../src/canvas/model/schema").CanvasDocument }).canonical;
    const account = await page.evaluate(async () => (await (await fetch("/auth/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).json()).user_id as string);
    const legacyDocument = structuredClone(before);
    const consoleView = legacyDocument.views.find((view) => view.id === "console")!;
    consoleView.name = "Local Console"; consoleView.cell.x += 2;
    const legacy = { key: `infraternal.canvas.${account}`, document: legacyDocument };
    await second.addCookies(await first.cookies());
    await second.addInitScript(({ key, document }) => localStorage.setItem(key, JSON.stringify(document)), legacy);
    const phone = watchLayout(await second.newPage()); await phone.goto(server.origin + "/?theme=ink&bg=none");
    await expect.poll(async () => {
      const value = await cache(phone) as { canonical?: { views: Array<{ name: string }> }; migration?: unknown };
      return value?.migration === undefined && value?.canonical?.views.every((view) => !view.name.startsWith("Recovered: "));
    }, { timeout: 30_000 }).toBe(true);
    await expect.poll(async () => (await cache(phone) as { canonical: unknown }).canonical).toEqual(before);
    await expect(phone.locator('.cl-label-name').filter({ hasText: "Recovered: Local Console" })).toHaveCount(0);
    await expect(page.locator('.cl-label-name').filter({ hasText: "Recovered: Local Console" })).toHaveCount(0);
    await expect(windows(page)).toHaveCount(1); await expect(windows(phone)).toHaveCount(1);
    expect(server.bridges.flatMap((bridge) => bridge.control).filter((frame) => frame.type === "Call" && frame.detail === "ssh.session.open")).toHaveLength(1);
    const views = (await cache(phone)).canonical.views.map(({ id, name }) => ({ id, name }));
    await writeFile(tracerEvidencePath("layout-sync", "legacy-recovery.json"), JSON.stringify({ sessionOpens: 1, originalConsoleWindows: 1, views }, null, 2));
    await page.screenshot({ path: tracerEvidencePath("layout-sync", "recovered-layout.png") });
  } finally { await second.close(); await first.close(); await server.dispose(); }
});
