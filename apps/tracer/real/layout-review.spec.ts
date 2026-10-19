/** Independent real-server review of split admission, offline journals and durable account layouts (D178, D183, D248; #243). */
import { devices, expect, test, type Page, type BrowserContext, type Browser } from "playwright/test";
import { WebSocket } from "ws";
import { isMacPlatform } from "../../../packages/ui/src/platform";
import { encodeMuxedFrame, WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { startRealServer, type RealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";
import type { CanvasDocument } from "../src/canvas/model/schema";
import { writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createHash, randomBytes, randomUUID } from "node:crypto";

test.setTimeout(180_000);
const windows = (page: Page) => page.locator('.cl[data-view="console"] .ui-window');
interface Cache { canonical: CanvasDocument; document: CanvasDocument; pending: Array<{ intent: { type: string }; op_id: string }> }
async function cache(page: Page): Promise<Cache> {
  return page.evaluate(() => {
    const key = Object.keys(localStorage).find((key) => key.startsWith("infraternal.canvas."));
    return key ? JSON.parse(localStorage.getItem(key)!) : undefined;
  });
}
const settled = async (page: Page): Promise<void> => {
  await expect.poll(async () => (await cache(page))?.pending.length, { timeout: 15_000 }).toBe(0);
};
async function enrol(page: Page, server: RealServer): Promise<void> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/?theme=ink&bg=none");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill("layout_review");
  await page.locator("#setup-display-name").fill("Layout review");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await expect(windows(page)).toHaveCount(1);
  await settled(page);
}
/** Public actions use the same authenticated protocol; cookies and replies stay in memory. */
async function request(server: RealServer, context: BrowserContext, action: string, input: unknown, snapshot = false): Promise<{ ok: boolean; value: Record<string, unknown> }> {
  const cookie = (await context.cookies()).map((c) => `${c.name}=${c.value}`).join("; ");
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder();
  const send = (frame: Parameters<typeof encodeMuxedFrame>[1]): void => { socket.send(encodeMuxedFrame(0, frame)); };
  try {
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(Error("review protocol response absent")), 15_000);
      socket.on("error", () => { clearTimeout(timer); reject(Error("review protocol connection failed")); });
      socket.on("message", (bytes) => decoder.feed(new Uint8Array(Buffer.from(bytes as Buffer)), (_stream, frame) => {
        if (frame.type === "Hello") send({ type: "Hello", version: 1, caps: 0n, clientInfo: "layout-review" });
        if (frame.type === "Ping") send({ ...frame, type: "Pong" });
        if (frame.type === "Welcome") {
          if (snapshot) send({ type: "Subscribe", subId: 1, filterJson: Buffer.from('{"topic":"canvas.layout"}') });
          else send({ type: "Call", callId: 1, actionId: action, inputJson: Buffer.from(typeof input === "string" ? input : JSON.stringify(input)) });
        }
        if (frame.type === "Result" || snapshot && frame.type === "Event") {
          clearTimeout(timer);
          resolve({ ok: frame.type === "Event" || frame.ok, value: JSON.parse(new TextDecoder().decode(frame.type === "Event" ? frame.eventJson : frame.json)) });
        }
      }));
    });
  } finally { socket.terminate(); }
}

/** Every test owns its server and browser partitions, including failed-assertion cleanup. */
async function pair(browser: Browser): Promise<{ server: RealServer; desktop: BrowserContext; phone: BrowserContext; page: Page; mobile: Page; dispose(): Promise<void> }> {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4673) });
  const desktop = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const phone = await browser.newContext({ ...devices["iPhone 15"], ignoreHTTPSErrors: true });
  try {
    const page = await desktop.newPage(); await enrol(page, server);
    await phone.addCookies(await desktop.cookies());
    const mobile = await phone.newPage(); await mobile.goto(server.origin + "/?theme=ink&bg=none");
    await expect(windows(mobile)).toHaveCount(1); await settled(mobile);
    return { server, desktop, phone, page, mobile, async dispose() { await phone.close(); await desktop.close(); await server.dispose(); } };
  } catch (error) { await phone.close(); await desktop.close(); await server.dispose(); throw error; }
}

test("ordinary repeated right splits never strand the account journal", async ({ browser }) => {
  const fixture = await pair(browser);
  const { page, mobile, server, desktop } = fixture;
  try {
    for (let step = 1; step <= 4; step++) {
      // Splits move focus to the new half; four normal shortcuts expose the weight floor.
      await page.keyboard.press("Control+Shift+D");
      await expect(windows(page)).toHaveCount(step + 1);
      if (step < 4) { await settled(page); await expect(windows(mobile)).toHaveCount(step + 1); }
    }
    await page.screenshot({ path: tracerEvidencePath("review-split-desktop.png") });
    await mobile.screenshot({ path: tracerEvidencePath("review-split-phone.png") });
    // A later valid close and a real reconnection must not remain behind the refused split.
    await windows(page).first().locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click());
    await expect(windows(page)).toHaveCount(4);
    await server.restart();
    await expect.poll(async () => (await cache(page)).pending.length, { timeout: 10_000 }).toBe(0);
    const canonical = await request(server, desktop, "", {}, true);
    expect(canonical.value.document).toEqual((await cache(page)).canonical);
    await expect(windows(mobile)).toHaveCount(4);
  } finally {
    try {
      const beforeReload = await cache(page);
      await writeFile(tracerEvidencePath("review-split-state.json"), JSON.stringify({ desktop: beforeReload, phone: await cache(mobile), calls: server.bridges.map((b) => b.control) }, null, 2));
      if (beforeReload.pending.length) {
        await page.reload(); await settled(page);
        await writeFile(tracerEvidencePath("review-split-reload.json"), JSON.stringify({ beforeReload, afterReload: await cache(page) }, null, 2));
      }
    } finally { await fixture.dispose(); }
  }
});

test("offline close races and later edits survive restart without duplicate windows", async ({ browser }) => {
  const fixture = await pair(browser);
  const { page, mobile, server, desktop } = fixture;
  try {
    await page.keyboard.press("Control+Shift+E"); await expect(windows(page)).toHaveCount(2); await settled(page); await expect(windows(mobile)).toHaveCount(2);
    await desktop.setOffline(true);
    // Close different windows on the disconnected desktop and online phone.
    await windows(page).first().locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click());
    await windows(mobile).last().locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click());
    await expect(windows(page)).toHaveCount(1); await expect(windows(mobile)).toHaveCount(1); await settled(mobile);
    await server.restart();
    await desktop.setOffline(false);
    await expect(windows(page)).toHaveCount(0); await expect(windows(mobile)).toHaveCount(0); await settled(page); await settled(mobile);
    expect((await cache(page)).canonical).toEqual((await cache(mobile)).canonical);
    await page.screenshot({ path: tracerEvidencePath("review-restart-desktop.png") });
    await mobile.screenshot({ path: tracerEvidencePath("review-restart-phone.png") });
  } finally { await desktop.setOffline(false); await fixture.dispose(); }
});

test("malformed and oversized requests preserve canonical state and subsequent valid edits", async ({ browser }) => {
  const fixture = await pair(browser);
  const { page, mobile, server, desktop } = fixture;
  try {
    const before = (await request(server, desktop, "", {}, true)).value;
    const base = Number(before.revision);
    for (const input of ["{", "[1]", JSON.stringify({ op_id: "huge", base_revision: base, intent: { type: "close", window_id: "x".repeat(9000) } }), { op_id: "account", base_revision: base, account: "other", intent: { type: "close", window_id: "foreign" } }, { op_id: "bounds", base_revision: base, intent: { type: "resize", window_id: "foreign", span: 0 } }]) {
      expect((await request(server, desktop, "canvas.layout.apply", input)).ok).toBe(false);
      expect((await request(server, desktop, "", {}, true)).value).toEqual(before);
    }
    await page.keyboard.press("Control+Shift+E"); await expect(windows(page)).toHaveCount(2); await settled(page); await expect(windows(mobile)).toHaveCount(2);
    expect((await cache(page)).canonical).toEqual((await cache(mobile)).canonical);
  } finally { await fixture.dispose(); }
});


/** Creates only this private fixture's second identity; the capability travels over stdin and stays in memory. */
async function secondAccount(server: RealServer, context: BrowserContext): Promise<void> {
  const token = randomBytes(32).toString("base64url");
  const digest = createHash("sha256").update(token).digest("base64url");
  const seed = spawn("python3", ["-c", `import json,sqlite3,sys,time
v=json.load(sys.stdin)
with sqlite3.connect(sys.argv[1]) as db:
 db.execute("INSERT INTO users(id,name,owner,recovery_hash,username,display_name) VALUES (?,'Review peer',0,'unused','review_peer','Review peer')",(v['user'],))
 db.execute("INSERT INTO sessions(token_hash,user_id,device,expires,fresh,unlocked) VALUES (?,?,'review',?,?,1)",(v['digest'],v['user'],int(time.time())+3600,int(time.time())))
`, server.dataDir + "/infraternal.sqlite"], { stdio: ["pipe", "ignore", "ignore"] });
  const ended = once(seed, "exit");
  seed.stdin.end(JSON.stringify({ user: randomUUID(), digest }));
  expect((await ended)[0]).toBe(0);
  await context.addCookies([{ name: "__Host-infraternal", value: token, url: server.origin, secure: true, httpOnly: true, sameSite: "Strict" }]);
}

test("a second account cannot read or retarget the first account layout", async ({ browser }) => {
  const fixture = await pair(browser);
  const { server, desktop, page } = fixture;
  const other = await browser.newContext({ viewport: { width: 393, height: 852 }, ignoreHTTPSErrors: true });
  try {
    const own = (await request(server, desktop, "", {}, true)).value;
    const doc = own.document as CanvasDocument;
    const view = doc.views.find((v) => v.id === "console")!;
    if (view.layout.type !== "tiled") throw Error("console must be tiled");
    const window = view.layout.columns[0]!.windows[0]!;
    await secondAccount(server, other);
    const isolated = (await request(server, other, "", {}, true)).value;
    expect((isolated.document as CanvasDocument).views).toEqual([]);
    const victim = await other.newPage(); await victim.goto(server.origin + "/?theme=ink&bg=none");
    await expect(windows(victim)).toHaveCount(1); await settled(victim);
    const base = Number((await request(server, other, "", {}, true)).value.revision);
    for (const intent of [
      { type: "open", view_id: "console", column_id: "foreign", window },
      { type: "target", window_id: window.id, target: window.target },
      { type: "close", window_id: window.id, account: "other" },
    ]) expect((await request(server, other, "canvas.layout.apply", { op_id: randomUUID(), base_revision: base, intent })).ok).toBe(false);
    // The same stable ID is scoped to the caller; a forged close is harmless to the first account.
    expect((await request(server, other, "canvas.layout.apply", { op_id: randomUUID(), base_revision: base, intent: { type: "close", window_id: window.id } })).ok).toBe(true);
    expect((await request(server, desktop, "", {}, true)).value).toEqual(own);
    await expect(windows(page)).toHaveCount(1);
  } finally { await other.close(); await fixture.dispose(); }
});

// A group can connect transitively through overlapping spans even when its leftmost window does not cross the split column.
test("a transitive span group reduces identically before and after a fresh snapshot", async ({ browser }) => {
  const fixture = await pair(browser);
  const { server, desktop, page, mobile } = fixture;
  try {
    const initial = (await cache(page)).canonical;
    const console = initial.views.find((v) => v.id === "console")!;
    if (console.layout.type !== "tiled") throw Error("console must be tiled");
    const target = console.layout.columns[0]!.windows[0]!.target;
    const incoming: CanvasDocument = { format: "infraternal.canvas", version: 1, revision: 0, views: [{ id: "chain", kind: "console", name: "Span chain", cell: { x: 1, y: 0 }, layout: { type: "tiled", columns: [
      { id: "a", weight: 1, windows: [{ id: "left", target, span: 2, rows: 1, row: 0 }] },
      { id: "b", weight: 1, windows: [{ id: "middle", target, span: 2, rows: 1, row: 1 }] },
      { id: "c", weight: 1, windows: [{ id: "right", target, span: 1, rows: 1, row: 0 }] },
    ] } }] };
    expect((await request(server, desktop, "canvas.layout.initialize", { op_id: randomUUID(), document: incoming })).ok).toBe(true);
    await settled(page); await settled(mobile);
    const before = (await request(server, desktop, "", {}, true)).value;
    const view = (before.document as CanvasDocument).views.find((v) => v.name === "Recovered: Span chain")!;
    if (view.layout.type !== "tiled") throw Error("chain must be tiled");
    const anchor = view.layout.columns[2]!.windows[0]!;
    expect((await request(server, desktop, "canvas.layout.apply", { op_id: randomUUID(), base_revision: before.revision, intent: { type: "split", view_id: view.id, anchor_id: anchor.id, axis: "down", column_id: view.layout.columns[2]!.id, window: { id: "new-chain", target } } })).ok).toBe(true);
    const snapshot = (await request(server, desktop, "", {}, true)).value.document as CanvasDocument;
    await expect.poll(async () => (await cache(page)).canonical.revision).toBe(snapshot.revision);
    await expect.poll(async () => (await cache(mobile)).canonical.revision).toBe(snapshot.revision);
    const liveDesktop = (await cache(page)).canonical, livePhone = (await cache(mobile)).canonical;
    await mobile.reload();
    await expect.poll(async () => (await cache(mobile)).canonical, { timeout: 15_000 }).toEqual(snapshot);
    await settled(mobile);
    await writeFile(tracerEvidencePath("review-span-chain.json"), JSON.stringify({ server: snapshot, desktop: liveDesktop, phone: livePhone, reloadedPhone: (await cache(mobile)).canonical }, null, 2));
    expect((await cache(mobile)).canonical).toEqual(snapshot);
    expect(liveDesktop).toEqual(snapshot);
  } finally { await fixture.dispose(); }
});

// A mixed resize must not place a null height in the browser cache while retaining a numeric height on the server.
test("nullable resize fields cannot diverge the live projection from a snapshot", async ({ browser }) => {
  const fixture = await pair(browser);
  const { server, desktop, page, mobile } = fixture;
  try {
    const before = (await request(server, desktop, "", {}, true)).value;
    const view = (before.document as CanvasDocument).views.find((v) => v.id === "console")!;
    if (view.layout.type !== "tiled") throw Error("console must be tiled");
    const id = view.layout.columns[0]!.windows[0]!.id;
    const result = await request(server, desktop, "canvas.layout.apply", { op_id: randomUUID(), base_revision: before.revision, intent: { type: "resize", window_id: id, height: null, rows: 2 } });
    if (!result.ok) {
      expect((await request(server, desktop, "", {}, true)).value).toEqual(before);
      return;
    }
    const snapshot = (await request(server, desktop, "", {}, true)).value.document as CanvasDocument;
    await expect.poll(async () => (await cache(page)).canonical.revision).toBe(snapshot.revision);
    await expect.poll(async () => (await cache(mobile)).canonical.revision).toBe(snapshot.revision);
    await writeFile(tracerEvidencePath("review-null-resize.json"), JSON.stringify({ server: snapshot, desktop: (await cache(page)).canonical, phone: (await cache(mobile)).canonical }, null, 2));
    expect((await cache(page)).canonical).toEqual(snapshot);
    expect((await cache(mobile)).canonical).toEqual(snapshot);
  } finally { await fixture.dispose(); }
});

test("sixty memberships, stale edits and checkpoint compaction preserve the same account canvas", async ({ browser }) => {
  const fixture = await pair(browser);
  const { server, desktop, phone, page, mobile } = fixture;
  try {
    const initial = (await cache(page)).canonical;
    const console = initial.views.find((v) => v.id === "console")!;
    if (console.layout.type !== "tiled") throw Error("console must be tiled");
    const column = console.layout.columns[0]!;
    const target = column.windows[0]!.target;
    const apply = (context: BrowserContext, intent: unknown) => request(server, context, "canvas.layout.apply", { op_id: randomUUID(), base_revision: initial.revision, intent });
    // Distinct window IDs may refer to one session; this exercises layout scale without creating 60 shells.
    for (let n = 1; n < 60; n++) expect((await apply(desktop, { type: "open", view_id: "console", column_id: column.id, after: n === 1 ? column.windows[0]!.id : `scale-${n - 1}`, window: { id: `scale-${n}`, target } })).ok).toBe(true);
    await expect(windows(page)).toHaveCount(60); await expect(windows(mobile)).toHaveCount(60);
    for (let n = 0; n < 65; n++) {
      const results = await Promise.all([
        apply(desktop, { type: "resize", window_id: "scale-1", height: n + 1 }),
        apply(phone, { type: "resize", window_id: "scale-2", rows: n % 2 + 1 }),
      ]);
      expect(results.every((r) => r.ok)).toBe(true);
    }
    const race = await Promise.all([
      apply(desktop, { type: "move", view_id: "console", window_id: "scale-3", column_id: "moved" }),
      apply(phone, { type: "close", window_id: "scale-3" }),
    ]);
    expect(race.every((r) => r.ok)).toBe(true);
    expect((await apply(phone, { type: "open", view_id: "console", column_id: column.id, window: { id: "reopened", target } })).ok).toBe(true);
    expect((await apply(desktop, { type: "move", view_id: "console", window_id: "scale-3", column_id: "stale" })).ok).toBe(true);
    const head = (await request(server, desktop, "", {}, true)).value;
    await expect.poll(async () => (await cache(page)).canonical.revision).toBe(head.revision);
    await expect.poll(async () => (await cache(mobile)).canonical.revision).toBe(head.revision);
    expect((await cache(page)).canonical).toEqual(head.document);
    expect((await cache(mobile)).canonical).toEqual(head.document);
    const ws = (head.document as CanvasDocument).views.flatMap((v) => v.layout.type === "tiled" ? v.layout.columns.flatMap((c) => c.windows) : []);
    expect(ws).toHaveLength(60); expect(new Set(ws.map((w) => w.id)).size).toBe(60);
    expect(ws.some((w) => w.id === "scale-3")).toBe(false);
    const query = spawn("python3", ["-c", `import sqlite3,sys,json
with sqlite3.connect(sys.argv[1]) as db:
 print(json.dumps({t:db.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in ['canvas_operations','canvas_snapshots','canvas_receipts']}))
`, server.dataDir + "/infraternal.sqlite"], { stdio: ["ignore", "pipe", "ignore"] });
    let output = ""; query.stdout.on("data", (bytes) => { output += bytes; });
    expect((await once(query, "exit"))[0]).toBe(0);
    const counts = JSON.parse(output) as { canvas_operations: number; canvas_snapshots: number; canvas_receipts: number };
    expect(counts.canvas_operations).toBeLessThan(128); expect(counts.canvas_snapshots).toBe(1);
    await writeFile(tracerEvidencePath("review-scale.json"), JSON.stringify({ windows: ws.length, snapshotBytes: Buffer.byteLength(JSON.stringify(head)), ...counts }, null, 2));
    await page.screenshot({ path: tracerEvidencePath("review-sixty-desktop.png") });
    await mobile.screenshot({ path: tracerEvidencePath("review-sixty-phone.png") });
  } finally { await fixture.dispose(); }
});

for (const reconnect of [false, true]) test(`review r2: a raced split refusal preserves later writes${reconnect ? " across reconnect" : " in the pipeline"}`, async ({ browser }) => {
  const fixture = await pair(browser);
  const { page, mobile, server, desktop, phone } = fixture;
  try {
    await page.keyboard.press("Control+Shift+E");
    await expect(windows(page)).toHaveCount(2); await settled(page); await expect(windows(mobile)).toHaveCount(2);
    const baseline = (await cache(page)).canonical;
    const view = baseline.views.find((v) => v.id === "console")!;
    if (view.layout.type !== "tiled") throw Error("expected tiled console");
    const column = view.layout.columns[0]!;
    expect((await request(server, desktop, "canvas.layout.apply", { op_id: randomUUID(), base_revision: baseline.revision, intent: { type: "weight", view_id: view.id, column_id: column.id, weight: 0.2 } })).ok).toBe(true);
    await expect.poll(async () => (await cache(page)).canonical.revision).toBe(baseline.revision + 1);
    let held = false, armed = true;
    const queued: Array<string | Buffer> = [];
    let release = (): void => {};
    let disconnect = (): void => {};
    // Hold the real split and its ordered suffix while the other device changes
    // the column. This creates a valid stale split without rewriting wire input.
    await page.routeWebSocket("**/v1/ws", (route) => {
      const upstream = route.connectToServer();
      const decoder = new WebSocketFrameDecoder();
      disconnect = () => route.close();
      release = () => { armed = false; held = false; for (const bytes of queued.splice(0)) upstream.send(bytes); };
      route.onMessage((bytes) => {
        if (armed && typeof bytes !== "string") decoder.feed(new Uint8Array(bytes), (_stream, frame) => {
          if (frame.type !== "Call" || frame.actionId !== "canvas.layout.apply") return;
          const input = JSON.parse(new TextDecoder().decode(frame.inputJson)) as { intent?: { type?: string } };
          if (input.intent?.type === "split") held = true;
        });
        if (held) queued.push(bytes); else upstream.send(bytes);
      });
    });
    await page.reload(); await expect(windows(page)).toHaveCount(2); await settled(page);
    await page.keyboard.press("Control+Shift+D"); await expect(windows(page)).toHaveCount(3);
    await expect.poll(() => held).toBe(true);
    await windows(page).first().locator('[data-action="close"]').evaluate((el) => (el as HTMLElement).click());
    await expect(windows(page)).toHaveCount(2);
    await expect.poll(async () => (await cache(page)).pending.length).toBeGreaterThanOrEqual(2);
    const pending = await cache(page);
    expect((await request(server, phone, "canvas.layout.apply", { op_id: randomUUID(), base_revision: baseline.revision, intent: { type: "weight", view_id: view.id, column_id: column.id, weight: 0.1 } })).ok).toBe(true);
    const notice = page.getByText("The server could not save that layout change. The saved layout has been restored.", { exact: true }).waitFor({ state: "visible" });
    void notice.catch(() => undefined);
    if (reconnect) { armed = false; held = false; queued.length = 0; disconnect(); }
    else release();
    await settled(page); await settled(mobile);
    await expect(windows(page)).toHaveCount(1); await expect(windows(mobile)).toHaveCount(1);
    await notice;
    const head = (await request(server, desktop, "", {}, true)).value.document;
    expect((await cache(page)).canonical).toEqual(head); expect((await cache(mobile)).canonical).toEqual(head);
    await writeFile(tracerEvidencePath(`review-r2-refusal-${reconnect ? "reconnect" : "pipeline"}.json`), JSON.stringify({ pending, desktop: await cache(page), phone: await cache(mobile) }, null, 2));
    await page.screenshot({ path: tracerEvidencePath(`review-r2-refusal-${reconnect ? "reconnect" : "pipeline"}.png`) });
    await page.reload(); await settled(page); await expect(windows(page)).toHaveCount(1);
    expect((await cache(page)).canonical).toEqual(head);
  } finally { await fixture.dispose(); }
});

test("review r2: narrow and wide device splits converge without refused windows", async ({ browser }) => {
  const fixture = await pair(browser);
  const { page, mobile, server, desktop } = fixture;
  try {
    await page.keyboard.press("Control+Shift+D");
    await expect(windows(page)).toHaveCount(2); await settled(page); await expect(windows(mobile)).toHaveCount(2);
    const baseline = (await cache(page)).canonical;
    const view = baseline.views.find((v) => v.id === "console")!;
    if (view.layout.type !== "tiled") throw Error("expected tiled console");
    const [narrow, wide] = view.layout.columns;
    for (const [column, weight] of [[narrow!, 0.1], [wide!, 1]] as const) expect((await request(server, desktop, "canvas.layout.apply", { op_id: randomUUID(), base_revision: baseline.revision, intent: { type: "weight", view_id: view.id, column_id: column.id, weight } })).ok).toBe(true);
    await expect.poll(async () => (await cache(page)).canonical.revision).toBe(baseline.revision + 2);
    await expect.poll(async () => (await cache(mobile)).canonical.revision).toBe(baseline.revision + 2);
    for (const [device, id] of [[page, narrow!.windows[0]!.id], [mobile, wide!.windows[0]!.id]] as const) await device.locator(`.ui-window[data-window-id="${id}"]`).evaluate((el) => el.dispatchEvent(new PointerEvent("pointerdown", { bubbles: true, button: 0 })));
    await Promise.all([page.keyboard.press("Control+Shift+D"), mobile.keyboard.press(await mobile.evaluate(isMacPlatform) ? "Meta+D" : "Control+Shift+D")]);
    await expect(windows(page)).toHaveCount(4); await expect(windows(mobile)).toHaveCount(4); await settled(page); await settled(mobile);
    const head = (await request(server, desktop, "", {}, true)).value.document;
    expect((await cache(page)).canonical).toEqual(head); expect((await cache(mobile)).canonical).toEqual(head);
    await writeFile(tracerEvidencePath("review-r2-two-bounds.json"), JSON.stringify({ desktop: await cache(page), phone: await cache(mobile) }, null, 2));
    await page.reload(); await mobile.reload(); await expect(windows(page)).toHaveCount(4); await expect(windows(mobile)).toHaveCount(4);
  } finally { await fixture.dispose(); }
});

test("review r2: down split admission respects the canonical height floor", async ({ browser }) => {
  const fixture = await pair(browser);
  const { page, mobile, server, desktop } = fixture;
  try {
    const baseline = (await cache(page)).canonical;
    const view = baseline.views.find((v) => v.id === "console")!;
    if (view.layout.type !== "tiled") throw Error("expected tiled console");
    const id = view.layout.columns[0]!.windows[0]!.id;
    expect((await request(server, desktop, "canvas.layout.apply", { op_id: randomUUID(), base_revision: baseline.revision, intent: { type: "resize", window_id: id, height: 0.05 } })).ok).toBe(true);
    await expect.poll(async () => (await cache(page)).canonical.revision).toBe(baseline.revision + 1);
    await page.keyboard.press("Control+Shift+E");
    await expect(windows(page)).toHaveCount(2);
    await settled(page); await settled(mobile);
    await writeFile(tracerEvidencePath("review-r2-height-floor.json"), JSON.stringify({ desktop: await cache(page), phone: await cache(mobile), calls: server.bridges.map((b) => b.control) }, null, 2));
    await page.screenshot({ path: tracerEvidencePath("review-r2-height-floor.png") });
    await expect(windows(page)).toHaveCount(2); await expect(windows(mobile)).toHaveCount(2);
  } finally { await fixture.dispose(); }
});
