/** Production-shaped recovery and operation delivery through desktop and phone browsers (#243, D248). */
import { watchLayout } from "./layout-observer";
import { WebSocketFrameDecoder } from "../../../packages/protocol/src/codec";
import { isMacPlatform } from "../../../packages/ui/src/platform";
import { devices, expect, test } from "playwright/test";
import { spawnSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import type { CanvasDocument, DocView } from "../src/canvas/model/schema";
import { cache, enrol, request, settled, windows } from "./layout-devices";
import { startRealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";

test.setTimeout(180_000);
test("44-window recovered account sends edits from both devices", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4293) });
  const desktop = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true });
  const phone = await browser.newContext({ ...devices["iPhone 15"], viewport: { width: 393, height: 852 }, ignoreHTTPSErrors: true });
  const evidence = tracerEvidencePath("layout-recovery"); await mkdir(evidence, { recursive: true });
  const baseline = process.env.LAYOUT_RECOVERY_BASELINE === "1";
  const counts: Array<{ device: string; step: string; calls: number; revision: number }> = [];
  let diagnostics: (() => Promise<unknown>) | undefined;
  const wire: Record<string, unknown>[] = [];
  const errors: Array<{ device: string; message: string; stack?: string }> = [];
  const record = (page: import("playwright/test").Page, device: string): void => {
    page.on("pageerror", (error) => errors.push({ device, message: error.message, ...(error.stack ? { stack: error.stack } : {}) }));
    page.on("websocket", (socket) => {
      const sent = new WebSocketFrameDecoder(), received = new WebSocketFrameDecoder();
      const calls = new Set<number>();
      socket.on("framesent", ({ payload }) => {
        if (typeof payload === "string") return;
        sent.feed(new Uint8Array(payload), (_stream, frame) => {
          if (frame.type !== "Call" || !frame.actionId.startsWith("canvas.layout.")) return;
          calls.add(frame.callId);
          const input = JSON.parse(new TextDecoder().decode(frame.inputJson));
          wire.push({ device, type: "call", call: frame.callId, action: frame.actionId, op: input.op_id, base: input.base_revision, intent: input.intent });
        });
      });
      socket.on("framereceived", ({ payload }) => {
        if (typeof payload === "string") return;
        received.feed(new Uint8Array(payload), (_stream, frame) => {
          if (frame.type === "Result" && calls.has(frame.callId)) wire.push({ device, type: "result", call: frame.callId, ok: frame.ok, value: JSON.parse(new TextDecoder().decode(frame.json)) });
        });
      });
    });
  };
  try {
    const page = watchLayout(await desktop.newPage()); record(page, "desktop"); await enrol(page, server);
    const initial = (await cache(page)).canonical;
    const first = initial.views.find((v) => v.id === "console")!;
    if (first.layout.type !== "tiled") throw Error("missing console");
    const target = first.layout.columns[0]!.windows[0]!.target;
    // Create real fixture sessions; no owner database or identifiers are copied.
    if (target.type !== "session") throw Error("missing session target");
    const targets = [target];
    for (let i = 1; i < 45; i++) {
      const result = await request(server, desktop, "ssh.session.open", {});
      expect(result.ok).toBe(true);
      targets.push({ ...target, id: String(result.value.session_id) });
    }
    let at = 0;
    const consoleView: DocView = {
      ...first,
      layout: {
        type: "tiled",
        columns: Array.from({ length: 29 }, (_, index) => ({
          id: `column-${index}`, weight: 1,
          windows: Array.from({ length: index < 15 ? 2 : 1 }, (_, row) => ({
            id: `window-${index}-${row}`, target: structuredClone(targets[at++]!), height: index < 15 ? 0.5 : 1,
          })),
        })),
      },
    };
    const recovered: DocView = {
      ...consoleView, id: "old-recovery", name: "Recovered: Console", cell: { x: 0, y: 4 },
      layout: { type: "tiled", columns: [{ id: "old-column", weight: 1, windows: [
        { id: "old-duplicate", target: structuredClone(target) },
        { id: "old-duplicate-two", target: structuredClone(targets[1]!) },
        { id: "old-new", height: 0.6, target: structuredClone(targets[44]!) },
      ] }] },
    };
    const mesh: DocView = { id: "mesh", kind: "mesh", name: "Mesh", cell: { x: 2, y: 4 }, layout: { type: "graph", pinned: {} } };
    const doc: CanvasDocument = { ...initial, revision: 2, views: [consoleView, recovered, mesh, { ...mesh, id: "old-mesh", name: "Recovered: Mesh", cell: { x: 4, y: 4 } }] };
    await server.restart(async () => {
      const seeded = spawnSync("python3", ["-c", `import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
 # Recreate the production v29 schema while stopped, then exercise the real upgrade.
 if sys.argv[3] == "0":
  for name in ("canvas_receipt_insert", "canvas_receipt_delete", "canvas_receipt_account"):
   db.execute("DROP TRIGGER " + name)
  db.execute("ALTER TABLE canvas_heads DROP COLUMN receipt_count")
  db.execute("DELETE FROM _sqlx_migrations WHERE version=30")
 account=db.execute("SELECT account FROM canvas_heads LIMIT 1").fetchone()[0]
 db.execute("UPDATE canvas_heads SET revision=2,document=?,initialized=1 WHERE account=?",(sys.argv[2],account))
 db.execute("DELETE FROM canvas_operations WHERE account=?",(account,))
 db.execute("DELETE FROM canvas_snapshots WHERE account=?",(account,))
`, `${server.dataDir}/infraternal.sqlite`, JSON.stringify(doc), baseline ? "1" : "0"], { encoding: "utf8" });
      expect(seeded.status).toBe(0);
    });
    // D312 mounts the repaired server snapshot without a private cached drawing.
    await page.reload(); await expect(windows(page)).toHaveCount(baseline ? 44 : 45); await settled(page);
    await phone.addCookies(await desktop.cookies());
    const mobile = watchLayout(await phone.newPage()); record(mobile, "phone"); await mobile.goto(server.origin + "/?theme=ink&bg=none");
    await expect(windows(mobile)).toHaveCount(baseline ? 44 : 45); await settled(mobile);
    for (const [name, device] of [["desktop", page], ["phone", mobile]] as const) {
      await device.locator("#capsule").click();
      await expect(device.getByRole("dialog", { name: "Views", exact: true })).toBeVisible();
      await device.screenshot({ path: `${evidence}/${baseline ? "before" : "after"}-${name}-menu.png` });
      if (!baseline) {
        await expect(device.locator('.cl-viewrow[data-view="old-recovery"]')).toHaveCount(0);
        await expect(device.locator('.cl-viewrow[data-view="old-mesh"]')).toHaveCount(0);
        await expect(device.locator('.cl-viewrow[data-view="settings"] .cl-viewrow-meta')).toHaveText("");
      }
      await device.keyboard.press("Escape");
    }
    diagnostics = async () => ({ steps: counts, wire, errors, desktop: await cache(page), phone: await cache(mobile), dom: { desktop: await windows(page).evaluateAll((nodes) => nodes.map((node) => ({ id: (node as HTMLElement).dataset.windowId, class: node.className }))), phone: await windows(mobile).evaluateAll((nodes) => nodes.map((node) => ({ id: (node as HTMLElement).dataset.windowId, class: node.className }))) }, controls: server.bridges.map((bridge) => bridge.control) });
    for (const [name, device, peer] of [["desktop", page, mobile], ["phone", mobile, page]] as const) {
      const start = await windows(device).count();
      await windows(device).first().dispatchEvent("pointerdown", { button: 0 });
      await device.keyboard.press(await device.evaluate(isMacPlatform) ? "Meta+d" : "Control+Shift+D");
      await expect(windows(peer)).toHaveCount(start + 1); await settled(device);
      counts.push({ device: name, step: "split", calls: server.bridges.flatMap((b) => b.control).filter((f) => f.type === "Call" && f.detail === "canvas.layout.apply").length, revision: (await cache(device)).canonical.revision });
      await windows(device).last().locator('[data-action="close"]').evaluate((node) => (node as HTMLElement).click());
      await expect(windows(peer)).toHaveCount(start); await settled(device);
      counts.push({ device: name, step: "close", calls: server.bridges.flatMap((b) => b.control).filter((f) => f.type === "Call" && f.detail === "canvas.layout.apply").length, revision: (await cache(device)).canonical.revision });
      const beforeOpen = await windows(device).evaluateAll((nodes) => nodes.map((node) => (node as HTMLElement).dataset.windowId));
      await windows(device).first().dispatchEvent("pointerdown", { button: 0 });
      await device.keyboard.press(await device.evaluate(isMacPlatform) ? "Meta+Enter" : "Control+Shift+Enter");
      await expect(windows(peer)).toHaveCount(start + 1); await settled(device);
      counts.push({ device: name, step: "open", calls: server.bridges.flatMap((b) => b.control).filter((f) => f.type === "Call" && f.detail === "canvas.layout.apply").length, revision: (await cache(device)).canonical.revision });
      const added = await windows(device).evaluateAll((nodes, old) => nodes.map((node) => (node as HTMLElement).dataset.windowId).find((id) => !old.includes(id)), beforeOpen);
      const card = device.locator(`.cl[data-view="console"] .ui-window[data-window-id="${added}"]`);
      const pill = card.locator(".ui-window-pill");
      await expect(pill).toBeVisible();
      const box = (await pill.boundingBox())!;
      const beforeMove = (await cache(peer)).canonical;
      await device.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await device.mouse.down();
      await device.mouse.move(5, box.y + box.height / 2 + 40, { steps: 12 });
      await expect(device.locator(".is-lifted")).toHaveCount(1);
      await device.mouse.up();
      await expect.poll(async () => (await cache(peer)).canonical).not.toEqual(beforeMove); await settled(device);
      counts.push({ device: name, step: "move", calls: server.bridges.flatMap((b) => b.control).filter((f) => f.type === "Call" && f.detail === "canvas.layout.apply").length, revision: (await cache(device)).canonical.revision });
      await card.locator('[data-action="close"]').evaluate((node) => (node as HTMLElement).click());
      await expect(windows(peer)).toHaveCount(start); await settled(device);
    }
    const persisted = spawnSync("python3", ["-c", `import json,sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
 print(json.dumps({"revision":db.execute("SELECT revision FROM canvas_heads LIMIT 1").fetchone()[0],"operations":db.execute("SELECT count(*) FROM canvas_operations").fetchone()[0],"migrations":db.execute("SELECT max(version) FROM _sqlx_migrations").fetchone()[0],"receipts":db.execute("SELECT count(*) FROM canvas_receipts").fetchone()[0],"receipt_count":db.execute("SELECT receipt_count FROM canvas_heads LIMIT 1").fetchone()[0] if sys.argv[2]=="0" else None}))
`, `${server.dataDir}/infraternal.sqlite`, baseline ? "1" : "0"], { encoding: "utf8" });
    expect(persisted.status).toBe(0);
    const stored = JSON.parse(persisted.stdout) as { revision: number; operations: number; migrations: number; receipts: number; receipt_count: number | null };
    expect(errors).toEqual([]);
    expect(wire.filter((frame) => frame.type === "result" && frame.ok === false)).toEqual([]);
    if (!baseline) expect(stored.receipt_count).toBe(stored.receipts);
    expect(stored.operations).toBeGreaterThan(0);
    expect(stored.migrations).toBe(baseline ? 29 : 30);
    await expect.poll(async () => (await cache(page)).canonical.revision).toBe(stored.revision);
    await expect.poll(async () => (await cache(mobile)).canonical.revision).toBe(stored.revision);
    expect((await cache(page)).canonical).toEqual((await cache(mobile)).canonical);
    await writeFile(`${evidence}/${baseline ? "before" : "after"}-operations.json`, JSON.stringify({ steps: counts, stored, wire }, null, 2));
    expect(counts.every((row) => row.calls > 0 && row.revision > 2)).toBe(true);
  } catch (error) {
    if (diagnostics) await writeFile(`${evidence}/${baseline ? "before" : "after"}-failure.json`, JSON.stringify(await diagnostics(), null, 2));
    throw error;
  } finally { await phone.close(); await desktop.close(); await server.dispose(); }
});


test("a repaired cached graph cannot build after its view was removed", async ({ browser }) => {
  const server = await startRealServer({ port: Number(process.env.TRACER_TEST_PORT ?? 4293) });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, ignoreHTTPSErrors: true, serviceWorkers: "block" });
  let release = (): void => {};
  const gate = new Promise<void>((resolve) => { release = resolve; });
  const errors: string[] = [];
  try {
    const page = watchLayout(await context.newPage()); page.on("pageerror", (error) => errors.push(error.message));
    await enrol(page, server);
    await expect.poll(async () => (await cache(page)).canonical.views.some((view) => view.id === "mesh")).toBe(true);
    const historical = structuredClone((await cache(page)).canonical);
    const mesh = historical.views.find((view) => view.id === "mesh")!;
    historical.views.push({ ...mesh, id: "delayed-recovery", name: "Recovered: Mesh", cell: { x: 0, y: 0 } });
    const account = await page.evaluate(async () => (await (await fetch("/auth/session", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" })).json()).user_id as string);
    await page.evaluate(({ account, document }) => localStorage.setItem(`infraternal.canvas.${account}`, JSON.stringify(document)), { account, document: historical });
    let blocked = false;
    await page.route("**/*.js", async (route) => {
      const response = await route.fetch();
      if ((await response.text()).includes("cl-graph-arrows")) { blocked = true; await gate; }
      await route.fulfill({ response });
    });
    await page.reload({ waitUntil: "domcontentloaded" });
    await expect.poll(() => blocked).toBe(true);
    await expect.poll(async () => (await cache(page)).canonical.views.some((view) => view.id === "delayed-recovery")).toBe(false);
    await expect(page.locator('.cl[data-view="delayed-recovery"]')).toHaveCount(0);
    release();
    await expect(page.locator('.cl[data-view="mesh"] .cl-graph-arrows')).toHaveCount(1);
    expect(errors).toEqual([]);
  } finally { release(); await context.unrouteAll({ behavior: "wait" }); await context.close(); await server.dispose(); }
});
