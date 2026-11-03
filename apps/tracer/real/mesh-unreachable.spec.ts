/** Exercises production Mesh inventory across cold CA restarts and invalid stored rows (#229). */
import { expect, test, type Page } from "playwright/test";
import { WebSocket } from "ws";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { WebSocketFrameDecoder, encodeMuxedFrame, type WireFrame } from "../../../packages/protocol/src/codec";
import { personName, startRealServer, type RealServer } from "./server";
import { tracerEvidencePath } from "../test/evidence-path";
let server: RealServer;
let page: Page;
const controls = () => server.bridges.flatMap((b) => b.control);
test.describe.configure({ mode: "serial" });
test.beforeAll(async ({ browser }) => {
  server = await startRealServer({ remoteListen: `127.0.0.1:${Number(process.env.TRACER_TEST_PORT ?? 4429) + 1000}` });
  const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 } });
  page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  await page.goto(server.origin + "/");
  await page.locator("#setup-token").fill(server.token);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.locator("#setup-username").fill(personName("mesh_real"));
  await page.locator("#setup-display-name").fill("Mesh real");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByRole("button", { name: "Create passkey" }).click();
  await page.getByRole("heading", { name: "Save your recovery key" }).waitFor();
  await page.locator(".auth-check").click();
  await page.getByRole("button", { name: "Open infraternal" }).click();
  await page.locator(".cl-viewport").waitFor();
  // The canvas asks for the mesh as soon as the connection is up; which block runs depends on the answer.
  await expect.poll(() => controls().some((c) => c.dir === "down" && c.type === "Result" && controls().some((u) => u.dir === "up" && u.detail === "mesh.list" && u.callId === c.callId)), { timeout: 20_000 }).toBe(true);
});
/** Runs one action on a second socket of the signed-in account (the way a CLI or another tab would) and returns its answer. */
async function act(action: string, input: Record<string, unknown>): Promise<{ ok: boolean; body: Record<string, unknown> }> {
  const cookie = (await page.context().cookies()).map((c) => `${c.name}=${c.value}`).join("; ");
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder();
  let deadline: ReturnType<typeof setTimeout>;
  const answer = new Promise<{ ok: boolean; body: Record<string, unknown> }>((resolve, reject) => {
    socket.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (_s: number, f: WireFrame) => {
      if (f.type === "Hello") socket.send(encodeMuxedFrame(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "mesh-real-act" }));
      if (f.type === "Welcome") socket.send(encodeMuxedFrame(0, { type: "Call", callId: 1, actionId: action, inputJson: new TextEncoder().encode(JSON.stringify(input)) }));
      if (f.type === "Result") resolve({ ok: f.ok, body: JSON.parse(new TextDecoder().decode(f.json)) as Record<string, unknown> });
    }));
    socket.on("error", reject);
    deadline = setTimeout(() => reject(new Error("no answer")), 15_000);
  });
  try { return await answer; } finally { clearTimeout(deadline!); socket.terminate(); }
}


test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

/** Exercise the real administrator ceremony while keeping private inputs in browser memory. */
async function unlock(): Promise<void> {
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  const action = page.getByLabel("Hosts settings").getByRole("button", { name: "Unlock", exact: true, includeHidden: true });
  await expect(action).toHaveAttribute("data-shown", "true");
  await action.evaluate(button => (button as HTMLButtonElement).click());
  await expect.poll(() => ca()).toEqual({ locked: false, initialized: true });
}
async function ca(): Promise<{ locked: boolean; initialized: boolean }> {
  return page.evaluate(async () => (await fetch("/remote/ca/status", { method: "POST" })).json());
}

/** Only controlled public inventory fields are changed; private fixture state is never read. */
function sql(statement: string): void {
  const result = spawnSync("python3", ["-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute(sys.argv[2]); c.commit(); c.close()", resolve(server.dataDir, "infraternal.sqlite"), statement]);
  expect(result.status).toBe(0);
}

test("production-shaped inventory remains readable before and after a cold CA unlock", async () => {
  await unlock();
  for (const [i, name] of ["alpha", "bravo", "never-connected", "revoked"].entries()) {
    const hostId = `00000000-0000-4000-8000-00000000000${i}`;
    expect(await page.evaluate(async host_id => (await fetch("/remote/invitations", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({host_id, mode: "rootless", execution_uid: 1000})})).ok, hostId)).toBe(true);
    const answer = await act("mesh.node.enroll", { name, host_id: hostId, public_key: Array.from({length: 32}, (_, k) => k + i + 1) });
    expect(answer.ok).toBe(true);
  }
  sql("UPDATE remote_hosts SET revoked_at=unixepoch() WHERE id=x'00000000000040008000000000000003'");
  const initial = await act("mesh.list", {});
  expect(initial.ok).toBe(true);
  const nodes = initial.body.nodes as Array<{node: {id: number; host: string}}>;
  const id = (host: string) => nodes.find(n => n.node.host === host)!.node.id;
  expect(nodes.some(n => n.node.host === "revoked")).toBe(false);
  for (const host of ["alpha", "bravo"]) expect((await act("mesh.node.observe", {node_id: id(host), last_rtt_us: 1000})).ok).toBe(true);
  expect((await act("mesh.grant.create", {name: "alpha-to-bravo", from: {Node: id("alpha")}, to: {Node: id("bravo")}, both_ways: false})).ok).toBe(true);
  await page.keyboard.press("Control+Shift+Digit2");
  await expect(page.locator('.cl[data-view="mesh"] .ui-window[data-window-id="n-never-connected"]')).toBeVisible();
  await page.screenshot({path: tracerEvidencePath("mesh-unreachable", "baseline-ready.png")});
  await server.restart();
  await expect.poll(ca).toEqual({locked: true, initialized: true});
  expect((await act("mesh.list", {})).ok).toBe(true);
  await expect(page.locator('.cl[data-view="mesh"] .cl-meshstate[data-open="true"]')).toHaveCount(0);
  await page.screenshot({path: tracerEvidencePath("mesh-unreachable", "cold-locked.png")});
  await unlock();
  expect((await act("mesh.list", {})).ok).toBe(true);
  await expect(page.locator('.cl[data-view="mesh"] .cl-meshstate[data-open="true"]')).toHaveCount(0);
  await page.screenshot({path: tracerEvidencePath("mesh-unreachable", "unlocked.png")});
  await page.setViewportSize({width: 393, height: 852});
  await page.screenshot({path: tracerEvidencePath("mesh-unreachable", "unlocked-mobile.png")});
  await page.setViewportSize({width: 1440, height: 900});
  console.log("MESH_PROOF enrolled=3 never_connected=1 revoked=1 observations=controlled cold_locked_list=ok unlocked_list=ok restart_after_unlock=false");
});

test("an invalid stored host leaves healthy inventory visible", async () => {
  sql("UPDATE mesh_nodes SET name='' WHERE name='never-connected'");
  try {
    const answer = await act("mesh.list", {});
    expect(answer.ok).toBe(true);
    const nodes = answer.body.nodes as Array<{node: {host: string}}>;
    expect(nodes.length).toBeGreaterThan(0);
    expect(nodes.some(n => n.node.host === "")).toBe(false);
    await page.reload();
    await page.locator(".cl-viewport").waitFor();
    await page.keyboard.press("Control+Shift+Digit2");
    await expect(page.locator('.cl[data-view="mesh"] .cl-meshstate[data-open="true"]')).toHaveCount(0);
    for (const host of ["alpha", "bravo"]) {
      await expect(page.locator(`.cl[data-view="mesh"] .ui-window[data-window-id="n-${host}"]`)).toBeVisible();
    }
    await page.screenshot({path: tracerEvidencePath("mesh-unreachable", "invalid-row.png")});
    console.log("MESH_PROOF invalid_stored_name=skipped healthy_inventory=visible");
  } finally { sql("UPDATE mesh_nodes SET name='never-connected' WHERE name=''"); }
  await expect(page.locator('.cl[data-view="mesh"] .cl-meshstate[data-open="true"]')).toHaveCount(0, {timeout: 40_000});
});

test("a database read failure produces an unavailable answer and retries after repair", async () => {
  sql("ALTER TABLE mesh_grants RENAME TO mesh_grants_unavailable");
  try {
    expect((await act("mesh.list", {})).body).toEqual({error: "mesh unavailable"});
    await page.reload();
    await page.locator(".cl-viewport").waitFor();
    await page.keyboard.press("Control+Shift+Digit2");
    await expect(page.locator('.cl[data-view="mesh"] .cl-meshstate[data-open="true"]')).toContainText("Could not reach the mesh");
    await page.screenshot({path: tracerEvidencePath("mesh-unreachable", "storage-error.png")});
    console.log("MESH_PROOF missing_table=mesh_unavailable_client_error");
  } finally { sql("ALTER TABLE mesh_grants_unavailable RENAME TO mesh_grants"); }
  await expect(page.locator('.cl[data-view="mesh"] .cl-meshstate[data-open="true"]')).toHaveCount(0, {timeout: 40_000});
});

test("disabled Mesh is refused and recovers after re-enable", async () => {
  expect((await act("plugins.set_enabled", {plugin: "mesh", enabled: false})).ok).toBe(true);
  try {
    const answer = await act("mesh.list", {});
    expect(answer.ok).toBe(false);
    expect(answer.body.error).toBe("mesh unavailable");
    console.log("MESH_PROOF disabled_mesh_refusal=mesh_unavailable");
    await page.reload();
    await page.locator(".cl-viewport").waitFor();
    await page.keyboard.press("Control+Shift+Digit2");
    await expect(page.locator('.cl[data-view="mesh"] .cl-meshstate[data-open="true"]')).toContainText("Could not reach the mesh");
  } finally {
    expect((await act("plugins.set_enabled", {plugin: "mesh", enabled: true})).ok).toBe(true);
  }
  await expect(page.locator('.cl[data-view="mesh"] .cl-meshstate[data-open="true"]')).toHaveCount(0, {timeout: 40_000});
});

test("subscription admission saturation returns a bounded Mesh error while calls keep working", async () => {
  const cookie = (await page.context().cookies()).map(c => `${c.name}=${c.value}`).join("; ");
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", {headers: {Origin: server.origin, Cookie: cookie}});
  const decoder = new WebSocketFrameDecoder();
  let deadline: ReturnType<typeof setTimeout>;
  const refused = new Promise<string>((resolve, reject) => {
    deadline = setTimeout(() => reject(new Error("subscription admission did not answer")), 15_000);
    socket.on("error", reject);
    socket.on("message", data => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (_stream, frame) => {
      if (frame.type === "Hello") socket.send(encodeMuxedFrame(0, {type: "Hello", version: 1, caps: 0n, clientInfo: "mesh-admission-proof"}));
      if (frame.type === "Welcome") for (let subId = 1; subId <= 40; subId++) socket.send(encodeMuxedFrame(0, {type: "Subscribe", subId, filterJson: new TextEncoder().encode(JSON.stringify({topic: "mesh"}))}));
      if (frame.type === "Event") {
        const event = JSON.parse(new TextDecoder().decode(frame.eventJson)) as {type?: string; error?: string};
        if (event.type === "error") resolve(event.error ?? "missing reason");
      }
    }));
  });
  try {
    expect(await refused).toBe("mesh unavailable");
    expect((await act("mesh.list", {})).ok).toBe(true);
    await expect(page.locator('.cl[data-view="mesh"] .cl-meshstate[data-open="true"]')).toHaveCount(0);
    console.log("MESH_PROOF saturated_subscriptions=mesh_unavailable separate_browser_view=ready");
  } finally { clearTimeout(deadline!); socket.terminate(); }
});
