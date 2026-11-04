/**
 * The Mesh view against the real server binary (issue #108, lane UI-2): the production build, the production
 * server, a real WebSocket. No test double.
 *
 * What the binary serves decides what is tested. The Mesh actions (`mesh.list` and the grant actions) are being
 * built on branch mesh-api; until the binary serves them, the honest thing to prove is the contract the canvas
 * keeps with a server that does not: it asks, is refused, offers no Mesh anywhere, subscribes to nothing it was
 * not shown (an unknown subscription closes the socket) and keeps working. When the binary does answer `mesh.list`,
 * the second block runs the whole flow against it; it is skipped (not passed) otherwise.
 *
 * `INFRATERNAL_BIN` is the server binary, built from a scratch merge of mesh-api; the merge is never committed.
 */
import { tracerEvidencePath } from "../test/evidence-path";
import { resolve } from "node:path";
import { expect, test, type Page } from "playwright/test";
import { WebSocket } from "ws";
import { WebSocketFrameDecoder, encodeMuxedFrame, type WireFrame } from "../../../packages/protocol/src/codec";
import { personName, startRealServer, type RealServer } from "./server";

test.describe.configure({ mode: "serial" });

let server: RealServer;
let page: Page;
const live = () => server.bridges.filter((b) => !b.closed);
const controls = () => server.bridges.flatMap((b) => b.control);

test.beforeAll(async ({ browser }) => {
  server = await startRealServer();
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
test.afterAll(async () => { await page?.context().close(); await server?.dispose(); });

/** True when the binary answers `mesh.list` for the signed-in owner (the Mesh API has landed in it). */
const meshServed = (): boolean => {
  const asked = controls().filter((c) => c.dir === "up" && c.type === "Call" && c.detail === "mesh.list").map((c) => c.callId);
  return controls().some((c) => c.dir === "down" && c.type === "Result" && c.detail === "ok" && asked.includes(c.callId));
};

test.describe("a server that does not serve the Mesh (yet)", () => {
  test("the canvas asks once, is refused, and offers no Mesh: no view, no palette row, no connector", async () => {
    test.skip(meshServed(), "this binary serves the Mesh API: the flow below runs instead");
    await expect.poll(() => controls().filter((c) => c.type === "Call" && c.detail === "mesh.list").length, { timeout: 15_000 }).toBeGreaterThanOrEqual(1);
    await expect.poll(() => controls().some((c) => c.dir === "down" && c.type === "Result" && c.detail === "refused")).toBe(true);
    await expect(page.locator('.cl[data-view="mesh"]')).toHaveCount(0);
    await expect(page.locator(".cl-port:not([hidden])")).toHaveCount(0);
    await page.keyboard.press("Control+Shift+K");
    await page.locator("#palette-input").fill("Go to Mesh");
    await expect(page.locator("#palette-results [role=option]").filter({ hasText: "Go to Mesh" })).toHaveCount(0);
    await page.keyboard.press("Escape");
  });

  test("it subscribes to nothing the server has not shown it serves, and the connection stays up", async () => {
    test.skip(meshServed(), "this binary serves the Mesh API");
    // An unknown subscription makes the server close the socket, so the only subscription is the recovery notice's.
    expect(controls().filter((c) => c.type === "Subscribe").map((c) => c.detail)).not.toContain("mesh");
    await page.waitForTimeout(1500);
    expect(live().length).toBeGreaterThan(0);
    await expect(page.locator("#terminal-host")).toHaveCount(1);
  });
});

/** Runs one action on a second socket of the signed-in account (the way a CLI or another tab would) and returns its answer. */
async function act(action: string, input: Record<string, unknown>): Promise<{ ok: boolean; body: Record<string, unknown> }> {
  const cookie = (await page.context().cookies()).map((c) => `${c.name}=${c.value}`).join("; ");
  const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
  const decoder = new WebSocketFrameDecoder();
  const answer = new Promise<{ ok: boolean; body: Record<string, unknown> }>((resolve, reject) => {
    socket.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (_s: number, f: WireFrame) => {
      if (f.type === "Hello") socket.send(encodeMuxedFrame(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "mesh-real-act" }));
      if (f.type === "Welcome") socket.send(encodeMuxedFrame(0, { type: "Call", callId: 1, actionId: action, inputJson: new TextEncoder().encode(JSON.stringify(input)) }));
      if (f.type === "Result") resolve({ ok: f.ok, body: JSON.parse(new TextDecoder().decode(f.json)) as Record<string, unknown> });
    }));
    socket.on("error", reject);
    setTimeout(() => reject(new Error("no answer")), 15_000);
  });
  try { return await answer; } finally { socket.terminate(); }
}

test.describe("a server that serves the Mesh", () => {
  test("the owner gets the Mesh view, empty at first, and hosts enrolled elsewhere appear live", async () => {
    test.skip(!meshServed(), "this binary does not serve the Mesh API yet (branch mesh-api, #108)");
    await expect(page.locator('.cl[data-view="mesh"]')).toBeVisible();
    expect(controls().filter((c) => c.type === "Subscribe").map((c) => c.detail)).toContain("mesh");
    await page.keyboard.press("Control+Shift+Digit2");
    await expect(page.locator(".cl-meshstate")).toContainText("No hosts in the mesh yet");
    for (const [i, name] of ["alpha", "bravo"].entries()) {
      const r = await act("mesh.node.enroll", { name, public_key: Array.from({ length: 32 }, (_, k) => (k + i + 1) % 255 + 1) });
      expect(r.ok).toBe(true);
    }
    await expect(page.locator('.cl[data-view="mesh"] .ui-window[data-window-id="n-alpha"]')).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('.cl[data-view="mesh"] .ui-window[data-window-id="n-bravo"]')).toBeVisible();
    await expect(page.locator(".cl-meshstate")).toHaveCount(0);
  });

  test("a grant made elsewhere draws an arrow named for it; today's server sends no access flags, so nothing is editable", async () => {
    test.skip(!meshServed(), "this binary does not serve the Mesh API yet");
    const nodes = ((await act("mesh.list", {})).body.nodes as Array<{ node: { id: number; host: string } }>).map((n) => n.node);
    const id = (h: string) => nodes.find((n) => n.host === h)!.id;
    const made = await act("mesh.grant.create", { name: "alpha-to-bravo", from: { Node: id("alpha") }, to: { Node: id("bravo") }, both_ways: false });
    expect(made.ok).toBe(true);
    const arrow = page.locator('.cl[data-view="mesh"] .cl-arrow[data-tip="alpha-to-bravo"]');
    await expect(arrow).toHaveCount(1, { timeout: 15_000 });
    expect(await page.locator(".cl-arrow-handle").count()).toBe(0); // least privilege until the server sends `access`
    await page.screenshot({ path: tracerEvidencePath("canvas-mesh", "real-server-ink-1440x900.png") });
  });

  test("a mesh bigger than one frame arrives in pages and shows every host", async () => {
    test.skip(!meshServed(), "this binary does not serve the Mesh API yet");
    test.setTimeout(120_000);
    // 450 hosts: a list of that size does not fit the 64 KiB a Mesh frame may be, so the server pages it.
    const cookie = (await page.context().cookies()).map((c) => `${c.name}=${c.value}`).join("; ");
    const socket = new WebSocket(server.backend.replace("http:", "ws:") + "/v1/ws", { headers: { Origin: server.origin, Cookie: cookie } });
    const decoder = new WebSocketFrameDecoder();
    const total = 450;
    let answered = 0, failed = 0;
    const enrol = (i: number): void => socket.send(encodeMuxedFrame(0, { type: "Call", callId: i + 1, actionId: "mesh.node.enroll", inputJson: new TextEncoder().encode(JSON.stringify({ name: `bulk-${String(i).padStart(4, "0")}`, public_key: Array.from({ length: 32 }, (_, k) => (k === 0 ? (i % 250) + 1 : k === 1 ? Math.floor(i / 250) + 1 : k + 1)) })) }));
    const finished = new Promise<void>((resolve, reject) => {
      socket.on("message", (data) => decoder.feed(new Uint8Array(Buffer.from(data as Buffer)), (_s: number, f: WireFrame) => {
        if (f.type === "Hello") socket.send(encodeMuxedFrame(0, { type: "Hello", version: 1, caps: 0n, clientInfo: "mesh-real-bulk" }));
        // One call at a time: a socket admits one running Mesh request and four queued, and refuses the rest.
        if (f.type === "Welcome") enrol(0);
        if (f.type === "Result") { answered++; if (!f.ok) failed++; if (answered === total) resolve(); else enrol(answered); }
      }));
      socket.on("error", reject);
      setTimeout(() => reject(new Error("bulk enrol timed out")), 100_000);
    });
    try { await finished; } finally { socket.terminate(); }
    expect(failed).toBe(0);
    await page.reload();
    await page.locator(".cl-viewport").waitFor();
    await expect(page.locator('.cl[data-view="mesh"] .cl-label-meta')).toContainText("452 hosts", { timeout: 30_000 });
  });
});
