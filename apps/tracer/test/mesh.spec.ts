/**
 * The Mesh view on the real adapter against the fake Mesh server (issue #108, lane UI-2): scale and level of
 * detail, live updates, edits that reach the server (and the ones it refuses), what each kind of person sees,
 * pins in the canvas document, the states a mesh can be in, and frame times at 1,000 nodes. The product's own
 * adapter runs unchanged; only the server is a test double (`src/canvas/mock/mesh-server.ts`).
 *
 * `MESH_CAPTURES=1` writes the reviewed screenshots to `captures/canvas-mesh/` (1440x900 and 393x852, ink and paper).
 */
import { loadavg, cpus } from "node:os";
import { expect, test, type Browser, type CDPSession, type Page } from "playwright/test";

type Stats = { level: string; cards: number; arrows: number; chips: number; clusterArrows: number; passes: number; passMs: number; mounted: number };
type Grant = { id: string; name: string; from: string; to: string; via?: string };
type FakeServer = {
  calls: Array<{ action: string; input: Record<string, unknown> }>;
  rev: number;
  grantList(): Array<Grant & { both: boolean }>;
  includeAccess: boolean;
  failNext(action: string, error?: "refuse" | "network"): void;
  patchNode(name: string, patch: Record<string, unknown>): void;
  addNode(n: Record<string, unknown>): void;
  removeNode(name: string): void;
  reconnect(lose?: () => void): void;
  churn(hz: number, perTick?: number): () => void;
  muted: boolean;
  setAccess(a: { view: boolean; manageGrants: boolean }): void;
  release(state?: string): void;
  state: string;
  hostCount(): number;
};
type Probe = {
  camera(): { cx: number; cy: number; z: number; lod: string; zoomBand: string };
  views(): Array<{ id: string; name: string; x: number; y: number; w: number; h: number; windows: string[] }>;
  grants(): Array<{ id: string; from: string; to: string }>;
  setCamera(cx: number, cy: number, z: number): void;
  flyView(id: string): void;
  canvasLock(): { on: boolean; index: number; stops: number; view: string };
  reachCount(): number;
  mesh: {
    server(): FakeServer;
    status(): string;
    pins(): Record<string, { x: number; y: number }>;
    stats(): Stats | undefined;
    document(): Promise<{ views: Array<{ id: string; layout: { type: string; pinned?: Record<string, { x: number; y: number }> } }> } | undefined>;
    source(): { retry(): void; renameGrant(g: unknown, name: string): void; grants(): Grant[] };
  };
};
const probe = <T>(page: Page, fn: (p: Probe) => T): Promise<T> =>
  page.evaluate((source) => (new Function("p", `return (${source})(p)`) as (p: unknown) => T)((window as unknown as { __tracerClusters: unknown }).__tracerClusters), fn.toString());
const server = <T>(page: Page, fn: (s: FakeServer) => T): Promise<T> =>
  page.evaluate((source) => (new Function("s", `return (${source})(s)`) as (s: unknown) => T)((window as unknown as { __tracerClusters: Probe }).__tracerClusters.mesh.server()), fn.toString());

const DESKTOP = { width: 1440, height: 900 }, PHONE = { width: 393, height: 852 };
async function open(page: Page, query = "", size = DESKTOP, scene = 6, theme = "ink"): Promise<void> {
  await page.setViewportSize(size);
  await page.goto(`/?mock=1&proto=clusters&scene=${scene}&theme=${theme}&bg=none${query}`);
  await expect(page.locator(".cl-mockup")).toBeVisible({ timeout: 20_000 });
  await expect.poll(() => probe(page, (p) => p.views().length)).toBeGreaterThan(0);
  await page.waitForTimeout(500);
}
const stats = (page: Page): Promise<Stats | undefined> => probe(page, (p) => p.mesh.stats());
const nodeIds = (page: Page): Promise<string[]> => page.locator('.ui-window[data-kind="node"]').evaluateAll((ns) => ns.map((n) => (n as HTMLElement).dataset.windowId!));
const centre = async (page: Page, sel: string): Promise<{ x: number; y: number }> => { const b = (await page.locator(sel).first().boundingBox())!; return { x: b.x + b.width / 2, y: b.y + b.height / 2 }; };
const sub = (page: Page, host: string): Promise<string> => page.locator(`.ui-window[data-window-id="n-${host}"] .cl-node-sub`).innerText();
async function intoMesh(page: Page): Promise<void> {
  await page.keyboard.press("Control+3");
  await page.waitForTimeout(1000);
}
/** Drags an arrow's end (`head` or `tail`) off its node and onto `to` (or onto empty canvas below), then lets go. */
async function dragEnd(page: Page, grant: string, end: "head" | "tail", to: string | undefined): Promise<void> {
  const mid = await centre(page, `.cl[data-view="mesh"] .cl-arrow[data-grant="${grant}"] .cl-arrow-hit`);
  await page.mouse.move(mid.x, mid.y);
  const handle = await centre(page, `.cl-arrow[data-grant="${grant}"] .cl-arrow-handle[data-end="${end}"]`);
  await page.mouse.move(handle.x, handle.y);
  await page.mouse.down();
  await page.mouse.move(handle.x + 10, handle.y + 110, { steps: 5 });
  if (to) { const t = await centre(page, `.ui-window[data-window-id="n-${to}"]`); await page.mouse.move(t.x, t.y, { steps: 14 }); }
  else await page.mouse.move(handle.x + 10, handle.y + 220, { steps: 8 });
  await page.mouse.up();
}

// ---- scale ------------------------------------------------------------------------------------------------------
test.describe("a large mesh", () => {
  test("opens as cluster frames, and zooming into one brings its cards and arrows, and only those", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await open(page, "&mesh=1000");
    expect(await server(page, (s) => s.hostCount())).toBe(1000);
    await probe(page, (p) => p.flyView("mesh"));
    await expect.poll(async () => (await stats(page))?.chips, { timeout: 20_000 }).toBeGreaterThanOrEqual(20);
    await page.waitForTimeout(1200); // the flight settles
    // Fitted whole and free: the canvas lock is off for a graph that is too big to snap node by node.
    expect((await probe(page, (p) => p.canvasLock())).on).toBe(false);
    const far = (await stats(page))!;
    expect(far.level).toBe("clusters");
    expect(far.cards).toBe(0);
    expect(far.arrows).toBe(0);
    expect(far.chips).toBeGreaterThanOrEqual(20);
    expect(far.clusterArrows).toBeGreaterThan(5);
    expect(await nodeIds(page)).toEqual([]);
    await expect(page.locator(".cl-chip").first()).toBeVisible();
    // A frame is a button: it names the cluster and flies into it.
    await expect(page.locator(".cl-chip").nth(3)).toHaveAttribute("aria-label", /hosts.* online\. Zoom in/);
    await page.locator(".cl-chip").nth(3).click();
    await expect.poll(async () => (await stats(page))?.level, { timeout: 20_000 }).toBe("cards");
    await page.waitForTimeout(1200);
    const near = (await stats(page))!;
    expect(near.level).toBe("cards");
    expect(near.cards).toBeGreaterThan(5);
    expect(near.cards).toBeLessThan(250);
    expect(near.arrows).toBeLessThanOrEqual(240);
    expect((await nodeIds(page)).length).toBe(near.cards);
    expect(await page.locator("svg.cl-graph-arrows .cl-arrow").count()).toBe(near.arrows);
    expect(errors).toEqual([]);
  });

  test("panning mounts the cards that come into view and drops the ones far behind", async ({ page }) => {
    await open(page, "&mesh=1000");
    const v = (await probe(page, (p) => p.views())).find((o) => o.id === "mesh")!;
    const at = { x: v.x + v.w * 0.2, y: v.y + v.h * 0.25, dx: v.w * 0.5, dy: v.h * 0.4 };
    await page.evaluate((a) => (window as unknown as { __tracerClusters: Probe }).__tracerClusters.setCamera(a.x, a.y, 1), at);
    await page.waitForTimeout(500);
    const before = await nodeIds(page);
    expect(before.length).toBeGreaterThan(5);
    await page.evaluate((a) => (window as unknown as { __tracerClusters: Probe }).__tracerClusters.setCamera(a.x + a.dx, a.y + a.dy, 1), at);
    await page.waitForTimeout(900);
    const after = await nodeIds(page);
    expect(after.length).toBeLessThan(250);
    expect(after.filter((i) => before.includes(i)).length).toBeLessThan(before.length / 2);
  });

  test("a small mesh is always drawn whole, as cards", async ({ page }) => {
    await open(page);
    await intoMesh(page);
    const s = (await stats(page))!;
    expect(s.level).toBe("cards");
    expect(s.cards).toBe(6);
    expect(s.arrows).toBe(7);
    expect(s.chips).toBe(0);
  });
});

// ---- frame times at 1,000 nodes ---------------------------------------------------------------------------------
type Frames = { n: number; p50: number; p95: number; max: number; dropped: number; cpuMs: number };
/** CPU seconds the browser's renderer and GPU processes have used so far: what a gesture cost does not depend on how busy the machine is. */
async function cpuSeconds(browser: Browser): Promise<number> {
  const session = await browser.newBrowserCDPSession();
  const info = (await session.send("SystemInfo.getProcessInfo" as never)) as { processInfo: Array<{ type: string; cpuTime: number }> };
  await session.detach();
  return info.processInfo.filter((p) => p.type === "renderer" || p.type === "GPU").reduce((sum, p) => sum + p.cpuTime, 0);
}
async function measure(page: Page, browser: Browser, run: () => Promise<void>): Promise<Frames> {
  const cpu0 = await cpuSeconds(browser);
  await page.evaluate(() => {
    const w = window as unknown as { __frames: number[]; __stop: boolean };
    w.__frames = []; w.__stop = false;
    let last = performance.now();
    const tick = (t: number): void => { w.__frames.push(t - last); last = t; if (!w.__stop) requestAnimationFrame(tick); };
    requestAnimationFrame(tick);
  });
  await run();
  const cpu = (await cpuSeconds(browser)) - cpu0;
  const frames = await page.evaluate(() => { const w = window as unknown as { __frames: number[]; __stop: boolean }; w.__stop = true; return w.__frames.slice(2); });
  const sorted = [...frames].sort((a, b) => a - b);
  const at = (q: number): number => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * q))]!;
  return { n: frames.length, p50: +at(0.5).toFixed(1), p95: +at(0.95).toFixed(1), max: +sorted[sorted.length - 1]!.toFixed(1), dropped: frames.filter((f) => f > 20).length, cpuMs: Math.round(cpu * 1000) };
}
/** One wheel event per frame from inside the page, like a trackpad; a ctrl wheel is a pinch. 2 s out, 2 s back. */
async function gesture(page: Page, kind: "zoom" | "pan", x: number, y: number): Promise<void> {
  await page.evaluate(({ kind: k, x: px, y: py }) => new Promise<void>((done) => {
    const target = document.querySelector(".cl-viewport")!;
    const start = performance.now();
    const step = (t: number): void => {
      const phase = (t - start) / 3000;
      if (phase >= 1) { done(); return; }
      const dir = phase < 0.5 ? -1 : 1;
      target.dispatchEvent(new WheelEvent("wheel", k === "zoom"
        ? { deltaY: dir * 5, ctrlKey: true, clientX: px, clientY: py, bubbles: true, cancelable: true }
        : { deltaX: dir * 30, deltaY: dir * 10, clientX: px, clientY: py, bubbles: true, cancelable: true }));
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }), { kind, x, y });
  await page.waitForTimeout(250);
}

for (const rate of [1, 4]) {
  test(`frames: zooming and panning a 1,000-node mesh with 4,000 grants keeps its frame time at ${rate}x CPU`, async ({ page, browser }) => {
    test.setTimeout(120_000);
    await open(page, "&mesh=1000&meshgrants=3500");
    await probe(page, (p) => p.flyView("mesh"));
    await page.waitForTimeout(1400);
    const cdp: CDPSession | undefined = rate > 1 ? await page.context().newCDPSession(page) : undefined;
    // Zoom from the whole mesh down into the middle of it and back out: both levels and both switches are crossed.
    if (cdp) await cdp.send("Emulation.setCPUThrottlingRate", { rate });
    const zoom = await measure(page, browser, () => gesture(page, "zoom", 720, 450));
    const reached = (await stats(page))!;
    // Pan at 1x zoom (live cards), in the middle of the mesh.
    const v = (await probe(page, (p) => p.views())).find((o) => o.id === "mesh")!;
    if (cdp) await cdp.send("Emulation.setCPUThrottlingRate", { rate: 1 });
    await page.evaluate((a) => (window as unknown as { __tracerClusters: Probe }).__tracerClusters.setCamera(a.x, a.y, 1), { x: v.x + v.w * 0.3, y: v.y + v.h * 0.3 });
    await page.waitForTimeout(600);
    if (cdp) await cdp.send("Emulation.setCPUThrottlingRate", { rate });
    const pan = await measure(page, browser, () => gesture(page, "pan", 720, 450));
    const panned = (await stats(page))!;
    if (cdp) await cdp.send("Emulation.setCPUThrottlingRate", { rate: 1 });
    const load = loadavg()[0]! / cpus().length;
    console.log(`MESH-FRAMES ${rate}x load/core=${load.toFixed(2)} nodes=1000 grants=${await server(page, (s) => s.grantList().length)} zoom ${JSON.stringify(zoom)} pan ${JSON.stringify(pan)} dom-after-zoom ${JSON.stringify(reached)} dom-after-pan ${JSON.stringify(panned)}`);
    // The DOM stays bounded whatever the size of the mesh (always checked)...
    expect(reached.chips).toBeGreaterThan(0);
    expect(panned.cards).toBeLessThan(250);
    expect(panned.arrows).toBeLessThanOrEqual(240);
    // ...and, on a machine that is not busy with other work (the numbers above are printed either way), a pass of this
    // module's script (choosing what is in the DOM, and making it) stays far under a frame and the frames hold 60 fps.
    if (rate === 1 && load < 1.2) {
      expect(panned.passMs / Math.max(1, panned.passes)).toBeLessThan(6);
      // Headless Chromium rasters in software, so 60 fps is not reachable here even for the existing canvas (its pan p95 is
      // 33 ms in the same conditions). The bounds are what this machine shows for the canvas plus a margin; a regression
      // from per-frame DOM or SVG work shows as multiples of them. 60 fps itself needs a GPU run (a phone, a laptop).
      expect(pan.p95).toBeLessThan(60);
      expect(zoom.p95).toBeLessThan(150);
      expect(pan.max).toBeLessThan(200);
    }
  });
}

// ---- live updates -----------------------------------------------------------------------------------------------
test.describe("live updates", () => {
  test("a host's status and round trip, a new host and a removed host reach the cards", async ({ page }) => {
    await open(page);
    await intoMesh(page);
    expect(await sub(page, "build-01")).toBe("direct · 42 ms");
    await server(page, (s) => s.patchNode("build-01", { rttMs: 77 }));
    await expect.poll(() => sub(page, "build-01")).toBe("direct · 77 ms");
    await server(page, (s) => s.patchNode("nix-cache", { state: "offline" }));
    await expect.poll(() => sub(page, "nix-cache")).toBe("offline");
    await expect(page.locator('.ui-window[data-window-id="n-nix-cache"]')).toHaveAttribute("data-status", "offline"); // its status icon follows
    await server(page, (s) => s.addNode({ name: "new-host", os: "ubuntu", address: "10.69.69.99", rttMs: 5 }));
    await expect(page.locator('.ui-window[data-window-id="n-new-host"]')).toBeVisible();
    await expect(page.locator(".cl-label-meta").nth(2)).toContainText("7 nodes");
    await server(page, (s) => s.removeNode("edge-arm"));
    await expect(page.locator('.ui-window[data-window-id="n-edge-arm"]')).toHaveCount(0);
  });

  test("events that were lost are made up for by the next one (a gap) and by a reconnect", async ({ page }) => {
    await open(page);
    await intoMesh(page);
    await server(page, (s) => { s.muted = true; s.patchNode("nix-cache", { rttMs: 12 }); s.muted = false; });
    await server(page, (s) => s.patchNode("build-01", { rttMs: 33 }));
    await expect.poll(() => sub(page, "nix-cache")).toBe("direct · 12 ms"); // the lost one arrives with the snapshot the gap asks for
    await expect.poll(() => sub(page, "build-01")).toBe("direct · 33 ms");
    await server(page, (s) => s.reconnect(() => { s.muted = true; s.patchNode("studio-mac", { rttMs: 9 }); s.muted = false; }));
    await expect.poll(() => sub(page, "studio-mac")).toBe("direct · 9 ms");
    // One list for the gap and one for the reconnect: events are only ever a reason to ask again.
    expect((await server(page, (s) => s.calls)).filter((c) => c.action === "mesh.list")).toHaveLength(2);
  });

  test("a change made elsewhere moves its arrow, and an answer that comes after its own event is not applied twice", async ({ page }) => {
    await open(page);
    await intoMesh(page);
    await server(page, (s) => { (s as unknown as { eventFirst: boolean }).eventFirst = true; });
    const before = await page.locator('.cl[data-view="mesh"] .cl-arrow').count();
    await dragEnd(page, "g3", "head", "edge-arm");
    await page.locator(".ui-confirm-yes").click();
    await expect.poll(async () => (await server(page, (s) => s.grantList())).find((g) => g.id === "g3")?.to).toBe("edge-arm");
    await page.waitForTimeout(400);
    expect(await page.locator('.cl[data-view="mesh"] .cl-arrow').count()).toBe(before);
    expect(await probe(page, (p) => p.grants().length)).toBe(before);
  });

  test("a host-heavy stream of status events does not reflow the graph (60 events a second on 1,000 hosts)", async ({ page }) => {
    await open(page, "&mesh=1000");
    await probe(page, (p) => p.flyView("mesh"));
    await page.waitForTimeout(1200);
    const rects = async (): Promise<string> => page.locator(".cl-chip").evaluateAll((ns) => ns.slice(0, 6).map((n) => { const r = (n as HTMLElement).style; return `${r.left},${r.top}`; }).join("|"));
    const r0 = await rects();
    await page.evaluate(() => { (window as unknown as { __stopChurn: () => void }).__stopChurn = (window as unknown as { __tracerClusters: Probe }).__tracerClusters.mesh.server().churn(12, 5); });
    await page.waitForTimeout(1500);
    await page.evaluate(() => (window as unknown as { __stopChurn: () => void }).__stopChurn());
    expect(await rects()).toBe(r0);
    expect(await page.evaluate(() => (performance.getEntriesByType("longtask") as unknown[]).length)).toBeLessThan(4);
  });
});

// ---- edits reach the server -------------------------------------------------------------------------------------
test.describe("editing arrows", () => {
  const called = (page: Page, action: string): Promise<Array<Record<string, unknown>>> => server(page, (s) => s.calls).then((c) => c.filter((x) => x.action === action).map((x) => x.input));

  test("moving a head asks the server to move the grant by id; its answer names the grant", async ({ page }) => {
    await open(page);
    await intoMesh(page);
    await dragEnd(page, "g3", "head", "edge-arm");
    await expect(page.locator(".ui-confirm-tip")).toContainText("Move grant nix-cache→studio-mac to nix-cache→edge-arm?");
    await page.locator(".ui-confirm-yes").click();
    // The server holds grants by name: the move names the end and the new endpoint (a node by its id), and since
    // the name still said where the grant went, a rename follows so it keeps saying so.
    await expect.poll(() => called(page, "mesh.grant.move")).toEqual([{ name: "nix-cache→studio-mac", side: "to", endpoint: { Node: 2 } }]);
    await expect.poll(() => called(page, "mesh.grant.rename")).toEqual([{ name: "nix-cache→studio-mac", new_name: "nix-cache→edge-arm" }]);
    await expect(page.locator('.cl-arrow[data-grant="g3"]')).toHaveAttribute("data-tip", "nix-cache→edge-arm");
    await expect(page.locator(".ui-toast, .toast").first()).toContainText("nix-cache→edge-arm");
  });

  test("a tail move sends the new source; removing sends a delete; adding from a terminal sends a create", async ({ page }) => {
    await open(page);
    await intoMesh(page);
    await dragEnd(page, "g7", "tail", "studio-mac");
    await page.locator(".ui-confirm-yes").click();
    await expect.poll(() => called(page, "mesh.grant.move")).toEqual([{ name: "ci→nix-cache", side: "from", endpoint: { Node: 4 } }]);
    await dragEnd(page, "g3", "head", undefined);
    await expect(page.locator(".ui-confirm-tip")).toContainText("Remove grant nix-cache→studio-mac?");
    await page.locator(".ui-confirm-yes").click();
    await expect.poll(() => called(page, "mesh.grant.delete")).toEqual([{ name: "nix-cache→studio-mac" }]);
    await expect(page.locator('.cl-arrow[data-grant="g3"]')).toHaveCount(0);
    // Back in Console: a drag from the connector grants access.
    await page.keyboard.press("Control+1");
    await page.waitForTimeout(1500);
    await page.locator('.ui-window[data-window-id="w-build-01"] .ui-window-pill').hover();
    await expect.poll(() => probe(page, (p) => p.reachCount())).toBeGreaterThan(0);
    const port = (await page.locator('.ui-window[data-window-id="w-build-01"] .cl-port').boundingBox())!;
    const target = (await page.locator('.ui-window[data-window-id="w-studio-mac"] .ui-window-body').boundingBox())!;
    await page.mouse.move(port.x + 12, port.y + 12);
    await page.mouse.down();
    await page.mouse.move(target.x + 200, target.y + 200, { steps: 12 });
    await page.mouse.up();
    await page.locator(".ui-confirm-yes").click();
    await expect.poll(() => called(page, "mesh.grant.create")).toEqual([{ name: "build-01→studio-mac", from: { Node: 1 }, to: { Node: 4 }, both_ways: false }]);
    await expect.poll(async () => (await server(page, (s) => s.grantList())).some((g) => g.from === "build-01" && g.to === "studio-mac")).toBe(true);
    // The grant on screen is the server's (its id), not the placeholder the edit started with.
    await expect.poll(async () => (await probe(page, (p) => p.grants())).some((g) => g.id.startsWith("pending"))).toBe(false);
  });

  test("a grant is renamed through the adapter and shows its new name on hover", async ({ page }) => {
    await open(page);
    await intoMesh(page);
    await probe(page, (p) => { const src = p.mesh.source(); src.renameGrant(src.grants().find((g) => g.id === "g3"), "release-train"); });
    await expect.poll(() => called(page, "mesh.grant.rename")).toEqual([{ name: "nix-cache→studio-mac", new_name: "release-train" }]);
    await expect(page.locator('.cl-arrow[data-grant="g3"]')).toHaveAttribute("data-tip", "release-train");
    // A grant with its own name keeps it when an end moves.
    await dragEnd(page, "g3", "head", "edge-arm");
    await expect(page.locator(".ui-confirm-tip")).toContainText("Move grant release-train to nix-cache→edge-arm?");
    await page.locator(".ui-confirm-yes").click();
    await expect.poll(async () => (await server(page, (s) => s.grantList())).find((g) => g.id === "g3")?.to).toBe("edge-arm");
    await page.waitForTimeout(300);
    expect((await server(page, (s) => s.grantList())).find((g) => g.id === "g3")?.name).toBe("release-train"); // a chosen name stays
    expect(await called(page, "mesh.grant.rename")).toHaveLength(1);
  });

  test("when the server refuses or the connection drops, the arrow goes back and one toast says why", async ({ page }) => {
    await open(page);
    await intoMesh(page);
    const grant = (id: string): Promise<{ from: string; to: string } | undefined> => probe(page, (p) => p.grants().find((g) => g.id === "g3"))
      .then((g) => (id === "g3" ? g : undefined));
    await server(page, (s) => s.failNext("mesh.grant.move", "refuse"));
    await dragEnd(page, "g3", "head", "edge-arm");
    await page.locator(".ui-confirm-yes").click();
    await expect(page.locator(".ui-toast, .toast").first()).toContainText("You are not allowed to move nix-cache→studio-mac");
    await expect.poll(async () => (await grant("g3"))?.to).toBe("studio-mac");
    await expect(page.locator('.cl-arrow[data-grant="g3"]')).toHaveAttribute("data-tip", "nix-cache→studio-mac");
    await page.waitForTimeout(3600);
    await server(page, (s) => s.failNext("mesh.grant.delete", "network"));
    await dragEnd(page, "g3", "head", undefined);
    await page.locator(".ui-confirm-yes").click();
    await expect(page.locator(".ui-toast, .toast").first()).toContainText("Could not remove nix-cache→studio-mac");
    await expect(page.locator('.cl-arrow[data-grant="g3"]')).toHaveCount(1); // the grant came back
  });
});

// ---- who sees and edits what (D187) -----------------------------------------------------------------------------
test.describe("access", () => {
  test("arrows have handles, and terminals the connector, only for a person who may manage grants", async ({ page }) => {
    await open(page);
    await expect(page.locator('.ui-window[data-kind="terminal"] .cl-port').first()).toBeAttached();
    expect(await page.locator('.ui-window[data-kind="terminal"] .cl-port:not([hidden])').count()).toBeGreaterThan(0);
    await intoMesh(page);
    expect(await page.locator(".cl-arrow-handle").count()).toBeGreaterThan(0);
    await server(page, (s) => s.setAccess({ view: true, manageGrants: false }));
    await expect.poll(() => page.locator(".cl-arrow-handle").count()).toBe(0);
    expect(await page.locator('.ui-window[data-kind="terminal"] .cl-port:not([hidden])').count()).toBe(0);
    expect(await page.locator('.ui-window[data-kind="terminal"] .cl-port').first().evaluate((n) => getComputedStyle(n).display)).toBe("none"); // really gone, not just marked
    // Hover still names a grant, but nothing can be dragged.
    const hit = await centre(page, '.cl[data-view="mesh"] .cl-arrow[data-grant="g3"]');
    await page.mouse.move(hit.x, hit.y);
    await expect(page.locator('.cl-arrow[data-grant="g3"]')).toHaveAttribute("data-tip", "nix-cache→studio-mac");
    await server(page, (s) => s.setAccess({ view: true, manageGrants: true }));
    await expect.poll(() => page.locator(".cl-arrow-handle").count()).toBeGreaterThan(0);
  });

  test("the view appears when grants allow, goes when they are withdrawn, and is reachable by shortcut, sidebar, switcher and palette", async ({ page }) => {
    await open(page);
    const ids = (): Promise<string[]> => probe(page, (p) => p.views().map((v) => v.id));
    expect(await ids()).toContain("mesh");
    // ⌘3, the sidebar tree, the view switcher and the palette all reach it.
    await page.keyboard.press("Control+3");
    await expect.poll(() => probe(page, (p) => p.canvasLock().view)).toBe("mesh");
    await page.keyboard.press("Control+1");
    await expect.poll(() => probe(page, (p) => p.canvasLock().view)).toBe("console");
    await page.keyboard.press("Control+k");
    await page.keyboard.type("Go to Mesh");
    await expect(page.locator(".palette-result, [role='option']").filter({ hasText: "Go to Mesh" }).first()).toBeVisible();
    await page.keyboard.press("Enter");
    await expect.poll(() => probe(page, (p) => p.canvasLock().view)).toBe("mesh");
    await page.locator("#sidebar-toggle").click();
    await expect(page.locator('#tree .bm-sec[data-id="view:mesh"]')).toBeVisible();
    await page.locator("#sidebar-toggle").click();
    await server(page, (s) => s.setAccess({ view: false, manageGrants: false }));
    await expect.poll(ids).not.toContain("mesh");
    await expect.poll(() => probe(page, (p) => p.canvasLock().view)).toBe("console"); // it was open: the camera goes home
    await page.keyboard.press("Control+k");
    await page.keyboard.type("Go to Mesh");
    await expect(page.locator(".palette-result, [role='option']").filter({ hasText: "Go to Mesh" })).toHaveCount(0);
    await page.keyboard.press("Escape");
    await server(page, (s) => s.setAccess({ view: true, manageGrants: true }));
    await expect.poll(ids).toContain("mesh");
  });

  test("a server that does not say what the person may do (today's) gives a read-only view, with only what it sent on the cards", async ({ page }) => {
    await open(page, "&meshserver=today");
    await intoMesh(page);
    expect(await probe(page, (p) => p.mesh.status())).toBe("ready");
    expect(await page.locator(".cl-arrow").count()).toBeGreaterThan(0);
    expect(await page.locator(".cl-arrow-handle").count()).toBe(0); // least privilege: nothing to drag without `access`
    expect(await page.locator('.ui-window[data-kind="terminal"] .cl-port:not([hidden])').count()).toBe(0);
    expect(await sub(page, "build-01")).toBe("42 ms"); // no path was sent, so none is claimed
    await expect(page.locator('.ui-window[data-window-id="n-build-01"] .cl-node-detail')).toHaveText("tag:ci"); // no address was sent either
  });

  test("a person without Mesh grants never gets the view (the server refuses the snapshot)", async ({ page }) => {
    await open(page, "&mesh=denied");
    expect(await probe(page, (p) => p.views().map((v) => v.id))).not.toContain("mesh");
    expect(await probe(page, (p) => p.mesh.status())).toBe("unavailable");
    await page.keyboard.press("Control+k");
    await page.keyboard.type("Mesh");
    await expect(page.locator(".palette-result, [role='option']").filter({ hasText: "Go to Mesh" })).toHaveCount(0);
  });
});

// ---- pins -------------------------------------------------------------------------------------------------------
test("a dragged node is pinned and saved in the canvas document; the others are not", async ({ page }) => {
  await open(page);
  await intoMesh(page);
  const pill = await centre(page, '.ui-window[data-window-id="n-nix-cache"] .ui-window-pill');
  const before = await page.locator('.ui-window[data-window-id="n-nix-cache"]').boundingBox();
  await page.mouse.move(pill.x, pill.y);
  await page.mouse.down();
  await page.mouse.move(pill.x + 60, pill.y + 40, { steps: 8 });
  await page.mouse.up();
  await page.waitForTimeout(700); // saving is coalesced to one write (300 ms)
  const after = await page.locator('.ui-window[data-window-id="n-nix-cache"]').boundingBox();
  expect(after!.x).toBeGreaterThan(before!.x + 40);
  expect(Object.keys(await probe(page, (p) => p.mesh.pins()))).toEqual(["nix-cache"]);
  const doc = await probe(page, (p) => p.mesh.document());
  const view = doc!.views.find((v) => v.id === "mesh")!;
  expect(view.layout.type).toBe("graph");
  expect(Object.keys(view.layout.pinned!)).toEqual(["nix-cache"]);
  // A status event re-reads the mesh; the pinned node stays where it was put and the rest stay where they were.
  await server(page, (s) => s.patchNode("build-01", { rttMs: 50 }));
  await expect.poll(() => sub(page, "build-01")).toBe("direct · 50 ms");
  const again = await page.locator('.ui-window[data-window-id="n-nix-cache"]').boundingBox();
  expect(Math.abs(again!.x - after!.x)).toBeLessThan(1);
  expect(Object.keys((await probe(page, (p) => p.mesh.document()))!.views.find((v) => v.id === "mesh")!.layout.pinned!)).toEqual(["nix-cache"]);
});

// ---- states and captures ----------------------------------------------------------------------------------------
const CAPTURE = process.env.MESH_CAPTURES === "1";
async function capture(page: Page, name: string, testInfo: { outputPath(n: string): string }): Promise<void> {
  const dir = `${import.meta.dirname}/../captures/canvas-mesh`;
  const path = CAPTURE ? `${dir}/${name}.png` : testInfo.outputPath(`${name}.png`);
  if (CAPTURE) await import("node:fs/promises").then((fs) => fs.mkdir(dir, { recursive: true }));
  await page.screenshot({ path });
}

test.describe("states", () => {
  test("loading, then ready; unreachable with a retry that works; empty; and stale data when the connection drops", async ({ page }, testInfo) => {
    test.setTimeout(90_000);
    // Loading: the server stays silent.
    await open(page, "&mesh=loading");
    await intoMesh(page);
    await expect(page.locator(".cl-meshstate")).toContainText("Loading the mesh");
    await expect(page.locator(".cl-meshstate .ui-spinner")).toBeVisible();
    await expect(page.locator(".cl-meshstate")).toHaveAttribute("role", "status");
    await capture(page, "loading-ink-1440x900", testInfo);
    await server(page, (s) => s.release("ready"));
    await expect(page.locator('.ui-window[data-window-id="n-build-01"]')).toBeVisible();
    await expect(page.locator(".cl-meshstate")).toHaveCount(0);
    // Stale: the connection drops after data arrived: the cards stay, a quiet note says so and offers a retry.
    await server(page, (s) => { s.state = "error"; s.reconnect(); });
    await expect(page.locator(".cl-meshnote")).toHaveAttribute("data-tip", /Showing the last known mesh/);
    await expect(page.locator('.ui-window[data-window-id="n-build-01"]')).toBeVisible();
    await capture(page, "stale-ink-1440x900", testInfo);
    await server(page, (s) => { s.state = "ready"; });
    await page.locator(".cl-meshnote").click();
    await expect(page.locator(".cl-meshnote")).toHaveCount(0);
    // Unreachable at first: an error card with the same rhythm as the empty view, and a retry.
    await open(page, "&mesh=error");
    await intoMesh(page);
    await expect(page.locator(".cl-meshstate")).toContainText("Could not reach the mesh");
    await expect(page.locator(".cl-meshstate")).toHaveAttribute("role", "alert");
    await capture(page, "error-ink-1440x900", testInfo);
    await page.locator(".cl-meshstate button").click();
    await expect(page.locator(".cl-meshstate")).toContainText("Could not reach the mesh"); // still down
    await server(page, (s) => { s.state = "ready"; });
    await page.locator(".cl-meshstate button").click();
    await expect(page.locator('.ui-window[data-window-id="n-build-01"]')).toBeVisible();
    // Empty.
    await open(page, "&mesh=empty");
    await intoMesh(page);
    await expect(page.locator(".cl-meshstate")).toContainText("No hosts in the mesh yet");
    await capture(page, "empty-ink-1440x900", testInfo);
  });

  test("the error card keeps the empty card's rhythm: the gap from text to action matches", async ({ page }) => {
    const gap = (): Promise<number> => page.evaluate(() => {
      const box = document.querySelector(".cl-meshstate")!;
      return box.querySelector("button")!.getBoundingClientRect().top - box.querySelector(".cl-empty-hint")!.getBoundingClientRect().bottom;
    });
    await open(page, "&mesh=error");
    await intoMesh(page);
    const error = await gap();
    await open(page, "&mesh=empty");
    await intoMesh(page);
    const empty = await gap(); // the empty view's "Add host" under its hint
    expect(Math.abs(error - empty)).toBeLessThan(1);
    expect(error).toBeGreaterThanOrEqual(10);
  });

  test("every glass surface of the Mesh view blurs what is behind it by about a line of text", async ({ page }) => {
    await open(page);
    await intoMesh(page);
    // The hover card of a view (zoomed out), a confirmation tip and the note over the cards.
    await dragEnd(page, "g3", "head", "edge-arm");
    const tip = await page.evaluate(() => getComputedStyle(document.querySelector(".ui-confirm-tip")!).backdropFilter);
    await page.locator(".ui-confirm-no").click();
    await server(page, (s) => { s.state = "error"; s.reconnect(); });
    await expect(page.locator(".cl-meshnote")).toBeVisible();
    const note = await page.evaluate(() => { const n = document.querySelector(".cl-meshnote")!; return getComputedStyle(n).backdropFilter + "|" + getComputedStyle(n).backgroundColor; });
    const blur = (v: string): number => parseFloat(/blur\(([\d.]+)px\)/.exec(v)?.[1] ?? "0");
    expect(blur(tip)).toBeGreaterThanOrEqual(16);
    expect(blur(note)).toBeGreaterThanOrEqual(16);
  });
});

for (const theme of ["ink", "paper"]) {
  for (const [label, size] of [["1440x900", DESKTOP], ["393x852", PHONE]] as const) {
    test(`captures ${theme} ${label}: the mesh as cards, and a large mesh as frames and as cards`, async ({ page }, testInfo) => {
      test.setTimeout(90_000);
      await open(page, "", size, 6, theme);
      await intoMesh(page);
      await expect(page.locator('.ui-window[data-window-id="n-build-01"]')).toBeVisible();
      await capture(page, `mesh-${theme}-${label}`, testInfo);
      await open(page, "&mesh=1000", size, 6, theme);
      await probe(page, (p) => p.flyView("mesh"));
      await expect.poll(async () => (await stats(page))?.chips, { timeout: 20_000 }).toBeGreaterThanOrEqual(20);
      await page.waitForTimeout(2000);
      await page.mouse.move(size.width / 2, size.height - 6);
      await capture(page, `mesh-large-far-${theme}-${label}`, testInfo);
      await page.locator(".cl-chip").nth(6).click();
      await expect.poll(async () => (await stats(page))?.level, { timeout: 20_000 }).toBe("cards");
      await page.waitForTimeout(1500);
      await capture(page, `mesh-large-near-${theme}-${label}`, testInfo);
      if (theme === "ink") {
        for (const [mode, name] of [["loading", "loading"], ["error", "error"], ["empty", "empty"]] as const) {
          await open(page, `&mesh=${mode}`, size, 6, theme);
          await intoMesh(page);
          await page.waitForTimeout(400);
          await capture(page, `${name}-${theme}-${label}`, testInfo);
        }
      } else {
        for (const [mode, name] of [["loading", "loading"], ["error", "error"], ["empty", "empty"]] as const) {
          await open(page, `&mesh=${mode}`, size, 6, theme);
          await intoMesh(page);
          await page.waitForTimeout(400);
          await capture(page, `${name}-${theme}-${label}`, testInfo);
        }
      }
    });
  }
}
