/**
 * The mockup: the canvas on the test double, with the scaffolding the review rounds use. Reached only through
 * `?mock=1&proto=clusters` and left out of the production bundle (build.ts).
 *
 * What lives here and nowhere else: the scene stepper and the "Mockup:" palette entries, the role switcher
 * (viewer, operator, new user, a second person), the "continue from another device" chip, the fake hosts, grants,
 * containers and devices, the logs ticker, the prompt seeding of the one live terminal, and the
 * `window.__tracerClusters` probe the specs drive. The canvas itself is the product code in `create.ts`; this file
 * only gives it mock adapters and calls its public operations.
 */
import { teachOnce } from "../../hints";
import type { WinRec } from "../context";
import { isMacPlatform, shortcutLabel } from "../../../../../packages/ui/src/platform";
import { PALETTE_KEYS } from "../../../../../packages/ui/src/shortcuts";
import type { CoreScreen, PaletteEntry } from "../../core-screen";
import { createCanvas, type CanvasController } from "../create";
import { boxOf, type Metrics } from "../layout/geometry";
import { reconcile } from "../model/reconcile";
import { MemoryCanvasStore } from "../model/store";
import type { CanvasDocument } from "../model/schema";
import type { ViewId } from "../model/types";
import { el } from "../dom";
import { CONTAINERS, LOG_BACKLOG, buildViews, logLine, type Role } from "./data";
import { offerMeshView } from "../mesh/offer";
import { DEFAULT_SESSION, createMockInventory } from "./inventory";
import { createAddHost } from "../addhost";
import { createAuthorityControl } from "../addhost/authority-unlock";
import { mockInboxItems } from "./inbox-items";
import { inboxFor } from "../inbox-host";
import { createOverlayFlowHost } from "../addhost/flow-host";
import { createWindowFlowHost } from "../addhost/window-host";
import type { EnrolledHost } from "../addhost/service";
import { createMockProvisioning } from "./addhost-service";
import { attachSetup, warmSetup } from "../addhost/setup-attach";
import { createSetupDemo, failStageFrom, runAutopilot } from "./addhost-setup-demo";
import { createMockMesh } from "./mesh";
import { createMockSessions } from "./sessions";
import { onDemand } from "../../on-demand";
import { SESSION_SCENES } from "./session-scene-list";
import type { SessionScenes } from "./session-scenes.on-demand";
import { createMockSettings } from "./settings";
import { createMockSharing } from "./shares";
import { createMockWorld } from "./world";
import { mountTransparencyCompare } from "./transparency";
import { createStartupDemo } from "./startup-demo";

const CLOSE = '<path d="m7 7 10 10M17 7 7 17"/>';

export interface MockupOptions { scene?: number; role?: Role }
export interface MockupController { dispose(): void }

interface Scene { name: string; hint: string; enter(): void }

export async function mountMockup(core: CoreScreen, options: MockupOptions = {}): Promise<MockupController> {
  const stage = core.stage;
  const world = await createMockWorld(options.role ?? "operator", Boolean(options.role));
  const inventory = await createMockInventory(world);
  const sessions = createMockSessions(core, world, inventory);
  const mesh = createMockMesh(world);
  const events = new AbortController();
  const signal = events.signal;

  // The add-host wizard runs on the real adapter against the test double. A host that finishes enrolling gets a
  // shell window in Console, which is also how the sidebar inventory learns of it (the tree lists windows).
  const query = new URLSearchParams(location.search);
  // `addhost-demo=pill` (#189, D255): every host added in this tab follows a script that opens its shell at once and
  // finishes setting up in the machine pill; `fail=install|join|start|ready` makes that stage fail the first time.
  const setupDemo = query.get("addhost-demo") === "pill" ? createSetupDemo(failStageFrom(query.get("fail")), Math.max(1, Number(query.get("slow")) || 1)) : undefined;
  // `startup-demo=1` (#251, D315): the "switch to the Infraternal Multiplexer?" question on a live terminal window.
  const startupDemo = query.get("startup-demo") === "1" ? createStartupDemo(core, query) : undefined;
  const base = createMockProvisioning({ savedKey: query.get("savedkey") === "1", authority: query.get("ca") ?? "ready" });
  const provisioning = setupDemo ? setupDemo.wrap(base) : base;
  // The lock on host connections: administrators (the operator role) can unlock it, anyone else only sees the state.
  const authority = createAuthorityControl(core, { service: async () => provisioning, canUnlock: () => world.role === "operator" });
  // `?inbox=3` adds two more kinds of waiting item, to see the card with several lines (test double only).
  if (new URLSearchParams(location.search).get("inbox") === "3") inboxFor(core).set("mock-extra", mockInboxItems());
  const addHost = createAddHost(core, {
    host: createWindowFlowHost(() => canvas.cx, createOverlayFlowHost(core.stage)),
    service: provisioning,
    sink: {
      enrolled: (hosts, status) => enrol(hosts, status),
      setupInPill: true,
      // The test double names an existing host by UUID; the mock world knows hosts by name.
      openHost: (id) => canvas.cx.win.open(MOCK_HOST_BY_ID[id] ?? id),
    },
  });
  const MOCK_HOST_BY_ID: Record<string, string> = { "6f1d0a52-7c3e-4b8a-9d21-0a5e4c7b1f30": "build-01" };
  function openAddHost(): void { warmSetup(); addHost.open(); }
  function enrol(hosts: EnrolledHost[], status?: Element): void {
    for (const host of hosts) {
      if (!world.screens.has(host.name)) world.screens.set(host.name, { os: host.os, user: host.user ?? "kayg", screen: [`${host.user ?? "kayg"}@${host.name}:~$ `] });
      // Production lists sessions from inventory, including newly enrolled hosts.
      sessions.enroll(host.name);
      if (!inventory.list(host.name).length) inventory.create?.(host.name);
      const rec = canvas.cx.win.open(host.name);
      // The wizard's glyph is read now (its box is the flight's start); the pill's code is already loaded.
      // Without the demo's script the host's own stream (the test double's) feeds the pill, as in production.
      if (rec && host.hostId && (host.sessionId || setupDemo)) {
        void attachSetup(rec, { host: host.name, hostId: host.hostId, status,
          // Removal needs the server's passkey ceremony, which the test double does not have: it only says so.
          remove: () => ({ label: "Remove host", run: () => core.toast.show({ message: "Removing a host needs the server (not in this mock).", duration: 4000 }) }),
          ...(setupDemo ? { source: setupDemo.source } : {}), ...(query.get("tickhold") ? { tickHold: Number(query.get("tickhold")) } : {}) });
      }
    }
  }

  const canvas: CanvasController = createCanvas(core, {
    float: true,
    dots: new URLSearchParams(location.search).get("dots") !== "0",
    adapters: {
      teach: (hint) => teachOnce("mock", hint),
      ...(startupDemo ? { startupHints: startupDemo.hints } : {}),
      sessions, inventory, details: () => onDemand(() => import("./details.on-demand")).then((m) => m.createMockDetails(world, inventory)), mesh, store: new MemoryCanvasStore(), sharing: createMockSharing(world), settings: createMockSettings(world),
      containers: { host: "build-01", rows: () => (world.role === "operator" ? CONTAINERS : []) },
      addHost: openAddHost,
      authority,
    },
  });
  const cx = canvas.cx;
  const { camera, state } = cx;
  const stopOffer = offerMeshView(cx, mesh);
  let sceneIndex = 0;

  // ---- building the world for a scene ---------------------------------------------------------------
  const build = (): void => {
    mesh.reset(); // the scene starts from its own mesh (and its grants)
    inventory.reset();
    const named = (host: string): { id: string; name: string } | undefined => { const id = DEFAULT_SESSION[host]; const rec = id ? inventory.get(host, id) : undefined; return rec ? { id: rec.id, name: rec.name } : undefined; };
    canvas.setViews((m: Metrics) => buildViews(world.role, m, mesh, world.screens, world.omit, sceneIndex === 6 && world.role === "operator", named));
    cx.sharing?.reset();
  };

  // ---- "Continue from <device>?": shown once when the app opens on a different device ---------------
  let chip: HTMLElement | undefined;
  const showContinueChip = (): void => {
    chip?.remove();
    const from = world.devices.find((d) => !d.current && d.online) ?? world.devices.find((d) => !d.current);
    if (!from) return;
    const chipEl = el("div", "cl-continue ui-pill");
    chipEl.setAttribute("role", "group");
    chipEl.setAttribute("aria-label", `Continue from ${from.name}?`);
    chipEl.innerHTML = `<span class="cl-continue-text"></span><button type="button" class="ui-window-action" aria-label="Continue" data-tip="Continue in ${from.view}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5.5 12.5 4 4 9-9"/></svg></button><button type="button" class="ui-window-action" aria-label="Dismiss" data-tip="Dismiss"><svg viewBox="0 0 24 24" aria-hidden="true">${CLOSE}</svg></button>`;
    (chipEl.querySelector(".cl-continue-text") as HTMLElement).textContent = `Continue from ${from.name}?`;
    const [yes, no] = chipEl.querySelectorAll<HTMLButtonElement>("button");
    const gone = (): void => { chipEl.dataset.open = "false"; window.setTimeout(() => chipEl.remove(), 220); if (chip === chipEl) chip = undefined; };
    yes!.addEventListener("click", () => { const id = from.view.toLowerCase() as ViewId; if (cx.views.has(id)) cx.nav.flyView(id); gone(); });
    no!.addEventListener("click", gone);
    stage.append(chipEl);
    chip = chipEl;
    chipEl.dataset.open = "false";
    requestAnimationFrame(() => { chipEl.dataset.open = "true"; });
    window.setTimeout(() => { if (chip === chipEl) gone(); }, 9000);
  };

  // ---- scenes ---------------------------------------------------------------------------------------
  const free = (): void => cx.nav.applyCanvasLock(false);
  const overview = (instant: boolean): void => camera.flyTo(cx.nav.overviewCam, instant);
  const scenes: Scene[] = [
    { name: "Overview", hint: "Three views on one canvas, canvasLock off. Hover a region for its summary; click one to fly in (canvasLock turns on). The sidebar and the command palette list the views.",
      enter() { world.role = "operator"; world.omit = []; build(); free(); overview(true); } },
    { name: "Fly in", hint: "The camera springs into Console and snaps. Esc flies out. In the command palette, type build and open a shell on build-01.",
      enter() { world.role = "operator"; world.omit = ["build-01"]; build(); free(); overview(true); window.setTimeout(() => { if (sceneIndex === 1 && camera.target === cx.nav.overviewCam) cx.nav.flyView("console"); }, 650); } },
    { name: "Arrows on demand", hint: "Hover a terminal's pill (long-press on touch) to see where it can reach. Drag from the connector next to the pill onto another terminal to allow access.",
      enter() { world.role = "operator"; world.omit = []; build(); cx.nav.flyView("console", true); } },
    { name: "Open from a container", hint: "Click a container: the top pill morphs into a floating terminal; the camera stays here. Expand it to fly into Console, or close it. The terminal has Split; the list does not.",
      enter() { world.role = "operator"; world.omit = []; build(); cx.nav.flyView("containers", true); } },
    { name: "Who sees what", hint: "The views a person sees come from the access they have. Palette: Mockup, sign in as viewer, operator or new user.",
      enter() { world.omit = []; if (world.role === "operator" && !world.forcedRole) world.role = "viewer"; build(); if (world.role === "operator") { free(); overview(true); } else cx.nav.flyView("console", true); } },
    { name: "Structure", hint: "Drag a window by its pill: the others reflow and it lands with a bounce. Drag a view by its label: it snaps to the grid and pushes a neighbour aside. Snap is off here.",
      enter() {
        world.role = "operator"; world.omit = []; build(); free();
        const r = cx.view.contentRect(cx.views.get("console")!);
        const narrow = state.metrics.narrow;
        camera.flyTo(() => ({ cx: r.x + r.w / 2 + (narrow ? 0 : 180), cy: r.y + r.h / 2 + (narrow ? 120 : 200), z: 0.62 }), true);
      } },
    { name: "Sharing", hint: `Share layout… (${shortcutLabel(PALETTE_KEYS)} or a view label's menu) sends views to a person or group. Then Mockup: view as asha: the copy arrives as a new view. Publish to team keeps followers linked and read-only.`,
      enter() { world.role = "operator"; world.omit = []; build(); cx.nav.flyView("incident", true); } },
  ];
  const mockupTag = el("button", "ui-pill cl-mockup", "mockup");
  mockupTag.type = "button";
  mockupTag.setAttribute("aria-label", "Mockup scenes");
  stage.append(mockupTag);
  mockupTag.addEventListener("click", () => {
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: isMacPlatform(), ctrlKey: !isMacPlatform(), bubbles: true }));
    window.setTimeout(() => { const input = stage.querySelector<HTMLInputElement>("#palette-input"); if (input) { input.value = "mockup"; input.dispatchEvent(new Event("input", { bubbles: true })); } }, 60);
  }, { signal });
  const goScene = (i: number): void => {
    sceneIndex = (i + scenes.length) % scenes.length;
    const def = scenes[sceneIndex]!;
    def.enter();
    mockupTag.dataset.tip = `Scene ${sceneIndex + 1} of ${scenes.length}, ${def.name}. ${def.hint}`;
    const url = new URL(location.href);
    url.searchParams.set("scene", String(sceneIndex + 1));
    history.replaceState(null, "", url);
    cx.pill.paint();
  };

  // ---- palette rows and actions that exist only in the mockup ---------------------------------------
  // The scenes' code loads the first time one runs.
  let scenesLoaded: Promise<SessionScenes> | undefined;
  const sessionScenes = {
    run: async (n: number): Promise<void> => {
      scenesLoaded ??= onDemand(() => import("./session-scenes.on-demand")).then((m) => m.installSessionScenes({ cx, inventory, rebuild: () => { world.role = "operator"; world.omit = []; build(); cx.nav.flyView("console", true); } }));
      await (await scenesLoaded).run(n);
    },
    entries: (): PaletteEntry[] => SESSION_SCENES.map((scene, i) => ({ group: "Mockup", glyph: "▷", label: `Mockup: sessions scene ${i + 1}`, hint: scene.hint, action: `proto:sessions-scene:${i + 1}` })),
    dispose: (): void => { void scenesLoaded?.then((loaded) => loaded.dispose()); },
  };
  const removeProvider = core.addPaletteProvider(() => {
    const out: PaletteEntry[] = [...sessionScenes.entries(), ...(startupDemo?.entries() ?? [])];
    scenes.forEach((sc, i) => out.push({ group: "Mockup", glyph: "◇", label: `Mockup: scene ${i + 1} – ${sc.name.toLowerCase()}`, hint: "scenes", action: `proto:scene:${i + 1}` }));
    out.push({ group: "Mockup", glyph: "◇", label: "Mockup: transparency", hint: "all card and window levels side by side", action: "proto:transparency" });
    out.push({ group: "Mockup", glyph: "◇", label: "Mockup: simulate device switch", hint: "continue from another device", action: "proto:devicechip" });
    out.push({ group: "Mockup", glyph: "◇", label: "Mockup: view as asha", hint: "receives shared layouts", action: "proto:role:asha" });
    out.push({ group: "Mockup", glyph: "◇", label: "Mockup: view as kayg", hint: "the owner", action: "proto:role:operator" });
    for (const r of ["viewer", "operator", "new"] as const) out.push({ group: "Mockup", glyph: "◇", label: `Mockup: sign in as ${r === "new" ? "a new user" : `a ${r}`}`, hint: "grants", action: `proto:role:${r}` });
    for (const host of cx.adapters.sessions.hosts()) out.push({ group: "Console", glyph: "▭", label: `Open remote desktop on ${host.name}`, hint: "vnc · rdp · arrives later", action: "proto:later" });
    return out;
  });
  window.addEventListener("tracer:canvas-action", (event) => {
    const action = (event as CustomEvent<{ action?: string }>).detail?.action ?? "";
    const [prefix, kind, value] = action.split(":");
    if (prefix !== "proto") return;
    if (kind === "sessions-scene" && value) { void sessionScenes.run(Number(value)); return; }
    if (kind === "startup") { startupDemo?.replay(); return; }
    if (kind === "transparency") mountTransparencyCompare(core);
    else if (kind === "devicechip") showContinueChip();
    else if (kind === "scene" && value) goScene(Number(value) - 1);
    else if (kind === "role" && value) { world.role = value as Role; world.forcedRole = true; goScene(4); window.setTimeout(showContinueChip, 900); }
    else if (kind === "later") core.toast.show({ message: "Remote desktop arrives later.", tone: "ok" });
  }, { signal });

  // ---- live-looking content -------------------------------------------------------------------------
  // Only visible logs tick. Keep the existing tail-follow controller and backlog;
  // parked windows must not force layout or repaint while nobody can see them.
  let logSerial = LOG_BACKLOG;
  const streamTimer = window.setInterval(() => {
    if (document.hidden) return; // a hidden page does nothing
    // One line, or a short burst now and then, like a service under a little load.
    const burst = logSerial % 7 === 0 ? 3 : 1;
    for (let k = 0; k < burst; k++, logSerial++) {
      const line = logLine(logSerial, Date.now());
      for (const c of cx.views.values()) for (const w of c.wins.values()) {
        if (!w.pushLog || !w.model.lines || !w.card.root.hasAttribute("data-onscreen")) continue;
        w.model.lines = [...w.model.lines.slice(-499), line];
        w.pushLog(line);
      }
    }
  }, 1600);
  // The live terminal's test double starts empty; give it one prompt so the window reads as a shell.
  let seedTries = 0;
  const seedTimer = window.setInterval(() => {
    const td = (window as unknown as { __tracerTestDouble?: { isConnected(): boolean; seedPrompt(): Promise<void> } }).__tracerTestDouble;
    if (td?.isConnected()) { window.clearInterval(seedTimer); void td.seedPrompt(); } else if (++seedTries > 80) window.clearInterval(seedTimer);
  }, 100);

  // ---- start ----------------------------------------------------------------------------------------
  // The pill demo starts where a terminal window is on screen (scene 3: Console), so the new window opens beside it.
  const startScene = Math.min(scenes.length - 1, Math.max(0, ((options.scene ?? (setupDemo || startupDemo ? 3 : 1)) | 0) - 1));
  goScene(startScene);
  if (setupDemo && query.get("autopilot") !== "0") window.setTimeout(() => { void runAutopilot(openAddHost); }, 500);
  startupDemo?.start();
  const sessionsScene = Number(new URLSearchParams(location.search).get("sessions")) || 0;
  if (sessionsScene) window.setTimeout(() => { void sessionScenes.run(sessionsScene); }, 400);

  const probe = {
    scene: () => sceneIndex + 1,
    setScene: (n: number) => goScene(n - 1),
    camera: () => ({ ...camera.cam, lod: camera.lod, zoomBand: camera.band, tx: camera.tx, ty: camera.ty }),
    setCamera: (cx_: number, cy: number, z: number) => { cx.nav.applyCanvasLock(false); camera.set({ cx: cx_, cy, z }); },
    flyCamera: (cx_: number, cy: number, z: number) => { cx.nav.applyCanvasLock(false); camera.flyTo(() => ({ cx: cx_, cy, z })); },
    views: () => [...cx.views.values()].map((c) => ({ id: c.view.id, name: c.view.name, team: Boolean(c.view.team), x: c.x, y: c.y, w: boxOf(c.view, state.metrics).w, h: boxOf(c.view, state.metrics).h, windows: [...c.wins.keys()] })),
    /** Lets the Mesh spec exercise graph pinning when its view id is outside the Mesh source. */
    setGraphViewId: (from: string, to: string) => {
      const c = cx.views.get(from as ViewId);
      if (c?.view.layout === "graph") c.view.id = to as ViewId;
    },
    /** The focused window's id (specs check where a flow handed the keys). */
    activeWindow: (): string | undefined => state.activeWin?.model.id,
    /** A new session on the host in its own window (the inventory creates it, as a split does). */
    newShell: (host: string): string | undefined => {
      const rec = inventory.create?.(host);
      if (rec) cx.win.openSession(host, rec.id);
      return rec?.id;
    },
    /** Makes a window active by its id, as a press on it does (the recency list records it, #121). */
    activateWindow: (id: string): boolean => {
      const rec = [...cx.views.values()].flatMap((c) => [...c.wins.values()]).find((w) => w.model.id === id);
      if (rec) cx.win.setActive(rec);
      return Boolean(rec);
    },
    grants: () => world.grants.map((g) => ({ ...g })),
    flyView: (id: ViewId) => cx.nav.flyView(id),
    /** Runs an appearance action (`theme:mocha`, `card:3`, `windows:4`, `bg:mesh`) as the palette does. */
    act: (action: string) => cx.core.act(action),
    overview: () => cx.nav.showOverview(),
    openSession: (host: string, container?: string) => cx.win.open(host, container),
    openSettings: (section: string) => { const c = cx.views.get("settings"); const rec = c?.wins.get(`s-${section}`) ?? [...(c?.wins.values() ?? [])][0]; if (rec) { cx.win.setActive(rec); cx.nav.focusWindow(rec); } },
    showContinueChip,
    float: () => cx.float.info(),
    setRole: (r: Role) => { world.role = r; world.forcedRole = true; goScene(4); },
    canvasLock: () => ({ on: state.canvasLock, index: state.snapIdx, stops: (() => { const c = cx.views.get(state.currentView); return c ? cx.nav.stopsFor(c).lefts.length : 0; })(), view: state.currentView }),
    setCanvasLock: (on: boolean) => cx.nav.setCanvasLock(on),
    /** The fake Mesh server and what the Mesh view has on screen (specs drive and read these). */
    mesh: {
      server: () => mesh.server,
      status: () => mesh.status(),
      pins: () => mesh.pins(),
      stats: () => cx.mesh?.graphStats(),
      reset: () => { mesh.reset(); },
      source: () => mesh,
      /** The saved canvas document (what a reload would restore). */
      document: () => cx.adapters.store.load(),
      /** Feeds a remote Mesh view through reconciliation while retaining the other mock views. */
      applyRemoteLayout: async (document: unknown): Promise<void> => {
        const remote = document as CanvasDocument;
        const kept = new Set([...cx.views.keys()].filter((id) => id !== "mesh"));
        await reconcile(cx, () => ({
          document: { ...remote, views: remote.views.filter((view) => view.id === "mesh") },
          protectedIds: new Set(),
          protectedViews: kept,
        }), () => undefined, () => true);
      },
    },
    sessions: () => ({ status: inventory.status(), hosts: inventory.hosts().map((host) => ({ host, sessions: inventory.list(host).map((s) => ({ id: s.id, name: s.name, state: s.state, activity: s.activity ?? null, pinned: s.pinned })) })) }),
    runSessionScene: (n: number) => sessionScenes.run(n),
  };
  (window as unknown as { __tracerClusters?: typeof probe }).__tracerClusters = probe;

  return {
    dispose() {
      authority.dispose();
      setupDemo?.dispose();
      startupDemo?.dispose();
      events.abort();
      window.clearInterval(streamTimer);
      window.clearInterval(seedTimer);
      removeProvider();
      sessionScenes.dispose();
      inventory.dispose();
      mockupTag.remove();
      chip?.remove();
      stopOffer();
      addHost.dispose();
      canvas.dispose();
      mesh.dispose();
      sessions.dispose();
      delete (window as unknown as { __tracerClusters?: unknown }).__tracerClusters;
    },
  };
}
