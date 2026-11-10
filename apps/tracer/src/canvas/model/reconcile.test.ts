/** Shared-view reconciliation keeps camera anchors and temporary app streams stable across receipts. */
import { expect, test } from "bun:test";
import type { Ctx, ViewRec, WinRec } from "../context";
import { CELL, metricsFor } from "../layout/geometry";
import { registerGroups, type Groups } from "../layout/groups-handle";
import { createLayoutModel } from "../mesh/layout-model";
import type { MeshData } from "../mesh/source";
import { toDocument } from "./document";
import type { ViewModel, WindowModel } from "./types";

Object.defineProperty(globalThis, "matchMedia", {
  configurable: true,
  value: () => ({ matches: false, addEventListener() {}, removeEventListener() {} }),
});
const { reconcile } = await import("./reconcile");

test("review: removing the current shared view selects a surviving camera anchor", async () => {
  const consoleView = { view: { id: "console" } } as unknown as ViewRec;
  const settingsView = { view: { id: "settings" }, wins: new Map() } as unknown as ViewRec;
  const views = new Map<string, ViewRec>([["console", consoleView], ["settings", settingsView]]);
  const state = { currentView: "console", activeWin: undefined };
  let settledAnchor = "", flownTo = "";
  const cx = {
    views,
    state,
    nav: { flyView(id: string) { flownTo = id; state.currentView = id; } },
    view: {
      remove(view: ViewRec) { views.delete(view.view.id); },
      settle(id: string) { settledAnchor = id; },
    },
    win: { setActive() {} },
    visibility: { unwatch() {}, lodChanged() {} },
    store: { reset() {}, changed() {}, uncommittedWindows: () => new Set(), uncommittedViews: () => new Set() },
    adapters: {},
    tree: { render() {} },
    pill: { paint() {} },
    toolbar: { update() {} },
  } as unknown as Ctx;

  await reconcile(cx, () => ({
    document: { format: "infraternal.canvas", version: 1, revision: 2, views: [] },
    protectedIds: new Set(), protectedViews: new Set(),
  }), () => undefined, () => true);

  expect(flownTo).toBe("settings");
  expect(state.currentView).toBe("settings");
  expect(settledAnchor).toBe("settings");
  expect(views.has(state.currentView)).toBe(true);
});

test("a remote negative pin and node update preserve the world position of an unchanged card", async () => {
  const metrics = metricsFor(1440, 900, false);
  const wireNode = (id: number, name: string) => ({ id, name, tags: [], state: "online" as const, rttMs: undefined, os: undefined, address: undefined, path: undefined, via: undefined });
  const data: MeshData = {
    version: 1,
    nodes: new Map([["moved", wireNode(1, "moved")], ["steady", wireNode(2, "steady")]]),
    tags: {}, pins: new Map(),
  };
  const initialPins = { moved: { x: 400, y: 200 }, steady: { x: 800, y: 400 } };
  const viewModel: ViewModel = {
    id: "mesh", name: "Mesh", layout: "graph" as const, cols: [], nodes: [], x: 2 * CELL, y: 3 * CELL,
    graphPins: initialPins, graph: { w: 0, h: 0 },
  };
  const layout = createLayoutModel({ data: () => data }, () => viewModel.graphPins);
  const beforeLayout = layout(metrics);
  viewModel.nodes = beforeLayout.nodes;
  viewModel.graph = beforeLayout.size;
  const originalX = viewModel.x, originalY = viewModel.y;
  const steadyBefore = beforeLayout.nodes.find((node) => node.id === "steady")!;
  const steadyPositionBefore = { x: steadyBefore.x, y: steadyBefore.y };
  const meshView = {
    view: viewModel, wins: new Map(), label: { querySelector: () => null },
    sx: { set: (x: number) => { viewModel.x = x; } }, sy: { set: (y: number) => { viewModel.y = y; } },
  } as unknown as ViewRec;
  const views = new Map<string, ViewRec>([["mesh", meshView]]);

  const nextPins = { ...initialPins, moved: { x: -1300, y: -490 } };
  data.version++;
  data.nodes = new Map([...data.nodes, ["new-host", wireNode(3, "new-host")]]);
  const expectedLayout = createLayoutModel({ data: () => data }, () => nextPins)(metrics);
  expect(expectedLayout.origin.x).toBeGreaterThan(0);
  expect(expectedLayout.origin.y).toBeGreaterThan(0);
  const nextCell = {
    x: 2 - expectedLayout.origin.x / CELL,
    y: 3 - expectedLayout.origin.y / CELL,
  };
  const cx = {
    views, state: { currentView: "mesh", activeWin: undefined, metrics }, adapters: {},
    mesh: { refreshLayout: () => { const next = layout(metrics); viewModel.nodes = next.nodes; viewModel.graph = next.size; } },
    view: { remove: () => {}, settle: () => {} }, win: { setActive: () => {} }, visibility: { unwatch: () => {}, lodChanged: () => {} },
    store: { reset: () => {}, changed: () => {}, uncommittedWindows: () => new Set(), uncommittedViews: () => new Set() },
    tree: { render: () => {} }, pill: { paint: () => {} }, toolbar: { update: () => {} },
  } as unknown as Ctx;

  await reconcile(cx, () => ({
    document: {
      format: "infraternal.canvas", version: 1, revision: 2,
      views: [{ id: "mesh", kind: "mesh", name: "Mesh", cell: nextCell, layout: { type: "graph", pinned: nextPins } }],
    },
    protectedIds: new Set(), protectedViews: new Set(),
  }), () => undefined, () => true);

  const steadyAfter = viewModel.nodes.find((node) => node.id === "steady")!;
  expect(viewModel.graph).toEqual(expectedLayout.size);
  expect(viewModel.x + steadyAfter.x).toBe(originalX + steadyPositionBefore.x);
  expect(viewModel.y + steadyAfter.y).toBe(originalY + steadyPositionBefore.y);
  expect(viewModel.nodes.some((node) => node.id === "new-host")).toBe(true);
});

test("a canonical receipt keeps temporary streams without re-journaling them", async () => {
  let disposed = 0, changed = 0;
  const models: WindowModel[] = ["app", "screen", "flow"].map((kind) => ({ id: kind, kind: kind as WindowModel["kind"], host: "local" }));
  const metrics = metricsFor(1440, 900, false);
  const view: ViewModel = { id: "console", name: "Console", layout: "tiled", x: 0, y: 0, nodes: [], cols: [{ id: "local", w: metrics.colW, wins: models }] };
  const wins = new Map(models.map((model) => [model.id, {
    model, binding: { dispose: () => disposed++ }, card: { dispose: () => disposed++ },
  } as unknown as WinRec]));
  const record = { view, wins } as unknown as ViewRec;
  const cx = {
    views: new Map([[view.id, record]]), state: { currentView: view.id, metrics, activeWin: wins.get("app") },
    view: { geometry() {}, paintEmpty() {}, settle() {} }, win: { setActive() {} },
    visibility: { unwatch() {}, lodChanged() {} }, adapters: {},
    store: { reset() {}, changed: () => changed++ }, tree: { render() {} }, pill: { paint() {} }, toolbar: { update() {} },
  } as unknown as Ctx;
  registerGroups({ applyCols() {} } as unknown as Groups);
  try {
    await reconcile(cx, () => ({ document: toDocument([view], metrics, 0), protectedIds: new Set(), protectedViews: new Set() }), () => undefined, () => true);
    expect(disposed).toBe(0);
    expect([...record.wins.keys()]).toEqual(["app", "screen", "flow"]);
    expect(record.view.cols.flatMap((column) => column.wins)).toEqual(models);
    expect(changed).toBe(0);
  } finally {
    // Other suites may load the real grouped implementation after this test.
    const { groups } = await import("../layout/groups.on-demand");
    registerGroups(groups);
  }
});

/** A shared host change must repaint an open panel before a timer or old reply can run. */
test("a shared retarget immediately replaces the open panel's old facts with pending facts", async () => {
  const { createLiveDetails } = await import("../sessions/details-live.on-demand");
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const originalLocation = Object.getOwnPropertyDescriptor(globalThis, "location");
  Object.defineProperty(globalThis, "window", { configurable: true, value: { setTimeout: () => 1, clearTimeout() {} } });
  Object.defineProperty(globalThis, "location", { configurable: true, value: { hostname: "server.example.invalid", protocol: "https:" } });
  const source = createLiveDetails({
    host: { name: "server" }, roundTrip: () => undefined,
    connection: { isWelcomed: true, isOpen: true, call: async () => ({ os: "Debian", version: "13", kernel: "6.12", architecture: "x86_64", logicalCpus: 16, executionUid: 0, mode: "embedded", engines: [] }) } as unknown as import("../../connection").MuxConnection,
  });
  const metrics = metricsFor(1440, 900, false);
  const model: WindowModel = { id: "stable", kind: "terminal", host: "server", sessionId: "same-session" };
  const rec = { model, card: { setTitle() {} } } as unknown as WinRec;
  const view: ViewModel = { id: "console", name: "Console", layout: "tiled", x: 0, y: 0, nodes: [], cols: [{ id: "c", w: metrics.colW, wins: [model] }] };
  const record = { view, wins: new Map([[model.id, rec]]), label: { querySelector: () => null } } as unknown as ViewRec;
  let shown: ReturnType<typeof source.facts>;
  /** Models the open popover's real read-on-refresh boundary without polling or a DOM double. */
  const paint = (): void => { shown = source.facts(rec); };
  const cx = {
    views: new Map([[view.id, record]]), state: { currentView: view.id, metrics, activeWin: rec },
    details: { refresh(id: string) { if (id === rec.model.id) paint(); } },
    view: { geometry() {}, paintEmpty() {}, settle() {} }, win: { setActive() {} },
    visibility: { unwatch() {}, lodChanged() {} }, adapters: {},
    store: { reset() {}, changed() {} }, tree: { render() {} }, pill: { paint() {} }, toolbar: { update() {} },
  } as unknown as Ctx;
  registerGroups({ applyCols() {} } as unknown as Groups);
  const stop = source.open!(rec, paint);
  try {
    for (let i = 0; i < 8; i++) await Promise.resolve();
    expect(shown!.sections[0]!.rows.find((row) => row.key === "Architecture")?.value).toBe("x86_64");
    const next = { ...view, cols: [{ ...view.cols[0]!, wins: [{ ...model, host: "unreadable" }] }] };
    await reconcile(cx, () => ({ document: toDocument([next], metrics, 1), protectedIds: new Set(), protectedViews: new Set() }), () => ({ sessionId: "same-session" }), () => true);
    expect(rec.model.host).toBe("unreadable");
    expect(shown!.sections[0]!.rows.find((row) => row.key === "System")?.value).toBe("Not known yet");
    expect(shown!.sections[0]!.rows.find((row) => row.key === "Architecture")?.value).toBe("");
  } finally {
    stop();
    const { groups } = await import("../layout/groups.on-demand");
    registerGroups(groups);
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow); else Reflect.deleteProperty(globalThis, "window");
    if (originalLocation) Object.defineProperty(globalThis, "location", originalLocation); else Reflect.deleteProperty(globalThis, "location");
  }
});
