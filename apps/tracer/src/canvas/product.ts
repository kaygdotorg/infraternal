/**
 * The product canvas: the canvas on real sessions. After sign-in the screen shows the Console view, whose windows
 * are terminal sessions on the embedded host (remote hosts join as #78 lands), several at once over the one
 * WebSocket. The layout persists through the store adapter (local storage until the server sync of #98).
 *
 * Only real things are offered: the Console view, and the Settings view with the sections that exist today
 * (appearance, toolbar, shortcuts, about). Containers, sharing and add-host appear when their adapters do.
 *
 * The Mesh view (#108) is offered only when the server says the person may see it (D187): it joins the canvas
 * when the first snapshot arrives and goes if access is withdrawn. A person whose saved layout already had it
 * sees it at once, loading, so its pinned nodes are kept in the document while the snapshot is on its way.
 * This module is a lazy chunk, loaded after sign-in and never on the sign-in path.
 */
import { onDemand } from "../on-demand";
import { ConnectionPool, MuxConnection } from "../connection";
import type { CoreScreen } from "../core-screen";
import type { TerminalClient, TerminalHooks } from "../terminal";
import { createCanvas, type CanvasController } from "./create";
import { CELL, boxOf } from "./layout/geometry";
import { columnsFromDocument, type DocTarget } from "./model/document";
import { LocalCanvasStore } from "./model/store";
import type { ViewModel, WindowModel } from "./model/types";
import { createMeshApi } from "./mesh/api";
import { connectionTransport } from "./mesh/transport";
import { offerMeshView } from "./mesh/offer";
import { createLiveSessions, type LiveSessions } from "./sessions/live";
import { createLiveInventory } from "./sessions/live-inventory";
import type { DetailsSourceLoader } from "./windows/details-source";
import { BUILTIN_SECTIONS, buildSettingsView } from "./views/settings";

export interface ProductCanvasOptions {
  /** The embedded host's name and the person's login. */
  host: { name: string; user?: string };
  /** Layouts are kept per account. */
  accountId: string;
  predictiveEcho?: boolean;
  /** Terminal hooks for the first window (the latency probe). */
  firstHooks?: TerminalHooks;
  onFirstClient?: (client: TerminalClient) => void;
  onRecoveryPending?: (readyAt: number | undefined) => void;
}

export interface ProductCanvas {
  readonly canvas: CanvasController;
  readonly sessions: LiveSessions;
  readonly connection: MuxConnection;
  dispose(): void;
}

export async function mountProductCanvas(core: CoreScreen, options: ProductCanvasOptions): Promise<ProductCanvas> {
  const connection = new MuxConnection({
    ...(options.onRecoveryPending ? { onRecoveryPending: options.onRecoveryPending } : {}),
    onConnectionChange: (connected) => core.setConnection(connected),
  });
  // The details source is loaded on a pill press, so keep the last sample for its first read.
  let roundTrip: number | undefined;
  const offRoundTrip = connection.onRoundTrip((ms) => { roundTrip = ms; core.setRoundTrip(ms); });
  // More windows than one socket takes (the server allows 32 attachments per socket) open on further sockets.
  const pool = new ConnectionPool(connection);
  const sessions = createLiveSessions({
    core, connection, pool, host: options.host,
    ...(options.predictiveEcho ? { predictiveEcho: true } : {}),
    ...(options.firstHooks ? { firstHooks: options.firstHooks } : {}),
    ...(options.onFirstClient ? { onFirstClient: options.onFirstClient } : {}),
  });
  const store = new LocalCanvasStore(options.accountId);
  const inventory = createLiveInventory({ accountId: options.accountId, host: options.host.name });
  const details: DetailsSourceLoader = () => onDemand(() => import("./sessions/details-live.on-demand"))
    .then((m) => m.createLiveDetails({ host: options.host, connection, inventory, roundTrip: () => roundTrip }));
  const saved = await store.load();
  // Positions the person pinned in the Mesh graph come back from the canvas document (D180).
  const savedMesh = saved?.views.find((v) => v.id === "mesh");
  const mesh = createMeshApi({ transport: connectionTransport(connection), pins: savedMesh?.layout.type === "graph" ? savedMesh.layout.pinned : {} });
  const canvas = createCanvas(core, {
    adapters: { sessions, inventory, details, store, settings: { sections: [], render: () => undefined }, mesh },
    float: false,
    persisted: (id) => id === "console" || id === "mesh",
  });
  canvas.setViews((m) => {
    const doc = saved?.views.find((v) => v.id === "console");
    const resolve = (target: DocTarget): Partial<WindowModel> | undefined => (target.type === "session"
      ? { host: options.host.name, sessionId: target.id, ...(target.name ? { session: target.name } : {}), ...(options.host.user ? { user: options.host.user } : {}) }
      : undefined);
    let cols = doc && doc.layout.type === "tiled" ? columnsFromDocument(doc.layout, m, resolve) : [];
    // First run, or nothing left to restore: one new shell.
    if (!cols.length) cols = [{ id: "c1", w: m.colW, wins: [sessions.open(options.host.name)] }];
    const console_: ViewModel = { id: "console", name: "Console", layout: "tiled", cols, nodes: [], x: 0, y: 0 };
    const settings = buildSettingsView(false, m, BUILTIN_SECTIONS);
    settings.x = boxOf(console_, m).w + CELL;
    return [console_, settings];
  });
  // The Mesh view follows the server's answer (D187).
  const offMeshView = offerMeshView(canvas.cx, mesh, { keep: Boolean(savedMesh) });
  canvas.cx.nav.flyView("console", true);
  const first = [...(canvas.cx.views.get("console")?.wins.values() ?? [])][0];
  if (first) canvas.cx.win.setActive(first);
  return {
    canvas, sessions, connection,
    dispose() {
      canvas.flush();
      offRoundTrip();
      offMeshView();
      canvas.dispose();
      mesh.dispose();
      inventory.dispose();
      sessions.dispose();
      pool.dispose();
      connection.dispose();
    },
  };
}
