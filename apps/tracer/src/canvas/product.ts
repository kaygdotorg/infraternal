/**
 * The product canvas: the canvas on real sessions. After sign-in the screen shows the Console view, whose windows
 * are terminal sessions on the embedded host (remote hosts join as #78 lands), several at once over the one
 * WebSocket. The layout persists through the store adapter (local storage until the server sync of #98).
 *
 * Only real things are offered: the Console view, and the Settings view with the sections that exist today
 * (appearance, toolbar, shortcuts, about). Containers, Mesh, sharing and add-host appear when their adapters do.
 * This module is a lazy chunk, loaded after sign-in and never on the sign-in path.
 */
import { MuxConnection } from "../connection";
import type { CoreScreen } from "../core-screen";
import type { TerminalClient, TerminalHooks } from "../terminal";
import { createAddHost } from "./addhost";
import { createOverlayFlowHost } from "./addhost/flow-host";
import { createRealProvisioning } from "./addhost/real";
import { createWindowFlowHost } from "./addhost/window-host";
import { createCanvas, type CanvasController } from "./create";
import { CELL, boxOf } from "./layout/geometry";
import { columnsFromDocument, type DocTarget } from "./model/document";
import { LocalCanvasStore } from "./model/store";
import type { ViewModel, WindowModel } from "./model/types";
import { createLiveSessions, type LiveSessions } from "./sessions/live";
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
  const offRoundTrip = connection.onRoundTrip((ms) => core.setRoundTrip(ms));
  const sessions = createLiveSessions({
    core, connection, host: options.host,
    ...(options.predictiveEcho ? { predictiveEcho: true } : {}),
    ...(options.firstHooks ? { firstHooks: options.firstHooks } : {}),
    ...(options.onFirstClient ? { onFirstClient: options.onFirstClient } : {}),
  });
  const store = new LocalCanvasStore(options.accountId);
  // The add-host wizard on the real provisioning API, in a flow window. A host that finishes enrolling needs a
  // remote-host session binding (#78) before a shell can open on it; until `sessions.hosts()` lists remote hosts
  // the sink has nothing to open, and the wizard's own "ready" toast is the whole result.
  const addHost = createAddHost(core, {
    service: createRealProvisioning(), sink: { enrolled: () => undefined },
    host: createWindowFlowHost(() => canvas.cx, createOverlayFlowHost(core.stage)),
  });
  const canvas = createCanvas(core, {
    adapters: { sessions, store, settings: { sections: [], render: () => undefined }, addHost: () => addHost.open() },
    float: false,
    persisted: (id) => id === "console",
  });
  const saved = await store.load();
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
  canvas.cx.nav.flyView("console", true);
  const first = [...(canvas.cx.views.get("console")?.wins.values() ?? [])][0];
  if (first) canvas.cx.win.setActive(first);
  return {
    canvas, sessions, connection,
    dispose() {
      canvas.flush();
      offRoundTrip();
      addHost.dispose();
      canvas.dispose();
      sessions.dispose();
      connection.dispose();
    },
  };
}
