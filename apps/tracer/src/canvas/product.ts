/**
 * The product canvas: the canvas on real sessions. After sign-in the screen shows the Console view, whose windows
 * are terminal sessions on the embedded host or admitted remote hosts, several at once over the one
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
import { ensureHostMarks, hostPlatformFromOs, type HostPlatform } from "../../../../packages/ui/src/host-icons";
import { ConnectionPool, MuxConnection } from "../connection";
import { isCanonicalUuid } from "../identifiers";
import type { CoreScreen } from "../core-screen";
import type { TerminalClient, TerminalHooks } from "../terminal";
import { createAddHost } from "./addhost";
import { createAuthorityControl } from "./addhost/authority-unlock";
import { createOverlayFlowHost } from "./addhost/flow-host";
import type { ProvisioningService } from "./addhost/service";
import { createWindowFlowHost } from "./addhost/window-host";
import { createCanvas, type CanvasController } from "./create";
import { CELL, boxOf } from "./layout/geometry";
import { columnsFromDocument, docHasGroups, type DocTarget } from "./model/document";
import { loadGroups } from "./layout/groups-handle";
import { LocalCanvasStore } from "./model/store";
import type { ViewModel, WindowModel } from "./model/types";
import { createLazyMeshApi } from "./mesh/lazy";
import { connectionTransport } from "./mesh/transport";
import { offerMeshView } from "./mesh/offer";
import { createLiveSessions, type LiveSessions } from "./sessions/live";
import { createLiveInventory } from "./sessions/live-inventory";
import { teachOnce } from "../hints";
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
  // The embedded host's system names the mark in its windows' pills. It is asked once, after the first welcome, with the
  // light read (no live figures); until it answers the pill shows the machine glyph.
  // Its account is the one the shell really runs as, not the signed-in person's name: the server does not send a login
  // name, so only root (execution uid 0) can be named; any other account shows the host alone until the server says it.
  const embedded: { name: string; user?: string; os?: HostPlatform } = { name: options.host.name };
  let canvasReady: (() => void) | undefined, osAsked = false;
  const connection: MuxConnection = new MuxConnection({
    ...(options.onRecoveryPending ? { onRecoveryPending: options.onRecoveryPending } : {}),
    onConnectionChange: (connected) => {
      core.setConnection(connected);
      if (!connected || osAsked) return;
      osAsked = true;
      connection.call("host.facts.read", { includeLive: false }).then((facts) => {
        if (typeof facts.os !== "string" || facts.os.length > 256) return;
        embedded.os = hostPlatformFromOs(facts.os);
        if (facts.executionUid === 0) embedded.user = "root";
        // The mark's artwork loads on first sight; the pill shows the machine glyph until it can draw the real one.
        void ensureHostMarks([embedded.os]).then(() => canvasReady?.());
      }, () => undefined);
    },
  });
  // The details source is loaded on a pill press, so keep the last sample for its first read.
  let roundTrip: number | undefined;
  const offRoundTrip = connection.onRoundTrip((ms) => { roundTrip = ms; core.setRoundTrip(ms); });
  // More windows than one socket takes (the server allows 32 attachments per socket) open on further sockets.
  const pool = new ConnectionPool(connection);
  const inventory = createLiveInventory({ accountId: options.accountId, host: options.host.name });
  let disposed = false, hostsStarted = false, hostsReady = false;
  let startHosts = (): void => {};
  let offHosts: (() => void) | undefined;
  const sessions = createLiveSessions({
    core, connection, pool, host: embedded,
    ...(options.predictiveEcho ? { predictiveEcho: true } : {}),
    ...(options.firstHooks ? { firstHooks: options.firstHooks } : {}),
    ...(options.onFirstClient ? { onFirstClient: options.onFirstClient } : {}),
    onFirstTerminalSettled: () => { hostsReady = true; startHosts(); },
    onSessionGone: inventory.gone,
    getEndedSession: (host, id) => {
      const session = inventory.get(host, id);
      return session?.gone ? (session.exit ? { status: session.exit.code } : {}) : undefined;
    },
  });
  const offSessionInventory = connection.subscribe({ topic: "terminal.sessions" }, (event) => {
    if (event.type === "terminal.sessions.unavailable") {
      inventory.unavailable(options.host.name);
    } else if (event.type === "terminal.sessions.snapshot" && Array.isArray(event.session_ids)) {
      const ids = event.session_ids.filter(isCanonicalUuid);
      const ended = Array.isArray(event.ended_sessions) ? event.ended_sessions.flatMap((value) => {
        if (!value || typeof value !== "object") return [];
        const row = value as { session_id?: unknown; status?: unknown };
        return isCanonicalUuid(row.session_id) && Number.isSafeInteger(row.status)
          && Number(row.status) >= -2147483648 && Number(row.status) <= 2147483647
          ? [{ id: row.session_id, status: Number(row.status) }]
          : [];
      }) : [];
      for (const row of inventory.reconcile(options.host.name, ids, ended)) {
        sessions.markGone(options.host.name, row.id, row.status);
      }
    }
  });
  const store = new LocalCanvasStore(options.accountId);
  const details: DetailsSourceLoader = () => onDemand(() => import("./sessions/details-live.on-demand"))
    .then((m) => m.createLiveDetails({ host: embedded, connection, inventory, roundTrip: () => roundTrip }));
  // A ready result carries the admitted UUID; labels are only presentation.
  // The real provisioning glue loads with the wizard on first use, then stays for the page (D188 deferred budget).
  let provisioning: Promise<ProvisioningService> | undefined;
  const loadProvisioning = (): Promise<ProvisioningService> =>
    (provisioning ??= onDemand(() => import("./addhost/real.on-demand")).then((m) => m.createRealProvisioning()).catch((e: unknown) => { provisioning = undefined; throw e; }));
  const addHost = createAddHost(core, {
    service: loadProvisioning, sink: { enrolled(hosts) {
      for (const host of hosts) {
        if (!host.hostId) { core.toast.show({ message: "The host did not return its connection identity. Add it again.", tone: "error", duration: 5000 }); continue; }
        sessions.registerHost({ id: host.hostId, name: host.name, ...(host.user ? { user: host.user } : {}), os: host.os, ...(host.address ? { address: host.address } : {}) });
        canvas.cx.win.open(host.hostId);
        applyIdentities([{ id: host.hostId, name: host.name, ...(host.user ? { user: host.user } : {}), os: host.os }]);
      }
    } },
    host: createWindowFlowHost(() => canvas.cx, createOverlayFlowHost(core.stage)),
  });
  const authority = createAuthorityControl(core, { service: loadProvisioning });
  let welcomedOnce = false;
  const offAuthorityWelcome = connection.onWelcome(() => {
    // A restart can lock the CA while this page retains its old unlocked state.
    // Refresh independently of terminal replay; the existing shared action owns unlock.
    if (welcomedOnce) void authority.refresh();
    welcomedOnce = true;
  });
  let readyRemoval: import("./context").Adapters["hostRemoval"];
  const removal: NonNullable<import("./context").Adapters["hostRemoval"]> = { label: () => readyRemoval?.label(), remove: (id, name, anchor) => readyRemoval?.remove(id, name, anchor) };
  // Registry metadata is optional chrome: load it without delaying the first terminal.
  void onDemand(() => import("./host-removal.on-demand")).then((module) => module.createHostRemoval(core, (id) => {
    sessions.forgetHost(id);
    for (const view of canvas.cx.views.values()) for (const rec of [...view.wins.values()]) if (rec.model.hostId === id) canvas.cx.win.close(rec);
    canvas.flush();
  })).then((adapter) => { readyRemoval = adapter; });
  const saved = await store.load();
  // Positions the person pinned in the Mesh graph come back from the canvas document (D180).
  const savedMesh = saved?.views.find((v) => v.id === "mesh");
  const mesh = createLazyMeshApi({ transport: connectionTransport(connection), pins: savedMesh?.layout.type === "graph" ? savedMesh.layout.pinned : {} });
  // A saved layout with a group needs the grouped module before its views are built (D212). Any other canvas starts the
  // fetch in createCanvas and does not wait for it.
  if (saved && docHasGroups(saved)) await loadGroups();
  const canvas = createCanvas(core, {
    adapters: { teach: (hint) => teachOnce(options.accountId, hint), sessions, activeTerminal: () => sessions.activeClient(), inventory, details, store, settings: { sections: [], render: () => undefined }, mesh, hostRemoval: removal, addHost: () => addHost.open(), authority },
    float: false,
    persisted: (id) => id === "console" || id === "mesh",
  });
  canvasReady = () => canvas.cx.win.setHostIdentity({ host: embedded.name }, { ...(embedded.os ? { os: embedded.os } : {}), ...(embedded.user ? { user: embedded.user } : {}) });
  // Remote hosts: every open window of a host takes what the list says, whenever the list says it.
  const applyIdentities = (hosts: readonly { id: string; name: string; user?: string; os?: HostPlatform }[]): void => {
    for (const h of hosts) canvas.cx.win.setHostIdentity({ host: h.name, hostId: h.id }, { ...(h.os ? { os: h.os } : {}), user: h.user });
  };
  canvas.setViews((m) => {
    const doc = saved?.views.find((v) => v.id === "console");
    const resolve = (target: DocTarget): Partial<WindowModel> | undefined => {
      if (target.type !== "session") return undefined;
      if (target.hostId) {
        sessions.registerHost({ id: target.hostId, name: target.host, ...(target.user ? { user: target.user } : {}), ...(target.address ? { address: target.address } : {}) });
        return { host: target.host, hostId: target.hostId, sessionId: target.id, ...(target.name ? { session: target.name } : {}), ...(target.user ? { user: target.user } : {}), ...(target.address ? { address: target.address } : {}) };
      }
      // Historical documents represent only the embedded host. Unknown labels are never rebound locally.
      return target.host === options.host.name ? { host: options.host.name, sessionId: target.id, ...(target.name ? { session: target.name } : {}), ...(embedded.user ? { user: embedded.user } : {}), ...(embedded.os ? { os: embedded.os } : {}) } : undefined;
    };
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
  canvasReady();
  const first = [...(canvas.cx.views.get("console")?.wins.values() ?? [])][0];
  if (first) canvas.cx.win.setActive(first);
  // Neither inventory code nor its RPC competes with the first terminal frame.
  startHosts = () => {
    if (disposed || hostsStarted) return;
    hostsStarted = true;
    void import("./sessions/hosts").then(({ syncAdmittedHosts }) => {
      if (disposed) return;
      offHosts = syncAdmittedHosts(connection, { replaceHosts(hosts) {
        const removed = new Set(sessions.replaceHosts(hosts));
        applyIdentities(hosts);
        for (const view of canvas.cx.views.values()) for (const rec of [...view.wins.values()]) if (rec.model.hostId && removed.has(rec.model.hostId)) canvas.cx.win.close(rec);
        if (removed.size) canvas.flush();
      } });
    }, () => { hostsStarted = false; });
  };
  const offHostWelcome = connection.onWelcome(() => { if (hostsReady) startHosts(); });
  return {
    canvas, sessions, connection,
    dispose() {
      canvas.flush();
      offRoundTrip();
      disposed = true;
      offHosts?.();
      offHostWelcome();
      offSessionInventory();
      offAuthorityWelcome();
      authority.dispose();
      offMeshView();
      addHost.dispose();
      canvas.dispose();
      mesh.dispose();
      inventory.dispose();
      sessions.dispose();
      pool.dispose();
      connection.dispose();
    },
  };
}
