/**
 * The product canvas: the canvas on real sessions. After sign-in the screen shows the Console view, whose windows
 * are terminal sessions on the embedded host or admitted remote hosts, several at once over the one
 * WebSocket. The server owns the shared layout; each tab holds only its live drawing and unconfirmed edits (D312).
 *
 * Only real things are offered: the Console view, and the Settings view with the sections that exist today
 * (appearance, toolbar, shortcuts, about). Containers, sharing and add-host appear when their adapters do.
 *
 * The Mesh view (#108) is offered only when the server says the person may see it (D187): it joins the canvas
 * when the first snapshot arrives and goes if access is withdrawn. A person whose saved layout already had it
 * sees it at once, loading, so its pinned nodes are kept in the document while the snapshot is on its way.
 * This module is a lazy chunk, loaded after sign-in and never on the sign-in path.
 */
import { mountToast } from "../../../../packages/ui/src/toast";
import { ICON_INFO } from "../../../../packages/ui/src/icons";
import type { StatusActionPref } from "../../../../packages/ui/src/settings-panels";
import type { SettingsSource } from "./views/settings-body.on-demand";
import { onDemand, whenIdle } from "../on-demand";
import { ensureHostMarks, hostPlatformFromOs, type HostPlatform } from "../../../../packages/ui/src/host-icons";
import { setLinkRoundTrip } from "../../../../packages/ui/src/window-card";
import { ConnectionPool, MuxConnection } from "../connection";
import { isCanonicalUuid } from "../identifiers";
import type { CoreScreen } from "../core-screen";
import type { TerminalClient, TerminalHooks } from "../terminal";
import type { AddHost } from "./addhost";
import { createAuthorityControl } from "./addhost/authority-unlock";
import type { ProvisioningService } from "./addhost/service";
import { installDocsSource } from "./docs/docs-source";
import { createCanvas, type CanvasController } from "./create";
import { CELL, boxOf } from "./layout/geometry";
import { columnsFromDocument, viewFromDocument, docHasGroups, type DocTarget } from "./model/document";
import { loadGroups } from "./layout/groups-handle";
import { ServerCanvasStore, type RevokedWork } from "./model/server-store";
import { lookBridge } from "./themes/controller";
import { reconcile } from "./model/reconcile";
import type { ViewModel, WindowModel } from "./model/types";
import { createLazyMeshApi } from "./mesh/lazy";
import { connectionTransport } from "./mesh/transport";
import { offerMeshView } from "./mesh/offer";
import { createLiveSessions, type LiveSessions } from "./sessions/live";
import { createAppWindowsAdapter } from "./appwin/adapter";
import { appWindowsWanted } from "./appwin/flag";
import { createStartupHints } from "./sessions/startup-hints";
import { createLiveInventory } from "./sessions/live-inventory";
import { teachOnce } from "../hints";
import { buildVersion } from "../build-version";
import type { DetailsSourceLoader } from "./windows/details-source";
import { buildSettingsMapView, visibleMap } from "./settings-rows/model";
import { createRowsDocs } from "./settings-rows/docs-adapter";
import { createProductRows } from "./settings-rows/product-source";

import type { CanvasStore } from "./model/store";
import { watchPendingNotice } from "./pending-notice";

/** How long the host list waits for the first terminal to settle before it starts on its own. */
const HOSTS_FALLBACK_MS = 2000;

export interface ProductCanvasOptions {
  /** Isolated preview documents never use the production transport. */
  previewStore?: CanvasStore;
  /** The embedded host's name and the person's login. */
  host: { name: string; user?: string };
  /** Layouts are kept per account. */
  accountId: string;
  sessionIncarnation?: string;
  predictiveEcho?: boolean;
  /** Terminal hooks for the first window (the latency probe). */
  firstHooks?: TerminalHooks;
  onFirstClient?: (client: TerminalClient) => void;
  isCurrent?: () => boolean;
  onSessionCheck?: () => void;
  /** Ends the old account screen when its authenticated lifetime changes; `work` says what happened to queued layout edits. */
  onSessionRevoked?: (work: RevokedWork) => void;
  onRecoveryPending?: (readyAt: number | undefined) => void;
  onRecoveryCompleted?: (message: string) => void;
  /** The signed-in person: the sidebar's person pill opens their card (D283). Absent, the pill keeps its small menu. */
  person?: { name: string; username: string };
}

export interface ProductCanvas {
  readonly canvas: CanvasController;
  readonly sessions: LiveSessions;
  readonly connection: MuxConnection;
  dispose(): void;
}

/** Mounts the product canvas on the signed-in page: the live sessions, the host list, the layout and every window, and returns the handle that tears it all down. */
export async function mountProductCanvas(core: CoreScreen, options: ProductCanvasOptions): Promise<ProductCanvas> {
  // The embedded host's system names the mark in its windows' pills. It is asked once, after the first welcome, with the
  // light read (no live figures); until it answers the pill shows the machine glyph.
  // Its account is the one the shell really runs as, not the signed-in person's name: the server does not send a login
  // name, so only root (execution uid 0) can be named; any other account shows the host alone until the server says it.
  const embedded: { name: string; user?: string; os?: HostPlatform } = { name: options.host.name };
  let canvasReady: (() => void) | undefined, osAsked = false;
  const connection: MuxConnection = new MuxConnection({
    ...(options.sessionIncarnation ? { sessionIncarnation: options.sessionIncarnation } : {}),
    // Declared in the Hello of each socket, only while app windows are wanted (D208; off by default).
    desktop: appWindowsWanted,
    ...(options.onRecoveryPending ? { onRecoveryPending: options.onRecoveryPending } : {}),
    ...(options.onRecoveryCompleted ? { onRecoveryCompleted: options.onRecoveryCompleted } : {}),
    onConnectionChange: (connected) => {
      core.setConnection(connected);
      if (!connected) options.onSessionCheck?.();
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
  const offRoundTrip = connection.onRoundTrip((ms) => { roundTrip = ms; core.setRoundTrip(ms); setLinkRoundTrip(ms); });
  // More windows than one socket takes (the server allows 32 attachments per socket) open on further sockets.
  const pool = new ConnectionPool(connection);
  const inventory = createLiveInventory({ accountId: options.accountId, host: options.host.name });
  let disposed = false, hostsStarted = false, hostsReady = false;
  let startHosts = (): void => {};
  let offHosts: (() => void) | undefined;
  const startupHints = createStartupHints(connection, core.toast);
  const sessions = createLiveSessions({
    core, connection, pool, host: embedded,
    onStartupSession: (session, hostId, name) => { void startupHints.inspect(session, hostId, name); },
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
  // Setup owns a shell before the account inventory admits its host; snapshots must not detach that window.
  const setupPendingHostIds = new Set<string>();
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
  const store = options.previewStore ?? new ServerCanvasStore(connection, options.accountId, (definitive, _delayed, capacity) => {
    if (disposed) return;
    if (capacity) core.toast.show({ message: "This tab has too many unsaved layout changes. Connect before making more.", tone: "error", duration: 0 });
    else if (definitive) core.toast.show({ message: "That layout change was not saved. The saved layout is back.", tone: "error", duration: 5000 });
    // A delayed save (`_delayed`) gets no toast of its own: the persistent "Not saved" status below is shown for exactly as long as
    // the layout is waiting and already says to keep the tab open. A second transient toast said the same and stacked on it (#377).
  }, options.onSessionRevoked);
  const pendingNotice = mountToast(core.stage, { aboveNotifications: true });
  // Shown only when an edit is still unsaved after about a second, so a normal move never flashes it (D358).
  const pendingWatch = watchPendingNotice(() => store.pending === true, {
    show: () => { pendingNotice.show({ message: "Not saved — keep this tab open", icon: ICON_INFO, duration: 0 }); },
    hide: () => { pendingNotice.dismiss(); },
  });
  const offPending = store.onPending?.(() => pendingWatch.update()); pendingWatch.update();

  const details: DetailsSourceLoader = () => onDemand(() => import("./sessions/details-live.on-demand"))
    .then((m) => m.createLiveDetails({ host: embedded, connection, inventory, roundTrip: () => roundTrip }));
  // A ready result carries the admitted UUID; labels are only presentation.
  // The real provisioning glue loads with the wizard on first use, then stays for the page (D188 deferred budget).
  let provisioning: Promise<ProvisioningService> | undefined;
  const loadProvisioning = (): Promise<ProvisioningService> =>
    (provisioning ??= onDemand(() => import("./addhost/real.on-demand")).then((m) => m.createRealProvisioning()).catch((e: unknown) => { provisioning = undefined; throw e; }));
  // Adding a host is something the person chooses, so its glue is on demand (addhost/mount.on-demand.ts, D188): fetched when the
  // browser is idle after the canvas is up, and on the first tap if that has not happened. Its palette row appears when it arrives.
  let addHostMount: Promise<AddHost | undefined> | undefined;
  const mountAddHostNow = (): Promise<AddHost | undefined> => addHostMount ??= onDemand(() => import("./addhost/mount.on-demand")).then((m) => {
    if (disposed) return undefined;
    const mounted = m.mountAddHost(core, { service: loadProvisioning, cx: () => canvas.cx, sessions, inventory, setupPendingHostIds, removal, applyIdentities: (hosts) => applyIdentities(hosts) });
    core.refreshPalette();
    return mounted;
  }, (error: unknown) => { addHostMount = undefined; throw error; });
  whenIdle(() => { void mountAddHostNow().catch(() => undefined); }, 1000);
  const addHost = {
    open(): void { void mountAddHostNow().then((mounted) => mounted?.open(), () => core.toast.show({ message: "The add-host flow couldn't load. Check your connection and try again." })); },
    dispose(): void { void addHostMount?.then((mounted) => mounted?.dispose(), () => undefined); },
  };
  const authority = createAuthorityControl(core, { service: loadProvisioning });
  let welcomedOnce = false;
  const offAuthorityWelcome = connection.onWelcome(() => {
    // A restart can lock the CA while this page retains its old unlocked state.
    // Refresh independently of terminal replay; the existing shared action owns unlock.
    if (welcomedOnce) void authority.refresh();
    welcomedOnce = true;
  });
  let readyRemoval: import("./context").Adapters["hostRemoval"];
  const removal: NonNullable<import("./context").Adapters["hostRemoval"]> = { label: () => readyRemoval?.label(), remove: (id, name, anchor, returnFocus) => readyRemoval?.remove(id, name, anchor, returnFocus) };
  // Registry metadata is optional chrome: load it without delaying the first terminal.
  void onDemand(() => import("./host-removal.on-demand")).then((module) => module.createHostRemoval(core, (id) => {
    setupPendingHostIds.delete(id);
    sessions.forgetHost(id);
    for (const view of canvas.cx.views.values()) for (const rec of [...view.wins.values()]) if (rec.model.hostId === id) canvas.cx.win.close(rec);
    canvas.flush();
  })).then((adapter) => { readyRemoval = adapter; });
  const saved = await store.load();
  if (options.isCurrent?.() === false) {
    disposed = true; offPending?.(); pendingWatch.dispose(); pendingNotice.dispose(); store.dispose?.(); offRoundTrip(); offSessionInventory(); offAuthorityWelcome(); authority.dispose(); addHost.dispose(); inventory.dispose(); sessions.dispose(); pool.dispose(); connection.dispose();
    throw Error("The signed-in screen changed while layout was loading.");
  }
  // Positions the person pinned in the Mesh graph come back from the canvas document (D180).
  const savedMesh = saved?.views.find((v) => v.id === "mesh");
  const mesh = createLazyMeshApi({ transport: connectionTransport(connection), pins: savedMesh?.layout.type === "graph" ? savedMesh.layout.pinned : {} });
  // A saved layout with a group needs the grouped module before its views are built (D212). Any other canvas starts the
  // fetch in createCanvas and does not wait for it.
  if (saved && docHasGroups(saved)) await loadGroups();
  // The account model and the Settings → Account rows are their own chunk (#330): they stay out of the critical class. It is
  // fetched with the card's code once the canvas is up, or at once when Settings → Account opens first. The shell rows below
  // are all that Settings needs synchronously: a row whose text is still undefined stays hidden and draws when the chunk lands.
  const person = options.person;
  let accountLoaded: import("./account/session.on-demand").AccountSession | undefined;
  let accountLoading: Promise<import("./account/session.on-demand").AccountSession> | undefined;
  const shellListeners = new Set<() => void>();
  const loadAccount = (): Promise<import("./account/session.on-demand").AccountSession> => accountLoading ??= onDemand(() => import("./account/session.on-demand")).then((module) => {
    const session = module.createAccountSession({ person: person!, accountId: options.accountId, sessionIncarnation: options.sessionIncarnation, toast: core.toast });
    accountLoaded = session;
    // One subscription covers both rows: the model drives the text, and the passkey row's own busy state reports through it.
    session.statuses[0]?.onChange(() => { for (const listener of shellListeners) listener(); });
    for (const listener of shellListeners) listener();
    return session;
  }, (error: unknown) => { accountLoading = undefined; throw error; });
  const shellRow = (index: number, id: string, title: string): StatusActionPref => ({
    id, title,
    text: () => accountLoaded?.statuses[index]?.text(),
    action: () => accountLoaded?.statuses[index]?.action(),
    act: () => accountLoaded?.statuses[index]?.act(),
    refresh: () => undefined,
    onChange: (listener) => { shellListeners.add(listener); return () => { shellListeners.delete(listener); }; },
  });
  const accountStatuses: SettingsSource["accountStatuses"] = person ? () => {
    void loadAccount().catch(() => { /* the rows stay hidden; opening Settings again retries */ });
    return [shellRow(0, "passkeys", "Passkeys"), shellRow(1, "recovery", "Recovery key")];
  } : undefined;
  const productRows = createProductRows(() => true);
  const canvas = createCanvas(core, {
    adapters: { teach: (hint) => teachOnce(options.accountId, hint), sessions, activeTerminal: () => sessions.activeClient(), inventory, details, store, ...(lookBridge() ? { look: lookBridge()! } : {}), settings: { sections: [], ...productRows, ...(accountStatuses ? { accountStatuses, accountRefresh: () => { void loadAccount().then((session) => session.model.refresh?.()).catch(() => undefined); } } : {}) }, mesh, docs: createRowsDocs(() => docs), hostRemoval: removal, addHost: () => addHost.open(), authority, appWindows: createAppWindowsAdapter(connection), startupHints },
    float: false,
    persisted: (id) => id !== "settings",
  });
  // The docs: a Docs view with a window per page, and searchable in the palette (#302).
  const docs = installDocsSource(core, canvas.cx);
  canvasReady = () => canvas.cx.win.setHostIdentity({ host: embedded.name }, { ...(embedded.os ? { os: embedded.os } : {}), ...(embedded.user ? { user: embedded.user } : {}) });
  // Remote hosts: every open window of a host takes what the list says, whenever the list says it.
  const applyIdentities = (hosts: readonly { id: string; name: string; user?: string; os?: HostPlatform }[]): void => {
    for (const h of hosts) canvas.cx.win.setHostIdentity({ host: h.name, hostId: h.id }, { ...(h.os ? { os: h.os } : {}), user: h.user });
  };
  const resolve = (target: DocTarget, windowId: string): Partial<WindowModel> | undefined => {
    if (target.type !== "session") return undefined;
    const reference = { host: target.host, ...(!store.unresolvedWindow?.(windowId) ? { sessionId: target.id } : {}), ...(target.name ? { session: target.name } : {}), ...(target.pinned ? { sessionPinned: true } : {}) };
    if (target.hostId) {
      const identity = { ...(target.user ? { user: target.user } : {}), ...(target.address ? { address: target.address } : {}) };
      sessions.registerHost({ id: target.hostId, name: target.host, ...identity });
      return { ...reference, hostId: target.hostId, ...identity };
    }
    // Historical references can select the known embedded host only.
    return target.host === options.host.name ? { ...reference, ...(embedded.user ? { user: embedded.user } : {}), ...(embedded.os ? { os: embedded.os } : {}) } : undefined;
  };
  canvas.setViews((m) => {
    const doc = saved?.views.find((v) => v.id === "console");
    let cols = doc && doc.layout.type === "tiled" ? columnsFromDocument(doc.layout, m, resolve) : [];
    // First run, or nothing left to restore: one new shell.
    if (!doc && !saved) cols = [{ id: "c1", w: m.colW, wins: [sessions.open(options.host.name)] }];
    const console_: ViewModel = { id: "console", name: "Console", layout: "tiled", cols, nodes: [], x: (doc?.cell.x ?? 0) * CELL, y: (doc?.cell.y ?? 0) * CELL };
    const settings = buildSettingsMapView(visibleMap(true), m, { id: "settings", name: "Settings", layout: "tiled", cols: [], nodes: [], x: 0, y: 0 });
    settings.x = boxOf(console_, m).w + CELL;
    const recovered = (saved?.views ?? []).filter((v) => v.id !== "console" && v.id !== "mesh").map((v) => viewFromDocument(v, v.layout.type === "tiled" ? columnsFromDocument(v.layout, m, resolve) : []));
    return [console_, ...recovered, settings];
  });
  // The Mesh view follows the server's answer (D187).
  const offMeshView = offerMeshView(canvas.cx, mesh, { keep: Boolean(savedMesh) });
  if (savedMesh) {
    const view = canvas.cx.views.get("mesh");
    if (view) { if (savedMesh.layout.type === "graph") view.view.graphPins = savedMesh.layout.pinned; view.view.x = savedMesh.cell.x * CELL; view.view.y = savedMesh.cell.y * CELL; view.sx.set(view.view.x, true); view.sy.set(view.view.y, true); }
  }
  // A touch screen draws wider columns than the layout saved (D309): views they now overlap move clear, for display only.
  if (canvas.cx.state.metrics.minW > 0) canvas.cx.view.settle(canvas.cx.state.currentView);
  // The account's look (D322) comes with the document: the one this account saved replaces what this page started with, and an account with none yet is offered this page's.
  const bridge = lookBridge();
  bridge?.apply(saved?.look);
  if (store.pending !== true) bridge?.confirmed(saved?.look);
  // Capture initial structure once; subsequent server paints reset the comparison baseline.
  if (saved?.views.some((view) => view.id === "console")) canvas.cx.store.reset(); else canvas.cx.store.changed();
  let paintRevision = 0, paintAfterDrop = false;
  const paintLayout = (): void => {
    if (canvas.cx.state.movingWindow) { paintAfterDrop = true; return; }
    const revision = ++paintRevision;
    void reconcile(canvas.cx, () => {
      canvas.flush();
      return { document: store.current!(), protectedIds: canvas.cx.store.uncommittedWindows(), protectedViews: canvas.cx.store.uncommittedViews() };
    }, resolve, () => !disposed && revision === paintRevision);
  };
  // A canonical update cannot reparent a lifted window in the middle of its gesture.
  const dropped = (): void => { if (paintAfterDrop) { paintAfterDrop = false; queueMicrotask(paintLayout); } };
  window.addEventListener("pointerup", dropped);
  window.addEventListener("pointercancel", dropped);
  // A look another device saved arrives with the document, through the same subscription as the layout.
  const offLook = store.current && bridge ? store.subscribe(() => {
    const document = store.current!();
    bridge.apply(document.look);
    if (store.pending !== true) bridge.confirmed(document.look);
  }) : () => {};
  const offLayout = store.current ? store.subscribe(paintLayout) : () => {};
  // Changes can arrive while grouped-layout code loads during mount.
  if (store.current) paintLayout();
  if (saved) inventory.setLayout(saved);
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
        for (const host of hosts) setupPendingHostIds.delete(host.id);
        const removed = new Set(sessions.replaceHosts(hosts, [...setupPendingHostIds]));
        applyIdentities(hosts);
        for (const view of canvas.cx.views.values()) for (const rec of [...view.wins.values()]) if (rec.model.hostId && removed.has(rec.model.hostId)) canvas.cx.win.close(rec);
        if (removed.size) canvas.flush();
      } });
    }, () => { hostsStarted = false; });
  };
  const offHostWelcome = connection.onWelcome(() => { if (hostsReady) startHosts(); });
  // The first terminal settling is the usual cue (above), but a canvas with no terminal, or one whose terminal never settles
  // (a refused or unreachable host), would then never learn its remote hosts and the palette would list none (#305). So the
  // list also starts once the page has been quiet for a moment: after the first frame had its chance, never instead of it.
  const hostsFallback = window.setTimeout(() => whenIdle(() => { hostsReady = true; startHosts(); }), HOSTS_FALLBACK_MS);
  // The version pill and its panel join the sidebar footer once the canvas is up (#216); the first screen carries none of it (D188).
  let versionArea: { dispose(): void } | undefined;
  const build = buildVersion();
  void onDemand(() => import("./version/mount.on-demand"))
    .then((m) => m.mountProductVersionArea(core, { version: build.short, commit: build.full, hosts: () => sessions.hosts().map((host) => host.name) }))
    .then((area) => { if (disposed) area?.dispose(); else versionArea = area; })
    .catch(() => { /* the pill is news, not a dependency */ });
  // The person's card (D283) hangs on the sidebar's person pill. Its code is its own chunk, fetched once the canvas is up.
  let account: import("./account/mount.on-demand").AccountMount | undefined;
  if (person) {
    // The card's chunk can arrive after the sidebar is open (a slow link, a busy device). A press on the pill in that gap must not
    // fall through to the pill's old small menu, which the card replaces: it is claimed here and the card opens once it is mounted.
    const foot = core.stage.querySelector<HTMLElement>(".ui-sidebar-foot");
    let pressedEarly = false;
    const claimPress = (event: MouseEvent): void => {
      if (!(event.target as Element | null)?.closest(".ui-sidebar-user")) return;
      event.stopImmediatePropagation();
      event.preventDefault();
      pressedEarly = true;
    };
    foot?.addEventListener("click", claimPress, true);
    // The card needs the model too (its own on-demand chunk), so the press stays claimed until both have arrived.
    void Promise.all([onDemand(() => import("./account/mount.on-demand")), loadAccount()]).then(([{ mountAccountCard }, session]) => {
      foot?.removeEventListener("click", claimPress, true);
      if (disposed) return;
      const mounted = mountAccountCard({ core, model: session.model, openSettings: (section) => {
        // The card is a summary: choosing its home must uncover Settings, especially under the phone sidebar.
        account?.panel()?.close(false, "keyboard");
        core.stage.querySelector<HTMLButtonElement>("#sidebar-toggle[aria-expanded='true']")?.click();
        window.dispatchEvent(new CustomEvent("tracer:canvas-action", { detail: { action: `canvas:settings:${section}`, source: "pointer" } }));
      } });
      account = mounted;
      if (pressedEarly) mounted?.show();
    }, () => { foot?.removeEventListener("click", claimPress, true); /* the old menu stays: better than a dead pill */ });
  }

  return {
    canvas, sessions, connection,
    dispose() {
      versionArea?.dispose();
      account?.dispose();
      canvas.flush();
      offLook(); offLayout(); offPending?.(); pendingWatch.dispose(); pendingNotice.dispose();
      window.removeEventListener("pointerup", dropped);
      window.removeEventListener("pointercancel", dropped);
      offRoundTrip();
      setLinkRoundTrip(undefined);
      disposed = true;
      offHosts?.();
      offHostWelcome();
      window.clearTimeout(hostsFallback);
      offSessionInventory();
      offAuthorityWelcome();
      authority.dispose();
      startupHints.dispose();
      offMeshView();
      addHost.dispose(); docs.dispose();
      canvas.dispose();
      mesh.dispose();
      inventory.dispose();
      sessions.dispose();
      pool.dispose();
      connection.dispose();
    },
  };
}
