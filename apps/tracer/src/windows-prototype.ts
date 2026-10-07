/** Mounts the mock-only window canvas and its machine, session, and promotion states. */
import {
  confirmAction,
  copyFeedback,
  installStretchingCapsule,
  refreshTip,
  showTip,
  swapIcon,
  type BranchSection,
  type HostPlatform,
  type StretchingCapsule,
  HOST_ICON_PATHS,
  hostIconMarkup,
} from "../../../packages/ui/src/index";
import type { CorePaletteEntry, CoreScreen, CoreScreenTab } from "./core-screen";

type Session = {
  id: string;
  name: string;
  lastOutput: string;
  age: string;
  viewers: number;
  size: string;
  fresh: boolean;
  busyProgram?: string;
  started: string;
  scrollback: string;
  screen: string[];
};

type Host = {
  id: string;
  user: string;
  name: string;
  os: Exclude<HostPlatform, "unknown">;
  osName: string;
  version: string;
  architecture: string;
  model: string;
  cpu: string;
  cores: number;
  memory: number;
  disk: number;
  uptime: string;
  load: string;
  kernel: string;
  init: string;
  virtualization: string;
  shell: string;
  locale: string;
  ips: string[];
  engines: string[];
  mode: "rootless" | "root";
  status: "live" | "reconnecting";
  connection: {
    route: string;
    transport: string;
    mesh: string;
    certificate: string;
    roundTrip: string;
    bytes: string;
    reconnects: number;
  };
  sessions: Session[];
};

type ViewNode = { kind: "view"; view: WindowView } | { kind: "split"; axis: "vertical" | "horizontal"; children: ViewNode[] };
type Group = { host: Host; element: HTMLElement; views: WindowView[]; root: ViewNode };
type WindowView = {
  id: string;
  hostId: string;
  sessionId: string;
  group: Group;
  card: HTMLElement;
  fakeTerminal: HTMLElement;
  fakeOutput: HTMLPreElement;
  fontSize: number;
  realTerminal?: HTMLElement;
};
type InfoTab = "machine" | "connection" | "session";
type PromotionState = "idle" | "running" | "done";
type EndTarget = { hostId: string; sessionId: string };

const HOSTS_URL = "/__mock/proto/windows";
const WINDOW_ICONS = {
  vertical: '<rect x="4" y="5" width="7" height="14" rx="1.4"/><rect x="13" y="5" width="7" height="14" rx="1.4"/>',
  horizontal: '<rect x="4" y="5" width="16" height="6" rx="1.4"/><rect x="4" y="13" width="16" height="6" rx="1.4"/>',
  sessions: '<rect x="5" y="4" width="14" height="16" rx="2"/><path d="M8 8h8M8 12h5M8 16h8"/>',
  previous: '<path d="M19 12H5m6-6-6 6 6 6"/>',
  next: '<path d="M5 12h14m-6-6 6 6-6 6"/>',
  overview: '<rect x="4" y="4" width="7" height="7" rx="1.3"/><rect x="13" y="4" width="7" height="7" rx="1.3"/><rect x="4" y="13" width="7" height="7" rx="1.3"/><rect x="13" y="13" width="7" height="7" rx="1.3"/>',
  machine: '<rect x="4" y="5" width="16" height="12" rx="2"/><path d="M8 20h8m-4-3v3"/>',
  connection: '<path d="M8.5 15.5 6 18a3 3 0 0 1-4-4l4-4a3 3 0 0 1 4 0m5-1.5L17.5 6a3 3 0 0 1 4 4l-4 4a3 3 0 0 1-4 0m-8 2 9-9"/>',
  session: WINDOW_ICONS_PATH_SESSION(),
  share: '<circle cx="18" cy="5" r="2.3"/><circle cx="6" cy="12" r="2.3"/><circle cx="18" cy="19" r="2.3"/><path d="m8.1 10.9 7.7-4.7M8.1 13.1l7.7 4.7"/>',
  copy: '<rect x="8" y="3" width="12" height="16" rx="2"/><path d="M16 5H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2v-2"/>',
  download: '<path d="M12 4v11m-4-4 4 4 4-4M5 18v2h14v-2"/>',
  close: '<path d="m6 6 12 12M18 6 6 18"/>',
  edit: '<path d="M12 20h9m-4.5-16.5 4 4L8 20l-5 1 1-5Z"/>',
  end: '<path d="M6 7h12M9 7V4h6v3m-7 0 1 13h6l1-13M10 11v5m4-5v5"/>',
} as const;

function WINDOW_ICONS_PATH_SESSION(): string {
  return '<path d="M5 6h14M5 12h14M5 18h14"/><circle cx="8" cy="6" r="1"/><circle cx="16" cy="12" r="1"/><circle cx="10" cy="18" r="1"/>';
}

const $ = <T extends HTMLElement>(root: ParentNode, selector: string): T => {
  const element = root.querySelector<T>(selector);
  if (!element) throw new Error(`Windows prototype is missing ${selector}`);
  return element;
};
const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (char) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;",
}[char]!));
const clamp = (value: number, minimum: number, maximum: number): number => Math.max(minimum, Math.min(maximum, value));
const icon = (paths: string): string => `<svg viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>`;
const hostById = (hosts: Host[], id: string): Host => {
  const host = hosts.find((candidate) => candidate.id === id);
  if (!host) throw new Error(`Prototype host ${id} is unavailable`);
  return host;
};
const sessionById = (host: Host, id: string): Session => {
  const session = host.sessions.find((candidate) => candidate.id === id);
  if (!session) throw new Error(`Prototype session ${id} is unavailable on ${host.name}`);
  return session;
};

/** Builds all mock-only windows from the test double while retaining the real first terminal. */
export async function mountWindowsPrototype(core: CoreScreen): Promise<{ dispose(): void }> {
  const response = await fetch(HOSTS_URL, { cache: "no-store" });
  if (!response.ok) throw new Error("The windows prototype fixtures are unavailable");
  const payload = await response.json() as { hosts?: unknown };
  if (!Array.isArray(payload.hosts) || payload.hosts.length !== 4) throw new Error("The windows prototype needs four host fixtures");
  const hosts = payload.hosts as Host[];
  const stage = core.stage;
  const panes = $(stage, ".panes");
  const originalCard = core.terminalHost.closest<HTMLElement>(".pane-card");
  if (!originalCard) throw new Error("The existing terminal pane is missing");

  const groups: Group[] = [];
  const views: WindowView[] = [];
  let active: WindowView | undefined;
  let overview = false;
  let viewSerial = 0;
  let sessionSerial = 2;
  let managerHostId = "";
  let infoHostId = "";
  let activeInfoTab: InfoTab = "machine";
  let activePopoverAnchor: HTMLElement | null = null;
  let capsule: StretchingCapsule | undefined;
  let liveMetricTimer = 0;
  let promotionTimer = 0;
  let popoverCloseTimer = 0;
  let promotionState: PromotionState = "idle";
  let promotionActivity: string[] = [];
  let ending: EndTarget | undefined;
  let sessionGesture: { pointerId: number; x: number; startedAt: number; row: HTMLElement } | undefined;
  let canvasPointer: { id: number; x: number; y: number; left: number; top: number; moved: boolean } | undefined;
  let ignoreNextStageClick = false;
  let ignoredClickTimer = 0;
  let touchGesture: {
    ids: [number, number];
    x: number;
    y: number;
    distance: number;
    left: number;
    top: number;
    fontSize: number;
    mode: "pending" | "pan" | "pinch";
    samples: Array<{ at: number; x: number; y: number }>;
  } | undefined;
  let momentumFrame = 0;
  let canvasResizeObserver: ResizeObserver | undefined;
  let spaceHeld = false;
  let disposed = false;
  const listeners: Array<() => void> = [];
  const suppressNextStageClick = (): void => {
    ignoreNextStageClick = true;
    window.clearTimeout(ignoredClickTimer);
    ignoredClickTimer = window.setTimeout(() => { ignoreNextStageClick = false; ignoredClickTimer = 0; }, 450);
  };

  stage.classList.add("has-windows-prototype");
  panes.dataset.windowCanvas = "true";
  const createView = (group: Group, session: Session, real = false, existingCard?: HTMLElement): WindowView => {
    const viewId = `window-${++viewSerial}`;
    const card = existingCard ?? document.createElement("section");
    card.className = "pane-card window-card";
    card.dataset.windowId = viewId;
    card.dataset.hostId = group.host.id;
    card.setAttribute("role", "group");
    const terminalHost = real ? core.terminalHost : undefined;
    const fakeTerminal = document.createElement("div");
    fakeTerminal.className = "window-fake-terminal";
    fakeTerminal.setAttribute("role", "application");
    const output = document.createElement("pre");
    output.className = "window-fake-output";
    fakeTerminal.append(output);
    const view: WindowView = { id: viewId, hostId: group.host.id, sessionId: session.id, group, card, fakeTerminal, fakeOutput: output, fontSize: 12, ...(terminalHost ? { realTerminal: terminalHost } : {}) };
    renderWindow(view, session);
    views.push(view);
    group.views.push(view);
    return view;
  };

  function makeHeader(view: WindowView): HTMLElement {
    const host = hostById(hosts, view.hostId);
    const header = document.createElement("header");
    header.className = "window-header";
    header.dataset.hostId = host.id;
    const pill = document.createElement("button");
    pill.type = "button";
    pill.className = "window-host-pill ui-pill ui-overlay-surface";
    pill.dataset.windowAction = "info";
    pill.setAttribute("aria-haspopup", "dialog");
    pill.setAttribute("aria-label", `Machine information for ${host.user}@${host.name}`);
    pill.dataset.tip = `Machine information · ${host.user}@${host.name}`;
    const hostLabel = document.createElement("span");
    hostLabel.className = "window-pill-host";
    hostLabel.textContent = `${host.user}@${host.name}`;
    const sessionLabel = document.createElement("span");
    sessionLabel.className = "window-pill-session";
    sessionLabel.dataset.windowSession = "true";
    const divider = document.createElement("span");
    divider.className = "window-pill-divider";
    divider.setAttribute("aria-hidden", "true");
    divider.textContent = "·";
    const promotion = document.createElement("span");
    promotion.className = "window-promotion-mark";
    promotion.setAttribute("aria-hidden", "true");
    promotion.hidden = host.id !== "edge-arm" || promotionState === "idle";
    if (!promotion.hidden) {
      promotion.dataset.state = promotionState;
      if (promotionState === "done") promotion.innerHTML = icon('<path d="m5 12 4 4L19 6"/>');
    }
    const status = document.createElement("span");
    status.className = `dot ${host.status === "live" ? "live" : "connecting"}`;
    status.dataset.windowStatus = "true";
    status.setAttribute("aria-hidden", "true");
    pill.append(
      document.createRange().createContextualFragment(hostIconMarkup(host.os, "os-mark window-os-mark")),
      hostLabel,
      divider,
      sessionLabel,
      promotion,
      status,
    );
    const actions = document.createElement("div");
    actions.className = "window-header-actions";
    actions.append(
      actionButton("Split vertically", "split-vertical", WINDOW_ICONS.vertical),
      actionButton("Split horizontally", "split-horizontal", WINDOW_ICONS.horizontal),
      actionButton("Manage sessions", "sessions", WINDOW_ICONS.sessions),
    );
    header.append(pill, actions);
    return header;
  }

  function renderWindow(view: WindowView, session: Session): void {
    const host = hostById(hosts, view.hostId);
    view.card.replaceChildren(makeHeader(view));
    if (view.realTerminal) {
      view.realTerminal.classList.add("window-real-terminal");
      // Keep the real renderer mounted for the product integration, while the mock fixture supplies every prototype screen.
      view.realTerminal.hidden = true;
      view.card.append(view.realTerminal);
    }
    view.fakeOutput.textContent = session.screen.join("\n");
    view.fakeTerminal.style.setProperty("--window-terminal-font-size", `${view.fontSize}px`);
    view.fakeTerminal.setAttribute("aria-label", `Terminal output for ${session.name} on ${host.name}`);
    view.fakeTerminal.hidden = false;
    view.card.append(view.fakeTerminal);
    view.card.setAttribute("aria-label", `${host.user}@${host.name}, ${session.name} terminal window`);
    view.card.querySelector<HTMLElement>("[data-window-session]")!.textContent = session.name;
    view.card.dataset.sessionId = session.id;
  }

  function actionButton(label: string, action: string, paths: string): HTMLButtonElement {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "window-header-action ui-icon-button";
    button.dataset.windowAction = action;
    button.setAttribute("aria-label", label);
    button.dataset.tip = label;
    button.innerHTML = icon(paths);
    return button;
  }

  const firstHost = hosts[0]!;
  for (const [index, host] of hosts.entries()) {
    const groupElement = document.createElement("section");
    groupElement.className = "window-group";
    groupElement.dataset.hostId = host.id;
    groupElement.setAttribute("aria-label", `${host.user}@${host.name} windows`);
    const group: Group = { host, element: groupElement, views: [], root: { kind: "split", axis: "vertical", children: [] } };
    groups.push(group);
    const card = index === 0 ? originalCard : undefined;
    const view = createView(group, host.sessions[0]!, index === 0, card);
    group.root = { kind: "view", view };
  }
  panes.replaceChildren(...groups.map((group) => group.element));
  for (const group of groups) renderGroup(group);
  const syncCanvasHeight = (): void => panes.style.setProperty("--window-canvas-height", `${panes.clientHeight}px`);
  syncCanvasHeight();
  canvasResizeObserver = new ResizeObserver(syncCanvasHeight);
  canvasResizeObserver.observe(panes);
  active = views[0];

  const popover = document.createElement("section");
  popover.className = "window-popover ui-overlay-surface";
  popover.dataset.overlaySize = "large";
  popover.hidden = true;
  popover.setAttribute("role", "dialog");
  popover.setAttribute("aria-label", "Window details");
  const shareLayer = document.createElement("div");
  shareLayer.className = "window-share-layer";
  shareLayer.hidden = true;
  shareLayer.setAttribute("role", "dialog");
  shareLayer.setAttribute("aria-modal", "true");
  shareLayer.setAttribute("aria-label", "Share machine details");
  shareLayer.innerHTML = `<div class="window-share-scrim" data-share-close></div>
    <section class="window-share-sheet ui-overlay-surface" data-overlay-size="large">
      <header class="window-share-heading"><h2>Share this machine</h2><button class="window-panel-close ui-icon-button" type="button" data-share-close aria-label="Close share card">${icon(WINDOW_ICONS.close)}</button></header>
      <canvas class="window-share-card" width="720" height="720" aria-label="Machine share card"></canvas>
      <label class="window-share-ips"><input type="checkbox" data-share-ips> Include IP addresses</label>
      <div class="window-share-actions">
        <button class="window-share-action ui-button" type="button" data-share-action="image" aria-label="Copy share card image">${swapIcon(WINDOW_ICONS.copy)}<span>Copy image</span></button>
        <button class="window-share-action ui-button" type="button" data-share-action="text" aria-label="Copy machine details as text">${swapIcon(WINDOW_ICONS.copy)}<span>Copy text</span></button>
        <button class="window-share-action ui-button" type="button" data-share-action="download" aria-label="Download share card image">${swapIcon(WINDOW_ICONS.download)}<span>Save image</span></button>
      </div>
      <p class="window-share-status" role="status" aria-live="polite"></p>
    </section>`;
  const endLayer = document.createElement("div");
  endLayer.className = "window-end-layer";
  endLayer.hidden = true;
  endLayer.setAttribute("role", "dialog");
  endLayer.setAttribute("aria-modal", "true");
  endLayer.setAttribute("aria-labelledby", "window-end-title");
  endLayer.innerHTML = `<div class="window-end-scrim" data-end-close></div><section class="window-end-card ui-overlay-surface" data-overlay-size="large">
    <h2 id="window-end-title">End session?</h2><p class="window-end-message"></p>
    <div class="window-end-actions"><button type="button" class="window-end-cancel ui-button" data-end-close>Keep session</button><button type="button" class="window-end-confirm ui-button">End session</button></div>
  </section>`;
  document.body.append(popover, shareLayer, endLayer);
  const shareCanvas = $(shareLayer, "canvas") as HTMLCanvasElement;
  const copyAnnouncement = document.createElement("p");
  copyAnnouncement.className = "window-copy-announcement";
  copyAnnouncement.setAttribute("role", "status");
  copyAnnouncement.setAttribute("aria-live", "polite");
  document.body.append(copyAnnouncement);

  function sessionFor(view: WindowView): Session { return sessionById(hostById(hosts, view.hostId), view.sessionId); }
  function stackRows(node: ViewNode): number {
    if (node.kind === "view") return 1;
    const rows = node.children.map(stackRows);
    return node.axis === "horizontal" ? rows.reduce((sum, count) => sum + count, 0) : Math.max(...rows, 1);
  }
  function renderNode(node: ViewNode): HTMLElement {
    if (node.kind === "view") return node.view.card;
    const split = document.createElement("div");
    split.className = "window-split";
    split.dataset.axis = node.axis;
    split.style.setProperty("--window-node-rows", String(stackRows(node)));
    for (const child of node.children) split.append(renderNode(child));
    return split;
  }
  function renderGroup(group: Group): void {
    const rows = stackRows(group.root);
    group.element.dataset.stacked = String(rows > 1);
    group.element.style.setProperty("--window-stack-rows", String(rows));
    group.element.replaceChildren(renderNode(group.root));
  }
  function addSplit(node: ViewNode, targetId: string, fresh: WindowView, axis: "vertical" | "horizontal"): { node: ViewNode; added: boolean } {
    if (node.kind === "view" && node.view.id === targetId) {
      return { node: { kind: "split", axis, children: [node, { kind: "view", view: fresh }] }, added: true };
    }
    if (node.kind === "split") {
      for (const [index, child] of node.children.entries()) {
        const result = addSplit(child, targetId, fresh, axis);
        if (result.added) {
          node.children[index] = result.node;
          return { node, added: true };
        }
      }
    }
    return { node, added: false };
  }

  function updateViewSession(view: WindowView, session: Session): void {
    view.sessionId = session.id;
    renderWindow(view, session);
  }

  function treeSections(): BranchSection[] {
    return hosts.map((host) => ({
      id: host.id,
      label: host.name,
      meta: `${host.sessions.length} sessions`,
      live: host.status === "live",
      icon: { path: HOST_ICON_PATHS[host.os] },
      open: true,
      leaves: host.sessions.map((session) => ({
        id: `${host.id}:${session.id}`,
        label: session.name,
        glyph: "›_",
        meta: session.viewers ? `${session.viewers} ${session.viewers === 1 ? "viewer" : "viewers"}` : "",
      })),
    }));
  }

  let hostTree = core.setHostTree(treeSections(), `${firstHost.id}:${firstHost.sessions[0]!.id}`, (id) => {
    const [hostId, sessionId] = id.split(":");
    if (!hostId || !sessionId) return;
    const host = hostById(hosts, hostId);
    const view = active?.hostId === hostId ? active : groupFor(hostId).views[0];
    if (!view) return;
    updateViewSession(view, sessionById(host, sessionId));
    setActiveView(view, "smooth");
  });

  function groupFor(hostId: string): Group {
    const group = groups.find((candidate) => candidate.host.id === hostId);
    if (!group) throw new Error(`Prototype group ${hostId} is unavailable`);
    return group;
  }
  function syncTree(): void {
    // Re-syncing the selected leaf must not call back into setActiveView.
    hostTree.select(`${active!.hostId}:${active!.sessionId}`, true, false);
  }
  function syncTabs(): void {
    const tabs: CoreScreenTab[] = views.map((view) => ({
      id: view.id,
      host: hostById(hosts, view.hostId).name,
      session: sessionFor(view).name,
    }));
    core.setTabs(tabs, active!.id, (id, instant) => {
      const view = views.find((candidate) => candidate.id === id);
      if (view) setActiveView(view, instant ? "auto" : "smooth");
    });
    core.setPrototypePalette(paletteEntries());
  }
  function syncIdentity(): void {
    const host = hostById(hosts, active!.hostId);
    const session = sessionFor(active!);
    core.setIdentity(`${host.user}@${host.name}`, session.name, host.status === "live");
    active!.card.classList.add("is-active");
    for (const view of views) {
      view.card.classList.toggle("is-active", view === active);
      view.card.setAttribute("aria-current", String(view === active));
    }
  }
  function setActiveView(view: WindowView, behavior: ScrollBehavior): void {
    active = view;
    for (const candidate of views) {
      if (candidate.realTerminal && candidate !== view) candidate.realTerminal.hidden = true;
      if (candidate !== view) candidate.fakeTerminal.hidden = false;
    }
    if (popoverOpen()) closePopover(false);
    const groupLeft = view.group.element.offsetLeft;
    panes.scrollTo({ left: groupLeft, behavior });
    view.card.scrollIntoView({ block: "nearest", inline: "nearest", behavior });
    syncIdentity();
    syncTree();
    syncTabs();
  }
  function focusActiveTerminal(view: WindowView): void {
    if (view.realTerminal) {
      view.fakeTerminal.hidden = true;
      view.realTerminal.hidden = false;
      core.terminalHost.focus({ preventScroll: true });
      return;
    }
    view.fakeTerminal.tabIndex = 0;
    view.fakeTerminal.focus({ preventScroll: true });
  }

  function openHost(host: Host, behavior: ScrollBehavior = "smooth"): void {
    const view = groupFor(host.id).views[0];
    if (view) setActiveView(view, behavior);
  }
  function splitView(view: WindowView, axis: "vertical" | "horizontal", session?: Session, behavior: ScrollBehavior = "smooth"): void {
    const fresh = createView(view.group, session ?? sessionFor(view));
    const result = addSplit(view.group.root, view.id, fresh, axis);
    if (!result.added) return;
    view.group.root = result.node;
    renderGroup(view.group);
    setActiveView(fresh, behavior);
  }
  function toggleOverview(force = !overview): void {
    overview = force;
    if (overview) panes.dataset.overview = "true";
    else delete panes.dataset.overview;
    for (const button of stage.querySelectorAll<HTMLButtonElement>("[data-proto-control='overview']")) {
      button.setAttribute("aria-pressed", String(overview));
    }
  }

  function paletteEntries(): CorePaletteEntry[] {
    const hostEntries = hosts.map((host) => ({
      group: "Hosts", glyph: "◉", label: `${host.user}@${host.name}`, hint: `${host.osName} · ${host.sessions[0]?.name ?? "no sessions"}`,
      action: `proto:host:${host.id}`,
    }));
    const sessionEntries = hosts.flatMap((host) => host.sessions.map((session) => ({
      group: "Sessions", glyph: "›_", label: session.name, hint: `${host.user}@${host.name} · ${session.lastOutput}`,
      action: `proto:session:${host.id}:${session.id}`,
    })));
    const actions: CorePaletteEntry[] = [
      { group: "Actions", glyph: "◫", label: "Window overview", hint: "See each host column", action: "proto:overview" },
      { group: "Actions", glyph: "▣", label: "Split vertically", hint: "Split this window beside itself", action: "proto:split:vertical" },
      { group: "Actions", glyph: "▤", label: "Split horizontally", hint: "Split this window below itself", action: "proto:split:horizontal" },
      { group: "Actions", glyph: "☷", label: "Manage sessions", hint: `Sessions on ${active ? hostById(hosts, active.hostId).name : "host"}`, action: "proto:manager" },
      { group: "Actions", glyph: "▣", label: "Machine information", hint: `Fastfetch details for ${active ? hostById(hosts, active.hostId).name : "host"}`, action: "proto:machine" },
      { group: "Actions", glyph: "↗", label: "Share machine", hint: "IP addresses hidden by default", action: "proto:share" },
      { group: "Actions", glyph: "↟", label: promotionState === "done" ? "Root infraternal agent ready" : "Simulate root promotion", hint: "mock mode only", action: "proto:promotion" },
    ];
    return [...hostEntries, ...sessionEntries, ...actions];
  }
  core.setPrototypePalette(paletteEntries());

  function findViewForHost(hostId: string): WindowView | undefined {
    return groupFor(hostId).views.find((view) => view === active) ?? groupFor(hostId).views[0];
  }
  function attachSession(host: Host, session: Session, behavior: ScrollBehavior = "smooth"): void {
    const view = findViewForHost(host.id);
    if (!view) return;
    updateViewSession(view, session);
    setActiveView(view, behavior);
    closePopover(false);
  }

  const tabLabels: Record<InfoTab, { title: string; icon: string }> = {
    machine: { title: "Machine", icon: WINDOW_ICONS.machine },
    connection: { title: "Connection", icon: WINDOW_ICONS.connection },
    session: { title: "Session", icon: WINDOW_ICONS.session },
  };
  function factsMarkup(rows: Array<[string, string]>): string {
    return rows.map(([label, value]) => `<div class="machine-fact ui-data-row">
      <span class="machine-key ui-data-key">${escapeHtml(label)}</span><button type="button" class="machine-value ui-data-value" data-copy-value="${escapeHtml(value)}" aria-label="Copy ${escapeHtml(label)}: ${escapeHtml(value)}">
        <span class="machine-value-text">${escapeHtml(value)}</span>${copyFeedbackMark()}</button></div>`).join("");
  }
  function renderMachine(host: Host, more: boolean): string {
    // Keep Intel's family/model token on phone widths; the vendor prefix adds no useful detail.
    const rows: Array<[string, string]> = [
      ["Kernel", host.kernel],
      ["Architecture", host.architecture],
      ["Model", host.model],
      ["CPU", `${host.cpu.replace(/^Intel\s+Core\s+/i, "")} · ${host.cores} cores`],
      ["Uptime", host.uptime],
      ["Load", host.load],
      ["Agent mode", host.mode],
      ["Engines", host.engines.join(" · ")],
    ];
    if (more) rows.push(["Init", host.init], ["Virtualization", host.virtualization], ["Shell", host.shell], ["Locale", host.locale], ["IP addresses", host.ips.join(" · ")]);
    return `<div class="machine-content" data-host-id="${escapeHtml(host.id)}">
      <div class="machine-heading">
        <div class="machine-logo">${hostIconMarkup(host.os, "os-mark machine-os-mark")}</div>
        <button type="button" class="machine-value ui-data-value machine-os-title" data-copy-value="${escapeHtml(`${host.osName} ${host.version}`)}" aria-label="Copy operating system: ${escapeHtml(`${host.osName} ${host.version}`)}">
          <span class="machine-value-text">${escapeHtml(`${host.osName} ${host.version}`)}</span>${copyFeedbackMark()}</button>
      </div>
      <div class="machine-facts">${factsMarkup(rows)}</div>
      <div class="machine-metrics">
        ${metricMarkup("Memory", host.memory, "memory")}
        ${metricMarkup("Disk", host.disk, "disk")}
      </div>
      <div class="machine-footer"><button type="button" class="machine-more ui-button" data-info-action="more" aria-expanded="${String(more)}">${more ? "Less" : "More"}</button><button type="button" class="machine-share ui-button" data-info-action="share">${icon(WINDOW_ICONS.share)}<span>Share</span></button></div>
      <p class="window-copy-announcement" role="status" aria-live="polite"></p>
    </div>`;
  }
  /** D103's row-end confirmation is a tick only; idle clipboard glyphs are deliberately absent. */
  function copyFeedbackMark(): string {
    return swapIcon("");
  }
  function metricMarkup(label: string, amount: number, id: "memory" | "disk"): string {
    const visible = `${amount}% used`;
    return `<div class="machine-metric ui-data-row" data-metric="${id}">
      <span class="machine-key ui-data-key">${label}</span><button type="button" class="machine-value ui-data-value" data-copy-value="${visible}" aria-label="Copy ${label.toLowerCase()} use: ${visible}">
        <span class="machine-value-text">${visible}</span>${copyFeedbackMark()}</button>
      <div class="machine-metric-track" role="progressbar" aria-label="${label} used" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${amount}"><span style="width:${amount}%"></span></div></div>`;
  }
  function renderConnection(host: Host): string {
    const connection = host.connection;
    return `<div class="connection-facts">
      ${factsMarkup([
        ["Route", connection.route], ["Transport", connection.transport], ["Mesh", connection.mesh],
        ["Certificate", connection.certificate], ["Round trip", connection.roundTrip], ["Traffic", connection.bytes],
        ["Reconnects", String(connection.reconnects)],
      ])}
      <p class="window-copy-announcement" role="status" aria-live="polite"></p>
    </div>`;
  }
  function renderSessionInfo(host: Host, session: Session): string {
    const activity = host.id === "edge-arm" ? promotionActivity : [];
    return `<div class="session-info-facts">
      ${factsMarkup([["Session", session.name], ["Started", session.started], ["Age", session.age], ["Viewers", String(session.viewers)], ["Size", session.size], ["Scrollback", session.scrollback], ["Last output", session.lastOutput]])}
      ${activity.length ? `<div class="session-activity">${activity.map((entry) => `<p>${escapeHtml(entry)}</p>`).join("")}</div>` : ""}
      <p class="window-copy-announcement" role="status" aria-live="polite"></p>
    </div>`;
  }
  let machineMore = false;
  let touchCopyTap: { target: HTMLElement; x: number; y: number; at: number } | undefined;
  function renderInfoBody(): void {
    if (!popoverOpen() || popover.dataset.kind !== "info") return;
    const host = hostById(hosts, infoHostId);
    const view = active?.hostId === infoHostId ? active : findViewForHost(infoHostId);
    if (!view) return;
    const body = $(popover, ".window-popover-body");
    body.innerHTML = activeInfoTab === "machine" ? renderMachine(host, machineMore)
      : activeInfoTab === "connection" ? renderConnection(host)
        : renderSessionInfo(host, sessionFor(view));
    positionPopover();
  }
  function openInfo(anchor: HTMLElement, tab: InfoTab = "machine", behavior: ScrollBehavior = "smooth"): void {
    const viewCard = anchor.closest<HTMLElement>(".window-card");
    const view = views.find((candidate) => candidate.id === viewCard?.dataset.windowId) ?? active;
    if (!view) return;
    if (popoverOpen() && popover.dataset.kind === "info" && activePopoverAnchor === anchor) { closePopover(false); return; }
    setActiveView(view, behavior);
    infoHostId = view.hostId;
    activeInfoTab = tab;
    machineMore = false;
    popover.dataset.kind = "info";
    popover.innerHTML = `<div class="segmented-tabs window-info-tabs" role="tablist" aria-label="Window information tabs">
      <span class="segmented-capsule" aria-hidden="true"></span>
      ${Object.entries(tabLabels).map(([id, data]) => `<button type="button" class="segmented-tab" role="tab" data-tab="${id}" aria-label="${data.title}" data-tip="${data.title}">${icon(data.icon)}</button>`).join("")}
    </div><div class="window-popover-body"></div>`;
    activePopoverAnchor = anchor;
    showPopover(anchor, "info", behavior === "auto");
    capsule?.dispose();
    capsule = installStretchingCapsule($(popover, ".window-info-tabs"), tab, (id) => {
      activeInfoTab = id as InfoTab;
      machineMore = false;
      renderInfoBody();
      startMetricUpdates();
    });
    renderInfoBody();
    startMetricUpdates();
  }

  function managerMarkup(host: Host): string {
    const rows = host.sessions.map((session) => `<article class="window-session-row ui-list-row" data-session-row data-session-id="${escapeHtml(session.id)}">
      <button type="button" class="window-session-main ui-button" data-manager-action="attach" aria-label="Attach to ${escapeHtml(session.name)}">
        <span class="window-session-topline"><span class="window-session-name">${escapeHtml(session.name)}${session.fresh ? '<i class="window-new-output" aria-label="New output"></i>' : ""}</span><span class="window-session-age">${escapeHtml(session.age)}</span></span>
        <span class="window-session-output">${escapeHtml(session.lastOutput)}</span>
        <span class="window-session-meta"><span>${session.viewers} ${session.viewers === 1 ? "viewer" : "viewers"}</span><span>${escapeHtml(session.size)}</span></span>
      </button>
      <div class="window-session-row-actions">
        <button type="button" class="ui-icon-button" data-manager-action="rename" aria-label="Rename ${escapeHtml(session.name)}" data-tip="Rename session">${icon(WINDOW_ICONS.edit)}</button>
        <button type="button" class="ui-icon-button" data-manager-action="beside" aria-label="Open ${escapeHtml(session.name)} beside" data-tip="Open beside">${icon(WINDOW_ICONS.vertical)}</button>
        <button type="button" class="ui-icon-button" data-manager-action="end" aria-label="End ${escapeHtml(session.name)}" data-tip="End session">${icon(WINDOW_ICONS.end)}</button>
      </div>
      <button type="button" class="window-session-swipe-end ui-button" data-manager-action="end" aria-label="End ${escapeHtml(session.name)}">End</button>
    </article>`).join("");
    return `<div class="window-manager-heading"><div><h2>${escapeHtml(host.name)}</h2><span>${host.sessions.length} sessions</span></div><button type="button" class="window-panel-close ui-icon-button" data-manager-action="close" aria-label="Close session manager">${icon(WINDOW_ICONS.close)}</button></div>
      <div class="window-session-list">${rows || '<p class="window-session-empty">No sessions on this host.</p>'}</div>
      <button type="button" class="window-new-session ui-button" data-manager-action="new"><span class="window-new-session-plus">${icon('<path d="M12 5v14M5 12h14"/>')}</span><span><strong>New session</strong><small>Start a shell on ${escapeHtml(host.name)}</small></span></button>`;
  }
  function openManager(anchor: HTMLElement, behavior: ScrollBehavior = "smooth"): void {
    const viewCard = anchor.closest<HTMLElement>(".window-card");
    const view = views.find((candidate) => candidate.id === viewCard?.dataset.windowId) ?? active;
    if (!view) return;
    setActiveView(view, behavior);
    managerHostId = view.hostId;
    popover.dataset.kind = "manager";
    popover.innerHTML = `<div class="window-manager-body"></div>`;
    $(popover, ".window-manager-body").innerHTML = managerMarkup(hostById(hosts, managerHostId));
    activePopoverAnchor = anchor;
    showPopover(anchor, "manager", behavior === "auto");
  }
  function showPopover(anchor: HTMLElement, kind: "info" | "manager", instant = false): void {
    window.clearTimeout(popoverCloseTimer);
    popoverCloseTimer = 0;
    popover.hidden = false;
    popover.dataset.kind = kind;
    popover.dataset.openKind = instant ? "keyboard" : "pointer";
    popover.dataset.open = String(instant);
    positionPopover();
    if (!instant) requestAnimationFrame(() => { if (!popover.hidden) popover.dataset.open = "true"; });
  }
  function positionPopover(): void {
    if (popover.hidden || !activePopoverAnchor) return;
    const anchor = activePopoverAnchor.getBoundingClientRect();
    if (anchor.bottom < 0 || anchor.top > innerHeight || anchor.right < 0 || anchor.left > innerWidth) {
      closePopover(false);
      return;
    }
    const width = Math.min(420, innerWidth - 24);
    popover.style.width = `${width}px`;
    popover.style.maxHeight = `${Math.min(660, innerHeight - 24)}px`;
    const body = popover.querySelector<HTMLElement>(".window-popover-body, .window-manager-body");
    if (body) body.style.maxHeight = `${Math.max(160, innerHeight - 150)}px`;
    const left = Math.max(12, Math.min(innerWidth - width - 12, anchor.left + anchor.width / 2 - width / 2));
    const below = innerHeight - anchor.bottom - 16;
    const above = anchor.top - 20;
    const side: "bottom" | "top" = popover.offsetHeight <= below || below >= above ? "bottom" : "top";
    const top = side === "bottom" ? anchor.bottom + 10 : Math.max(12, anchor.top - popover.offsetHeight - 10);
    popover.style.left = `${left}px`;
    popover.style.top = `${top}px`;
    popover.dataset.side = side;
    popover.style.setProperty("--tail-x", `${Math.max(18, Math.min(width - 18, anchor.left + anchor.width / 2 - left))}px`);
  }
  function popoverOpen(): boolean { return !popover.hidden; }
  function stopMetricUpdates(): void {
    window.clearInterval(liveMetricTimer);
    liveMetricTimer = 0;
  }
  function updateMetric(id: "memory" | "disk"): void {
    const host = hostById(hosts, infoHostId);
    const metric = popover.querySelector<HTMLElement>(`[data-metric="${id}"]`);
    if (!metric) return;
    const amount = host[id];
    const value = `${amount}% used`;
    const copyTarget = metric.querySelector<HTMLButtonElement>(".machine-value")!;
    copyTarget.dataset.copyValue = value;
    copyTarget.setAttribute("aria-label", `Copy ${id} use: ${value}`);
    copyTarget.querySelector<HTMLElement>(".machine-value-text")!.textContent = value;
    const track = metric.querySelector<HTMLElement>(".machine-metric-track")!;
    track.setAttribute("aria-valuenow", String(amount));
    track.querySelector<HTMLElement>("span")!.style.width = `${amount}%`;
  }
  function startMetricUpdates(): void {
    stopMetricUpdates();
    if (!popoverOpen() || popover.dataset.kind !== "info" || activeInfoTab !== "machine") return;
    liveMetricTimer = window.setInterval(() => {
      const host = hostById(hosts, infoHostId);
      host.memory = Math.max(36, Math.min(88, host.memory + (host.id === "build-01" ? 1 : -1)));
      host.disk = Math.max(28, Math.min(78, host.disk + (host.id === "nix-cache" ? -1 : 1)));
      updateMetric("memory");
      updateMetric("disk");
    }, 4800);
  }
  function closePopover(restoreFocus: boolean, instant = false): void {
    if (popover.hidden) return;
    popover.dataset.open = "false";
    stopMetricUpdates();
    capsule?.dispose();
    capsule = undefined;
    const anchor = activePopoverAnchor;
    activePopoverAnchor = null;
    if (restoreFocus) anchor?.focus({ preventScroll: true });
    window.clearTimeout(popoverCloseTimer);
    popoverCloseTimer = window.setTimeout(() => {
      if (popover.dataset.open === "false") popover.hidden = true;
      popoverCloseTimer = 0;
    }, instant ? 0 : matchMedia("(prefers-reduced-motion: reduce)").matches ? 150 : 140);
  }

  function shareText(host: Host, includeIps: boolean): string {
    return [
      `${host.osName} ${host.version}`,
      `${host.user}@${host.name} · ${host.architecture}`,
      host.model,
      `${host.cpu} · ${host.cores} cores`,
      `Uptime ${host.uptime} · infraternal agent ${host.mode}`,
      ...host.engines,
      ...(includeIps ? host.ips.map((address) => `IP ${address}`) : []),
    ].join("\n");
  }
  function drawShareCard(): void {
    if (shareLayer.hidden || !active) return;
    const host = hostById(hosts, active.hostId);
    const canvasContext = shareCanvas.getContext("2d");
    if (!canvasContext) return;
    const context = canvasContext;
    const colors = getComputedStyle(stage);
    const bg = colors.getPropertyValue("--bg").trim() || "#101113";
    const fg = colors.getPropertyValue("--fg").trim() || "#ececee";
    const accent = colors.getPropertyValue("--accent").trim() || "#7a9cff";
    const gradient = context.createLinearGradient(32, 28, 688, 692);
    gradient.addColorStop(0, bg);
    gradient.addColorStop(0.53, accent);
    gradient.addColorStop(1, bg);
    context.clearRect(0, 0, 720, 720);
    context.fillStyle = gradient;
    context.fillRect(0, 0, 720, 720);
    context.fillStyle = "rgba(255,255,255,.08)";
    context.beginPath(); context.arc(600, 120, 250, 0, Math.PI * 2); context.fill();
    context.fillStyle = fg;
    context.font = "600 24px 'Geist Sans', system-ui, sans-serif";
    context.fillText("infraternal", 56, 72);
    context.globalAlpha = 0.78;
    context.font = "500 20px 'Geist Mono', monospace";
    context.fillText(host.osName, 56, 236);
    context.globalAlpha = 1;
    context.font = "600 50px 'Geist Sans', system-ui, sans-serif";
    context.fillText(host.name, 56, 306, 608);
    context.globalAlpha = 0.88;
    context.font = "450 22px 'Geist Mono', monospace";
    context.fillText(`${host.user} · ${host.architecture}`, 56, 360, 608);
    context.globalAlpha = 0.82;
    context.font = "450 18px 'Geist Mono', monospace";
    context.fillText(host.model, 56, 456, 608);
    context.fillText(`${host.cpu} · ${host.cores} cores`, 56, 492, 608);
    context.fillText(`Uptime ${host.uptime}`, 56, 528, 608);
    const includeIps = $(shareLayer, "[data-share-ips]") as HTMLInputElement;
    if (includeIps.checked) {
      context.globalAlpha = 0.72;
      context.font = "450 14px 'Geist Mono', monospace";
      context.fillText(host.ips.join(" · "), 56, 620, 608);
    }
    context.globalAlpha = 1;
    context.fillStyle = fg;
    context.globalAlpha = 0.6;
    context.font = "500 13px 'Geist Mono', monospace";
    context.fillText("MACHINE SNAPSHOT", 56, 672);
    context.globalAlpha = 1;
  }
  function openShare(): void {
    if (!active) return;
    shareLayer.hidden = false;
    ($(shareLayer, "[data-share-ips]") as HTMLInputElement).checked = false;
    $(shareLayer, ".window-share-status").textContent = "IP addresses are hidden by default.";
    drawShareCard();
    $(shareLayer, ".window-share-action")?.focus({ preventScroll: true });
  }
  function closeShare(): void { shareLayer.hidden = true; }
  function saveShareImage(): void {
    const host = active ? hostById(hosts, active.hostId) : undefined;
    if (!host) return;
    const link = document.createElement("a");
    link.download = `${host.name}-machine.png`;
    link.href = shareCanvas.toDataURL("image/png");
    link.click();
  }
  async function copyShareImage(button: HTMLElement): Promise<void> {
    const status = $(shareLayer, ".window-share-status");
    try {
      if (!navigator.clipboard?.write || typeof ClipboardItem === "undefined") throw new Error("Image clipboard is unavailable");
      const blob = await new Promise<Blob>((resolve, reject) => shareCanvas.toBlob((imageBlob) => imageBlob ? resolve(imageBlob) : reject(new Error("Image encoding failed")), "image/png"));
      await navigator.clipboard.write([new ClipboardItem({ "image/png": blob })]);
      confirmAction(button, "Image copied");
      status.textContent = "Machine card copied as an image.";
    } catch {
      saveShareImage();
      confirmAction(button, "Image saved");
      status.textContent = "Image clipboard is unavailable; the card was saved instead.";
    }
  }
  function createSession(host: Host): Session {
    sessionSerial += 1;
    const name = `shell-${sessionSerial}`;
    const session: Session = {
      id: `${host.id}-${name}`, name, lastOutput: "Shell ready", age: "0m", viewers: 1, size: "0 KB", fresh: false,
      started: "Just now", scrollback: "0 lines", screen: [`${host.osName} ${host.version} · ${host.architecture}`, "", `${host.user}@${host.name}:~$ _`],
    };
    host.sessions.unshift(session);
    renderManagerIfOpen(host);
    refreshTree();
    core.setPrototypePalette(paletteEntries());
    syncTabs();
    return session;
  }
  function refreshTree(): void {
    hostTree = core.setHostTree(treeSections(), `${active!.hostId}:${active!.sessionId}`, (id) => {
      const [hostId, sessionId] = id.split(":");
      if (!hostId || !sessionId) return;
      const view = findViewForHost(hostId);
      if (view) { updateViewSession(view, sessionById(hostById(hosts, hostId), sessionId)); setActiveView(view, "smooth"); }
    });
    addPromotionTreeMark();
  }
  function renderManagerIfOpen(host: Host): void {
    if (popoverOpen() && popover.dataset.kind === "manager" && managerHostId === host.id) {
      $(popover, ".window-manager-body").innerHTML = managerMarkup(host);
      positionPopover();
    }
  }
  function beginRename(host: Host, session: Session, row: HTMLElement): void {
    const name = row.querySelector<HTMLElement>(".window-session-name");
    if (!name) return;
    name.innerHTML = `<input class="window-rename-input" value="${escapeHtml(session.name)}" aria-label="Rename ${escapeHtml(session.name)}">`;
    const input = $(name, "input") as HTMLInputElement;
    input.focus();
    input.select();
    let finished = false;
    const finish = (cancel: boolean): void => {
      if (finished) return;
      finished = true;
      if (!cancel && input.value.trim()) {
        session.name = input.value.trim();
        for (const view of views.filter((candidate) => candidate.hostId === host.id && candidate.sessionId === session.id)) renderWindow(view, session);
        syncTabs();
        renderManagerIfOpen(host);
      } else {
        renderManagerIfOpen(host);
      }
    };
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") { event.preventDefault(); finish(false); }
      if (event.key === "Escape") { event.preventDefault(); finish(true); }
    });
    input.addEventListener("blur", () => finish(false), { once: true });
  }
  function askEnd(host: Host, session: Session): void {
    ending = { hostId: host.id, sessionId: session.id };
    const message = $(endLayer, ".window-end-message");
    message.textContent = session.busyProgram
      ? `${session.busyProgram} is running in '${session.name}'. End it?`
      : `End '${session.name}'? Its host-local process and scrollback will be removed.`;
    endLayer.hidden = false;
    $(endLayer, ".window-end-confirm").focus({ preventScroll: true });
  }
  function finishEnd(): void {
    if (!ending) return;
    const host = hostById(hosts, ending.hostId);
    const session = host.sessions.find((candidate) => candidate.id === ending!.sessionId);
    if (!session) { endLayer.hidden = true; ending = undefined; return; }
    host.sessions.splice(host.sessions.indexOf(session), 1);
    if (!host.sessions.length) createSession(host);
    const fallback = host.sessions[0]!;
    for (const view of views.filter((candidate) => candidate.hostId === host.id && candidate.sessionId === session.id)) updateViewSession(view, fallback);
    refreshTree();
    syncIdentity();
    syncTabs();
    endLayer.hidden = true;
    ending = undefined;
    renderManagerIfOpen(host);
  }
  function handleManagerClick(event: MouseEvent): void {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const action = target.closest<HTMLElement>("[data-manager-action]")?.dataset.managerAction;
    if (!action) return;
    if (action === "close") { closePopover(false); return; }
    const host = hostById(hosts, managerHostId);
    if (action === "new") { attachSession(host, createSession(host)); closePopover(false); return; }
    const row = target.closest<HTMLElement>("[data-session-row]");
    const sessionId = row?.dataset.sessionId;
    if (!row || !sessionId) return;
    const session = sessionById(host, sessionId);
    if (action === "attach") { attachSession(host, session); return; }
    if (action === "rename") { beginRename(host, session, row); return; }
    if (action === "beside") { if (active) splitView(active, "vertical", session); closePopover(false); return; }
    if (action === "end") askEnd(host, session);
  }
  function handlePopoverClick(event: MouseEvent): void {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const managerAction = target.closest<HTMLElement>("[data-manager-action]");
    if (managerAction) { handleManagerClick(event); return; }
    const infoAction = target.closest<HTMLElement>("[data-info-action]")?.dataset.infoAction;
    if (infoAction === "more") {
      machineMore = !machineMore;
      renderInfoBody();
      return;
    }
    if (infoAction === "share") { openShare(); return; }
    const value = target.closest<HTMLElement>("[data-copy-value]");
    if (!value) return;
    const pointerType = (event as PointerEvent).pointerType;
    const touch = pointerType === "touch" || (!pointerType && matchMedia("(pointer: coarse)").matches && event.detail !== 0);
    if (!touch) void copyValue(value, value.dataset.copyValue ?? "", event.detail === 0);
  }
  function onCopyPointerUp(event: PointerEvent): void {
    if (event.pointerType !== "touch") return;
    const target = event.target instanceof Element ? event.target.closest<HTMLElement>("[data-copy-value]") : null;
    if (!target) { touchCopyTap = undefined; return; }
    const prior = touchCopyTap;
    const elapsed = prior ? event.timeStamp - prior.at : Infinity;
    // A 350 ms / 24 px same-target pair filters scrolls; touch-action: manipulation disables iOS zoom.
    const closeEnough = prior && Math.hypot(event.clientX - prior.x, event.clientY - prior.y) <= 24;
    if (prior?.target === target && elapsed <= 350 && closeEnough) {
      touchCopyTap = undefined;
      void copyValue(target, target.dataset.copyValue ?? "", false);
      return;
    }
    // A first tap stays inert; only a nearby second tap on the same value copies.
    touchCopyTap = { target, x: event.clientX, y: event.clientY, at: event.timeStamp };
  }
  async function copyValue(element: HTMLElement, value: string, instant: boolean): Promise<void> {
    const copied = await copyFeedback(element, value, instant);
    const announcement = element.closest<HTMLElement>(".machine-content, .connection-facts, .session-info-facts")?.querySelector<HTMLElement>(".window-copy-announcement");
    if (announcement) announcement.textContent = copied ? "Copied" : "Clipboard unavailable";
    if (copied) showTip(element, "Copied");
  }

  function addPromotionTreeMark(): void {
    const head = stage.querySelector<HTMLElement>(`.bm-sec[data-id="edge-arm"] .bm-head`);
    if (!head || head.querySelector(".window-promotion-tree-mark")) return;
    const mark = document.createElement("span");
    mark.className = "window-promotion-tree-mark";
    mark.setAttribute("aria-hidden", "true");
    mark.hidden = promotionState === "idle";
    if (promotionState !== "idle") {
      mark.dataset.state = promotionState;
      if (promotionState === "done") mark.innerHTML = icon('<path d="m5 12 4 4L19 6"/>');
    }
    const meta = head.querySelector(".bm-meta");
    head.insertBefore(mark, meta);
  }
  function setPromotionMarks(state: PromotionState): void {
    promotionState = state;
    const message = state === "running"
      ? "Upgrading to a root infraternal agent: moving 2 sessions and removing user services…"
      : state === "done" ? "Root infraternal agent ready; 2 sessions moved and user services removed." : "";
    for (const mark of stage.querySelectorAll<HTMLElement>(`.window-header[data-host-id="edge-arm"] .window-promotion-mark, .bm-sec[data-id="edge-arm"] .window-promotion-tree-mark`)) {
      mark.hidden = state === "idle";
      mark.dataset.state = state;
      mark.innerHTML = state === "done" ? icon('<path d="m5 12 4 4L19 6"/>') : "";
      if (state === "idle") delete mark.dataset.tip;
      else mark.dataset.tip = message;
      refreshTip(mark);
    }
    for (const pill of stage.querySelectorAll<HTMLElement>(`.window-header[data-host-id="edge-arm"] .window-host-pill`)) {
      if (state === "idle") delete pill.dataset.tip;
      else pill.dataset.tip = message;
      refreshTip(pill);
    }
    const treeHead = stage.querySelector<HTMLElement>(`.bm-sec[data-id="edge-arm"] .bm-head`);
    if (treeHead) {
      if (state === "idle") delete treeHead.dataset.tip;
      else treeHead.dataset.tip = message;
      refreshTip(treeHead);
    }
  }
  function simulatePromotion(): void {
    if (promotionState !== "idle") return;
    setPromotionMarks("running");
    promotionTimer = window.setTimeout(() => {
      promotionTimer = 0;
      const host = hostById(hosts, "edge-arm");
      host.mode = "root";
      promotionActivity = ["Root infraternal agent ready · moved 2 sessions and removed user services"];
      setPromotionMarks("done");
      core.setPrototypePalette(paletteEntries());
      if (popoverOpen() && popover.dataset.kind === "info" && activeInfoTab === "session" && infoHostId === host.id) renderInfoBody();
    // Keep the mock operation visible long enough for the mobile tooltip long-press.
    }, 3200);
  }

  function handlePaletteAction(event: Event): void {
    if (!(event instanceof CustomEvent) || !event.detail || typeof event.detail !== "object") return;
    const detail = event.detail as { action?: unknown; source?: unknown };
    if (typeof detail.action !== "string") return;
    const action = detail.action;
    const behavior: ScrollBehavior = detail.source === "keyboard" ? "auto" : "smooth";
    if (!action.startsWith("proto:")) return;
    const [, kind, ...parts] = action.split(":");
    if (kind === "host" && parts[0]) openHost(hostById(hosts, parts[0]), behavior);
    else if (kind === "session" && parts[0] && parts[1]) attachSession(hostById(hosts, parts[0]), sessionById(hostById(hosts, parts[0]), parts[1]), behavior);
    else if (kind === "overview") toggleOverview();
    else if (kind === "split" && (parts[0] === "vertical" || parts[0] === "horizontal") && active) splitView(active, parts[0], undefined, behavior);
    else if (kind === "manager" && active) openManager(active.card.querySelector<HTMLElement>("[data-window-action='sessions']")!, behavior);
    else if (kind === "machine" && active) openInfo(active.card.querySelector<HTMLElement>("[data-window-action='info']")!, "machine", behavior);
    else if (kind === "share" && active) { openInfo(active.card.querySelector<HTMLElement>("[data-window-action='info']")!, "machine", behavior); openShare(); }
    else if (kind === "promotion") simulatePromotion();
  }

  function moveActive(direction: -1 | 1, behavior: ScrollBehavior = "smooth"): void {
    const current = views.indexOf(active!);
    const next = views[(current + direction + views.length) % views.length];
    if (next) setActiveView(next, behavior);
  }
  function addCanvasControls(): HTMLButtonElement[] {
    const tray = $(stage, ".keytray");
    const controls = [
      ["previous", "Previous window", WINDOW_ICONS.previous],
      ["next", "Next window", WINDOW_ICONS.next],
      ["overview", "Window overview", WINDOW_ICONS.overview],
    ] as const;
    const buttons = controls.map(([action, label, paths]) => {
      const button = document.createElement("button");
      button.type = "button";
      button.dataset.protoControl = action;
      button.setAttribute("aria-label", label);
      button.dataset.tip = label;
      if (action === "overview") button.setAttribute("aria-pressed", "false");
      button.innerHTML = icon(paths);
      return button;
    });
    tray.prepend(...buttons);
    return buttons;
  }
  const canvasControls = addCanvasControls();

  function onStageClick(event: MouseEvent): void {
    const target = event.target;
    if (!(target instanceof Element)) return;
    if (ignoreNextStageClick) {
      ignoreNextStageClick = false;
      window.clearTimeout(ignoredClickTimer);
      ignoredClickTimer = 0;
      return;
    }
    const control = target.closest<HTMLButtonElement>("[data-proto-control]");
    if (control) {
      const action = control.dataset.protoControl;
      if (action === "previous") moveActive(-1);
      if (action === "next") moveActive(1);
      if (action === "overview") toggleOverview();
      return;
    }
    const actionButton = target.closest<HTMLElement>("[data-window-action]");
    if (actionButton) {
      const view = views.find((candidate) => candidate.id === actionButton.closest<HTMLElement>(".window-card")?.dataset.windowId);
      if (!view) return;
      if (actionButton.dataset.windowAction === "info") openInfo(actionButton, "machine");
      else if (actionButton.dataset.windowAction === "sessions") openManager(actionButton);
      else if (actionButton.dataset.windowAction === "split-vertical") splitView(view, "vertical");
      else if (actionButton.dataset.windowAction === "split-horizontal") splitView(view, "horizontal");
      return;
    }
    const card = target.closest<HTMLElement>(".window-card");
    if (!card || target.closest("button, input, textarea, select, a, [role='button']")) return;
    const selection = window.getSelection();
    if (selection && !selection.isCollapsed && card.contains(selection.anchorNode)) return;
    const view = views.find((candidate) => candidate.id === card.dataset.windowId);
    if (!view) return;
    if (view !== active) setActiveView(view, "smooth");
    else focusActiveTerminal(view);
  }
  function onCanvasScroll(): void { if (popoverOpen()) positionPopover(); }
  function onWheel(event: WheelEvent): void {
    if (event.shiftKey) {
      panes.scrollLeft += event.deltaY || event.deltaX;
      event.preventDefault();
      return;
    }
    const terminal = event.target instanceof Element
      ? event.target.closest<HTMLElement>(".window-fake-terminal, .window-real-terminal")
      : null;
    if (!terminal && (event.deltaY || event.deltaX)) {
      panes.scrollTop += event.deltaY;
      panes.scrollLeft += event.deltaX;
      event.preventDefault();
    }
  }
  function onCanvasPointerDown(event: PointerEvent): void {
    if ((event.button !== 1 && !(spaceHeld && event.button === 0)) || !(event.target instanceof Element)) return;
    if (event.target.closest("button, input, textarea, a")) return;
    cancelAnimationFrame(momentumFrame);
    canvasPointer = { id: event.pointerId, x: event.clientX, y: event.clientY, left: panes.scrollLeft, top: panes.scrollTop, moved: false };
    panes.setPointerCapture(event.pointerId);
    stage.classList.add("is-panning-canvas");
    event.preventDefault();
  }
  function onCanvasPointerMove(event: PointerEvent): void {
    if (!canvasPointer || canvasPointer.id !== event.pointerId) return;
    if (Math.hypot(event.clientX - canvasPointer.x, event.clientY - canvasPointer.y) > 4) canvasPointer.moved = true;
    panes.scrollLeft = canvasPointer.left - (event.clientX - canvasPointer.x);
    panes.scrollTop = canvasPointer.top - (event.clientY - canvasPointer.y);
  }
  function onCanvasPointerEnd(event: PointerEvent): void {
    if (canvasPointer?.id !== event.pointerId) return;
    if (canvasPointer.moved) suppressNextStageClick();
    canvasPointer = undefined;
    stage.classList.remove("is-panning-canvas");
  }
  function onTouchStart(event: TouchEvent): void {
    // Leave single-finger input to the terminal's native scroller; the canvas only
    // claims a gesture after a second contact is present.
    if (event.touches.length < 2) return;
    // TouchList order is not stable, so retain identifiers and re-find those contacts.
    const points = [...event.touches].sort((left, right) => left.identifier - right.identifier).slice(0, 2);
    const [first, second] = points;
    if (!first || !second) return;
    cancelAnimationFrame(momentumFrame);
    const centerX = (first.clientX + second.clientX) / 2;
    const centerY = (first.clientY + second.clientY) / 2;
    touchGesture = {
      ids: [first.identifier, second.identifier],
      x: centerX,
      y: centerY,
      distance: Math.max(1, Math.hypot(second.clientX - first.clientX, second.clientY - first.clientY)),
      left: panes.scrollLeft,
      top: panes.scrollTop,
      fontSize: active?.fontSize ?? 12,
      mode: "pending",
      samples: [{ at: event.timeStamp, x: panes.scrollLeft, y: panes.scrollTop }],
    };
    event.preventDefault();
  }
  function onTouchMove(event: TouchEvent): void {
    const gesture = touchGesture;
    if (!gesture || event.touches.length < 2) return;
    const first = [...event.touches].find((point) => point.identifier === gesture.ids[0]);
    const second = [...event.touches].find((point) => point.identifier === gesture.ids[1]);
    if (!first || !second) return;
    const centerX = (first.clientX + second.clientX) / 2;
    const centerY = (first.clientY + second.clientY) / 2;
    const distance = Math.max(1, Math.hypot(second.clientX - first.clientX, second.clientY - first.clientY));
    const translation = Math.hypot(centerX - gesture.x, centerY - gesture.y);
    const distanceChange = Math.abs(distance - gesture.distance);
    // Lock the first decisive motion so finger jitter cannot turn a pan into a zoom.
    // Ignore <12 px drift; pinch needs 12% separation change (at least 14 px).
    if (gesture.mode === "pending") {
      if (distanceChange > Math.max(14, gesture.distance * 0.12)) gesture.mode = "pinch";
      else if (translation > 12) gesture.mode = "pan";
    }
    if (gesture.mode === "pan") {
      panes.scrollLeft = gesture.left - (centerX - gesture.x);
      panes.scrollTop = gesture.top - (centerY - gesture.y);
      gesture.samples.push({ at: event.timeStamp, x: panes.scrollLeft, y: panes.scrollTop });
      // A short trailing sample window captures release speed without stale motion.
      while (gesture.samples.length > 6 || (gesture.samples[0] && event.timeStamp - gesture.samples[0].at > 120)) gesture.samples.shift();
      suppressNextStageClick();
    } else if (gesture.mode === "pinch" && active) {
      active.fontSize = clamp(gesture.fontSize * distance / gesture.distance, 8, 28);
      active.fakeTerminal.style.setProperty("--window-terminal-font-size", `${active.fontSize}px`);
      if (active.realTerminal) core.setTerminalFontSize(active.fontSize);
      suppressNextStageClick();
    }
    if (gesture.mode !== "pending") event.preventDefault();
  }
  function startCanvasMomentum(vx: number, vy: number): void {
    // Velocities are sampled from canvas offsets, so their signs already match scroll.
    // Time-based decay keeps the release distance stable across frame rates.
    let previous = performance.now();
    const step = (now: number): void => {
      const elapsed = Math.min(32, now - previous);
      previous = now;
      const oldLeft = panes.scrollLeft;
      const oldTop = panes.scrollTop;
      panes.scrollLeft += vx * elapsed;
      panes.scrollTop += vy * elapsed;
      if (panes.scrollLeft === oldLeft) vx = 0;
      if (panes.scrollTop === oldTop) vy = 0;
      const decay = Math.pow(0.9, elapsed / 16);
      vx *= decay;
      vy *= decay;
      if (Math.abs(vx) < 0.025 && Math.abs(vy) < 0.025) { momentumFrame = 0; return; }
      momentumFrame = requestAnimationFrame(step);
    };
    if (Math.abs(vx) >= 0.08 || Math.abs(vy) >= 0.08) momentumFrame = requestAnimationFrame(step);
  }
  function onTouchEnd(event: TouchEvent): void {
    if (!touchGesture || event.touches.length >= 2) return;
    const gesture = touchGesture;
    touchGesture = undefined;
    if (gesture.mode !== "pan" || gesture.samples.length < 2) return;
    const last = gesture.samples.at(-1)!;
    // Use a recent interval of at least 32 ms to avoid amplifying a single noisy frame.
    const first = gesture.samples.find((sample) => last.at - sample.at >= 32) ?? gesture.samples[0]!;
    const elapsed = Math.max(1, last.at - first.at);
    startCanvasMomentum((last.x - first.x) / elapsed, (last.y - first.y) / elapsed);
    event.preventDefault();
  }
  function onGlobalKeyDown(event: KeyboardEvent): void {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    const editing = target.isContentEditable || Boolean(target.closest("input, textarea, select"));
    if (event.key === " " && !editing) {
      spaceHeld = true;
      event.preventDefault();
      return;
    }
    if (event.key === "Escape") {
      if (!shareLayer.hidden) { closeShare(); event.preventDefault(); return; }
      if (!endLayer.hidden) { endLayer.hidden = true; ending = undefined; event.preventDefault(); return; }
      if (popoverOpen()) { closePopover(true); event.preventDefault(); return; }
    }
    if (editing || event.metaKey || event.altKey) return;
    if (event.ctrlKey && event.key === "Tab") {
      event.preventDefault(); moveActive(event.shiftKey ? -1 : 1, "auto"); return;
    }
    if ((target === document.body || target === document.documentElement || target === stage || target === panes) && event.key.startsWith("Arrow")) {
      if (event.key === "ArrowLeft" || event.key === "ArrowRight") panes.scrollLeft += event.key === "ArrowLeft" ? -80 : 80;
      else panes.scrollTop += event.key === "ArrowUp" ? -80 : 80;
      event.preventDefault();
    }
  }
  function onGlobalKeyUp(event: KeyboardEvent): void {
    if (event.key !== " ") return;
    spaceHeld = false;
    event.preventDefault();
  }
  function onManagerPointerDown(event: PointerEvent): void {
    if (event.pointerType !== "touch") return;
    const target = event.target;
    if (!(target instanceof Element) || target.closest("button, input")) return;
    const row = target.closest<HTMLElement>("[data-session-row]");
    if (!row) return;
    row.setPointerCapture(event.pointerId);
    sessionGesture = { pointerId: event.pointerId, x: event.clientX, startedAt: event.timeStamp, row };
  }
  function onManagerPointerMove(event: PointerEvent): void {
    if (!sessionGesture || sessionGesture.pointerId !== event.pointerId) return;
    const delta = event.clientX - sessionGesture.x;
    if (delta < -34) {
      sessionGesture.row.dataset.swiped = "true";
      if (delta < -70) event.preventDefault();
    } else if (delta > 34) delete sessionGesture.row.dataset.swiped;
  }
  function onManagerPointerEnd(event: PointerEvent): void {
    if (sessionGesture?.pointerId !== event.pointerId) return;
    const gesture = sessionGesture;
    sessionGesture = undefined;
    const distance = event.clientX - gesture.x;
    const elapsed = Math.max(1, event.timeStamp - gesture.startedAt);
    const shouldEnd = distance < -72 || (distance < -24 && -distance / elapsed > 0.11);
    const host = hostById(hosts, managerHostId);
    if (shouldEnd) {
      const session = host.sessions.find((candidate) => candidate.id === gesture.row.dataset.sessionId);
      if (session) askEnd(host, session);
      delete gesture.row.dataset.swiped;
      event.preventDefault();
    } else if (distance < -34) {
      gesture.row.dataset.swiped = "true";
    } else if (distance > 34) {
      delete gesture.row.dataset.swiped;
    }
  }
  function onManagerPointerCancel(event: PointerEvent): void {
    if (sessionGesture?.pointerId !== event.pointerId) return;
    delete sessionGesture.row.dataset.swiped;
    sessionGesture = undefined;
  }
  function onDocumentPointerDown(event: PointerEvent): void {
    if (shareLayer.hidden && endLayer.hidden && popoverOpen() && !popover.contains(event.target as Node) && !activePopoverAnchor?.contains(event.target as Node)) closePopover(false);
  }
  function onShareClick(event: MouseEvent): void {
    const target = event.target;
    if (!(target instanceof Element)) return;
    if (target.closest("[data-share-close]")) { closeShare(); return; }
    if (target.matches("[data-share-ips]")) { drawShareCard(); return; }
    const button = target.closest<HTMLElement>("[data-share-action]");
    if (!button) return;
    if (button.dataset.shareAction === "image") void copyShareImage(button);
    else if (button.dataset.shareAction === "text" && active) {
      const textButton = button.querySelector<HTMLElement>(".swap") ?? button;
      void copyFeedback(textButton, shareText(hostById(hosts, active.hostId), ($(shareLayer, "[data-share-ips]") as HTMLInputElement).checked));
      $(shareLayer, ".window-share-status").textContent = "Machine details copied as text.";
    } else if (button.dataset.shareAction === "download") { saveShareImage(); confirmAction(button, "Image saved"); }
  }
  function onEndClick(event: MouseEvent): void {
    const target = event.target;
    if (!(target instanceof Element)) return;
    if (target.closest("[data-end-close]")) { endLayer.hidden = true; ending = undefined; return; }
    if (target.closest(".window-end-confirm")) finishEnd();
  }

  const registrations: Array<[EventTarget, string, EventListener, AddEventListenerOptions | boolean | undefined]> = [
    [stage, "click", onStageClick as EventListener, undefined],
    [popover, "click", handlePopoverClick as EventListener, undefined],
    [popover, "pointerdown", onManagerPointerDown as EventListener, undefined],
    [popover, "pointermove", onManagerPointerMove as EventListener, undefined],
    [popover, "pointerup", onCopyPointerUp as EventListener, undefined],
    [popover, "pointerup", onManagerPointerEnd as EventListener, undefined],
    [popover, "pointercancel", onManagerPointerCancel as EventListener, undefined],
    [shareLayer, "click", onShareClick as EventListener, undefined],
    [shareLayer, "change", onShareClick as EventListener, undefined],
    [endLayer, "click", onEndClick as EventListener, undefined],
    [document, "pointerdown", onDocumentPointerDown as EventListener, true],
    [document, "keydown", onGlobalKeyDown as EventListener, true],
    [document, "keyup", onGlobalKeyUp as EventListener, true],
    [panes, "scroll", onCanvasScroll as EventListener, { passive: true }],
    [panes, "wheel", onWheel as EventListener, { passive: false }],
    [panes, "pointerdown", onCanvasPointerDown as EventListener, undefined],
    [panes, "pointermove", onCanvasPointerMove as EventListener, undefined],
    [panes, "pointerup", onCanvasPointerEnd as EventListener, undefined],
    [panes, "pointercancel", onCanvasPointerEnd as EventListener, undefined],
    [panes, "touchstart", onTouchStart as EventListener, { passive: false }],
    [panes, "touchmove", onTouchMove as EventListener, { passive: false }],
    [panes, "touchend", onTouchEnd as EventListener, { passive: false }],
    [window, "resize", positionPopover as EventListener, { passive: true }],
    [window, "tracer:proto-action", handlePaletteAction as EventListener, undefined],
  ];
  for (const [target, name, handler, options] of registrations) {
    target.addEventListener(name, handler, options);
    listeners.push(() => target.removeEventListener(name, handler, options));
  }
  const shareResize = (): void => { if (!shareLayer.hidden) drawShareCard(); };
  window.addEventListener("resize", shareResize, { passive: true });
  listeners.push(() => window.removeEventListener("resize", shareResize));
  const touchViewport = window.visualViewport;
  if (touchViewport) {
    touchViewport.addEventListener("resize", positionPopover, { passive: true });
    listeners.push(() => touchViewport.removeEventListener("resize", positionPopover));
  }
  const controlCleanup = (): void => { for (const button of canvasControls) button.remove(); };
  listeners.push(controlCleanup);

  addPromotionTreeMark();
  syncIdentity();
  syncTabs();

  return {
    dispose() {
      if (disposed) return;
      disposed = true;
      window.clearInterval(liveMetricTimer);
      window.clearTimeout(promotionTimer);
      window.clearTimeout(ignoredClickTimer);
      cancelAnimationFrame(momentumFrame);
      canvasResizeObserver?.disconnect();
      capsule?.dispose();
      for (const remove of listeners) remove();
      for (const view of views) {
        view.card.classList.remove("is-active");
        view.card.removeAttribute("aria-current");
      }
      panes.removeAttribute("data-window-canvas");
      delete panes.dataset.overview;
      stage.classList.remove("has-windows-prototype", "is-panning-canvas");
      popover.remove();
      shareLayer.remove();
      endLayer.remove();
      copyAnnouncement.remove();
    },
  };
}
