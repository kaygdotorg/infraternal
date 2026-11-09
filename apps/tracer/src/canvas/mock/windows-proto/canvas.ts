/**
 * The window canvas (DECISIONS 118, 125, 158–159; prototype behind `?proto=windows`).
 *
 * Every session is a window card (packages/ui window-card) on one pannable canvas. The
 * live terminal keeps its renderer: its host element is moved into the first window, and
 * the other windows show static previews from the test double.
 *
 * Panning is one GPU transform on the canvas layer, never scrollLeft:
 * - trackpad: horizontal swipes pan anywhere, even over a terminal; vertical swipes scroll
 *   a terminal they are over and pan the canvas over gaps and headers; Shift+wheel pans
 *   horizontally; Space+drag and middle-drag pan with momentum;
 * - touch: one finger scrolls the terminal it is on (and pans over gaps), two fingers pan
 *   the canvas, a pinch changes the font size of the window under it.
 * At rest the offset snaps to whole device pixels, so text renders exactly as it does
 * outside the canvas (TASTE §5, crisp text).
 *
 * Activation: a tap or click on an inactive window only activates it (accent hairline),
 * without focusing input, so no iPhone keyboard appears; a second tap types. The header
 * pill opens the details popover (machine, connection, session).
 *
 * Lock (D160): a window can be locked. Locked, every key goes to its terminal (except ⌘K on
 * macOS and the cross-platform chord Ctrl+Shift+L), canvas gestures that start inside it are
 * ignored, and presses on other windows are ignored too, with a tiny pulse on the lock so the
 * reason is visible without any text. The rest of the canvas keeps working.
 *
 * Flows (D160): the add-host flow gets windows from this canvas (`openFlowWindow`), mounts
 * its card in the window body, and when it succeeds turns the same window into the host's
 * terminal window (`becomeHost`). New windows are placed by the canvas's own layout (one
 * row, equal widths, fixed gap, so none can overlap) and revealed with its own pan spring.
 */
import { Spring } from "../../../../../../packages/ui/src/spring";
import { createWindowCard, type WindowCard } from "../../../../../../packages/ui/src/window-card";
import { hostIconMarkup, type HostPlatform } from "../../../../../../packages/ui/src/host-icons";
import type { ToastController } from "../../../../../../packages/ui/src/toast";
import { registerShortcuts } from "../../../../../../packages/ui/src/shortcuts";
import { shortcutLabel } from "../../../../../../packages/ui/src/platform";
import { attachWindowResize, type ResizeFrame, type ResizeStart, type WindowResize, type WindowResizeHost } from "../../../../../../packages/ui/src/window-resize";
import { previewLine } from "../../windows/preview";
import { openDetailsPopover, type DetailsPopover } from "../../windows/details.on-demand";
import { prototypeFacts } from "./details-facts";
import type { BranchSection, BranchedMenu } from "../../../../../../packages/ui/src/branched";
import type { CoreScreen } from "../../../core-screen";
import { EASE_OUT } from "../../../../../../packages/ui/src/motion";

/** A session as the prototype windows show it: its name, size and age, and the lines of its screen. */
export interface CanvasSession {
  id: string;
  name: string;
  lastOutput: string;
  age: string;
  viewers: number;
  size: string;
  started: string;
  scrollback: string;
  screen: string[];
}

/** A host as the prototype windows show it. `card` is the host's window card. */
export interface CanvasHost {
  id: string;
  user: string;
  name: string;
  os: HostPlatform;
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
  sessions: CanvasSession[];
}

/** A canvas window handed to a flow: its card body is the flow's to fill until `becomeHost`. */
export interface CanvasWindowHandle {
  readonly id: string;
  readonly card: WindowCard;
}

/** A window that holds a flow. `becomeHost` turns it into a finished host's terminal window; `remove` takes it off the canvas. */
export interface CanvasFlowWindow extends CanvasWindowHandle {
  /** Turns this window into the terminal window of a finished host (title, mark, popover, preview). */
  becomeHost(host: CanvasHost): void;
  /** Takes the window off the canvas (a cancelled flow). */
  remove(): void;
}

/** The prototype canvas. Windows are addressed by id. */
export interface CanvasController {
  dispose(): void;
  /** Appends a window for a flow, activates it and pans to it. */
  openFlowWindow(spec: { title: string; icon: string }): CanvasFlowWindow;
  /** Adds a finished host's terminal window right after `after` (does not pan). Returns its handle. */
  openHostWindow(host: CanvasHost, after: string): CanvasWindowHandle;
  /** Makes the window the active one (accent hairline, capsule label); it does not pan. */
  activate(id: string): void;
  /** Pans so the window is visible; `start` puts it at the left edge, `nearest` moves minimally. */
  reveal(id: string, align?: "start" | "nearest"): void;
  /** Ids of every window in layout order. */
  windowIds(): string[];
  /** The one shared toast: every transient message on the canvas uses it, in its standard place. */
  readonly toast: ToastController;
}

/** One window on the prototype canvas, with its host, session, card and (when dragged) its own size. */
interface CanvasWindow {
  id: string;
  flow?: boolean;
  host: CanvasHost;
  session: CanvasSession;
  card: WindowCard;
  live: boolean;
  preview?: HTMLElement;
  fontSize: number;
  /** A size the user dragged this window to; windows without one follow the canvas default. */
  size?: { width: number; height: number; top: number };
  resize?: WindowResize;
}

/** The test double's endpoint for the prototype's hosts. */
const HOSTS_URL = "/__mock/proto/windows";
/** The gap between windows, in pixels. */
const GAP = 12;
/** How far in pixels a press may move and still count as a tap. */
const TAP_SLOP = 8;
/** How far in pixels a touch must travel before it counts as a pan. */
const PAN_THRESHOLD = 10;
/** How far in pixels two touches must spread or close before they count as a pinch. */
const PINCH_THRESHOLD = 24;
/** How long in milliseconds after the last movement the canvas counts as at rest. */
const REST_DELAY = 140;
/** The momentum friction: the share of speed kept each millisecond after a fling. */
const DECELERATION = 0.998;
/** Smallest dragged window: about 40 columns by 10 rows of the 14 px terminal face plus its chrome. */
const MIN_COLUMNS = 40;
/** The fewest rows a dragged window may have (see `MIN_COLUMNS`). */
const MIN_ROWS = 10;
/** The narrowest a dragged window may be, in pixels. */
const MIN_WIDTH = 260;
/** The column the docked sidebar takes from the canvas: its 292 px plus the 12 px gap (style.css). */
const DOCK_WIDTH = 292 + 12;

/** True while the primary pointer is coarse (a finger). */
const coarse = matchMedia("(pointer: coarse)");
/** True while the person asked for reduced motion. */
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");

/** Mounts the canvas into the core screen's pane area and returns its disposer. */
export function mountCanvas(core: CoreScreen, hostName: string): CanvasController {
  const stage = core.stage;
  const panes = core.panes;
  stage.dataset.canvas = "on";
  const viewport = document.createElement("div");
  viewport.className = "canvas-viewport";
  const layer = document.createElement("div");
  layer.className = "canvas-layer";
  viewport.append(layer);

  // The live terminal moves into its window; the plain pane card it lived in goes away.
  const oldCard = core.terminalHost.closest(".pane-card");
  const windows: CanvasWindow[] = [];
  let active: CanvasWindow | undefined;
  let popover: DetailsPopover | undefined;

  const events = new AbortController();
  const signal = events.signal;

  // ---- one toast, no second status surface -----------------------------------------------
  // The terminal client reports connection state and transient failures by writing text into
  // the core screen's status line. On the canvas that line is hidden (canvas.css) and its text
  // is shown through the shared toast instead, so nothing toast-like ever appears on its own.
  const toast = core.toast;
  let relaying = false;
  const relayStatus = (): void => {
    const message = core.status.textContent?.trim() ?? "";
    // Routine connection states (starting, connecting, reconnecting, resuming, resumed, paused)
    // never produce text: they belong to the status icon. Only a real failure reaches the toast.
    if (message && !/(…|\.\.\.)$/.test(message) && !/reconnect|resum|connecting|starting|paused|approximate/i.test(message)) {
      relaying = true;
      toast.show({ message, tone: /could not|failed|error|unavailable/i.test(message) ? "error" : "ok", duration: 5000 });
    } else if (relaying) {
      // Only take down a message this relay put up; a flow's own toast is not ours to dismiss.
      relaying = false;
      toast.dismiss();
    }
  };
  const statusWatch = new MutationObserver(relayStatus);
  statusWatch.observe(core.status, { childList: true, characterData: true, subtree: true });

  // ---- window lock ------------------------------------------------------------------------
  let locked: CanvasWindow | undefined;
  const insideLocked = (target: EventTarget | null): boolean => !!locked && locked.card.root.contains(target as Node | null);
  /** True (after a pulse on the lock) when a locked window means `entry` must not take input. */
  const lockedAgainst = (entry: CanvasWindow | undefined): boolean => {
    if (!locked || !entry || entry === locked) return false;
    locked.card.lock.nudge();
    return true;
  };
  const setLock = (entry: CanvasWindow, next: boolean, instant: boolean): void => {
    if (next) {
      if (locked && locked !== entry) { const previous = locked; locked = undefined; previous.card.setLocked(false, true); }
      locked = entry;
      stage.toggleAttribute("data-locked", true);
      entry.card.setLocked(true, instant);
      activate(entry, false);
      // Input goes to this window's terminal now (a phone keeps its keyboard closed until a tap).
      if (entry.live && !coarse.matches) core.terminalHost.focus({ preventScroll: true });
    } else if (locked === entry) {
      locked = undefined;
      stage.toggleAttribute("data-locked", false);
      entry.card.setLocked(false, instant);
    }
  };
  const toggleActiveLock = (instant: boolean): void => {
    if (active && !active.flow) setLock(active, locked !== active, instant);
  };
  // The cross-platform chord. It is taken before any terminal sees the key.
  window.addEventListener("keydown", (event) => {
    if (!(event.ctrlKey && event.shiftKey && !event.altKey && !event.metaKey && event.code === "KeyL")) return;
    event.preventDefault();
    event.stopPropagation();
    toggleActiveLock(true);
  }, { capture: true, signal });
  const LOCK_ICON = '<rect x="5" y="11" width="14" height="9.5" rx="2.5"/><path d="M8.5 11V8a3.5 3.5 0 0 1 7 0v3"/>';
  const UNLOCK_ICON = '<rect x="5" y="11" width="14" height="9.5" rx="2.5"/><path d="M8.5 11V7.5a3.5 3.5 0 0 1 6.6-1.6"/>';
  const removeShortcuts = registerShortcuts({ id: "canvas", title: "Canvas", area: "canvas", shortcuts: [
    { id: "lock", label: "Lock or unlock", keys: "Ctrl+Shift+L" },
    { id: "previous", label: "Previous window", keys: "Ctrl+Shift+←" },
    { id: "next", label: "Next window", keys: "Ctrl+Shift+→" },
    { id: "pan", label: "Pan sideways", keys: "Shift+Scroll" },
  ] });
  const removeProvider = core.addPaletteProvider(() => {
    if (!active || active.flow) return [];
    const isLocked = locked === active;
    return [{
      group: "Actions", glyph: "", icon: isLocked ? UNLOCK_ICON : LOCK_ICON,
      label: isLocked ? "Unlock window" : "Lock window",
      hint: shortcutLabel("Ctrl+Shift+L"),
      action: isLocked ? "proto:unlock" : "proto:lock",
    }];
  });
  window.addEventListener("tracer:canvas-action", (event) => {
    const detail = (event as CustomEvent<{ action?: string; source?: string }>).detail;
    if (detail?.action === "proto:lock" && active && !active.flow) setLock(active, true, detail.source === "keyboard");
    else if (detail?.action === "proto:unlock" && locked) setLock(locked, false, detail.source === "keyboard");
  }, { signal });

  // ---- offset, springs and rest snapping ---------------------------------------------
  let x = 0, y = 0;
  let minX = 0, minY = 0;
  let moving = false;
  let restTimer = 0;
  const dpr = (): number => devicePixelRatio || 1;
  const snap = (value: number): number => Math.round(value * dpr()) / dpr();
  // The layer stays composited (will-change in canvas.css): promoting it on the first pan
  // frame and demoting it at rest re-rasterised every window and dropped frames. Text stays
  // crisp because the resting offset is always a whole number of device pixels.
  const paint = (): void => {
    moving = true;
    layer.style.transform = `translate3d(${x}px, ${y}px, 0)`;
  };
  const rest = (): void => {
    window.clearTimeout(restTimer);
    restTimer = 0;
    x = snap(x);
    y = snap(y);
    moving = false;
    layer.style.transform = `translate3d(${x}px, ${y}px, 0)`;
  };
  const restSoon = (): void => {
    window.clearTimeout(restTimer);
    restTimer = window.setTimeout(rest, REST_DELAY);
  };
  let targetX = 0, targetY = 0;
  const springX = new Spring(0, (value) => { x = value; paint(); if (Math.abs(value - targetX) < 0.01) restSoon(); }, { visualDuration: 0.28 });
  const springY = new Spring(0, (value) => { y = value; paint(); if (Math.abs(value - targetY) < 0.01) restSoon(); }, { visualDuration: 0.28 });
  const stopSprings = (): void => {
    springX.set(x, true);
    springY.set(y, true);
  };
  const clampX = (value: number): number => Math.min(0, Math.max(minX, value));
  const clampY = (value: number): number => Math.min(0, Math.max(minY, value));
  const rubber = (value: number, min: number, size: number): number => {
    const over = value > 0 ? value : value < min ? value - min : 0;
    if (!over) return value;
    const damped = (over * size * 0.55) / (size + 0.55 * Math.abs(over));
    return (value > 0 ? 0 : min) + damped;
  };
  const glideTo = (nextX: number, nextY: number, instant = false): void => {
    popover?.close("pointer");
    targetX = clampX(nextX);
    targetY = clampY(nextY);
    if (instant || reducedMotion.matches) {
      stopSprings();
      x = targetX; y = targetY;
      springX.set(x, true); springY.set(y, true);
      paint();
      rest();
      return;
    }
    springX.value = x; springY.value = y;
    springX.set(targetX);
    springY.set(targetY);
  };
  // Measured once per resize (layout()); panning never reads layout, so it cannot force
  // a synchronous reflow while terminals stream output.
  let viewWidth = 0, viewHeight = 0;
  const panBy = (dx: number, dy: number, elastic: boolean): void => {
    popover?.close("pointer");
    stopSprings();
    x = elastic ? rubber(x + dx, minX, viewWidth) : clampX(x + dx);
    y = elastic ? rubber(y + dy, minY, viewHeight) : clampY(y + dy);
    springX.set(x, true);
    springY.set(y, true);
    paint();
  };

  // ---- layout -----------------------------------------------------------------------
  // The viewport is padded by the gutter so window shadows are never clipped; all layout
  // math uses its content box.
  const inner = (): { width: number; height: number } => {
    const style = getComputedStyle(viewport);
    return {
      width: viewport.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight),
      height: viewport.clientHeight - parseFloat(style.paddingTop) - parseFloat(style.paddingBottom),
    };
  };
  // The default window width, and each window's own width (a dragged size wins).
  let baseWidth = 0;
  const widthOf = (entry: CanvasWindow): number => entry.size?.width ?? baseWidth;
  const lefts = (): number[] => {
    let left = 0;
    return windows.map((entry) => { const at = left; left += widthOf(entry) + GAP; return at; });
  };
  const contentWidth = (): number => windows.reduce((sum, entry) => sum + widthOf(entry), 0) + Math.max(0, windows.length - 1) * GAP;
  /** Writes a window's own size (or hands it back to the canvas default). One style write per window. */
  const paintSize = (entry: CanvasWindow): void => {
    const style = entry.card.root.style;
    if (!entry.size) { style.width = ""; style.height = ""; style.marginTop = ""; return; }
    style.width = `${entry.size.width}px`;
    style.height = `${entry.size.height}px`;
    style.marginTop = `${entry.size.top}px`;
  };
  const layout = (): void => {
    const rect = inner();
    viewWidth = rect.width;
    viewHeight = rect.height;
    // Window sizes follow the screen, not the room the docked sidebar leaves: opening the sidebar only
    // moves the canvas, so no window (and no terminal) is resized, re-measured and redrawn for it.
    const roomWidth = rect.width + (stage.dataset.sidebar === "docked" ? DOCK_WIDTH : 0);
    // Desktop shows two windows and a peek of the third (the canvas invites a pan);
    // phones show one window and a sliver of the next.
    const width = coarse.matches || roomWidth < 720
      ? Math.max(260, rect.width - 28)
      : Math.max(420, Math.min(860, (roomWidth - GAP * 2) / 2.25));
    const height = rect.height;
    baseWidth = Math.round(width);
    layer.style.setProperty("--window-w", `${baseWidth}px`);
    layer.style.setProperty("--window-h", `${Math.round(height)}px`);
    // A dragged size must still fit a smaller viewport.
    for (const entry of windows) {
      if (!entry.size) continue;
      const fitted = Math.min(entry.size.height, Math.round(height));
      entry.size = { width: Math.min(entry.size.width, Math.max(MIN_WIDTH, Math.round(rect.width))), height: fitted, top: Math.max(0, Math.min(entry.size.top, Math.round(height) - fitted)) };
      paintSize(entry);
    }
    // A canvas scrolled to its far end stays at its far end when the room changes (the docked sidebar takes
    // a column), so the last window is never pushed out of view; otherwise the offset is only clamped.
    const atEnd = minX < 0 && (moving ? targetX : x) <= minX + 0.5;
    minX = Math.min(0, rect.width - contentWidth());
    minY = 0;
    if (moving) {
      // A pan or glide is in flight: keep it going, only aim it at the new bounds (it rests by itself).
      targetX = atEnd ? minX : clampX(targetX);
      targetY = clampY(targetY);
      springX.set(targetX);
      springY.set(targetY);
      return;
    }
    x = atEnd ? minX : clampX(x);
    y = clampY(y);
    springX.set(x, true);
    springY.set(y, true);
    rest();
  };

  // ---- windows ----------------------------------------------------------------------
  const icons = {
    machine: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    connection: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
    session: '<path d="m5 8 4 4-4 4"/><path d="M12 16h7"/>',
  };
  const updateCapsule = (window: CanvasWindow): void => {
    const hostLabel = stage.querySelector<HTMLElement>("#capsule-host");
    // A window that only hosts a flow has no session: the capsule shows its title once.
    stage.querySelector<HTMLElement>("#capsule")?.toggleAttribute("data-flow", Boolean(window.flow));
    const sessionLabel = stage.querySelector<HTMLElement>(".capsule-session");
    // The pill shows the window's host operating system (a flow shows the add mark) instead of the dot.
    const os = stage.querySelector<HTMLElement>("#capsule-os");
    if (os) os.innerHTML = window.flow ? '<svg viewBox="0 0 24 24" aria-hidden="true" class="is-line"><path d="M12 5v14M5 12h14"/></svg>' : hostIconMarkup(window.host.os, "ui-host-mark");
    if (hostLabel) hostLabel.textContent = window.live ? hostName : `${window.host.user ? `${window.host.user}@` : ""}${window.host.name}`;
    if (sessionLabel) sessionLabel.textContent = window.flow ? "" : window.session.name;
  };
  // ---- the sidebar's host tree lists the canvas's windows ------------------------------
  // One section per host, one leaf per window (its session); the active window's row is
  // marked current. The tree is rebuilt in one microtask after any change, so a batch of
  // new windows is one rebuild; only sections that were not there before animate in.
  let tree: BranchedMenu | undefined;
  let treeQueued = false;
  let treeSeeded = false;
  const knownSections = new Set<string>();
  const syncTree = (): void => {
    treeQueued = false;
    if (signal.aborted) return;
    const order: string[] = [];
    const byHost = new Map<string, CanvasWindow[]>();
    for (const entry of windows) {
      if (entry.flow) continue;
      const list = byHost.get(entry.host.id);
      if (list) list.push(entry); else { byHost.set(entry.host.id, [entry]); order.push(entry.host.id); }
    }
    const sections: BranchSection[] = order.map((id) => {
      const list = byHost.get(id)!;
      // The tree's own current marker, branch and colour show the active row (aria-current).
      return {
        id, label: list[0]!.live ? hostName : list[0]!.host.name, live: list[0]!.host.status === "live", open: true,
        leaves: list.map((entry) => ({ id: entry.id, label: entry.session.name })),
      };
    });
    tree = core.setHostTree(sections, active && !active.flow ? active.id : "", (id) => {
      const target = windows.find((entry) => entry.id === id);
      if (!target || lockedAgainst(target)) return;
      activate(target, false);
      // The canvas's own pan brings it into view; on a phone the sheet gets out of the way.
      revealWindow(target);
      const sidebar = stage.querySelector<HTMLElement>("#sidebar");
      if (coarse.matches && sidebar && !sidebar.hidden) stage.querySelector<HTMLButtonElement>("#sidebar-toggle")?.click();
    });
    if (treeSeeded) {
      const fresh = [...stage.querySelectorAll<HTMLElement>("#tree .bm-sec")].filter((section) => !knownSections.has(section.dataset.id ?? ""));
      fresh.forEach((section, index) => {
        const height = section.offsetHeight;
        const delay = index * 45;
        if (reducedMotion.matches) {
          section.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, delay, easing: "ease", fill: "backwards" });
        } else {
          // Height and opacity together, short stagger; no fill so nothing stays clipped at rest.
          section.style.overflow = "hidden";
          const animation = section.animate([{ height: "0px", opacity: 0 }, { height: `${height}px`, opacity: 1 }],
            { duration: 260, delay, easing: EASE_OUT, fill: "backwards" });
          animation.onfinish = animation.oncancel = () => { section.style.overflow = ""; };
        }
      });
    }
    knownSections.clear();
    for (const id of order) knownSections.add(id);
  };
  const queueTree = (): void => {
    if (treeQueued) return;
    treeQueued = true;
    queueMicrotask(syncTree);
  };

  const activate = (target: CanvasWindow, reveal: boolean): void => {
    if (active === target) return;
    // Keystrokes belong to the active window only: leaving the live terminal blurs it.
    if (!target.live && core.terminalHost.contains(document.activeElement)) (document.activeElement as HTMLElement).blur();
    active?.card.setActive(false);
    active = target;
    target.card.setActive(true);
    updateCapsule(target);
    // Synchronise the tree's current row without re-notifying (a rebuild is queued by the
    // callers that change the set of windows).
    tree?.select(target.id, false, false);
    if (reveal) revealWindow(target);
  };
  const revealWindow = (target: CanvasWindow, align: "start" | "nearest" = "nearest"): void => {
    const rect = { width: viewWidth, height: viewHeight };
    const index = windows.indexOf(target);
    const left = lefts()[index] ?? 0;
    const right = left + widthOf(target);
    // Touch pages window by window, so a revealed window lands on its page position.
    if (coarse.matches || align === "start") { glideTo(-left, y); return; }
    if (left + x < 0) glideTo(-left, y);
    else if (right + x > rect.width) glideTo(rect.width - right, y);
  };
  const togglePopover = (target: CanvasWindow, source: "pointer" | "keyboard"): void => {
    if (popover?.windowId === target.id) { popover.close(source); return; }
    popover?.close("keyboard");
    popover = openDetailsPopover(stage, target.card.pill, {
      windowId: target.id,
      read: () => prototypeFacts(target.host, target.session, target.live ? hostName : target.host.name, icons),
      // `?removal=1` shows the product's destructive row so its look is reviewable here; the prototype has no host to remove.
      ...(new URLSearchParams(location.search).has("removal") ? { action: { label: "Remove host", hint: "Remove a host and uninstall its infraternal agent.", run: () => undefined } } : {}),
    }, source, () => { popover = undefined; });
  };

  // ---- resizing a window (window-resize.ts owns the gestures; this owns the geometry) ----
  // A dragged size lives on the window card itself (width, height, margin-top), so the row's
  // flex layout shifts every neighbour and none can overlap. Each frame is one style write
  // plus the layer's compositor transform. The live terminal is pinned to its starting pixel
  // size while the pointer is down, so its observer stays quiet and it refits exactly once,
  // on release, at its final size.
  const resizeHost = (entry: CanvasWindow): WindowResizeHost => {
    let startX = 0;
    const terminal = core.terminalHost;
    const unpin = (): void => { terminal.style.inset = ""; terminal.style.width = ""; terminal.style.height = ""; };
    return {
      begin(): ResizeStart {
        popover?.close("pointer");
        stopSprings();
        activate(entry, false);
        const font = coarse.matches ? 13 : 14;
        const columns = coarse.matches ? 24 : MIN_COLUMNS;
        const cell = font * 0.6, line = Math.round(font * 1.2857);
        const header = entry.card.header.offsetHeight;
        if (entry.live) {
          const box = terminal.getBoundingClientRect();
          terminal.style.inset = "0 auto auto 0";
          terminal.style.width = `${box.width}px`;
          terminal.style.height = `${box.height}px`;
        }
        startX = x;
        const maxWidth = Math.max(MIN_WIDTH, Math.round(viewWidth));
        return {
          width: widthOf(entry),
          height: entry.size?.height ?? Math.round(viewHeight),
          top: entry.size?.top ?? 0,
          minWidth: Math.min(maxWidth, Math.max(MIN_WIDTH, Math.ceil(columns * cell + 32))),
          minHeight: Math.min(Math.round(viewHeight), header + MIN_ROWS * line + 28),
          maxWidth,
          areaHeight: Math.round(viewHeight),
        };
      },
      apply(frame: ResizeFrame) {
        entry.size = { width: snap(frame.width), height: snap(frame.height), top: snap(frame.top) };
        paintSize(entry);
        minX = Math.min(0, viewWidth - contentWidth());
        // Dragging a west edge grows the window to the left: the row shifts so its right edge stays put.
        x = startX + frame.shiftX;
        paint();
      },
      end() {
        unpin();
        minX = Math.min(0, viewWidth - contentWidth());
        glideTo(x, y);
      },
      onTouchMode() { touchPan = undefined; },
    };
  };

  const attachPreview = (entry: CanvasWindow): void => {
    const preview = document.createElement("pre");
    preview.className = "canvas-preview";
    preview.setAttribute("aria-label", `Preview of ${entry.host.name}, ${entry.session.name}`);
    preview.innerHTML = entry.session.screen.map(previewLine).join("\n");
    entry.card.body.append(preview);
    entry.preview = preview;
  };
  /** Adds a window at the end of the row, or right after `after`; the DOM order is the layout order. */
  const addWindow = (host: CanvasHost, session: CanvasSession, live: boolean, after?: CanvasWindow, flow = false): CanvasWindow => {
    const card = createWindowCard({
      id: `${host.id}:${session.id}`,
      title: { host: live ? hostName : host.name, ...(host.user ? { user: host.user } : {}), ...(flow ? {} : { session: session.name }) },
      icon: hostIconMarkup(host.os, "ui-host-mark"),
      status: flow ? "none" : host.status === "live" ? "live" : "connecting",
      onLockChange: (next, source) => { if (!flow || locked === entry) setLock(entry, next, source === "keyboard"); },
    });
    const entry: CanvasWindow = { id: `${host.id}:${session.id}`, host, session, card, live, fontSize: coarse.matches ? 13 : 14, ...(flow ? { flow } : {}) };
    if (live) card.body.append(core.terminalHost);
    else if (!flow) attachPreview(entry);
    entry.resize = attachWindowResize(card, resizeHost(entry));
    card.pill.addEventListener("click", (event) => {
      if (lockedAgainst(entry)) return;
      activate(entry, false);
      // A window still hosting a flow has no machine to describe yet.
      if (!entry.flow) togglePopover(entry, event.detail === 0 ? "keyboard" : "pointer");
    }, { signal });
    const index = after ? windows.indexOf(after) + 1 : windows.length;
    layer.insertBefore(card.root, windows[index]?.card.root ?? null);
    windows.splice(index, 0, entry);
    return entry;
  };
  const enter = (entry: CanvasWindow, delay = 0): void => {
    if (reducedMotion.matches) return;
    // No fill: nothing stays transformed at rest, so text keeps rendering crisp.
    entry.card.root.animate([{ opacity: 0, transform: "translateY(10px) scale(0.985)" }, { opacity: 1, transform: "none" }],
      { duration: 280, delay, easing: EASE_OUT, fill: "backwards" });
  };
  let serial = 0;
  const hostFromFixture = (id: string, name: string): CanvasHost => ({
    id, user: "", name, os: "unknown", osName: "", version: "", architecture: "", model: "", cpu: "", cores: 0, memory: 0, disk: 0,
    uptime: "", load: "", kernel: "", init: "", virtualization: "", shell: "", locale: "", ips: [], engines: [], mode: "rootless", status: "live",
    connection: { route: "", transport: "", mesh: "", certificate: "", roundTrip: "", bytes: "", reconnects: 0 }, sessions: [],
  });
  const shellSession = (host: CanvasHost): CanvasSession => ({
    id: "shell", name: "SSH shell", lastOutput: "", age: "just now", viewers: 1, size: "", started: "Just now", scrollback: "",
    screen: [[[host.osName, host.version].filter(Boolean).join(" "), host.architecture].filter(Boolean).join(" · "), "", `${host.user}@${host.name}:~$ `],
  });

  // The live window first, so the terminal is never without a frame.
  const liveHost: CanvasHost = {
    id: "live", user: "", name: hostName, os: "unknown", osName: "Linux", version: "", architecture: "", model: "", cpu: "",
    cores: 0, memory: 0, disk: 0, uptime: "", load: "", kernel: "", init: "", virtualization: "", shell: "", locale: "",
    ips: [], engines: [], mode: "root", status: "live",
    connection: { route: "", transport: "", mesh: "", certificate: "", roundTrip: "", bytes: "", reconnects: 0 },
    sessions: [],
  };
  const liveSession: CanvasSession = { id: "shell", name: "SSH shell", lastOutput: "", age: "", viewers: 1, size: "", started: "", scrollback: "", screen: [] };
  const liveWindow = addWindow(liveHost, liveSession, true);
  oldCard?.remove();
  panes.append(viewport);
  activate(liveWindow, false);
  layout();
  syncTree();

  void fetch(HOSTS_URL, { credentials: "same-origin" }).then((response) => response.ok ? response.json() : undefined)
    .then((data: { hosts?: CanvasHost[] } | undefined) => {
      if (signal.aborted) return;
      if (!data?.hosts?.length) { treeSeeded = true; return; }
      // The live window borrows the first host's machine facts so its details are complete.
      const [first, ...rest] = data.hosts;
      Object.assign(liveHost, { ...first!, id: "live", name: hostName, sessions: [] });
      liveWindow.card.setIcon(hostIconMarkup(liveHost.os, "ui-host-mark"));
      liveWindow.card.setTitle({ host: hostName, user: liveHost.user, session: liveSession.name });
      if (active === liveWindow) updateCapsule(liveWindow);
      // Inserted after the live window in order, ahead of any flow window already open.
      let anchor = liveWindow;
      for (const host of [first!, ...rest]) anchor = addWindow(host, host.sessions[0]!, false, anchor);
      layout();
      // Windows inserted ahead of a flow window push it to the right; keep it in view.
      if (active && active !== liveWindow) revealWindow(active, "start");
      syncTree();
      treeSeeded = true;
    })
    .catch(() => undefined);

  // ---- activation without focus -------------------------------------------------------
  let tap: { window: CanvasWindow; id: number; x: number; y: number } | undefined;
  let swallowClick = false;
  const windowOf = (target: EventTarget | null): CanvasWindow | undefined => {
    const root = (target as Element | null)?.closest?.(".ui-window");
    return windows.find((entry) => entry.card.root === root);
  };
  // A tap or click on empty canvas (a gap, outside every window) leaves no window active: no
  // accent border anywhere, and keys go to canvas navigation instead of a terminal. A locked
  // window keeps its input, so the lock is the only way to give it up.
  let emptyTap: { id: number; x: number; y: number } | undefined;
  const clearActive = (): void => {
    if (locked || !active) return;
    if (core.terminalHost.contains(document.activeElement)) (document.activeElement as HTMLElement).blur();
    active.card.setActive(false);
    active = undefined;
    popover?.close("pointer");
  };
  // Decided by the pointer's coordinates, not its target: a fingertip's hit-test snaps to the
  // nearest window content, so a tap in a 12 px gap would otherwise read as a tap on a window.
  const inAnyWindow = (x: number, y: number): boolean => windows.some((entry) => {
    const box = entry.card.root.getBoundingClientRect();
    return x >= box.left && x <= box.right && y >= box.top && y <= box.bottom;
  });
  viewport.addEventListener("pointerdown", (event) => {
    if (!inAnyWindow(event.clientX, event.clientY)) {
      if (event.button === 0) emptyTap = { id: event.pointerId, x: event.clientX, y: event.clientY };
      return;
    }
    const target = windowOf(event.target);
    if (!target) return;
    // The lock acts for itself, on any window: one click focuses that window and locks it (moving a
    // lock from another window), so it must not be swallowed as the "first touch activates" press.
    if ((event.target as Element).closest(".ui-window-lock")) return;
    // A locked window keeps the input: presses elsewhere are ignored, with a pulse on the lock.
    if (lockedAgainst(target) && !(event.target as Element).closest(".ui-window-head")) { event.preventDefault(); event.stopPropagation(); return; }
    if (target === active) return;
    if ((event.target as Element).closest(".ui-window-head, .ui-window-resize")) return; // the pill and the handles act for themselves
    // First touch on an inactive window: claim it so the terminal neither focuses nor
    // opens the keyboard; the release activates it if the finger did not move.
    event.preventDefault();
    event.stopPropagation();
    tap = { window: target, id: event.pointerId, x: event.clientX, y: event.clientY };
  }, { capture: true, signal });
  viewport.addEventListener("pointerup", (event) => {
    if (emptyTap && emptyTap.id === event.pointerId) {
      const moved = Math.hypot(event.clientX - emptyTap.x, event.clientY - emptyTap.y) > TAP_SLOP;
      emptyTap = undefined;
      if (!moved && !twoFinger && !spaceHeld) clearActive();
      return;
    }
    if (!tap || tap.id !== event.pointerId) return;
    const moved = Math.hypot(event.clientX - tap.x, event.clientY - tap.y) > TAP_SLOP;
    if (!moved && !twoFinger) {
      activate(tap.window, true);
      swallowClick = true;
    }
    tap = undefined;
    event.stopPropagation();
  }, { capture: true, signal });
  viewport.addEventListener("pointercancel", () => { tap = undefined; emptyTap = undefined; }, { capture: true, signal });
  viewport.addEventListener("click", (event) => {
    if (!swallowClick) return;
    swallowClick = false;
    event.preventDefault();
    event.stopPropagation();
  }, { capture: true, signal });
  // Clicking a window body that is already active still marks it active (no-op) and lets
  // the terminal take focus as usual.

  // ---- trackpad and wheel -------------------------------------------------------------
  const inScrollableBody = (target: EventTarget | null): HTMLElement | undefined => {
    const element = target as Element | null;
    return element?.closest?.<HTMLElement>(".terminal-host, .canvas-preview, [data-canvas-scroll]") ?? undefined;
  };
  viewport.addEventListener("wheel", (event) => {
    if (event.ctrlKey) return; // browser zoom / trackpad pinch stays with the browser
    // Inside a locked window the wheel is the terminal's alone: it never pans (or later zooms) the canvas.
    if (insideLocked(event.target)) return;
    const horizontal = event.shiftKey ? event.deltaY || event.deltaX : event.deltaX;
    const vertical = event.shiftKey ? 0 : event.deltaY;
    const overBody = inScrollableBody(event.target);
    if (Math.abs(horizontal) > Math.abs(vertical)) {
      panBy(-horizontal, 0, false);
      restSoon();
      event.preventDefault();
      event.stopPropagation();
    } else if (!overBody && vertical) {
      // Over gaps and headers a vertical swipe moves along the canvas.
      panBy(minY < 0 ? 0 : -vertical, minY < 0 ? -vertical : 0, false);
      restSoon();
      event.preventDefault();
      event.stopPropagation();
    }
  }, { capture: true, passive: false, signal });

  // ---- Space+drag and middle-drag -----------------------------------------------------
  let spaceHeld = false;
  window.addEventListener("keydown", (event) => {
    if (event.code !== "Space" || event.repeat || locked) return;
    const typing = (event.target as Element | null)?.closest?.("input, textarea, [contenteditable], .terminal-host");
    if (!typing) { spaceHeld = true; viewport.dataset.grab = "ready"; }
  }, { signal });
  window.addEventListener("keyup", (event) => {
    if (event.code === "Space") { spaceHeld = false; delete viewport.dataset.grab; }
  }, { signal });

  type Sample = { t: number; x: number; y: number };
  let drag: { id: number; lastX: number; lastY: number; samples: Sample[] } | undefined;
  const velocity = (samples: Sample[]): { vx: number; vy: number } => {
    const now = samples.at(-1);
    const from = samples.find((sample) => now && now.t - sample.t <= 90) ?? samples[0];
    if (!now || !from || now.t === from.t) return { vx: 0, vy: 0 };
    return { vx: ((now.x - from.x) / (now.t - from.t)) * 1000, vy: ((now.y - from.y) / (now.t - from.t)) * 1000 };
  };
  const project = (v: number): number => (v / 1000) * DECELERATION / (1 - DECELERATION);
  // Touch pans page window by window: the projected landing point picks the direction, but
  // one gesture moves at most one window from where it started (a flick never skips ahead).
  const release = (vx: number, vy: number, snapToWindows: boolean, originX = x): void => {
    let nextX = x + project(vx);
    const nextY = y + project(vy);
    if (snapToWindows) {
      // Windows can have different widths, so snap to the nearest window's left edge.
      const stops = lefts();
      const nearest = (at: number): number => stops.reduce((best, stop, index) => Math.abs(stop + at) < Math.abs((stops[best] ?? 0) + at) ? index : best, 0);
      const origin = nearest(originX);
      const wanted = nearest(nextX);
      nextX = -(stops[Math.max(origin - 1, Math.min(origin + 1, wanted))] ?? 0);
    }
    glideTo(nextX, nextY);
  };
  viewport.addEventListener("pointerdown", (event) => {
    if (event.pointerType === "touch") return;
    const middle = event.button === 1;
    if (!middle && !(spaceHeld && event.button === 0)) return;
    if (insideLocked(event.target)) return;
    event.preventDefault();
    event.stopPropagation();
    viewport.setPointerCapture(event.pointerId);
    viewport.dataset.grab = "dragging";
    stopSprings();
    drag = { id: event.pointerId, lastX: event.clientX, lastY: event.clientY, samples: [{ t: event.timeStamp, x: event.clientX, y: event.clientY }] };
  }, { capture: true, signal });
  viewport.addEventListener("pointermove", (event) => {
    if (!drag || drag.id !== event.pointerId) return;
    panBy(event.clientX - drag.lastX, event.clientY - drag.lastY, true);
    drag.lastX = event.clientX;
    drag.lastY = event.clientY;
    drag.samples.push({ t: event.timeStamp, x: event.clientX, y: event.clientY });
    if (drag.samples.length > 12) drag.samples.shift();
  }, { signal });
  const endDrag = (event: PointerEvent): void => {
    if (!drag || drag.id !== event.pointerId) return;
    const { vx, vy } = velocity(drag.samples);
    drag = undefined;
    viewport.dataset.grab = spaceHeld ? "ready" : "";
    if (!spaceHeld) delete viewport.dataset.grab;
    release(vx, vy, false);
  };
  viewport.addEventListener("pointerup", endDrag, { signal });
  viewport.addEventListener("pointercancel", endDrag, { signal });
  viewport.addEventListener("auxclick", (event) => { if (event.button === 1) event.preventDefault(); }, { signal });

  // ---- touch: one finger on gaps, two fingers anywhere, pinch for font size -----------
  let twoFinger = false;
  let touchPan: { mode: "undecided" | "pan" | "pinch" | "single"; cx: number; cy: number; spread: number; startCx: number; startCy: number; samples: Sample[]; window?: CanvasWindow; baseFont: number; originX: number } | undefined;
  const midpoint = (touches: TouchList): { cx: number; cy: number; spread: number } => {
    const a = touches[0]!, b = touches[1]!;
    return { cx: (a.clientX + b.clientX) / 2, cy: (a.clientY + b.clientY) / 2, spread: Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY) };
  };
  viewport.addEventListener("touchstart", (event) => {
    if (insideLocked(event.target)) return; // canvas gestures that start in a locked window are ignored
    stopSprings();
    if (event.touches.length === 2) {
      twoFinger = true;
      tap = undefined;
      const { cx, cy, spread } = midpoint(event.touches);
      const target = windowOf(event.target);
      touchPan = { mode: "undecided", cx, cy, spread, startCx: cx, startCy: cy, samples: [{ t: event.timeStamp, x: cx, y: cy }], baseFont: target?.fontSize ?? 14, originX: x, ...(target ? { window: target } : {}) };
    } else if (event.touches.length === 1 && !inScrollableBody(event.target) && !(event.target as Element).closest("button, .ui-window-resize")) {
      const touch = event.touches[0]!;
      touchPan = { mode: "single", cx: touch.clientX, cy: touch.clientY, spread: 0, startCx: touch.clientX, startCy: touch.clientY, samples: [{ t: event.timeStamp, x: touch.clientX, y: touch.clientY }], baseFont: 14, originX: x };
    }
  }, { capture: true, passive: true, signal });
  viewport.addEventListener("touchmove", (event) => {
    if (!touchPan) return;
    if (touchPan.mode === "single") {
      const touch = event.touches[0];
      if (!touch || event.touches.length !== 1) return;
      panBy(touch.clientX - touchPan.cx, touch.clientY - touchPan.cy, true);
      touchPan.cx = touch.clientX;
      touchPan.cy = touch.clientY;
      touchPan.samples.push({ t: event.timeStamp, x: touch.clientX, y: touch.clientY });
      if (touchPan.samples.length > 12) touchPan.samples.shift();
      event.preventDefault();
      return;
    }
    if (event.touches.length !== 2) return;
    const { cx, cy, spread } = midpoint(event.touches);
    if (touchPan.mode === "undecided") {
      const travelled = Math.hypot(cx - touchPan.startCx, cy - touchPan.startCy);
      const stretched = Math.abs(spread - touchPan.spread);
      if (stretched > PINCH_THRESHOLD && stretched > travelled) touchPan.mode = "pinch";
      else if (travelled > PAN_THRESHOLD) touchPan.mode = "pan";
      else { event.preventDefault(); event.stopPropagation(); return; }
    }
    if (touchPan.mode === "pinch") {
      // The live terminal pinches itself (terminal-touch.ts); previews change size here.
      const target = touchPan.window;
      if (target?.preview) {
        const size = Math.round(Math.min(24, Math.max(9, touchPan.baseFont * (spread / touchPan.spread))) * 2) / 2;
        target.fontSize = size;
        target.preview.style.setProperty("--preview-font", `${size}px`);
        event.preventDefault();
      }
      return;
    }
    panBy(cx - touchPan.cx, cy - touchPan.cy, true);
    touchPan.cx = cx;
    touchPan.cy = cy;
    touchPan.samples.push({ t: event.timeStamp, x: cx, y: cy });
    if (touchPan.samples.length > 12) touchPan.samples.shift();
    event.preventDefault();
    event.stopPropagation();
  }, { capture: true, passive: false, signal });
  const touchEnd = (event: TouchEvent): void => {
    if (!touchPan) return;
    if (event.touches.length > 0 && touchPan.mode !== "single") return;
    const mode = touchPan.mode;
    const originX = touchPan.originX;
    const { vx, vy } = velocity(touchPan.samples);
    touchPan = undefined;
    window.setTimeout(() => { twoFinger = false; }, 0);
    if (mode === "pan" || mode === "single") release(vx, vy, true, originX);
  };
  viewport.addEventListener("touchend", touchEnd, { capture: true, signal });
  viewport.addEventListener("touchcancel", touchEnd, { capture: true, signal });

  // ---- keyboard: move between windows -------------------------------------------------
  window.addEventListener("keydown", (event) => {
    if (!(event.ctrlKey && event.shiftKey) || (event.key !== "ArrowLeft" && event.key !== "ArrowRight") || locked) return;
    const index = active ? windows.indexOf(active) : 0;
    const next = windows[Math.max(0, Math.min(windows.length - 1, index + (event.key === "ArrowRight" ? 1 : -1)))];
    if (!next) return;
    event.preventDefault();
    activate(next, false);
    revealWindow(next);
  }, { capture: true, signal });

  const resizeObserver = new ResizeObserver(() => layout());
  resizeObserver.observe(viewport);

  // Test hook (mock mode only): lets browser tests read the offset and stream output.
  (window as unknown as { __tracerCanvas?: unknown }).__tracerCanvas = {
    offset: () => ({ x, y, minX, minY, moving, transform: layer.style.transform, willChange: layer.style.willChange }),
    active: () => active?.id,
    windows: () => windows.map((entry) => entry.id),
    stream(lines: number) {
      for (const entry of windows) {
        if (!entry.preview) continue;
        const text = `${entry.host.user}@${entry.host.name}:~$ tail -f build.log · line ${lines}`;
        entry.preview.insertAdjacentHTML("beforeend", `\n${previewLine(text)}`);
        while (entry.preview.childNodes.length > 400) entry.preview.firstChild?.remove();
        entry.preview.scrollTop = entry.preview.scrollHeight;
      }
    },
  };

  const byId = (id: string): CanvasWindow | undefined => windows.find((entry) => entry.id === id);
  const flowWindow = (entry: CanvasWindow): CanvasFlowWindow => ({
    id: entry.id,
    card: entry.card,
    becomeHost(host) {
      const session = host.sessions[0] ?? shellSession(host);
      entry.flow = false;
      entry.host = host;
      entry.session = session;
      entry.card.setIcon(hostIconMarkup(host.os, "ui-host-mark"));
      entry.card.setTitle({ host: host.name, user: host.user, session: session.name });
      entry.card.setStatus(host.status === "live" ? "live" : "connecting");
      entry.card.root.dataset.windowId = entry.id;
      attachPreview(entry);
      if (active === entry) updateCapsule(entry);
      queueTree();
    },
    remove() {
      const index = windows.indexOf(entry);
      if (index < 0) return;
      windows.splice(index, 1);
      if (popover?.windowId === entry.id) popover.close("keyboard");
      if (active === entry) { active = undefined; const next = windows[Math.max(0, index - 1)]; if (next) activate(next, false); }
      entry.resize?.dispose();
      entry.card.dispose();
      layout();
      queueTree();
    },
  });
  const controller: CanvasController = {
    openFlowWindow(spec) {
      // A flow is something the person asked for: it ends a lock rather than being refused by it.
      if (locked) setLock(locked, false, true);
      const host = hostFromFixture(`new-${++serial}`, spec.title);
      const entry = addWindow(host, { ...shellSession(host), id: "flow", name: "Add hosts" }, false, undefined, true);
      entry.card.setIcon(spec.icon);
      layout();
      activate(entry, false);
      updateCapsule(entry);
      enter(entry);
      revealWindow(entry, "start");
      return flowWindow(entry);
    },
    openHostWindow(host, after) {
      const anchor = byId(after);
      const session = host.sessions[0] ?? shellSession(host);
      const entry = addWindow(host, session, false, anchor);
      layout();
      queueTree();
      enter(entry, 120);
      return { id: entry.id, card: entry.card };
    },
    activate(id) {
      const target = byId(id);
      if (target) activate(target, false);
    },
    reveal(id, align = "nearest") {
      const target = byId(id);
      if (target) revealWindow(target, align);
    },
    windowIds: () => windows.map((entry) => entry.id),
    toast,
    dispose() {
      events.abort();
      removeProvider();
      removeShortcuts();
      statusWatch.disconnect();
      resizeObserver.disconnect();
      popover?.close("keyboard");
      for (const entry of windows) { entry.resize?.dispose(); entry.card.dispose(); }
      viewport.remove();
      delete stage.dataset.canvas;
      delete (window as unknown as { __tracerCanvas?: unknown }).__tracerCanvas;
    },
  };
  return controller;
}
