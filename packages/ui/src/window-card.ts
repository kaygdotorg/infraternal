/**
 * The one window card (D160): the framed surface every terminal, flow or tool lives in on
 * the canvas. It looks exactly like the core screen's pane card (same fill, hairline,
 * radius and shadow) and adds a quiet header: a title pill (host mark, `user@host`,
 * session, status dot) on the left and optional icon actions on the right.
 *
 * Consumers own the body: a live terminal host, a static preview or a wizard. The card
 * never measures or animates its body, so it costs nothing while idle.
 *
 * API (stable; the add-host flow uses the same card):
 *   const card = createWindowCard({ id, title, icon, status, actions, label });
 *   card.root     → mount it anywhere (canvas layer, panes)
 *   card.body     → put content here; it fills the card under the header
 *   card.pill     → the title pill button (anchor popovers to it)
 *   card.setActive(active)   → accent hairline, `aria-current`
 *   card.setTitle(title) / card.setStatus(status) / card.setIcon(svgMarkup)
 *   card.locked / card.setLocked(locked, instant?)  → the window lock (lock-toggle.ts): the persistent
 *        state lives here (`data-locked`, a stronger hairline); the consumer decides what it means
 *   card.lock            → the lock toggle, for nudges
 *   card.dispose()
 *
 * An action may carry an `alt` (#280): the same button when Option (macOS) or Alt (Windows, Linux) is held with the
 * pointer near the header's actions, or with keyboard focus on one of them. Its icon morphs into the alternative's
 * (icon-morph.ts), the warm tooltip and the accessible name change with it, and a click runs the alternative. The
 * listeners that watch for the key exist only while the pointer is over the window or focus is in the actions, so an
 * idle canvas has none running.
 */
import { createLockToggle, trackLockReveal, type LockSource, type LockToggle } from "./lock-toggle";
import { createConnectionIndicator, type ConnectionIndicator, type ConnectionIndicatorState } from "./connection-indicator";
import { createIconMorph, type IconMorph, type MorphSpec } from "./icon-morph";
import { refreshTip } from "./tooltip";
import type { AnchoredPopover } from "./anchored-popover";
import type { WindowMenuItem } from "./window-menu.on-demand";

/** `none` hides the dot: a window that is not a connection yet (a flow in progress). */
export type WindowStatus = "live" | "connecting" | "offline" | "none";

export interface WindowTitle {
  host: string;
  user?: string;
  session?: string;
}

export interface WindowAction {
  id: string;
  label: string;
  icon: string; // inner SVG markup on a 24×24 grid, stroked
  onSelect(event: MouseEvent): void;
  /** What the button does while Option (Alt) is held: its icon morphs into this one (the base icon is the morph's start). */
  alt?: { label: string; morph: MorphSpec; onSelect(event: MouseEvent): void };
}

export interface WindowCardOptions {
  id: string;
  title: WindowTitle;
  icon?: string; // full <svg> markup for the host mark
  status?: WindowStatus;
  actions?: WindowAction[];
  label?: string; // accessible name of the whole window
  /**
   * A card with no lock (default true). The lock's reveal watches every card on every pointer move (a layout read per
   * card), so a canvas that shows hundreds of cards which can never be locked (the Mesh's nodes) turns it off.
   */
  lockable?: boolean;
  /** Runs after the user (or `setLocked`) changes the lock; the card has already updated itself. */
  onLockChange?(locked: boolean, source: LockSource): void;
}

export interface WindowCard {
  readonly root: HTMLElement;
  readonly header: HTMLElement;
  readonly pill: HTMLButtonElement;
  readonly body: HTMLElement;
  readonly lock: LockToggle;
  readonly locked: boolean;
  setLocked(locked: boolean, instant?: boolean): void;
  setActive(active: boolean): void;
  setTitle(title: WindowTitle): void;
  setStatus(status: WindowStatus): void;
  /**
   * The window's link in the shared connection indicator (#212): the exact state, an optional plain reason shown after
   * "Offline.", and how many typed keys are kept for sending once the link is back. `setStatus` sets the indicator's
   * default from its three states; a caller that knows more (slow, resumed, kept keys) says so here after it.
   */
  setConnection(state: ConnectionIndicatorState, detail?: string, held?: number): void;
  setIcon(svg: string): void;
  dispose(): void;
}

/**
 * The browser-to-server round trip is one number for the whole page, so every window's indicator reads the same one: a link
 * above the indicator's threshold reads as slow in all of them at once. A card made later starts from the latest number.
 */
const indicators = new Set<ConnectionIndicator>();
let sharedRoundTrip: number | undefined;
export function setLinkRoundTrip(ms: number | undefined): void {
  sharedRoundTrip = ms;
  for (const indicator of indicators) indicator.setRoundTrip(ms);
}

const STATUS_LABEL: Record<WindowStatus, string> = { live: "connected", connecting: "reconnecting", offline: "offline", none: "" };

/** Builds a window card; nothing is attached to the document until the caller mounts `root`. */
export function createWindowCard(options: WindowCardOptions): WindowCard {
  const root = document.createElement("section");
  root.className = "ui-window";
  root.dataset.windowId = options.id;

  const header = document.createElement("header");
  header.className = "ui-window-head";

  const pill = document.createElement("button");
  pill.type = "button";
  pill.className = "ui-window-pill";
  pill.setAttribute("aria-haspopup", "dialog");
  pill.innerHTML = `<span class="ui-window-mark"></span><span class="ui-window-title"><span class="ui-window-user"></span><span class="ui-window-host"></span></span><span class="ui-window-session"></span>`;
  // One indicator per window, in the place the status dot had: the same small icon as the top pill, with its warm tooltip.
  const conn: ConnectionIndicator = createConnectionIndicator();
  conn.root.classList.add("ui-window-conn");
  pill.append(conn.root);
  indicators.add(conn);
  conn.setRoundTrip(sharedRoundTrip);
  const mark = pill.querySelector<HTMLElement>(".ui-window-mark")!;
  const user = pill.querySelector<HTMLElement>(".ui-window-user")!;
  const host = pill.querySelector<HTMLElement>(".ui-window-host")!;
  const session = pill.querySelector<HTMLElement>(".ui-window-session")!;

  const actions = document.createElement("div");
  actions.className = "ui-window-actions";
  const handlers: Array<[HTMLButtonElement, (event: MouseEvent) => void]> = [];
  const alts: Array<{ button: HTMLButtonElement; action: WindowAction & { alt: NonNullable<WindowAction["alt"]> }; morph: IconMorph }> = [];
  for (const action of options.actions ?? []) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "ui-window-action";
    button.dataset.action = action.id;
    button.setAttribute("aria-label", action.label);
    button.dataset.tip = action.label; // the warm tooltip names the control
    button.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${action.icon}</svg>`;
    const alt = action.alt;
    if (alt) alts.push({ button, action: action as (typeof alts)[number]["action"], morph: createIconMorph(button.querySelector("svg")!, alt.morph) });
    // The key decides at the click itself, whatever the icon shows: a click that lands as Option is released still means what was pressed.
    // Ctrl or Meta with Alt is a different chord (AltGr on Windows reports it; Ctrl-click is a context click on a Mac).
    const handler = (event: MouseEvent): void => { if (alt && event.altKey && !event.ctrlKey && !event.metaKey) alt.onSelect(event); else action.onSelect(event); };
    button.addEventListener("click", handler);
    handlers.push([button, handler]);
    actions.append(button);
  }
  // Title first (TASTE): a header too narrow for the title and every action keeps the title. With more than one action,
  // a narrow card (styles.css, a container query) shows one ⋯ instead, and the ⋯ opens the same actions in the anchored
  // popover. A card with one action never collapses (a phone header keeps its Close).
  const actionList = options.actions ?? [];
  let menu: AnchoredPopover | undefined;
  const more = document.createElement("button");
  more.type = "button";
  more.className = "ui-window-action ui-window-more";
  more.setAttribute("aria-label", "More window actions");
  more.setAttribute("aria-haspopup", "menu");
  more.dataset.tip = "More";
  more.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h.01M12 12h.01M19 12h.01"/></svg>';
  const openMenu = (event: MouseEvent): void => {
    if (menu) { menu.close("pointer"); return; }
    const source = event.detail === 0 ? "keyboard" : "pointer";
    void import("./window-menu.on-demand").then((m) => {
      if (menu) return;
      const items: WindowMenuItem[] = actionList.map((action) => ({ id: action.id, label: action.label, icon: action.icon, run: (e) => action.onSelect(e) }));
      menu = m.openWindowMenu(root, more, items, source, () => { menu = undefined; });
    });
  };
  if (actionList.length > 1) {
    actions.dataset.collapsible = "";
    actions.append(more);
    more.addEventListener("click", openMenu);
  }
  header.append(pill, actions);

  // ---- Option (Alt) turns the header's split buttons into "new window" (#280) ---------------------------------------
  // The modifier is Option on a Mac and Alt on Windows and Linux; the browser reports both as `key === "Alt"` and
  // `altKey`, so one code path serves every platform (AltGr reports "AltGraph" and never counts). The pointer being near
  // the actions pill, or keyboard focus being on one of its buttons, is what counts: the key alone, far away, changes
  // nothing. The card listens for the key only while the pointer is over the window or focus is in its actions, so an
  // idle canvas has no listener running.
  const NEAR = 28;
  let altOn = false;
  let pointer = { x: -1, y: -1 };
  let pointerIn = false;
  let focusIn = false;
  let listening = false;
  const nearActions = (): boolean => {
    // Keyboard focus (shown by the focus ring) on a button counts as "near": Tab to the button, hold Alt, press Enter.
    if (focusIn && actions.querySelector(":focus-visible")) return true;
    if (!pointerIn) return false;
    const r = actions.getBoundingClientRect();
    return pointer.x >= r.left - NEAR && pointer.x <= r.right + NEAR && pointer.y >= r.top - NEAR && pointer.y <= r.bottom + NEAR;
  };
  const setAlt = (next: boolean): void => {
    if (next === altOn) return;
    altOn = next;
    for (const { button, action, morph } of alts) {
      const label = next ? action.alt.label : action.label;
      morph.set(next);
      button.dataset.tip = label;
      button.setAttribute("aria-label", label);
      if (next) button.dataset.alt = ""; else delete button.dataset.alt;
      refreshTip(button, true);
    }
  };
  const onKey = (event: KeyboardEvent): void => {
    if (event.key !== "Alt") return;
    const near = nearActions();
    setAlt(event.altKey && near);
    // On Windows and Linux a bare Alt press that is released alone moves focus to the browser's menu. Near the buttons the
    // key means something else, so it is ours; any other time (and every Alt+key chord) it goes on as before.
    if (near) event.preventDefault();
  };
  const onBlur = (): void => setAlt(false);
  /** Key listeners exist exactly while the pointer is over the window or focus is in the actions. */
  const listen = (): void => {
    const want = pointerIn || focusIn;
    if (want === listening) return;
    listening = want;
    const toggle = want ? window.addEventListener.bind(window) : window.removeEventListener.bind(window);
    toggle("keydown", onKey as EventListener);
    toggle("keyup", onKey as EventListener);
    toggle("blur", onBlur);
    if (!want) setAlt(false);
  };
  const onEnter = (event: PointerEvent): void => {
    if (event.pointerType !== "mouse" && event.pointerType !== "pen") return;
    pointer = { x: event.clientX, y: event.clientY };
    pointerIn = true;
    listen();
    setAlt(event.altKey && nearActions());
  };
  const onMove = (event: PointerEvent): void => {
    pointer = { x: event.clientX, y: event.clientY };
    if (event.altKey || altOn) setAlt(event.altKey && nearActions());
  };
  // Leaving the window or the focus turns the buttons back, unless the other of the two still holds them.
  const onLeave = (): void => { pointerIn = false; if (altOn && !nearActions()) setAlt(false); listen(); };
  const onFocusIn = (): void => { focusIn = true; listen(); };
  const onFocusOut = (event: FocusEvent): void => {
    if (event.relatedTarget instanceof Node && actions.contains(event.relatedTarget)) return;
    focusIn = false;
    if (altOn && !nearActions()) setAlt(false);
    listen();
  };
  if (alts.length) {
    root.addEventListener("pointerenter", onEnter);
    root.addEventListener("pointermove", onMove, { passive: true });
    root.addEventListener("pointerleave", onLeave);
    actions.addEventListener("focusin", onFocusIn);
    actions.addEventListener("focusout", onFocusOut);
  }

  const body = document.createElement("div");
  body.className = "ui-window-body";
  const lockable = options.lockable !== false;
  const lock = createLockToggle({
    onToggle(next, source) { setLocked(next, source === "keyboard"); options.onLockChange?.(next, source); },
  });
  root.append(header, body);
  if (lockable) root.append(lock.root);
  const stopReveal = lockable ? trackLockReveal(root, lock) : () => undefined;
  const setLocked = (next: boolean, instant = false): void => {
    if (next === lock.locked) return;
    root.toggleAttribute("data-locked", next);
    lock.setLocked(next, instant);
  };

  let title = options.title;
  let status: WindowStatus = options.status ?? "live";
  let shownStatus: WindowStatus | undefined;
  const label = (): void => {
    const name = `${title.user ? `${title.user}@` : ""}${title.host}${title.session ? `, ${title.session}` : ""}`;
    root.setAttribute("aria-label", options.label ?? name);
    pill.setAttribute("aria-label", status === "none" ? name : `${name}, ${STATUS_LABEL[status]}. Show details`);
  };
  const setTitle = (next: WindowTitle): void => {
    title = next;
    user.textContent = next.user ? `${next.user}@` : "";
    host.textContent = next.host;
    session.textContent = next.session ?? "";
    session.hidden = !next.session;
    label();
  };
  const setStatus = (next: WindowStatus): void => {
    status = next;
    root.dataset.status = next;
    // The indicator follows the three states unless the caller then says more with `setConnection`. A repaint with the
    // same status must not undo a richer state the caller set (slow, resumed, kept keys), so it only moves on a change.
    if (next !== "none" && next !== shownStatus) conn.set(next === "live" ? "connected" : next === "connecting" ? "reconnecting" : "offline");
    shownStatus = next;
    label();
  };
  const setIcon = (svg: string): void => {
    // A setup ring over the mark (setup-ring.ts) outlives a change of icon: the host's system may be learned mid-setup.
    const ring = mark.querySelector(":scope > .ui-setup-ring");
    mark.innerHTML = svg;
    if (ring) mark.append(ring);
    mark.hidden = !svg;
  };

  setTitle(title);
  setStatus(status);
  setIcon(options.icon ?? "");

  return {
    root,
    header,
    pill,
    body,
    lock,
    get locked() { return lock.locked; },
    setLocked,
    setActive(active) {
      root.toggleAttribute("data-active", active);
      if (active) root.setAttribute("aria-current", "true");
      else root.removeAttribute("aria-current");
    },
    setTitle,
    setStatus,
    setConnection: (state: ConnectionIndicatorState, detail?: string, held?: number): void => conn.set(state, detail, held),
    setIcon,
    dispose() {
      indicators.delete(conn);
      conn.dispose();
      stopReveal();
      lock.dispose();
      menu?.close("keyboard");
      if (alts.length) {
        root.removeEventListener("pointerenter", onEnter);
        root.removeEventListener("pointermove", onMove);
        root.removeEventListener("pointerleave", onLeave);
        actions.removeEventListener("focusin", onFocusIn);
        actions.removeEventListener("focusout", onFocusOut);
        pointerIn = false;
        focusIn = false;
        listen();
        setAlt(false);
        for (const { morph } of alts) morph.dispose();
      }
      more.removeEventListener("click", openMenu);
      for (const [button, handler] of handlers) button.removeEventListener("click", handler);
      root.remove();
    },
  };
}
