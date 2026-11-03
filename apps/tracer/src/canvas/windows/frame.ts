/**
 * The window frame on the canvas: making a window card for a model, activating it, grabbing it by its pill to
 * move it, and resizing it (D159, D160, D177).
 *
 * - Activation: a press on a window makes it the active one (accent hairline) without focusing input, so no
 *   on-screen keyboard appears; the second press types. The binding is told, so the session can take focus.
 * - The pill moves the window (`move.on-demand.ts`); it opens nothing. A touch long-press on a terminal's pill shows where
 *   its host can reach (the mesh module, when there is one).
 * - Resizing is the shared engine in packages/ui (`window-resize.ts`); here it sets the column width and the
 *   window height. Split windows share their column and are not resizable on their own.
 * - App-window shape fitting uses this same resize host from its on-demand body.
 * - The window's kind decides its actions: only a terminal has split controls, only terminals and logs close.
 */
import { createWindowCard, type WindowAction } from "../../../../../packages/ui/src/window-card";
import { attachWindowResize, type ResizeFrame, type ResizeStart, type WindowResizeHost } from "../../../../../packages/ui/src/window-resize";
import type { Ctx, ViewRec, WinRec } from "../context";
import type { WindowModel } from "../model/types";
import { ICON, SESSION_ICON, iconFor } from "../views/icons";
import { openWindowDocs } from "./docs-action";
import { isInteractive, isTerminal, makeBody } from "../views/body";
import { onDemand, whenIdle } from "../../on-demand";
import { coarse } from "../dom";
import { scrollerOf } from "../layout/columns";
import { drawnWidthOf, setColumnWidth } from "../layout/column-els";
import { maxColumnWidth } from "../window-sizes";
import { currentUiScale } from "../../../../../packages/ui/src/ui-scale";
import { RecentList } from "../recency";

/**
 * Moving a window is not part of the first screen: its code is its own chunk (D188). It is fetched as soon as the page is idle after the
 * first window is made (within 200 ms), and again (a no-op once it is there) on the first press of a pill, so a drag finds it loaded.
 */
let moveChunk: Promise<typeof import("./move.on-demand")> | undefined;
const loadMove = (): Promise<typeof import("./move.on-demand")> => (moveChunk ??= onDemand(() => import("./move.on-demand")));

export function makeWindow(cx: Ctx, c: ViewRec, m: WindowModel): WinRec {
  const actions: WindowAction[] = [];
  const rec: WinRec = {} as WinRec;
  if (!moveChunk) whenIdle(() => void loadMove(), 200);
  // The window's kind decides what it can do: only a terminal has a split control.
  const readOnly = Boolean(c.view.team);
  // On a touch device the header keeps only Close (TASTE: phone headers carry two actions at most); splits and the
  // session manager are in the canvas row while a terminal is focused, and in ⌘K.
  const header = !coarse.matches;
  if (m.kind === "terminal" && !m.noAccess && !readOnly && header) {
    // Option (macOS) or Alt (Windows, Linux) held near the buttons turns them into "new window right / below" (#280, D212):
    // the other pair of the four actions, reached from the same place.
    actions.push({ id: "split-right", label: "Split right", icon: ICON.splitRight, onSelect: () => { void cx.win.split(rec, "right"); },
      alt: { label: "New window right", morph: "right", onSelect: () => { void cx.win.newWindow(rec, "right"); } } });
    actions.push({ id: "split-down", label: "Split down", icon: ICON.splitDown, onSelect: () => { void cx.win.split(rec, "down"); },
      alt: { label: "New window below", morph: "down", onSelect: () => { void cx.win.newWindow(rec, "below"); } } });
  }
  // The session manager sits beside the splits when the canvas has an inventory (D127); a team layout's windows are read-only.
  if (m.kind === "terminal" && !m.noAccess && cx.adapters.inventory && header) {
    actions.push({ id: "sessions", label: "Sessions", icon: SESSION_ICON.sessions, onSelect: (e) => cx.sessionUi?.toggleManager(rec, e.currentTarget as HTMLElement, e.detail === 0 ? "keyboard" : "pointer") });
  }
  if (m.kind !== "node" && m.kind !== "settings" && m.kind !== "docs" && !readOnly) actions.push({ id: "close", label: "Close", icon: ICON.close, onSelect: () => cx.win.close(rec) });
  // "Read about this window" comes first, before split, sessions and close, when the docs adapter has something to say about it (#304).
  if (cx.adapters.docs?.for(m)) actions.unshift({ id: "docs", label: "Read about this window", icon: ICON.help, onSelect: (e) => openWindowDocs(cx, rec, e.detail === 0 ? "keyboard" : "pointer") });
  // An app window or a screen is named by what it shows ("Notebook · Today"); the machine it lives on is the quiet part that gives
  // way first in a narrow pill, with its OS mark in front (D208). A terminal is the other way round: the machine, then its session.
  const title = m.kind === "app" || m.kind === "screen" ? { host: m.session ?? m.host, session: m.host } : { host: m.host, ...(m.user ? { user: m.user } : {}), ...(m.session ? { session: m.session } : {}) };
  const card = createWindowCard({ id: m.id, title, icon: iconFor(m), status: m.kind === "terminal" && !m.noAccess ? "live" : m.kind === "app" || m.kind === "screen" ? "connecting" : "none", actions, label: `${m.host} ${m.session ?? m.kind}`, onLockChange: (locked) => {
    // The lock icon on the window is the input lock (the padlock): one lock at a time, on this window.
    const held = cx.inputLock.state;
    if (locked) {
      setActive(cx, rec);
      if (held && held.win !== rec) cx.inputLock.toggle();
      if (!cx.inputLock.state) cx.inputLock.toggle();
    } else if (held?.win === rec) cx.inputLock.toggle();
    cx.toolbar.update();
  } });
  Object.assign(rec, { model: m, card, owner: c });
  card.root.dataset.kind = m.kind;
  if (m.h) { card.root.style.height = m.h <= 1 ? `calc(var(--clh) * ${m.h})` : `${m.h}px`; card.root.style.flex = "none"; }
  // Where a window stands in its group (D212) is read back from these; the tracks module writes them from then on.
  if (m.span && m.span > 1) card.root.dataset.span = String(m.span);
  if (m.rows && m.rows > 1) card.root.dataset.rows = String(m.rows);
  if (m.row !== undefined) card.root.dataset.row = String(m.row);
  makeBody(cx, rec);
  wireWindow(cx, rec);
  // A window showing a session means that session is open (D178); the surfaces about it follow the inventory.
  if (isTerminal(rec) && m.sessionId) cx.adapters.inventory?.attach(m.host, m.sessionId);
  cx.sessionUi?.paint(rec);
  const unwatch = cx.memory.watch(card.root);
  const bodyCleanup = rec.cleanup;
  rec.cleanup = () => { unwatch(); bodyCleanup?.(); };
  if (rec.binding) cx.visibility.watch(rec);
  return rec;
}

/**
 * A press on the pill that did not move the window. A terminal's pill opens its details (#127). An app window's or a screen's pill
 * is its machine's pill: it opens the machine's list of windows to add (D208 A1), narrowed to that machine, from the pill.
 */
function pillPress(cx: Ctx, rec: WinRec, how: "pointer" | "keyboard"): void {
  if (rec.setup?.handlePill(how)) return;
  if ((rec.model.kind === "app" || rec.model.kind === "screen") && cx.adapters.appWindows?.available()) {
    const loading = cx.appWindows?.load();
    if (loading) { void loading.then((runtime) => { if (runtime && rec.card.pill.isConnected) runtime.togglePicker(rec.card.pill, how, rec.model.host); }); }
    return;
  }
  cx.details?.toggle(rec, how);
}

/** A window made active counts as used: it moves to the front of its view's recency list (#121). */
function recordUse(state: Ctx["state"], rec: WinRec): void {
  const view = rec.owner.view.id;
  let list = state.recent.get(view);
  if (!list) state.recent.set(view, (list = new RecentList<string>()));
  list.touch(rec.model.id);
}

/** Makes `rec` the active window (or none): accent hairline, the binding's focus state, the pill, the toolbar and the tree. */
export function setActive(cx: Ctx, rec: WinRec | undefined): void {
  const { state } = cx;
  if (state.activeWin === rec) return;
  const prev = state.activeWin;
  prev?.card.setActive(false);
  prev?.binding?.setActive(false);
  state.activeWin = rec;
  if (rec) recordUse(state, rec);
  rec?.card.setActive(true);
  rec?.binding?.setActive(true);
  cx.pill.paint();
  cx.toolbar.update();
  cx.tree.render();
}

function wireWindow(cx: Ctx, rec: WinRec): void {
  const { signal, camera } = cx;
  const root = rec.card.root;
  const pill = rec.card.pill;
  root.addEventListener("pointerdown", () => setActive(cx, rec), { signal, capture: true });
  // A tap in a terminal window types into it (the key row of the toolbar then shows).
  root.addEventListener("click", (e) => {
    if (!isInteractive(rec) || (e.target as Element).closest(".ui-window-head, .ui-window-lock, .ui-window-resize, .cl-sx-strip, .cl-sx-badge, .aw-action")) return;
    rec.binding?.focus();
  }, { signal });
  // The pill moves the window, and a press that does not move opens the details popover (#127). A pointer opens on release
  // (the press is then known not to be a drag); Enter or Space on the focused pill is a click with no pointer (detail 0).
  pill.addEventListener("click", (e) => { e.preventDefault(); if (e.detail === 0 && camera.lod !== "thumb") pillPress(cx, rec, "keyboard"); }, { signal });
  pill.style.touchAction = "none";
  pill.dataset.grab = "";
  let press: { id: number; x: number; y: number; timer: number; touch: boolean } | undefined;
  pill.addEventListener("pointerdown", (e) => {
    if (e.button !== 0 || camera.lod === "thumb" || rec.owner.view.team) return;
    const touch = e.pointerType !== "mouse";
    press = { id: e.pointerId, x: e.clientX, y: e.clientY, touch, timer: 0 };
    pill.setPointerCapture(e.pointerId);
    void loadMove(); // the drag code is fetched while the finger is down, so it is there by the time the pill has moved 6 px
  }, { signal });
  let latest: PointerEvent | undefined;
  pill.addEventListener("pointermove", (e) => {
    if (!press && latest && e.pointerId === latest.pointerId) latest = e; // a drag waiting for its chunk follows the pointer
    if (!press || e.pointerId !== press.id) return;
    if (Math.hypot(e.clientX - press.x, e.clientY - press.y) < 6) return;
    window.clearTimeout(press.timer);
    const start = press;
    press = undefined;
    // A finger lifted before the chunk arrived has ended the press: starting a drag then would leave a window stuck to nothing.
    // The drag starts from where the pointer is when the chunk arrives, not from where it was at 6 px.
    latest = e;
    void loadMove().then((m) => { if (pill.hasPointerCapture(start.id)) m.beginMove(cx, rec, latest!, start); });
  }, { signal });
  const release = (e: PointerEvent): void => {
    if (!press || e.pointerId !== press.id) return;
    window.clearTimeout(press.timer);
    press = undefined;
    if (e.type === "pointerup") pillPress(cx, rec, "pointer");
    // A failed setup explains itself in the pill first; the details are one press further.
  };
  pill.addEventListener("pointerup", release, { signal });
  pill.addEventListener("pointercancel", release, { signal });
  // Any window in a strip resizes (D195), whatever it shows; a split pane shares its column's width.
  if (rec.owner.view.layout === "tiled" && !rec.model.splitOf && !rec.owner.view.team) {
    const host = resizeHost(cx, rec);
    rec.stopResize = attachWindowResize(rec.card, host).dispose;
  }
}

/**
 * Every window has its own four edges and four corners: the grabbed edge follows the pointer and the opposite edge stays
 * where it is on screen (D195). A column grows to the right and a window downward, so the other directions move the
 * origin instead of the opposite edge:
 * - west: the width changes and the whole view moves by the growth (`ViewRec.x`), so the right edge holds and the
 *   neighbours make room by moving, never by resizing;
 * - north: the window sits in a strip of fixed height, so its top is free space above it (`margin-top`) and the height
 *   is what is left: the bottom holds. A window can grow upward only back to the strip's top.
 * Shifts are taken from the sizes that were really written (rounded), so the held edge does not drift by a pixel.
 * The width is limited by a minimum and by the widest of the Window Sizes options (D191): the viewport's 99%.
 */
export function resizeHost(cx: Ctx, rec: WinRec): WindowResizeHost {
  const { camera } = cx;
  const cam = camera.cam;
  let origin = { x: 0, w: 0 };
  return {
    // The pill has its own long-press (arrows on demand), so the resize hold starts on the rest of the header.
    holdOnPill: false,
    begin(): ResizeStart {
      const colEl = rec.card.root.parentElement as HTMLElement;
      // A column in a group has no box of its own (D212): its width is the one it was given.
      const width = (drawnWidthOf(colEl) || colEl.offsetWidth) * cam.z;
      origin = { x: rec.owner.x, w: Math.round(width / cam.z) };
      const top = (parseFloat(rec.card.root.style.marginTop) || 0) * cam.z;
      const widest = maxColumnWidth(cx.viewport.clientWidth);
      return { width, height: rec.card.root.offsetHeight * cam.z, top, minWidth: 300 * currentUiScale() * cam.z, minHeight: 160 * currentUiScale() * cam.z, maxWidth: widest * cam.z, areaHeight: (scrollerOf(colEl).clientHeight - 28) * cam.z };
    },
    apply(f: ResizeFrame): void {
      const colEl = rec.card.root.parentElement as HTMLElement;
      const w = Math.round(f.width / cam.z);
      setColumnWidth(colEl, w, cx.state.metrics);
      colEl.dataset.user = "1";
      const root = rec.card.root;
      const h = Math.round(f.height / cam.z);
      root.style.height = `${h}px`;
      root.style.marginTop = f.top > 0 ? `${Math.round(f.top / cam.z)}px` : "";
      root.style.flex = "none";
      const c = rec.owner;
      // A band of a group (D212) is one height: every window of the band takes the one the person set.
      const scroller = scrollerOf(colEl);
      if (scroller !== colEl) {
        for (const n of scroller.querySelectorAll<HTMLElement>(":scope > .cl-col > .ui-window")) {
          if (n.dataset.row !== undefined && n.dataset.row === root.dataset.row && !n.dataset.rows) { const other = c.wins.get(n.dataset.windowId ?? ""); if (other) other.model.h = h; }
        }
      }
      c.sx.set(origin.x + (f.shiftX ? origin.w - w : 0), true);
      cx.view.geometry(c);
      cx.invalidate();
    },
    end(): void {
      const c = rec.owner;
      c.view.x = c.x;
      cx.view.settle(c.view.id);
      rec.binding?.refit();
      cx.store.changed();
    },
  };
}
