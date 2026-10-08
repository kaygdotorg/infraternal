/**
 * The window frame on the canvas: making a window card for a model, activating it, grabbing it by its pill to
 * move it, and resizing it (D159, D160, D177).
 *
 * - Activation: a press on a window makes it the active one (accent hairline) without focusing input, so no
 *   on-screen keyboard appears; the second press types. The binding is told, so the session can take focus.
 * - The pill moves the window (`move.ts`); it opens nothing. A touch long-press on a terminal's pill shows where
 *   its host can reach (the mesh module, when there is one).
 * - Resizing is the shared engine in packages/ui (`window-resize.ts`); here it sets the column width and the
 *   window height. Split windows share their column and are not resizable on their own.
 * - The window's kind decides its actions: only a terminal has split controls, only terminals and logs close.
 */
import { createWindowCard, type WindowAction } from "../../../../../packages/ui/src/window-card";
import { attachWindowResize, type ResizeFrame, type ResizeStart, type WindowResizeHost } from "../../../../../packages/ui/src/window-resize";
import type { Ctx, ViewRec, WinRec } from "../context";
import type { WindowModel } from "../model/types";
import { ICON, iconFor } from "../views/icons";
import { isTerminal, makeBody } from "../views/body";
import { beginMove } from "./move";

export function makeWindow(cx: Ctx, c: ViewRec, m: WindowModel): WinRec {
  const actions: WindowAction[] = [];
  const rec: WinRec = {} as WinRec;
  // The window's kind decides what it can do: only a terminal has a split control.
  const readOnly = Boolean(c.view.team);
  if (m.kind === "terminal" && !m.noAccess && !readOnly) {
    actions.push({ id: "split-right", label: "Split right", icon: ICON.splitRight, onSelect: () => { void cx.win.split(rec, "right"); } });
    actions.push({ id: "split-down", label: "Split down", icon: ICON.splitDown, onSelect: () => { void cx.win.split(rec, "down"); } });
  }
  if (m.kind !== "node" && m.kind !== "settings" && !readOnly) actions.push({ id: "close", label: "Close", icon: ICON.close, onSelect: () => cx.win.close(rec) });
  const title = { host: m.host, ...(m.user ? { user: m.user } : {}), ...(m.session ? { session: m.session } : {}) };
  const card = createWindowCard({ id: m.id, title, icon: iconFor(m), status: m.kind === "terminal" && !m.noAccess ? "live" : "none", actions, label: `${m.host} ${m.session ?? m.kind}`, onLockChange: (locked) => {
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
  makeBody(cx, rec);
  wireWindow(cx, rec);
  const unwatch = cx.memory.watch(card.root);
  const bodyCleanup = rec.cleanup;
  rec.cleanup = () => { unwatch(); bodyCleanup?.(); };
  if (rec.binding) cx.visibility.watch(rec);
  return rec;
}

/** Makes `rec` the active window (or none): accent hairline, the binding's focus state, the pill, the toolbar and the tree. */
export function setActive(cx: Ctx, rec: WinRec | undefined): void {
  const { state } = cx;
  if (state.activeWin === rec) return;
  const prev = state.activeWin;
  prev?.card.setActive(false);
  prev?.binding?.setActive(false);
  state.activeWin = rec;
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
    if (!isTerminal(rec) || (e.target as Element).closest(".ui-window-head, .ui-window-lock, .ui-window-resize")) return;
    rec.binding?.focus();
  }, { signal });
  // The pill moves the window; it opens nothing.
  pill.addEventListener("click", (e) => e.preventDefault(), { signal });
  pill.style.touchAction = "none";
  pill.dataset.grab = "";
  let press: { id: number; x: number; y: number; timer: number; touch: boolean } | undefined;
  pill.addEventListener("pointerdown", (e) => {
    if (e.button !== 0 || camera.lod === "thumb" || rec.owner.view.team) return;
    const touch = e.pointerType !== "mouse";
    press = { id: e.pointerId, x: e.clientX, y: e.clientY, touch, timer: 0 };
    if (touch && rec.model.kind === "terminal" && cx.mesh) {
      press.timer = window.setTimeout(() => { if (press) { cx.mesh?.showReach(rec, true); press = undefined; } }, 450);
    }
    pill.setPointerCapture(e.pointerId);
  }, { signal });
  pill.addEventListener("pointermove", (e) => {
    if (!press || e.pointerId !== press.id) return;
    if (Math.hypot(e.clientX - press.x, e.clientY - press.y) < 6) return;
    window.clearTimeout(press.timer);
    const start = press;
    press = undefined;
    beginMove(cx, rec, e, start);
  }, { signal });
  const release = (e: PointerEvent): void => {
    if (press && e.pointerId === press.id) { window.clearTimeout(press.timer); press = undefined; }
  };
  pill.addEventListener("pointerup", release, { signal });
  pill.addEventListener("pointercancel", release, { signal });
  if (!isTerminal(rec)) return;
  // Arrows on demand (hover on the pill, the port to grant access) belong to the mesh.
  cx.mesh?.wireTerminal(rec);
  if (!rec.model.splitOf && !rec.owner.view.team) {
    rec.stopResize = attachWindowResize(rec.card, resizeHost(cx, rec)).dispose;
  }
}

function resizeHost(cx: Ctx, rec: WinRec): WindowResizeHost {
  const { camera } = cx;
  const cam = camera.cam;
  return {
    // The pill has its own long-press (arrows on demand), so the resize hold starts on the rest of the header.
    holdOnPill: false,
    begin(): ResizeStart {
      const colEl = rec.card.root.parentElement as HTMLElement;
      return { width: colEl.offsetWidth * cam.z - 28 * cam.z, height: rec.card.root.offsetHeight * cam.z, top: 0, minWidth: 300 * cam.z, minHeight: 160 * cam.z, maxWidth: 900 * cam.z, areaHeight: 4000 };
    },
    apply(f: ResizeFrame): void {
      const colEl = rec.card.root.parentElement as HTMLElement;
      const w = Math.round(f.width / cam.z);
      colEl.dataset.w = String(w);
      colEl.dataset.user = "1";
      colEl.style.setProperty("--w", `${w}px`);
      rec.card.root.style.height = `${Math.round(f.height / cam.z)}px`;
      rec.card.root.style.flex = "none";
      cx.view.geometry(rec.owner);
      cx.invalidate();
    },
    end(): void {
      cx.view.settle(rec.owner.view.id);
      rec.binding?.refit();
      cx.store.changed();
      // The view's stops moved with its width: with the canvas lock on the framing follows (centred stays centred).
      const c = rec.owner;
      if (cx.state.canvasLock && cx.state.currentView === c.view.id) cx.nav.goStop(c, cx.nav.nearestStop(c, cx.camera.cam.cx));
    },
  };
}
