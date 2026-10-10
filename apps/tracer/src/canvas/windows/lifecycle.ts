/**
 * The window lifecycle: open a window beside the others, close one, split one (D178, D183).
 *
 * - Opening adds a window in a new column at the end of the Console view; the others glide aside (FLIP).
 * - Closing never ends the session (D178): the binding is disposed, the session keeps running, detached. What
 *   remains in the column takes the freed height; an emptied column goes and its neighbours close the gap, all as
 *   one FLIP; the camera re-snaps to the nearest stop that still exists.
 * - A split always opens a new shell on the same host, no prompt. `down` stacks the new window in the same
 *   column; `right` opens it in a new column of the same width. The view is laid out first and then the droplet
 *   plays in the split's direction. Splits are windows in the one structure: no nesting.
 *
 * Every layout change measures, changes, then plays (layout/flip.ts); the terminal refits once at the new size.
 */
import { Spring } from "../../../../../packages/ui/src/spring";
import { clamp } from "../camera/camera";
import type { Ctx, ViewRec, WinRec } from "../context";
import { loadDroplet } from "../layout/droplet-handle";
import { COLUMN_GAP } from "../layout/geometry";
import type { ViewId, WindowModel } from "../model/types";
import { coarse, reduced } from "../dom";
import { endActivity, setActivity } from "../../perf-activity";
import { makeWindow, setActive } from "./frame";
import { isTerminal, makeBody } from "../views/body";
import { SCALE_REST, restAt } from "../springs";

export interface WindowsModule {
  make(c: ViewRec, m: WindowModel): WinRec;
  setActive(rec: WinRec | undefined): void;
  /** Adds a window in a new column at `index` of a tiled view; the others glide aside. */
  addColumn(c: ViewRec, m: WindowModel, index: number, w?: number, silent?: boolean, opaque?: boolean): WinRec;
  close(rec: WinRec): void;
  /** Splits a terminal window: a new shell beside or below it, or (with `session`) an existing session of the host. */
  /** `instant`: no motion at all (a keyboard split); the layout and the focus land in the same frame. */
  split(rec: WinRec, direction?: "down" | "right", session?: string, instant?: boolean): Promise<void>;
  /** Points a terminal window at another session of its host; the old one keeps running (detached). */
  attach(rec: WinRec, sessionId: string): void;
  /** Brings a window's name and screen in line with its session in the inventory (a rename, a run again). */
  syncSession(rec: WinRec, reshow?: boolean): void;
  /** Shows a session: flies to its window, or opens one (a detached or exited session) in Console. */
  openSession(host: string, sessionId: string): WinRec | undefined;
  /** Opens a shell on `host` as a window in Console (or flies to the one that is already there). */
  open(host: string, container?: string): WinRec | undefined;
  /** Scales the window up a little and back: "this is the one". */
  pulse(rec: WinRec): void;
  /** Every window of the current view in reading order (column by column, top to bottom). */
  flat(): WinRec[];
  /** Makes the next (1) or previous (-1) window of the current view active and brings it into view. */
  step(dir: number, instant?: boolean): void;
}

export function createWindows(cx: Ctx): WindowsModule {
  const { camera, state, views, flip } = cx;

  /** `opaque`: the window's content is there from the first frame (a session already exists); only its size springs. */
  const enterAnimation = (rec: WinRec, opaque = false): void => {
    if (reduced.matches) { rec.card.root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160 }); return; }
    const root = rec.card.root;
    const spring = new Spring(1, (p) => {
      if (p === 0) { root.style.transform = ""; root.style.opacity = ""; root.style.transformOrigin = ""; return; }
      root.style.transformOrigin = "0 50%";
      root.style.transform = `scale(${1 - 0.06 * p})`;
      root.style.opacity = opaque ? "" : String(clamp(1 - p * 1.4, 0, 1));
      cx.invalidate();
    }, { visualDuration: 0.5, bounce: 0.28 });
    // p scales the window by 6 % and fades it: it rests when the scale is within 0.0005 (p about 0.008).
    restAt(spring, SCALE_REST / 0.06);
    spring.set(0);
  };

  const addColumn = (c: ViewRec, m: WindowModel, index: number, w = state.metrics.colW, silent = false, opaque = false): WinRec => {
    const before = flip.measure(flip.targets(c.colsEl));
    const rec = makeWindow(cx, c, m);
    c.wins.set(m.id, rec);
    const colEl = cx.view.newCol({ id: `c${++state.serial}`, w, wins: [m] });
    colEl.append(rec.card.root);
    const kids = c.colsEl.querySelectorAll<HTMLElement>(":scope > .cl-col");
    c.colsEl.insertBefore(colEl, kids[index] ?? null);
    c.empty?.remove(); delete c.empty;
    cx.view.geometry(c);
    cx.view.settle(c.view.id);
    flip.play(before);
    if (!silent) enterAnimation(rec, opaque);
    cx.tree.render();
    cx.invalidate();
    return rec;
  };

  /** Where a closed window stood, so Undo can put it back. */
  interface Placed { view: ViewId; model: WindowModel; colIndex: number; aboveId: string | undefined; w: number }
  const placeOf = (rec: WinRec): Placed => {
    const root = rec.card.root;
    const colEl = root.parentElement as HTMLElement;
    const cols = [...rec.owner.colsEl.querySelectorAll<HTMLElement>(":scope > .cl-col")];
    const above = root.previousElementSibling as HTMLElement | null;
    return { view: rec.owner.view.id, model: rec.model, colIndex: Math.max(0, cols.indexOf(colEl)), aboveId: above?.dataset.windowId, w: Number(colEl.dataset.w) || state.metrics.colW };
  };
  /** Undo of a close: the window comes back where it was (under its upper neighbour, or in its own column). */
  const reopen = (at: Placed): void => {
    const c = views.get(at.view);
    const inv = cx.adapters.inventory;
    if (!c || c.wins.has(at.model.id)) return;
    const above = at.aboveId ? c.wins.get(at.aboveId) : undefined;
    const rec = above ? undefined : addColumn(c, at.model, Math.min(at.colIndex, c.colsEl.querySelectorAll(":scope > .cl-col").length), at.w);
    if (above) void splitInto(above, "down", at.model);
    const shown = rec ?? c.wins.get(at.model.id);
    if (!shown) return;
    if (at.model.sessionId) inv?.attach(at.model.host, at.model.sessionId);
    setActive(cx, shown);
    cx.nav.focusWindow(shown);
    cx.store.changed();
  };

  const close = (rec: WinRec): void => {
    const c = rec.owner;
    // Closing never ends the session (D178): it keeps running, detached, and the toast says so.
    const inv = cx.adapters.inventory;
    const sess = inv && isTerminal(rec) && rec.model.sessionId ? inv.get(rec.model.host, rec.model.sessionId) : undefined;
    const placed = sess ? placeOf(rec) : undefined;
    const wasRunning = sess?.state === "open";
    if (sess && wasRunning) inv!.detach(rec.model.host, sess.id);
    if (placed && wasRunning) cx.toast.show({ message: "Session keeps running", action: { label: "Undo", onSelect: () => reopen(placed) }, duration: 6000 });
    if (cx.inputLock.state?.win === rec) cx.inputLock.toggle();
    if (state.activeWin === rec) setActive(cx, undefined);
    const root = rec.card.root;
    const finish = (): void => {
      const before = flip.measure(flip.targets(c.colsEl));
      c.wins.delete(rec.model.id);
      const colEl = root.parentElement as HTMLElement | null;
      const freed = root.offsetHeight + COLUMN_GAP;
      rec.stopResize?.();
      cx.visibility.unwatch(rec);
      rec.binding?.dispose();
      rec.cleanup?.();
      root.remove();
      // The structure re-tiles: what remains in the column takes the freed height, an emptied column goes
      // and its neighbours close the gap. Everything animates as one move (a FLIP on the same spring as
      // every other layout move); the terminal refits once, at the new size.
      if (colEl) {
        const rest = [...colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")];
        if (!rest.length) colEl.remove();
        else if (rest.length === 1) { rest[0]!.style.height = ""; rest[0]!.style.flex = ""; }
        else {
          const total = rest.reduce((sum, w) => sum + w.offsetHeight, 0) + (rest.length - 1) * COLUMN_GAP;
          const k = (total + freed) / total;
          for (const w of rest) { w.style.height = `${Math.round(w.offsetHeight * k)}px`; w.style.flex = "none"; }
        }
      }
      cx.view.geometry(c);
      cx.view.paintEmpty(c);
      cx.view.settle(c.view.id);
      // Neighbours close the gap without overshoot (a critically damped spring): no value passes its final place.
      flip.play(before, true, { visualDuration: 0.38, bounce: 0 });
      for (const w of c.wins.values()) w.binding?.refit();
      cx.tree.render();
      // The view's stops changed: the camera re-snaps (canvas lock) to the nearest one that still exists.
      if (state.canvasLock && state.currentView === c.view.id && views.has(c.view.id)) cx.nav.goStop(c, cx.nav.nearestStop(c, camera.cam.cx));
      cx.store.changed();
    };
    if (reduced.matches) { finish(); return; }
    root.style.pointerEvents = "none";
    const spring = new Spring(0, (p) => {
      root.style.transform = `scale(${1 - 0.04 * p})`;
      root.style.opacity = String(1 - p);
      if (p >= 1) finish();
    }, { visualDuration: 0.22, bounce: 0 });
    restAt(spring, SCALE_REST);
    spring.set(1);
  };

  const split = async (rec: WinRec, direction: "down" | "right" = "down", session?: string, instant = false): Promise<void> => {
    if (!isTerminal(rec)) return;
    const nm = session ? { ...cx.adapters.sessions.open(rec.model.host, { session }), splitOf: rec.model.id } : cx.adapters.sessions.open(rec.model.host, { from: rec.model });
    await splitInto(rec, direction, nm, instant);
  };

  /** Puts a window for model `nm` beside or below `rec` and plays the droplet. Splits are windows in the one structure: no nesting. */
  const splitInto = async (rec: WinRec, direction: "down" | "right", nm: WindowModel, instant = false): Promise<void> => {
    const c = rec.owner;
    const root = rec.card.root;
    const colEl = root.parentElement as HTMLElement;
    const before = flip.measure(flip.targets(c.colsEl));
    const b = makeWindow(cx, c, nm);
    c.wins.set(nm.id, b);
    if (direction === "down") {
      const half = Math.round((root.offsetHeight - COLUMN_GAP) / 2);
      root.style.height = `${half}px`; root.style.flex = "none";
      b.card.root.style.height = `${half}px`; b.card.root.style.flex = "none";
      root.after(b.card.root);
    } else {
      const next = cx.view.newCol({ id: `c${++state.serial}`, w: Number(colEl.dataset.w) || state.metrics.colW, wins: [nm] });
      next.append(b.card.root);
      colEl.after(next);
    }
    cx.view.geometry(c);
    cx.view.settle(c.view.id);
    cx.tree.render();
    rec.binding?.refit();
    if (direction === "right" && !instant) flip.play(before);
    // A split lands you in the new window: it becomes the active one and the camera brings it fully into view, at rest
    // (the old window may then be partly off screen, as on a phone, where one window fills the screen). The keyboard
    // only follows on a device that has one (a phone is never asked to open it).
    cx.win.setActive(b);
    cx.nav.focusWindow(b, instant);
    if (!coarse.matches) b.binding?.focus();
    if (instant) {
      // A keyboard action never animates (TASTE): the new window is simply there, refit once, with no silhouette.
      rec.binding?.refit();
      b.binding?.refit();
      cx.store.changed();
      return;
    }
    colEl.dataset.split = "";
    setActivity("split");
    const { dropletSplit } = await loadDroplet();
    await dropletSplit(root, b.card.root, direction, c.colsEl);
    endActivity("split");
    delete colEl.dataset.split;
    rec.binding?.refit();
    b.binding?.refit();
    cx.store.changed();
  };

  /** Makes the window's model, title and body agree with its session in the inventory. */
  const syncSession = (rec: WinRec, force = false): void => {
    const s = isTerminal(rec) && rec.model.sessionId ? cx.adapters.inventory?.get(rec.model.host, rec.model.sessionId) : undefined;
    if (!s) return;
    const renamed = rec.model.session !== s.name;
    // A session without a stored screen (the product's: the renderer is the screen) is re-shown only when asked to.
    const reshown = force || (s.screen.length > 0 && rec.model.lines !== s.screen);
    rec.model.session = s.name;
    if (s.screen.length) rec.model.lines = s.screen;
    if (renamed) {
      rec.card.setTitle({ host: rec.model.host, ...(rec.model.user ? { user: rec.model.user } : {}), session: s.name });
      cx.pill.paint();
    }
    // A different screen (another session, a run again): the old binding goes and the new one mounts. The work is
    // done at once; only the frame and the name animate (session-ui.ts).
    if (reshown) {
      // Another session of this window: the same terminal shows it (the renderer, the atlas and the canvas stay, and
      // the last known screen is on screen at once); only a binding that cannot do that is built again.
      if (force && rec.binding?.retarget?.(rec.model)) { rec.binding.refit(); cx.sessionUi?.paint(rec); }
      else {
        rec.binding?.dispose();
        makeBody(cx, rec);
        rec.binding?.setActive(state.activeWin === rec);
        rec.binding?.refit();
        cx.sessionUi?.paint(rec);
      }
    }
    if (renamed || reshown) { cx.tree.render(); cx.store.changed(); }
  };

  const attach = (rec: WinRec, sessionId: string): void => {
    const inv = cx.adapters.inventory;
    if (!inv || !isTerminal(rec) || rec.model.sessionId === sessionId || !inv.get(rec.model.host, sessionId)) return;
    const previous = rec.model.sessionId;
    // The window's model first, so the change events the inventory sends see a consistent window.
    rec.model.sessionId = sessionId;
    if (previous) inv.detach(rec.model.host, previous);
    inv.attach(rec.model.host, sessionId);
    syncSession(rec, true);
    cx.sessionUi?.arrived(rec);
  };

  /** Shows a session: its window if it has one, else a new window in Console that the camera flies to. */
  const openSession = (host: string, sessionId: string): WinRec | undefined => {
    const inv = cx.adapters.inventory;
    const c = views.get("console" as ViewId);
    if (!inv || !c || !inv.get(host, sessionId)) return undefined;
    const existing = cx.sessionUi?.windowFor(host, sessionId);
    const model = cx.adapters.sessions.open(host, { session: sessionId });
    // The window carries the session's name from the first frame (the inventory knows it).
    const named = inv.get(host, sessionId)?.name;
    if (named && !model.session) model.session = named;
    const rec = existing ?? addColumn(c, model, c.colsEl.querySelectorAll(":scope > .cl-col").length, state.metrics.colW, false, true);
    if (existing) pulse(rec);
    setActive(cx, rec);
    cx.nav.focusWindow(rec);
    cx.store.changed();
    return rec;
  };

  const pulse = (rec: WinRec): void => {
    rec.card.root.animate([{ transform: "scale(1)" }, { transform: "scale(1.012)" }, { transform: "scale(1)" }], { duration: 360, easing: "cubic-bezier(0.23, 1, 0.32, 1)" });
  };

  /**
   * Opens a session (a host's shell, or a container's) as a window in Console. Where you are decides what you
   * see: in Console (or zoomed out) the camera flies to the window; anywhere else the camera stays put and the
   * top pill morphs into a floating terminal that is a view of that same Console window.
   */
  const open = (host: string, container?: string): WinRec | undefined => {
    const c = views.get("console" as ViewId);
    if (!c) return undefined;
    const model = cx.adapters.sessions.open(host, container ? { container } : {});
    let rec = c.wins.get(model.id);
    const here = state.currentView === "console" || camera.band === "out";
    if (!rec) rec = addColumn(c, model, c.view.cols.length, state.metrics.colW, !here);
    else if (here) pulse(rec);
    setActive(cx, rec);
    if (here || !cx.flags.float) cx.nav.focusWindow(rec); else cx.float.open(rec);
    // On a desktop the new shell takes the keys at once; on a phone the keyboard waits for a tap.
    if (!coarse.matches) rec.binding?.focus();
    cx.store.changed();
    return rec;
  };

  const flat = (): WinRec[] => {
    const c = views.get(state.currentView);
    return c ? [...c.colsEl.querySelectorAll<HTMLElement>(".ui-window")].map((n) => c.wins.get(n.dataset.windowId ?? "")).filter((w): w is WinRec => !!w) : [];
  };

  return {
    make: (c, m) => makeWindow(cx, c, m),
    setActive: (rec) => setActive(cx, rec),
    addColumn, close, split, attach, syncSession, openSession, open, pulse, flat,
    step(dir, instant = false) {
      const list = flat();
      if (!list.length) return;
      const at = state.activeWin ? list.indexOf(state.activeWin) : -1;
      const next = list[clamp((at < 0 ? (dir > 0 ? -1 : list.length) : at) + dir, 0, list.length - 1)]!;
      setActive(cx, next);
      cx.nav.focusWindow(next, instant, true);
    },
  };
}
