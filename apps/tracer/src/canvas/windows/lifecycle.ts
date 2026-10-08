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
import { dropletSplit } from "../layout/droplet";
import { COLUMN_GAP } from "../layout/geometry";
import type { ViewId, WindowModel } from "../model/types";
import { reduced } from "../dom";
import { makeWindow, setActive } from "./frame";
import { isTerminal } from "../views/body";

export interface WindowsModule {
  make(c: ViewRec, m: WindowModel): WinRec;
  setActive(rec: WinRec | undefined): void;
  /** Adds a window in a new column at `index` of a tiled view; the others glide aside. */
  addColumn(c: ViewRec, m: WindowModel, index: number, w?: number, silent?: boolean): WinRec;
  close(rec: WinRec): void;
  split(rec: WinRec, direction?: "down" | "right"): Promise<void>;
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

  const enterAnimation = (rec: WinRec): void => {
    if (reduced.matches) { rec.card.root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160 }); return; }
    const root = rec.card.root;
    const spring = new Spring(1, (p) => {
      if (p === 0) { root.style.transform = ""; root.style.opacity = ""; root.style.transformOrigin = ""; return; }
      root.style.transformOrigin = "0 50%";
      root.style.transform = `scale(${1 - 0.06 * p})`;
      root.style.opacity = String(clamp(1 - p * 1.4, 0, 1));
      cx.invalidate();
    }, { visualDuration: 0.5, bounce: 0.28 });
    spring.set(0);
  };

  const addColumn = (c: ViewRec, m: WindowModel, index: number, w = state.metrics.colW, silent = false): WinRec => {
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
    if (!silent) enterAnimation(rec);
    cx.tree.render();
    cx.invalidate();
    return rec;
  };

  const close = (rec: WinRec): void => {
    const c = rec.owner;
    if (cx.inputLock.state?.win === rec) cx.inputLock.toggle();
    if (state.activeWin === rec) setActive(cx, undefined);
    if (cx.mesh?.reachFor() === rec) cx.mesh.hideReach(true);
    const root = rec.card.root;
    const finish = (): void => {
      const before = flip.measure(flip.targets(c.colsEl));
      c.wins.delete(rec.model.id);
      const colEl = root.parentElement as HTMLElement | null;
      const freed = root.offsetHeight + COLUMN_GAP;
      rec.stopResize?.();
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
      flip.play(before, true);
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
    spring.set(1);
  };

  const split = async (rec: WinRec, direction: "down" | "right" = "down"): Promise<void> => {
    if (!isTerminal(rec)) return;
    const c = rec.owner;
    const root = rec.card.root;
    const colEl = root.parentElement as HTMLElement;
    const nm = cx.adapters.sessions.open(rec.model.host, { from: rec.model });
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
    if (direction === "right") {
      flip.play(before);
      // Canvas locked: glide so the window and its new neighbour are both on screen while the droplet divides.
      if (state.canvasLock) cx.nav.focusWindow(rec);
    }
    colEl.dataset.split = "";
    await dropletSplit(root, b.card.root, direction, c.colsEl);
    delete colEl.dataset.split;
    rec.binding?.refit();
    b.binding?.refit();
    cx.store.changed();
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
    addColumn, close, split, open, pulse, flat,
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
