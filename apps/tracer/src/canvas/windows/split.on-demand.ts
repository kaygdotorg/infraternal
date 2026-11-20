// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Splitting a window and opening a new one beside it (D212): the part of the window lifecycle that only runs when the
 * person asks for it, so it loads on demand (D188, #322). `lifecycle.ts` keeps open, close and re-attach, which the first
 * screen needs; `createWindows` hands `split` and `newWindow` to this module through `split-handle.ts`, which fetches it
 * when the browser is idle after the canvas is up, so the first split does not wait for a download.
 *
 * Invariant: nothing outside on-demand code imports this file. A static import from deferred code would make the bundler
 * link the chunk into the deferred class again and move nothing.
 */
import type { Ctx, ViewRec, WinRec } from "../context";
import { COLUMN_GAP } from "../layout/geometry";
import { freshColumnId, columnEls } from "../layout/columns";
import { setColumnWidth } from "../layout/column-els";
import type { Col } from "../layout/grid";
import { inGroup, loadGroups, type Groups } from "../layout/groups-handle";
import type { WindowModel } from "../model/types";
import { MIN_COLUMN_WEIGHT } from "../model/schema";
import { coarse } from "../dom";
import { triggeredByKeyboard } from "../../../../../packages/ui/src/input-source";
import { EASE_OUT } from "../../../../../packages/ui/src/motion";
import { makeWindow } from "./frame";
import { isTerminal } from "../views/body";

/** How long a new window takes to fade in after a pointer split, in milliseconds (owner, #484: "make this animation a fade in instead and speed it up"). */
const SPLIT_FADE_MS = 150;
/** The glide of the windows a pointer split moves aside: a quick ease-out, well under 200 ms (`flip.play`'s `visualDuration`, in seconds). */
const SPLIT_GLIDE = { visualDuration: 0.15 };

/**
 * Fades `el` in on the product's ease-out and resolves when it is done. Only opacity changes, so the window's own content is
 * never scaled or drawn twice; a window that is cancelled or removed mid-fade resolves too. Reduced motion keeps the
 * fade (opacity only is what it asks for).
 */
const fadeIn = (el: HTMLElement): Promise<void> =>
  el.animate([{ opacity: 0 }, { opacity: 1 }], { duration: SPLIT_FADE_MS, easing: EASE_OUT }).finished.then(() => undefined, () => undefined);

/**
 * The split actions. Each resolves when its motion is over. Whether they animate is read from the input source (input-source.ts) when
 * they run, not passed in: a split or new window started by a key (its chord or a palette row) lands in the same frame, a pointer one
 * glides the other columns aside. No caller can pass the wrong answer (#427).
 */
export interface SplitModule {
  /** Divides a terminal window's own space into two windows (see `WindowsModule.split`). */
  split(rec: WinRec, direction: "down" | "right"): Promise<boolean>;
  /** Opens a new full-size window next to a terminal window (see `WindowsModule.newWindow`). */
  newWindow(rec: WinRec, side: "right" | "below", session?: string): Promise<void>;
  /** Splits `rec` with an already made model: the undo of a close puts a split half back this way. */
  splitInto(rec: WinRec, direction: "down" | "right", nm: WindowModel): Promise<void>;
}

/** Makes the split actions for the canvas `cx`. Only on-demand code may import this file (see the module comment). */
export function createSplit(cx: Ctx): SplitModule {
  const { state, flip } = cx;

  /**
   * A grid change (D212): measures the windows for the motion (none for a keyboard action), lets `change` decide the new
   * model from what the DOM holds, writes it into the DOM, reads it back and plays the motion.
   */
  const reshape = (g: Groups, c: ViewRec, instant: boolean, change: () => Col[]): void => {
    const before = instant ? undefined : flip.measure(flip.targets(c.colsEl));
    const next = change();
    g.applyCols(cx, c, g.fromGrid(c, next));
    cx.view.geometry(c);
    if (before) flip.play(before, false, SPLIT_GLIDE);
  };

  /** A window's column is its own when no other window stands in it: only then can it divide sideways as a plain pair. */
  const ownsColumn = (rec: WinRec): boolean => {
    const colEl = rec.card.root.parentElement;
    return !!colEl && colEl.querySelectorAll(":scope > .ui-window").length === 1;
  };

  const split = async (rec: WinRec, direction: "down" | "right"): Promise<boolean> => {
    if (!isTerminal(rec)) return false;
    await splitInto(rec, direction, cx.adapters.sessions.open(rec.model.host, { from: rec.model }));
    return true;
  };

  const newWindow = async (rec: WinRec, side: "right" | "below", session?: string): Promise<void> => {
    if (!isTerminal(rec)) return;
    const instant = triggeredByKeyboard();
    const nm = session ? { ...cx.adapters.sessions.open(rec.model.host, { session }), splitOf: rec.model.id } : cx.adapters.sessions.open(rec.model.host, { from: rec.model });
    const c = rec.owner;
    const root = rec.card.root;
    const colEl = root.parentElement as HTMLElement;
    const grouped = inGroup(colEl);
    // The grouped module loads before the window is made: a keyboard action then finds it there (warmed when a view is built).
    const g = grouped ? await loadGroups() : undefined;
    const before = flip.measure(flip.targets(c.colsEl));
    if (g) {
      // Inside a group the grid decides where the window goes (D212): a full-size window beside the group, or a band below.
      const b = makeWindow(cx, c, side === "below" ? { ...nm, h: 1 } : nm);
      c.wins.set(nm.id, b);
      reshape(g, c, instant, () => {
        const cols = g.readColumns(cx, c);
        if (side === "right") return g.newRight(cols, rec.model.id, { id: nm.id, colId: freshColumnId(cx, c) }, Number(colEl.dataset.w) || state.metrics.colW);
        const at = columnEls(c.colsEl).indexOf(colEl);
        const run = g.runsOf(cols).find((r) => at >= r.from && at <= r.to);
        for (let j = run?.from ?? at; j <= (run?.to ?? at); j++) for (const m of cols[j]?.wins ?? []) {
          const el = c.wins.get(m.id)?.card.root;
          if (el && (m.rows ?? 1) === 1) m.h = el.offsetHeight;
        }
        return g.splitDown(cols, rec.model.id, { id: nm.id }, undefined, 1);
      });
    } else if (side === "right") {
      const next = cx.view.newCol({ id: freshColumnId(cx, c), w: Number(colEl.dataset.w) || state.metrics.colW, wins: [nm] });
      const b = makeWindow(cx, c, nm);
      c.wins.set(nm.id, b);
      next.append(b.card.root);
      colEl.after(next);
    } else {
      // The windows already there keep their heights: a window that flexes would shrink to its minimum next to a full
      // size one. Their heights are pinned in pixels, in the model too, so a saved layout reopens the same way.
      for (const w of colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")) {
        const h = w.offsetHeight;
        w.style.height = `${h}px`; w.style.flex = "none";
        const pinned = c.wins.get(w.dataset.windowId ?? "")?.model;
        if (pinned) pinned.h = h;
      }
      // Full size: a ratio of the column's height (1), so it is saved as "one column height" and the column grows by it.
      const b0: WindowModel = { ...nm, h: 1 };
      const b = makeWindow(cx, c, b0);
      c.wins.set(nm.id, b);
      root.after(b.card.root);
    }
    if (!grouped) cx.view.geometry(c);
    cx.view.settle(c.view.id);
    cx.tree.render();
    const b = c.wins.get(nm.id)!;
    rec.binding?.refit();
    // A new window by mouse glides the others aside (FLIP), as a new column always has. A keyboard action is instant.
    if (!instant) flip.play(before, false, SPLIT_GLIDE);
    land(b, instant);
    b.binding?.refit();
    cx.store.changed();
  };

  /**
   * Brings a new window in: it becomes the active one, the camera brings it fully into view and it takes the keys.
   * A keyboard action lands in the same frame. The keyboard only follows on a device that has one (a phone is never
   * asked to open it).
   */
  const land = (b: WinRec, instant: boolean): void => {
    cx.win.setActive(b);
    cx.nav.focusWindow(b, instant);
    if (!coarse.matches) b.binding?.focus();
  };

  /**
   * Divides a window (D212). In a plain column the base path does it: `down` stacks the new window under it, `right` (a
   * window that owns its column) gives it the other half; the new window fades in (about 150 ms) and the sizes snap. A window in a group, or a stacked window
   * split right, goes through the grid: the windows around it span the new half. Splits are windows in the one structure:
   * no nesting, and the total footprint does not change.
   */
  const splitInto = async (rec: WinRec, direction: "down" | "right", nm: WindowModel): Promise<void> => {
    const instant = triggeredByKeyboard();
    cx.store.changed({ windowId: nm.id, anchorId: rec.model.id, axis: direction });
    const c = rec.owner;
    const root = rec.card.root;
    const b = makeWindow(cx, c, nm);
    c.wins.set(nm.id, b);
    const colEl = root.parentElement as HTMLElement;
    // The window's height before the split: a window in a group is its band, which the split halves.
    const h0 = root.offsetHeight;
    // A stacked window split right, or any window in a group, is the grouped module's; a plain split is the flat path.
    const plain = !inGroup(colEl) && (direction === "down" || ownsColumn(rec));
    const g = plain ? undefined : await loadGroups();
    // The other windows, measured before the change so the ones a split right moves aside can glide (a grid change measures its own).
    const before = plain && !instant ? flip.measure(flip.targets(c.colsEl)) : undefined;
    if (plain) {
      if (direction === "down") {
        const half = Math.round((h0 - COLUMN_GAP) / 2);
        root.style.height = `${half}px`; root.style.flex = "none";
        b.card.root.style.height = `${half}px`; b.card.root.style.flex = "none";
        root.after(b.card.root);
      } else {
        // The column's width splits into two columns with the gap between them: the pair is exactly the old width.
        const w = Number(colEl.dataset.w) || state.metrics.colW;
        const minimum = Math.ceil(state.metrics.colW * MIN_COLUMN_WEIGHT);
        const first = Math.max(minimum, Math.round((w - COLUMN_GAP) / 2));
        setColumnWidth(colEl, first, state.metrics);
        const next = cx.view.newCol({ id: freshColumnId(cx, c), w: Math.max(minimum, w - COLUMN_GAP - first), wins: [nm] });
        // The two halves name each other: closing one of them gives its width back to the other (see `close`).
        const pair = `p${++state.serial}`;
        colEl.dataset.half = pair; next.dataset.half = pair;
        next.append(b.card.root);
        colEl.after(next);
      }
      cx.view.geometry(c);
      cx.view.settle(c.view.id);
      // Sizes snap to their new value (scaling a terminal's text would ghost it); only a window that changes place glides.
      if (before) flip.play(before, false, SPLIT_GLIDE);
    } else {
      reshape(g!, c, instant, () => {
        const cols = g!.readColumns(cx, c);
        if (direction === "right") return g!.splitRight(cols, rec.model.id, { id: nm.id, colId: freshColumnId(cx, c), pair: `p${++state.serial}` }, COLUMN_GAP, Math.ceil(state.metrics.colW * MIN_COLUMN_WEIGHT));
        const half = Math.round((h0 - COLUMN_GAP) / 2);
        return g!.splitDown(cols, rec.model.id, { id: nm.id }, half, half);
      });
    }
    cx.tree.render();
    rec.binding?.refit();
    land(b, instant);
    // The new size is final at once, so the terminals refit now and the layout is saved now.
    b.binding?.refit();
    cx.store.changed();
    // A keyboard action never animates (TASTE): the new window is simply there. A pointer split fades it in.
    if (instant) return;
    await fadeIn(b.card.root);
  };

  return { split, newWindow, splitInto };
}
