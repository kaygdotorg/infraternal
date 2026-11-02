/**
 * Column scrolling: a tiled column scrolls by itself, and snapping to a window is ours to animate. One spring
 * per scroll; reduced motion or `instant` jumps.
 *
 * Columns of a group (D212) share one grid, so the group is the scroller: its columns scroll together, and a step goes
 * to the next band of the group. A plain column scrolls on its own, as it always did. Callers pass a column element either
 * way; `scrollerOf` says what actually scrolls.
 */
import { randomUuid } from "../../identifiers";
import { Spring } from "../../../../../packages/ui/src/spring";
import type { Ctx, ViewRec } from "../context";
import { columnEls, drawnWidthOf } from "./column-els";
import { clamp } from "../camera/camera";
import { restPx } from "../springs";

const reduced = matchMedia("(prefers-reduced-motion: reduce)");
/** The gap above a window inside a column that a snapped scroll keeps visible. */
const WINDOW_INSET = 14;

/**
 * One scroll spring per column, retargeted by every new step. A new spring per step left the earlier ones still writing
 * `scrollTop` every frame, so quick swipes fought each other; one spring keeps its velocity and simply aims elsewhere.
 */
const scrolls = new WeakMap<HTMLElement, { sp: Spring; target: number }>();

/** The element that columns of a view are in, in order: plain columns and group wrappers (D212). */
export { columnEls } from "./column-els";

/** The child of `colsEl` that holds `el`: a plain column, or the group that holds it (D212). */
export function topItem(colsEl: HTMLElement, el: HTMLElement): HTMLElement | null {
  let n: HTMLElement | null = el;
  while (n && n.parentElement !== colsEl) n = n.parentElement;
  return n;
}

/**
 * The screen rectangle of a column, as a drop target sees it. A column in a group has no box of its own (D212), so its
 * track is measured from the group's frame: the same rectangle a plain column's box has (its 14 px of margin each side).
 */
export function columnRect(colEl: HTMLElement): DOMRect {
  const group = colEl.closest<HTMLElement>(".cl-group");
  if (!group) return colEl.getBoundingClientRect();
  const frame = group.getBoundingClientRect();
  const z = group.offsetWidth ? frame.width / group.offsetWidth : 1;
  let left = 14; // the group's padding: where its first track starts
  for (const other of group.querySelectorAll<HTMLElement>(":scope > .cl-col")) {
    if (other === colEl) break;
    left += drawnWidthOf(other) + 12;
  }
  const w = drawnWidthOf(colEl) + 28;
  return new DOMRect(frame.left + (left - 14) * z, frame.top, w * z, frame.height);
}

/** What scrolls for a column: its group (D212), or the column itself. */
export function scrollerOf(colEl: HTMLElement): HTMLElement {
  return (colEl.closest<HTMLElement>(".cl-group") ?? colEl);
}

/**
 * The windows a step can land on: the column's own windows, or every band of a group once (one per top edge), in reading
 * order. A window spanning several columns of a group appears once.
 */
export function stepTargets(colEl: HTMLElement): HTMLElement[] {
  const scroller = scrollerOf(colEl);
  if (scroller === colEl) return [...colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")];
  const seen = new Map<number, HTMLElement>();
  for (const w of scroller.querySelectorAll<HTMLElement>(":scope > .cl-col > .ui-window")) if (!seen.has(w.offsetTop)) seen.set(w.offsetTop, w);
  return [...seen.entries()].sort((a, b) => a[0] - b[0]).map(([, w]) => w);
}

/** Springs a column's scroll to a window's start. A step in flight is retargeted, never dropped. */
export function scrollColumn(colEl: HTMLElement, top: number, instant = false): void {
  const box = scrollerOf(colEl);
  const target = clamp(top, 0, box.scrollHeight - box.clientHeight);
  let run = scrolls.get(box);
  if (reduced.matches || instant) { if (run) run.target = target; run?.sp.set(target, true); box.scrollTop = target; delete box.dataset.wheel; return; }
  const idle = box.dataset.wheel === undefined;
  box.dataset.wheel = "";
  if (run && idle) run.sp.set(box.scrollTop, true); // the column was moved by something else since: start from where it is
  if (!run) {
    const own = { sp: undefined as unknown as Spring, target };
    own.sp = restPx(new Spring(box.scrollTop, (v) => { box.scrollTop = v; if (v === own.target) delete box.dataset.wheel; }, { visualDuration: 0.4 }));
    scrolls.set(box, own);
    run = own;
  }
  run.target = target;
  run.sp.set(target);
}

/** Scrolls a column to the window above (`dir` -1) or below (1) the one the column is at, or is already heading to. */
export function stepWindow(colEl: HTMLElement, dir: number): void {
  const wins = stepTargets(colEl);
  if (wins.length < 2) return;
  const box = scrollerOf(colEl);
  // From where a step in flight is going, so a second quick swipe adds to the first instead of restarting from halfway.
  const from = scrolls.get(box) && box.dataset.wheel !== undefined ? scrolls.get(box)!.target : box.scrollTop;
  let at = 0;
  wins.forEach((w, i) => { if (Math.abs(w.offsetTop - WINDOW_INSET - from) < Math.abs(wins[at]!.offsetTop - WINDOW_INSET - from)) at = i; });
  scrollColumn(colEl, wins[clamp(at + dir, 0, wins.length - 1)]!.offsetTop - WINDOW_INSET);
}

/** Scrolls a column so a window starts at its top. */
export function scrollToWindow(colEl: HTMLElement, win: HTMLElement, instant = false): void {
  scrollColumn(colEl, win.offsetTop - WINDOW_INSET, instant);
}

/** An id no column of the view has: a new column never takes the id of one that is already there (the scene's ids too). */
export function freshColumnId(_cx: Ctx, _c: ViewRec): string {
  // Per-device counters collide when two devices create columns from the same snapshot (D183).
  return `c-${randomUuid()}`;
}
