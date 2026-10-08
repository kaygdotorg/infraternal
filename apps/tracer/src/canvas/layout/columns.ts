/**
 * Column scrolling: a tiled column scrolls by itself, and snapping to a window is ours to animate. One spring
 * per scroll; reduced motion or `instant` jumps.
 */
import { Spring } from "../../../../../packages/ui/src/spring";
import { clamp } from "../camera/camera";
import { restPx } from "../springs";

const reduced = matchMedia("(prefers-reduced-motion: reduce)");
/** The gap above a window inside a column that a snapped scroll keeps visible. */
const WINDOW_INSET = 14;

/** Springs a column's scroll to a window's start. */
export function scrollColumn(colEl: HTMLElement, top: number, instant = false): void {
  const target = clamp(top, 0, colEl.scrollHeight - colEl.clientHeight);
  if (reduced.matches || instant) { colEl.scrollTop = target; return; }
  colEl.dataset.wheel = "";
  const sp = restPx(new Spring(colEl.scrollTop, (v) => { colEl.scrollTop = v; if (v === target) delete colEl.dataset.wheel; }, { visualDuration: 0.4, bounce: 0.1 }));
  sp.set(target);
}

/** Scrolls a column to the window above (`dir` -1) or below (1) the one nearest its current scroll. */
export function stepWindow(colEl: HTMLElement, dir: number): void {
  const wins = [...colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")];
  if (wins.length < 2) return;
  let at = 0;
  wins.forEach((w, i) => { if (Math.abs(w.offsetTop - WINDOW_INSET - colEl.scrollTop) < Math.abs(wins[at]!.offsetTop - WINDOW_INSET - colEl.scrollTop)) at = i; });
  scrollColumn(colEl, wins[clamp(at + dir, 0, wins.length - 1)]!.offsetTop - WINDOW_INSET);
}

/** Scrolls a column so a window starts at its top. */
export function scrollToWindow(colEl: HTMLElement, win: HTMLElement, instant = false): void {
  scrollColumn(colEl, win.offsetTop - WINDOW_INSET, instant);
}
