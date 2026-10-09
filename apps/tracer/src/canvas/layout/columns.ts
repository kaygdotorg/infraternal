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

/**
 * One scroll spring per column, retargeted by every new step. A new spring per step left the earlier ones still writing
 * `scrollTop` every frame, so quick swipes fought each other; one spring keeps its velocity and simply aims elsewhere.
 */
const scrolls = new WeakMap<HTMLElement, { sp: Spring; target: number }>();

/** Springs a column's scroll to a window's start. A step in flight is retargeted, never dropped. */
export function scrollColumn(colEl: HTMLElement, top: number, instant = false): void {
  const target = clamp(top, 0, colEl.scrollHeight - colEl.clientHeight);
  let run = scrolls.get(colEl);
  if (reduced.matches || instant) { if (run) run.target = target; run?.sp.set(target, true); colEl.scrollTop = target; delete colEl.dataset.wheel; return; }
  const idle = colEl.dataset.wheel === undefined;
  colEl.dataset.wheel = "";
  if (run && idle) run.sp.set(colEl.scrollTop, true); // the column was moved by something else since: start from where it is
  if (!run) {
    const own = { sp: undefined as unknown as Spring, target };
    own.sp = restPx(new Spring(colEl.scrollTop, (v) => { colEl.scrollTop = v; if (v === own.target) delete colEl.dataset.wheel; }, { visualDuration: 0.4, bounce: 0.1 }));
    scrolls.set(colEl, own);
    run = own;
  }
  run.target = target;
  run.sp.set(target);
}

/** Scrolls a column to the window above (`dir` -1) or below (1) the one the column is at, or is already heading to. */
export function stepWindow(colEl: HTMLElement, dir: number): void {
  const wins = [...colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")];
  if (wins.length < 2) return;
  // From where a step in flight is going, so a second quick swipe adds to the first instead of restarting from halfway.
  const from = scrolls.get(colEl) && colEl.dataset.wheel !== undefined ? scrolls.get(colEl)!.target : colEl.scrollTop;
  let at = 0;
  wins.forEach((w, i) => { if (Math.abs(w.offsetTop - WINDOW_INSET - from) < Math.abs(wins[at]!.offsetTop - WINDOW_INSET - from)) at = i; });
  scrollColumn(colEl, wins[clamp(at + dir, 0, wins.length - 1)]!.offsetTop - WINDOW_INSET);
}

/** Scrolls a column so a window starts at its top. */
export function scrollToWindow(colEl: HTMLElement, win: HTMLElement, instant = false): void {
  scrollColumn(colEl, win.offsetTop - WINDOW_INSET, instant);
}
