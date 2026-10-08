/**
 * Stops: the places the camera rests while the canvas lock is on (D177). A tiled view has one stop per column
 * (or fewer when the whole view fits), a graph view one per node column. Pure (no DOM): the caller passes the
 * view's content rectangle and the viewport size, so the rule can be tested alone.
 */
import { clamp } from "../camera/camera";
import { COLUMN_GAP, type Rect } from "./geometry";
import type { ViewModel } from "../model/types";

export interface Stops {
  /** The zoom at which the view is as tall as the viewport (never above 1). */
  z: number;
  /** The camera's vertical centre. */
  cy: number;
  /** Left edges (world x) of the viewport at each stop, ascending. */
  lefts: number[];
  /** Width of the viewport in world units at this zoom. */
  view: number;
}

export function stopsFor(view: ViewModel, r: Rect, vw: number, vh: number): Stops {
  const z = Math.min(1, vh / r.h);
  const width = vw / z;
  let lefts: number[];
  if (r.w <= width) lefts = [Math.round(r.x + r.w / 2 - width / 2)];
  else {
    const max = Math.round(r.x + r.w - width);
    let x = r.x;
    const raw = view.layout === "graph" ? view.nodes.map((n) => r.x + n.x - 30) : view.cols.map((col) => { const at = x - Math.max(0, (width - col.w) / 2); x += col.w + COLUMN_GAP; return at; });
    lefts = [...new Set(raw.map((v) => Math.round(clamp(v, r.x, max))).concat(max))].sort((p, q) => p - q);
  }
  return { z, cy: r.h * z <= vh ? r.y + r.h / 2 : r.y + vh / (2 * z), lefts, view: width };
}

/** The index of the stop whose centre is nearest to world x `cx`. */
export function nearestStop(st: Stops, cx: number): number {
  let best = 0;
  st.lefts.forEach((l, i) => { if (Math.abs(l + st.view / 2 - cx) < Math.abs(st.lefts[best]! + st.view / 2 - cx)) best = i; });
  return best;
}
