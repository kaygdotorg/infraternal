/**
 * Stops: the places the camera rests while the canvas lock is on (D177). A tiled view has one stop per column
 * (or fewer when the whole view fits), a graph view one per node column. Pure (no DOM): the caller passes the
 * view's content rectangle and the viewport size, so the rule can be tested alone.
 */
import { clamp } from "../camera/camera";
import { COLUMN_GAP, drawnWidth, type Rect } from "./geometry";
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
  /** The column each stop is for (a tiled view; empty for a graph). Where columns share a stop, the first owns it, and the last owns the one at the right edge. */
  owners: number[];
}

/** A graph with more nodes than this is too big to snap card by card: it opens fitted whole, with the canvas free. */
export const FREE_GRAPH_NODES = 40;
const MIN_FREE_ZOOM = 0.1;
export const isFreeView = (view: ViewModel): boolean => view.layout === "graph" && view.nodes.length > FREE_GRAPH_NODES;

export function stopsFor(view: ViewModel, r: Rect, vw: number, vh: number, centred = false, minW = 0, maxW = 0): Stops {
  // A big graph has one stop, at the zoom where all of it fits; from there the person zooms into a cluster.
  // (with a margin, so the view's label above it and the top pill over it stay clear of the content)
  // On a narrow screen it does not shrink below where the names of the clusters can still be read: it starts at the
  // top left of the graph and the person pans.
  const free = isFreeView(view);
  const z = free ? Math.max(MIN_FREE_ZOOM, Math.min(1, (0.86 * vh) / r.h, (0.9 * vw) / r.w)) : Math.min(1, vh / r.h);
  const width = vw / z;
  let lefts: number[];
  let owners: number[] = [];
  if (free && r.w > width) lefts = [Math.round(r.x - 0.04 * width)];
  else if (r.w <= width) { lefts = [Math.round(r.x + r.w / 2 - width / 2)]; owners = [0]; }
  else {
    const max = Math.round(r.x + r.w - width);
    let x = r.x;
    const raw = view.layout === "graph" ? view.nodes.map((n) => r.x + n.x - 30) : view.cols.map((col) => { const w = drawnWidth(col.w, { minW, maxW }); const at = x - Math.max(0, (width - w) / 2); x += w + COLUMN_GAP; return at; });
    // `centred` (a phone's tiled view): every column rests in the middle of the screen, the first and last included, so the
    // slices of the neighbours at the two edges are equal and the strip's ends show empty canvas rather than a wider window.
    const tiled = view.layout !== "graph";
    const placed = centred && tiled ? raw.map(Math.round) : raw.map((v) => Math.round(clamp(v, r.x, max)));
    lefts = [...new Set(centred && tiled ? placed : placed.concat(max))].sort((p, q) => p - q);
    if (tiled) owners = lefts.map((l) => (l === max && !centred ? (placed.lastIndexOf(l) < 0 ? placed.length - 1 : placed.lastIndexOf(l)) : placed.indexOf(l)));
  }
  return { z, cy: r.h * z <= vh ? r.y + r.h / 2 : r.y + (free ? vh / (2 * z) - 0.04 * vh / z : vh / (2 * z)), lefts, view: width, owners };
}

/** The index of the stop whose centre is nearest to world x `cx`. */
export function nearestStop(st: Stops, cx: number): number {
  let best = 0;
  st.lefts.forEach((l, i) => { if (Math.abs(l + st.view / 2 - cx) < Math.abs(st.lefts[best]! + st.view / 2 - cx)) best = i; });
  return best;
}
