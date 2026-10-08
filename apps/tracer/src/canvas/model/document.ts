/**
 * The canvas document (D180): our own small, versioned JSON format, `infraternal.canvas`, per account (D178).
 *
 * - It holds layout and references only, never content: no scrollback, no secrets, no configuration.
 * - Views have a kind and a layout. Tiled: columns of windows with relative weights. Graph: the nodes the
 *   person pinned (the rest are laid out automatically). Views sit on a coarse grid, stored in cells.
 * - Windows reference their target by a stable id plus a readable name (the same ids back deep links, #86).
 * - Edges and grants are never stored here; the Mesh owns them.
 * - Sync (#98) works by small server-applied operations with a revision number. Until then the whole document is
 *   saved locally, and `revision` counts saves so the two paths agree on order.
 *
 * `toDocument` and `fromDocument` convert between this and the runtime model (`types.ts`). `parseDocument` is the
 * only way untrusted JSON (storage, an import, the server) becomes a document: it checks shape and bounds and
 * returns nothing when the input is not a document of this format, so a damaged store can never break the canvas.
 */
import { CELL, type Metrics } from "../layout/geometry";
import type { ColumnModel, ViewModel, WindowModel } from "./types";

export const FORMAT = "infraternal.canvas";
export const VERSION = 1;

/** What a window shows, by stable reference. */
export type DocTarget =
  | { type: "session"; id: string; host: string; name?: string }
  | { type: "settings"; section: string }
  | { type: "containers" | "logs"; host: string };

export interface DocWindow {
  /** Stable id of the window (not of its session). */
  id: string;
  target: DocTarget;
  /** The window's height as a share of its column; absent when the column shares equally. */
  height?: number;
}
export interface DocColumn { id: string; weight: number; windows: DocWindow[] }
export type DocLayout =
  | { type: "tiled"; columns: DocColumn[] }
  | { type: "graph"; pinned: Record<string, { x: number; y: number }> };
export interface DocView { id: string; kind: string; name: string; cell: { x: number; y: number }; layout: DocLayout }

export interface CanvasDocument {
  format: typeof FORMAT;
  version: typeof VERSION;
  revision: number;
  views: DocView[];
}

const MAX_VIEWS = 64, MAX_COLUMNS = 64, MAX_WINDOWS = 256, MAX_TEXT = 200;

/** Turns a runtime window into its stable reference. Windows that cannot be referenced (node cards) are left out. */
function targetOf(w: WindowModel): DocTarget | undefined {
  if (w.kind === "terminal") return w.sessionId ? { type: "session", id: w.sessionId, host: w.host, ...(w.session ? { name: w.session } : {}) } : undefined;
  if (w.kind === "settings") return { type: "settings", section: w.id.slice(2) };
  if (w.kind === "containers" || w.kind === "logs") return { type: w.kind, host: w.host };
  return undefined;
}

export function toDocument(views: readonly ViewModel[], metrics: Metrics, revision: number): CanvasDocument {
  return {
    format: FORMAT, version: VERSION, revision,
    views: views.map((v): DocView => ({
      id: v.id, kind: v.id, name: v.name, cell: { x: Math.round(v.x / CELL), y: Math.round(v.y / CELL) },
      layout: v.layout === "graph"
        ? { type: "graph", pinned: Object.fromEntries(v.nodes.map((n) => [n.id, { x: Math.round(n.x), y: Math.round(n.y) }])) }
        : {
          type: "tiled",
          columns: v.cols.map((c): DocColumn => ({
            id: c.id, weight: Number((c.w / metrics.colW).toFixed(3)),
            windows: c.wins.flatMap((w): DocWindow[] => {
              const target = targetOf(w);
              return target ? [{ id: w.id, target, ...(w.h ? { height: w.h } : {}) }] : [];
            }),
          })),
        },
    })),
  };
}

/**
 * Rebuilds runtime columns from a document's tiled layout. `resolve` turns a stable reference into the window's
 * live fields (host, user, system, name); it returns nothing for a target that no longer exists, and that window
 * is dropped rather than shown broken.
 */
export function columnsFromDocument(layout: Extract<DocLayout, { type: "tiled" }>, metrics: Metrics, resolve: (target: DocTarget) => Partial<WindowModel> | undefined): ColumnModel[] {
  const cols: ColumnModel[] = [];
  for (const c of layout.columns) {
    const wins: WindowModel[] = [];
    for (const w of c.windows) {
      const live = resolve(w.target);
      if (!live) continue;
      const base: WindowModel = { id: w.id, kind: w.target.type === "session" ? "terminal" : w.target.type, host: "host" in w.target ? w.target.host : "", ...(w.height ? { h: w.height } : {}) };
      wins.push({ ...base, ...live, id: w.id });
    }
    if (wins.length) cols.push({ id: c.id, w: Math.round(c.weight * metrics.colW), wins });
  }
  return cols;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const text = (v: unknown): v is string => typeof v === "string" && v.length > 0 && v.length <= MAX_TEXT;
const finite = (v: unknown, lo: number, hi: number): v is number => typeof v === "number" && Number.isFinite(v) && v >= lo && v <= hi;

function parseTarget(v: unknown): DocTarget | undefined {
  if (!isObject(v)) return undefined;
  if (v.type === "session" && text(v.id) && text(v.host)) return { type: "session", id: v.id, host: v.host, ...(text(v.name) ? { name: v.name } : {}) };
  if (v.type === "settings" && text(v.section)) return { type: "settings", section: v.section };
  if ((v.type === "containers" || v.type === "logs") && text(v.host)) return { type: v.type, host: v.host };
  return undefined;
}

/** Checks untrusted JSON and returns a document, or nothing. */
export function parseDocument(input: unknown): CanvasDocument | undefined {
  if (!isObject(input) || input.format !== FORMAT || input.version !== VERSION || !finite(input.revision, 0, Number.MAX_SAFE_INTEGER)) return undefined;
  if (!Array.isArray(input.views) || input.views.length > MAX_VIEWS) return undefined;
  const views: DocView[] = [];
  for (const raw of input.views) {
    if (!isObject(raw) || !text(raw.id) || !text(raw.kind) || !text(raw.name) || !isObject(raw.cell) || !finite(raw.cell.x, -1000, 1000) || !finite(raw.cell.y, -1000, 1000) || !isObject(raw.layout)) return undefined;
    const cell = { x: Math.round(raw.cell.x), y: Math.round(raw.cell.y) };
    if (raw.layout.type === "graph") {
      if (!isObject(raw.layout.pinned)) return undefined;
      const pinned: Record<string, { x: number; y: number }> = {};
      for (const [k, p] of Object.entries(raw.layout.pinned)) {
        if (!isObject(p) || !finite(p.x, -100000, 100000) || !finite(p.y, -100000, 100000)) return undefined;
        pinned[k] = { x: p.x, y: p.y };
      }
      views.push({ id: raw.id, kind: raw.kind, name: raw.name, cell, layout: { type: "graph", pinned } });
      continue;
    }
    if (raw.layout.type !== "tiled" || !Array.isArray(raw.layout.columns) || raw.layout.columns.length > MAX_COLUMNS) return undefined;
    const columns: DocColumn[] = [];
    let count = 0;
    for (const c of raw.layout.columns) {
      if (!isObject(c) || !text(c.id) || !finite(c.weight, 0.1, 10) || !Array.isArray(c.windows)) return undefined;
      const windows: DocWindow[] = [];
      for (const w of c.windows) {
        const target = isObject(w) ? parseTarget(w.target) : undefined;
        if (!isObject(w) || !text(w.id) || !target || (w.height !== undefined && !finite(w.height, 0.05, 10000))) return undefined;
        if (++count > MAX_WINDOWS) return undefined;
        windows.push({ id: w.id, target, ...(typeof w.height === "number" ? { height: w.height } : {}) });
      }
      columns.push({ id: c.id, weight: c.weight, windows });
    }
    views.push({ id: raw.id, kind: raw.kind, name: raw.name, cell, layout: { type: "tiled", columns } });
  }
  return { format: FORMAT, version: VERSION, revision: input.revision as number, views };
}
