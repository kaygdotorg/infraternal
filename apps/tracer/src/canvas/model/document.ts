/**
 * The canvas document (D180): our own small, versioned JSON format, `infraternal.canvas`, per account (D178).
 *
 * - It holds layout and references only, never content: no scrollback, no secrets, no configuration.
 * - Views have a kind and a layout. Tiled: columns of windows with relative weights. Graph: the nodes the
 *   person pinned (the rest are laid out automatically). Views sit on a coarse grid, stored in cells.
 * - Windows reference their target by a stable id plus a readable name (the same ids back deep links, #86).
 * - Network access rules are never stored here; the Mesh owns them.
 * - Shared revisions come from server-applied semantic operations. Each tab keeps its drawing and unconfirmed edits in memory (D312).
 *
 * `toDocument` and `fromDocument` convert between this and the runtime model (`types.ts`). `parseDocument` is the
 * only way untrusted JSON (storage, an import, the server) becomes a document: it checks shape and bounds and
 * returns nothing when the input is not a document of this format, so a damaged store can never break the canvas.
 */
import { CELL, type Metrics } from "../layout/geometry";
import type { ColumnModel, ViewModel, WindowModel } from "./types";

import { FORMAT, VERSION, type CanvasDocument, type DocTarget, type DocColumn, type DocWindow, type DocLayout, type DocLook, type DocView } from "./schema";
export * from "./schema";

/** Turns a runtime window into its stable reference. Windows that cannot be referenced (node cards) are left out. */
function targetOf(w: WindowModel, pending: boolean): DocTarget | undefined {
  if (w.kind === "terminal") return w.sessionId || pending ? { type: "session", id: w.sessionId ?? w.id, host: w.host, ...(w.hostId ? { hostId: w.hostId, ...(w.user ? { user: w.user } : {}), ...(w.address ? { address: w.address } : {}) } : {}), ...(w.session ? { name: w.session } : {}), ...(w.sessionPinned ? { pinned: true } : {}) } : undefined;
  if (w.kind === "settings") return { type: "settings", section: w.id.slice(2) };
  if (w.kind === "containers" || w.kind === "logs") return { type: w.kind, host: w.host };
  return undefined;
}

/**
 * The saved form of a view's columns (D212). A window's span, band and row are written only when they say something: a
 * plain window is saved exactly as it always was. The model is settled before a save (the grouped layout writes each
 * group window's band when it arranges it), so the windows are written as they stand. `row` exists only for a window in a
 * group, where the list order alone cannot place a window that spans columns.
 */
function docColumns(cols: readonly ColumnModel[], metrics: Metrics, pending: boolean): DocColumn[] {
  return cols.map((c): DocColumn => ({
    id: c.id, weight: Number((c.w / metrics.colW).toFixed(3)),
    windows: c.wins.flatMap((w): DocWindow[] => {
      const target = targetOf(w, pending);
      if (!target) return [];
      return [{
        id: w.id, target, ...(w.h ? { height: w.h } : {}),
        ...(w.span && w.span > 1 ? { span: w.span } : {}), ...(w.rows && w.rows > 1 ? { rows: w.rows } : {}), ...(w.row !== undefined ? { row: w.row } : {}),
      }];
    }),
  }));
}

/** True when a document holds a group: a window that spans columns, takes several bands, or has a band (D212). */
export function docHasGroups(doc: CanvasDocument): boolean {
  return doc.views.some((v) => v.layout.type === "tiled" && v.layout.columns.some((c) => c.windows.some((w) => (w.span ?? 1) > 1 || (w.rows ?? 1) > 1 || w.row !== undefined)));
}

/** The document of the canvas as drawn now. `look` is the account's look (D322), carried through unchanged by the layout code; absent when this page has none to save. */
export function toDocument(views: readonly ViewModel[], metrics: Metrics, revision: number, pending = false, look?: DocLook): CanvasDocument {
  return {
    format: FORMAT, version: VERSION, revision, ...(look ? { look } : {}),
    views: views.map((v): DocView => ({
      id: v.id, kind: v.id, name: v.name, cell: { x: Math.round((v.home ?? v).x / CELL), y: Math.round((v.home ?? v).y / CELL) },
      layout: v.layout === "graph"
        ? { type: "graph", pinned: v.graphPins ? structuredClone(v.graphPins) : Object.fromEntries(v.nodes.filter((n) => n.pinned).map((n) => [n.id, { x: Math.round(n.x), y: Math.round(n.y) }])) }
        : {
          type: "tiled",
          columns: docColumns(v.cols, metrics, pending),
        },
    })),
  };
}

/**
 * Rebuilds runtime columns from a document's tiled layout. `resolve` turns a stable reference into the window's
 * live fields (host, user, system, name); it returns nothing for a target that no longer exists, and that window
 * is dropped rather than shown broken.
 */
export function columnsFromDocument(layout: Extract<DocLayout, { type: "tiled" }>, metrics: Metrics, resolve: (target: DocTarget, windowId: string) => Partial<WindowModel> | undefined): ColumnModel[] {
  const cols: ColumnModel[] = [];
  for (const c of layout.columns) {
    const wins: WindowModel[] = [];
    for (const w of c.windows) {
      const live = resolve(w.target, w.id);
      if (!live) continue;
      const base: WindowModel = {
        id: w.id, kind: w.target.type === "session" ? "terminal" : w.target.type, host: "host" in w.target ? w.target.host : "", ...(w.height ? { h: w.height } : {}),
        ...(w.span && w.span > 1 ? { span: w.span } : {}), ...(w.rows && w.rows > 1 ? { rows: w.rows } : {}), ...(w.row !== undefined ? { row: w.row } : {}),
      };
      wins.push({ ...base, ...live, id: w.id });
    }
    if (wins.length) cols.push({ id: c.id, w: Math.round(c.weight * metrics.colW), wins });
  }
  return cols;
}


/** Build shared view metadata once for startup and later server projections. */
export function viewFromDocument(view: DocView, cols: ColumnModel[] = []): ViewModel {
  return { id: view.id, name: view.name, layout: view.layout.type, cols, nodes: [], x: view.cell.x * CELL, y: view.cell.y * CELL, ...(view.layout.type === "graph" ? { graphPins: view.layout.pinned } : {}) };
}
