/** Stable-ID intents and optimistic reduction for account layouts (D180, D183, #243). */
import type { CanvasDocument, DocColumn, DocView, DocWindow } from "./document";
export type Intent =
  | { type: "view.add"; view: DocView }
  | { type: "view.remove"; view_id: string }
  | { type: "open"; view_id: string; column_id: string; window: DocWindow; after?: string }
  | { type: "split"; view_id: string; column_id: string; window: DocWindow; anchor_id: string; axis: "right" | "down" }
  | { type: "close"; window_id: string }
  | { type: "move" | "membership.add"; view_id: string; column_id: string; window_id: string; after?: string }
  | { type: "membership.remove"; view_id: string; window_id: string }
  | { type: "resize"; window_id: string; height?: number; span?: number; rows?: number; row?: number }
  | { type: "weight"; view_id: string; column_id: string; weight: number }
  | { type: "pin"; view_id: string; node_id: string; position?: { x: number; y: number } };
export interface SplitEdit { windowId: string; anchorId: string; axis: "right" | "down" }
const cols = (v: DocView): DocColumn[] => v.layout.type === "tiled" ? v.layout.columns : [];
const windows = (d: CanvasDocument): DocWindow[] => d.views.flatMap((v) => cols(v).flatMap((c) => c.windows));
const equal = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);
/** Compare completed changes using stable neighbours, never numeric placement indexes. */
export function edits(before: CanvasDocument, after: CanvasDocument, splits: ReadonlyMap<string, SplitEdit> = new Map()): Intent[] {
  const result: Intent[] = [];
  const old = new Map(windows(before).map((w) => [w.id, w]));
  const live = new Set(windows(after).map((w) => w.id));
  for (const id of old.keys()) if (!live.has(id)) result.push({ type: "close", window_id: id });
  for (const v of before.views) if (!after.views.some((n) => n.id === v.id)) result.push({ type: "view.remove", view_id: v.id });
  for (const v of after.views) {
    const previous = before.views.find((p) => p.id === v.id);
    if (!previous) result.push({ type: "view.add", view: { ...v, layout: v.layout.type === "graph" ? { type: "graph", pinned: {} } : { type: "tiled", columns: [] } } });
    if (v.layout.type === "graph") {
      const pins = previous?.layout.type === "graph" ? previous.layout.pinned : {};
      for (const id of new Set([...Object.keys(pins), ...Object.keys(v.layout.pinned)])) if (!equal(pins[id], v.layout.pinned[id])) {
        const position = v.layout.pinned[id]; result.push({ type: "pin", view_id: v.id, node_id: id, ...(position ? { position } : {}) });
      }
      continue;
    }
    const pendingSplits = v.layout.columns.flatMap((c) => c.windows.flatMap((w) => !old.has(w.id) && splits.has(w.id) ? [{ c, w, edit: splits.get(w.id)! }] : []));
    if (pendingSplits.length) {
      for (const { c, w, edit } of pendingSplits) result.push({ type: "split", view_id: v.id, column_id: c.id, window: w, anchor_id: edit.anchorId, axis: edit.axis });
      continue;
    }
    const previousCols = previous ? cols(previous) : [];
    const memberships = new Map(previousCols.flatMap((c) => c.windows.map((w, i) => [w.id, { col: c.id, after: c.windows[i - 1]?.id }] as const)));
    for (const id of memberships.keys()) if (live.has(id) && !v.layout.columns.some((c) => c.windows.some((w) => w.id === id))) result.push({ type: "membership.remove", view_id: v.id, window_id: id });
    for (const c of v.layout.columns) {
      for (const [i, w] of c.windows.entries()) {
        const neighbour = c.windows[i - 1]?.id;
        const at = { view_id: v.id, column_id: c.id, ...(neighbour ? { after: neighbour } : {}) };
        const was = old.get(w.id), membership = memberships.get(w.id), split = splits.get(w.id);
        if (!was) result.push(split ? { type: "split", view_id: v.id, column_id: c.id, window: w, anchor_id: split.anchorId, axis: split.axis } : { type: "open", ...at, window: w });
        else if (!membership) result.push({ type: "membership.add", ...at, window_id: w.id });
        else if (membership.col !== c.id || membership.after !== neighbour) result.push({ type: "move", ...at, window_id: w.id });
        if (was) {
          const size: Extract<Intent, { type: "resize" }> = { type: "resize", window_id: w.id }; let changed = false;
          for (const field of ["height", "span", "rows", "row"] as const) if (was[field] !== w[field]) { size[field] = w[field] ?? (field === "row" ? 0 : 1); changed = true; }
          if (changed) result.push(size);
        }
      }
      const prior = previousCols.find((p) => p.id === c.id);
      if (c.windows.length && Math.abs((prior?.weight ?? 1) - c.weight) > 0.001) result.push({ type: "weight", view_id: v.id, column_id: c.id, weight: Math.max(0.1, Math.min(10, c.weight)) });
    }
  }
  return result;
}
/** Missing memberships stay missing after close; callers deduplicate the server's ordered revisions. */
export function reduce(doc: CanvasDocument, intent: Intent): void {
  if (intent.type === "view.add") { if (!doc.views.some((v) => v.id === intent.view.id)) doc.views.push(structuredClone(intent.view)); return; }
  if (intent.type === "view.remove") { doc.views = doc.views.filter((v) => v.id !== intent.view_id); return; }
  if (intent.type === "close") { for (const v of doc.views) for (const c of cols(v)) c.windows = c.windows.filter((w) => w.id !== intent.window_id); return; }
  if (intent.type === "resize") { for (const w of windows(doc)) if (w.id === intent.window_id) for (const k of ["height", "span", "rows", "row"] as const) if (intent[k] !== undefined) w[k] = intent[k]; return; }
  const view = doc.views.find((v) => v.id === intent.view_id); if (!view) return;
  if (intent.type === "pin") { if (view.layout.type === "graph") { if (intent.position) view.layout.pinned[intent.node_id] = { ...intent.position }; else delete view.layout.pinned[intent.node_id]; } return; }
  const columns = cols(view);
  if (intent.type === "weight") { const col = columns.find((c) => c.id === intent.column_id); if (col) col.weight = intent.weight; return; }
  if (intent.type === "membership.remove") { for (const c of columns) c.windows = c.windows.filter((w) => w.id !== intent.window_id); return; }
  if (intent.type === "split") { split(columns, intent); return; }
  let window: DocWindow | undefined;
  if (intent.type === "open") window = structuredClone(intent.window);
  else if (intent.type === "membership.add") window = windows(doc).find((w) => w.id === intent.window_id);
  else for (const c of columns) { const at = c.windows.findIndex((w) => w.id === intent.window_id); if (at >= 0) { window = c.windows.splice(at, 1)[0]; break; } }
  if (!window || columns.some((c) => c.windows.some((w) => w.id === window!.id))) return;
  let col = columns.find((c) => c.id === intent.column_id);
  if (!col) { col = { id: intent.column_id, weight: 1, windows: [] }; columns.push(col); }
  const at = intent.after ? col.windows.findIndex((w) => w.id === intent.after) : -1;
  col.windows.splice(intent.after && at < 0 ? col.windows.length : at + 1, 0, structuredClone(window));
}
/** Integer-band split matching the server; pixel measurements never enter the canonical reducer. */
function split(columns: DocColumn[], intent: Extract<Intent, { type: "split" }>): void {
  if (columns.some((c) => c.windows.some((w) => w.id === intent.window.id))) return;
  const index = columns.findIndex((c) => c.windows.some((w) => w.id === intent.anchor_id));
  const column = columns[index], anchor = column?.windows.find((w) => w.id === intent.anchor_id); if (!column || !anchor) return;
  const taken = columns.map(() => new Set<number>());
  const free = (col: number, span: number, row: number, rows: number): boolean =>
    taken.slice(col, col + span).every((bands) => Array.from({ length: rows }, (_, i) => row + i).every((r) => !bands.has(r)));
  const mark = (col: number, span: number, row: number, rows: number): void => {
    for (const bands of taken.slice(col, col + span)) for (let r = row; r < row + rows; r++) bands.add(r);
  };
  for (const [i, c] of columns.entries()) for (const w of c.windows) {
    w.span = Math.min(w.span ?? 1, columns.length - i); w.rows ??= 1;
    if (w.row !== undefined) { if (free(i, w.span, w.row, w.rows)) mark(i, w.span, w.row, w.rows); else delete w.row; }
  }
  for (const [i, c] of columns.entries()) { let cursor = 0; for (const w of c.windows) {
    if (w.row === undefined) { while (cursor <= 64 && !free(i, w.span!, cursor, w.rows!)) cursor++; w.row = cursor; mark(i, w.span!, cursor, w.rows!); }
    cursor = Math.max(cursor, w.row + w.rows!);
  } }
  const added = structuredClone(intent.window), row = anchor.row ?? 0, span = anchor.span ?? 1, rows = anchor.rows ?? 1;
  if (intent.axis === "right") {
    added.row = row; added.rows = rows;
    if (added.height === undefined && anchor.height !== undefined) added.height = anchor.height;
    if (span > 1) { const left = Math.ceil(span / 2); anchor.span = left; added.span = span - left; columns[index + left]?.windows.push(added); }
    else {
      if (columns.some((c) => c.id === intent.column_id)) return;
      for (const [i, c] of columns.entries()) for (const w of c.windows) if (w !== anchor && i <= index && index < i + (w.span ?? 1)) w.span = (w.span ?? 1) + 1;
      column.weight /= 2; added.span = 1; columns.splice(index + 1, 0, { id: intent.column_id, weight: column.weight, windows: [added] });
    }
  } else {
    let from = index, to = index + span - 1;
    for (let i = 0; i < columns.length; i++) for (const w of columns[i]!.windows) if (i <= to && i + (w.span ?? 1) - 1 >= from) { from = Math.min(from, i); to = Math.max(to, i + (w.span ?? 1) - 1); }
    const boundary = row + rows;
    for (let i = from; i <= to; i++) for (const w of columns[i]?.windows ?? []) {
      const start = w.row ?? 0, height = w.rows ?? 1;
      if (start >= boundary) w.row = start + 1;
      else if (start + height >= boundary && !(i < index + span && index < i + (w.span ?? 1))) w.rows = height + 1;
    }
    if (anchor.height !== undefined) { anchor.height /= 2; added.height ??= anchor.height; }
    added.row = boundary; added.rows = 1; added.span = span; column.windows.push(added);
  }
  for (const c of columns) c.windows.sort((a, b) => (a.row ?? 0) - (b.row ?? 0));
}
