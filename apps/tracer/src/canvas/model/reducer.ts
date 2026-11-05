/** Pure stable-ID layout projection shared by optimistic edits and offline journal validation (D180, D183, D245). */
import { documentWindows as windows, type CanvasDocument, type DocColumn, type DocView, type DocWindow } from "./schema";
import type { Intent } from "./operations";
const cols = (v: DocView): DocColumn[] => v.layout.type === "tiled" ? v.layout.columns : [];
/** Missing memberships stay missing after close; callers deduplicate the server's ordered revisions. */
export function reduce(doc: CanvasDocument, intent: Intent): void {
  apply(doc, intent);
  if (intent.type !== "close" && intent.type !== "move" && intent.type !== "membership.remove") return;
  for (const view of doc.views) {
    const columns = cols(view);
    for (let at = columns.length - 1; at >= 0; at--) if (!columns[at]!.windows.length && !columns.slice(0, at).some((c, from) => c.windows.some((w) => (w.span ?? 1) > at - from))) columns.splice(at, 1);
  }
}
function apply(doc: CanvasDocument, intent: Intent): void {
  if (intent.type === "look.set") { doc.look = structuredClone(intent.look); return; }
  if (intent.type === "view.add") { if (!doc.views.some((v) => v.id === intent.view.id)) doc.views.push(structuredClone(intent.view)); return; }
  if (intent.type === "view.remove") { doc.views = doc.views.filter((v) => v.id !== intent.view_id); return; }
  if (intent.type === "close") { for (const v of doc.views) for (const c of cols(v)) c.windows = c.windows.filter((w) => w.id !== intent.window_id); return; }
  if (intent.type === "resize") { for (const w of windows(doc)) if (w.id === intent.window_id) for (const k of ["height", "span", "rows", "row"] as const) if (intent[k] != null) w[k] = intent[k]; return; }
  if (intent.type === "target") { for (const w of windows(doc)) if (w.id === intent.window_id) w.target = structuredClone(intent.target); return; }
  const view = doc.views.find((v) => v.id === intent.view_id); if (!view) return;
  if (intent.type === "view.update") { if (intent.cell) view.cell = { ...intent.cell }; if (intent.name) view.name = intent.name; return; }
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
  if (!col) { col = { id: intent.column_id, weight: 1, windows: [] };
    const neighbour = columns.findIndex((c) => c.id === intent.column_after);
    columns.splice(intent.column_after === null ? 0 : neighbour < 0 ? columns.length : neighbour + 1, 0, col); }
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
    // Scan runs from the left. Extending the frontier also visits every newly reached column,
    // so transitive members to the left of the anchor cannot be missed (same closure as storage).
    let from = 0, to = 0;
    while (from < columns.length) {
      to = from;
      for (let cursor = from; cursor <= to; cursor++) for (const w of columns[cursor]!.windows) to = Math.max(to, cursor + (w.span ?? 1) - 1);
      if (index <= to) break;
      from = to + 1;
    }
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
