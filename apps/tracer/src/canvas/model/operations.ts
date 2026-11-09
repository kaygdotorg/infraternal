/** Stable-ID intents and optimistic reduction for account layouts (D180, D183, #243). */
import { reduce } from "./reducer";
export { reduce } from "./reducer";
import { MIN_COLUMN_WEIGHT, MIN_WINDOW_HEIGHT, documentWindows as windows } from "./schema";
import type { CanvasDocument, DocColumn, DocLook, DocTarget, DocView, DocWindow } from "./schema";
export type Intent =
  | { type: "view.add"; view: DocView }
  | { type: "view.update"; view_id: string; cell?: { x: number; y: number }; name?: string }
  | { type: "target"; window_id: string; target: DocTarget }
  | { type: "view.remove"; view_id: string }
  | { type: "open"; view_id: string; column_id: string; window: DocWindow; after?: string; column_after?: string | null }
  | { type: "split"; view_id: string; column_id: string; window: DocWindow; anchor_id: string; axis: "right" | "down" }
  | { type: "close"; window_id: string }
  | { type: "move" | "membership.add"; view_id: string; column_id: string; window_id: string; after?: string; column_after?: string | null }
  | { type: "membership.remove"; view_id: string; window_id: string }
  | { type: "resize"; window_id: string; height?: number | null; span?: number | null; rows?: number | null; row?: number | null }
  | { type: "weight"; view_id: string; column_id: string; weight: number }
  | { type: "pin"; view_id: string; node_id: string; position?: { x: number; y: number } }
  /** Replaces the account's whole look (D322): the server orders edits, so the last one to arrive is every device's look. */
  | { type: "look.set"; look: DocLook };
export interface MoveEdit { windowId: string; move: true }
export type LayoutEdit = SplitEdit | MoveEdit;
export interface SplitEdit { windowId: string; anchorId: string; axis: "right" | "down" }
const cols = (v: DocView): DocColumn[] => v.layout.type === "tiled" ? v.layout.columns : [];
const equal = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);
/**
 * The one bound check for every split. The server halves the anchor's width (right) or height (down) and refuses a
 * result under its sizing floor, so a narrow or short anchor is first grown, with the ordinary ordered sizing intent,
 * to exactly twice the floor: both new windows then stay valid and the offered split always lands. The grow intent is
 * pipelined with the split and never waits for its receipt.
 */
function widenForSplit(working: CanvasDocument, intent: Extract<Intent, { type: "split" }>): Intent | undefined {
  const view = working.views.find((v) => v.id === intent.view_id), columns = view ? cols(view) : [];
  const at = columns.findIndex((c) => c.windows.some((w) => w.id === intent.anchor_id));
  const column = columns[at], anchor = column?.windows.find((w) => w.id === intent.anchor_id);
  if (!column || !anchor) return undefined;
  if (intent.axis === "down") {
    return anchor.height !== undefined && anchor.height < MIN_WINDOW_HEIGHT * 2 ? { type: "resize", window_id: anchor.id, height: MIN_WINDOW_HEIGHT * 2 } : undefined;
  }
  // Only a window that owns its column divides the column's weight; a spanning one shares the next column instead.
  if (Math.min(anchor.span ?? 1, columns.length - at) === 1 && column.weight < MIN_COLUMN_WEIGHT * 2) return { type: "weight", view_id: intent.view_id, column_id: column.id, weight: MIN_COLUMN_WEIGHT * 2 };
  return undefined;
}
/** Compare completed changes using stable neighbours, never numeric placement indexes. */
export function edits(before: CanvasDocument, after: CanvasDocument, splits: ReadonlyMap<string, LayoutEdit> = new Map()): Intent[] {
  const result: Intent[] = [];
  const moving = [...splits.values()].some((edit) => "move" in edit);
  const old = new Map(windows(before).map((w) => [w.id, w]));
  const live = new Set(windows(after).map((w) => w.id));
  for (const id of old.keys()) if (!live.has(id)) result.push({ type: "close", window_id: id });
  for (const v of before.views) if (!after.views.some((n) => n.id === v.id)) result.push({ type: "view.remove", view_id: v.id });
  for (const v of after.views) {
    const previous = before.views.find((p) => p.id === v.id);
    if (!previous) result.push({ type: "view.add", view: { ...v, layout: v.layout.type === "graph" ? { type: "graph", pinned: {} } : { type: "tiled", columns: [] } } });
    if (!moving && previous && (!equal(previous.cell, v.cell) || previous.name !== v.name)) result.push({ type: "view.update", view_id: v.id, ...(!equal(previous.cell, v.cell) ? { cell: v.cell } : {}), ...(previous.name !== v.name ? { name: v.name } : {}) });
    if (v.layout.type === "graph") {
      const pins = previous?.layout.type === "graph" ? previous.layout.pinned : {};
      for (const id of new Set([...Object.keys(pins), ...Object.keys(v.layout.pinned)])) if (!equal(pins[id], v.layout.pinned[id])) {
        const position = v.layout.pinned[id]; result.push({ type: "pin", view_id: v.id, node_id: id, ...(position ? { position } : {}) });
      }
      continue;
    }
    const placed = v.layout.columns.flatMap((c) => c.windows.map((w) => ({ c, w })));
    const pendingSplits = [...splits.values()].flatMap((edit) => { if (!("axis" in edit)) return []; const at = placed.find(({ w }) => w.id === edit.windowId && !old.has(w.id)); return at ? [{ ...at, edit }] : []; });
    const moved = placed.filter(({ w }) => old.has(w.id) && "move" in (splits.get(w.id) ?? {}));
    if (moved.length) {
      for (const { c, w } of moved) {
        const after = c.windows[c.windows.indexOf(w) - 1]?.id;
        const preceding = v.layout.columns[v.layout.columns.indexOf(c) - 1]?.id;
        result.push({ type: "move", view_id: v.id, window_id: w.id, column_id: c.id, ...(after ? { after } : {}), column_after: preceding ?? null });
      }
      continue;
    }
    if (pendingSplits.length) {
      const anchors = new Set(pendingSplits.map(({ edit }) => edit.anchorId));
      const reference = (w: DocWindow): DocWindow => anchors.has(w.id) ? { id: w.id, target: w.target } : w;
      for (const { c, w } of placed) if (!old.has(w.id) && !splits.has(w.id)) result.push({ type: "open", view_id: v.id, column_id: c.id, window: reference(w) });
      for (const { c, w, edit } of pendingSplits) result.push({ type: "split", view_id: v.id, column_id: c.id, window: reference(w), anchor_id: edit.anchorId, axis: edit.axis });
      continue;
    }
    const previousCols = previous ? cols(previous) : [];
    const memberships = new Map(previousCols.flatMap((c) => c.windows.map((w, i) => [w.id, { col: c.id, after: c.windows[i - 1]?.id }] as const)));
    for (const id of memberships.keys()) if (live.has(id) && !v.layout.columns.some((c) => c.windows.some((w) => w.id === id))) result.push({ type: "membership.remove", view_id: v.id, window_id: id });
    for (const [ci, c] of v.layout.columns.entries()) {
      for (const [i, w] of c.windows.entries()) {
        const neighbour = c.windows[i - 1]?.id;
        const at = { view_id: v.id, column_id: c.id, ...(!previousCols.some((p) => p.id === c.id) ? { column_after: v.layout.columns[ci - 1]?.id ?? null } : {}), ...(neighbour ? { after: neighbour } : {}) };
        const was = old.get(w.id), membership = memberships.get(w.id);
        if (!was) result.push({ type: "open", ...at, window: w });
        else if (!membership) result.push({ type: "membership.add", ...at, window_id: w.id });
        else if (membership.col !== c.id || membership.after !== neighbour) result.push({ type: "move", ...at, window_id: w.id });
        if (was) {
          if (!equal(was.target, w.target)) result.push({ type: "target", window_id: w.id, target: w.target });
          const size: Extract<Intent, { type: "resize" }> = { type: "resize", window_id: w.id }; let changed = false;
          for (const field of ["height", "span", "rows", "row"] as const) if (was[field] !== w[field]) { size[field] = w[field] ?? (field === "row" ? 0 : 1); changed = true; }
          if (changed) result.push(size);
        }
      }
      const prior = previousCols.find((p) => p.id === c.id);
      if (c.windows.length && Math.abs((prior?.weight ?? 1) - c.weight) > 0.001) result.push({ type: "weight", view_id: v.id, column_id: c.id, weight: Math.max(0.1, Math.min(10, c.weight)) });
    }
  }
  // The account's look is one value: when it differs, the new one replaces the old whole.
  if (after.look && !equal(before.look, after.look)) result.push({ type: "look.set", look: after.look });
  const working = structuredClone(before), compact: Intent[] = [];
  // Earlier insertions already move their following neighbours. Do not turn one drag into redundant moves.
  for (let intent of [...result.filter((i) => i.type !== "membership.remove"), ...result.filter((i) => i.type === "membership.remove")]) {
    if (intent.type === "split") {
      const grow = widenForSplit(working, intent);
      if (grow) {
        compact.push(grow); reduce(working, grow);
        // The drawn half was measured before the grow; the grown anchor divides evenly, so the server's own half is right.
        if (grow.type === "resize") { const { height: _drawn, ...window } = intent.window; intent = { ...intent, window }; }
      }
    }
    if (intent.type === "move") {
      const view = working.views.find((v) => v.id === intent.view_id);
      const col = view && cols(view).find((c) => c.id === intent.column_id);
      const at = col?.windows.findIndex((w) => w.id === intent.window_id) ?? -1;
      if (at >= 0 && col?.windows[at - 1]?.id === intent.after) continue;
    }
    compact.push(intent); reduce(working, intent);
  }
  return compact;
}
