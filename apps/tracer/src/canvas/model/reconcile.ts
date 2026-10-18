/** Paint shared layout changes without replacing live terminal bindings or this device's focus/camera (D178). */
import type { Ctx } from "../context";
import { CELL } from "../layout/geometry";
import { groupsLoaded, loadGroups } from "../layout/groups-handle";
import { columnsFromDocument, docHasGroups, type CanvasDocument, type DocTarget } from "./document";
import type { WindowModel } from "./types";

export async function reconcile(cx: Ctx, document: CanvasDocument, resolve: (target: DocTarget) => Partial<WindowModel> | undefined, current: () => boolean): Promise<void> {
  if (docHasGroups(document)) await loadGroups();
  if (!current()) return;
  const keep = new Set(document.views.map((v) => v.id));
  for (const c of [...cx.views.values()]) if (c.view.id !== "settings" && !keep.has(c.view.id)) cx.view.remove(c);
  for (const view of document.views) {
    let c = cx.views.get(view.id);
    // Graph content is owned by its existing source; layout only positions its pins.
    if (view.layout.type === "graph") {
      if (c) { c.view.x = view.cell.x * CELL; c.view.y = view.cell.y * CELL; c.sx.set(c.view.x, true); c.sy.set(c.view.y, true); }
      continue;
    }
    const columns = columnsFromDocument(view.layout, cx.state.metrics, resolve);
    if (!c) {
      c = cx.view.build({ id: view.id, name: view.name, layout: "tiled", cols: columns, nodes: [], x: view.cell.x * CELL, y: view.cell.y * CELL });
      cx.views.set(view.id, c); continue;
    }
    // New shells have not acquired a stable reference yet; do not discard them when another device edits.
    for (const col of c.view.cols) for (const w of col.wins) if (w.kind === "flow" || (w.kind === "terminal" && !w.sessionId)) {
      const destination = columns.find((n) => n.id === col.id);
      if (destination) destination.wins.push(w); else columns.push({ ...col, wins: [w] });
    }
    const ids = new Set(columns.flatMap((col) => col.wins.map((w) => w.id)));
    for (const [id, rec] of c.wins) if (!ids.has(id)) {
      if (cx.state.activeWin === rec) cx.win.setActive(undefined);
      rec.stopResize?.(); cx.visibility.unwatch(rec); rec.binding?.dispose(); rec.cleanup?.(); rec.card.dispose(); c.wins.delete(id);
    }
    for (const col of columns) for (const model of col.wins) {
      const rec = c.wins.get(model.id);
      if (!rec) c.wins.set(model.id, cx.win.make(c, model));
      else { for (const k of ["h", "span", "rows", "row"] as const) { if (model[k] === undefined) delete rec.model[k]; else rec.model[k] = model[k]; } }
    }
    const grouped = groupsLoaded();
    if (grouped) grouped.applyCols(cx, c, columns);
    else {
      c.colsEl.replaceChildren(...columns.map((col) => { const el = cx.view.newCol(col); for (const w of col.wins) { const rec = c!.wins.get(w.id); if (rec) el.append(rec.card.root); } return el; }));
    }
    c.view.cols = columns;
    c.view.x = view.cell.x * CELL; c.view.y = view.cell.y * CELL;
    c.sx.set(c.view.x, true); c.sy.set(c.view.y, true);
    cx.view.geometry(c); cx.view.paintEmpty(c);
  }
  cx.tree.render(); cx.pill.paint(); cx.toolbar.update(); cx.visibility.lodChanged();
}
