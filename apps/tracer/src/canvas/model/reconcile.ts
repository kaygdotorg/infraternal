/** Paint shared layout changes without replacing live terminal bindings or this device's focus/camera (D178). */
import type { Ctx } from "../context";
import { CELL } from "../layout/geometry";
import { loadGroups } from "../layout/groups-handle";
import { columnsFromDocument, type CanvasDocument, type DocTarget } from "./document";
import { makeBody } from "../views/body";
import type { WindowModel } from "./types";

export async function reconcile(cx: Ctx, document: CanvasDocument, resolve: (target: DocTarget) => Partial<WindowModel> | undefined, current: () => boolean, protectedIds: ReadonlySet<string> = new Set()): Promise<void> {
  const grouped = await loadGroups();
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
    for (const col of c.view.cols) for (const w of col.wins) if (w.kind === "flow" || protectedIds.has(w.id) || (w.kind === "terminal" && !w.sessionId)) {
      if (columns.some((column) => column.wins.some((window) => window.id === w.id))) continue;
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
      else {
        const sameHost = rec.model.hostId === model.hostId && rec.model.host === model.host;
        const retargeted = rec.model.sessionId !== model.sessionId || rec.model.hostId !== model.hostId;
        rec.model.host = model.host;
        for (const k of ["sessionId", "session", "hostId", "user", "address", "os"] as const) { if (model[k] === undefined) delete rec.model[k]; else Object.assign(rec.model, { [k]: model[k] }); }
        if (retargeted && (!sameHost || !rec.binding?.retarget?.(rec.model))) { rec.binding?.dispose(); makeBody(cx, rec); rec.binding?.setActive(cx.state.activeWin === rec); }
        rec.card.setTitle({ host: rec.model.host, ...(rec.model.user ? { user: rec.model.user } : {}), ...(rec.model.session ? { session: rec.model.session } : {}) });
        for (const k of ["h", "span", "rows", "row"] as const) { if (model[k] === undefined) delete rec.model[k]; else rec.model[k] = model[k]; } }
    }
    grouped.applyCols(cx, c, columns);
    c.view.name = view.name;
    const name = c.label.querySelector(".cl-label-name"); if (name) name.textContent = view.name;
    c.view.cols = columns;
    c.view.x = view.cell.x * CELL; c.view.y = view.cell.y * CELL;
    c.sx.set(c.view.x, true); c.sy.set(c.view.y, true);
    cx.view.geometry(c); cx.view.paintEmpty(c);
  }
  if (!cx.state.activeWin) { const first = cx.views.get(cx.state.currentView)?.wins.values().next().value; if (first) cx.win.setActive(first); }
  cx.tree.render(); cx.pill.paint(); cx.toolbar.update(); cx.visibility.lodChanged();
}
