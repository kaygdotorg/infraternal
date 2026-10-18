/** Paint shared layout changes without replacing live terminal bindings or this device's focus/camera (D178). */
import type { Ctx, ViewRec } from "../context";
import { CELL } from "../layout/geometry";
import { loadGroups } from "../layout/groups-handle";
import { columnsFromDocument, type CanvasDocument, type DocTarget, type DocView } from "./document";
import { makeBody } from "../views/body";
import type { WindowModel } from "./types";

/** Metadata changes leave terminal geometry and device focus alone. */
function place(view: ViewRec, document: DocView): void {
  if (view.view.name !== document.name) { view.view.name = document.name; const label = view.label.querySelector(".cl-label-name"); if (label) label.textContent = document.name; }
  const x = document.cell.x * CELL, y = document.cell.y * CELL;
  if (view.view.x !== x || view.view.y !== y) { view.view.x = x; view.view.y = y; view.sx.set(x, true); view.sy.set(y, true); }
}
export interface SharedPaint { document: CanvasDocument; protectedIds: ReadonlySet<string>; protectedViews: ReadonlySet<string> }
export async function reconcile(cx: Ctx, read: () => SharedPaint, resolve: (target: DocTarget, windowId: string) => Partial<WindowModel> | undefined, current: () => boolean): Promise<void> {
  const grouped = await loadGroups();
  if (!current()) return;
  // Imports may have yielded to input; capture the latest projection only after those boundaries.
  const { document, protectedIds, protectedViews } = read();
  if (!current()) return;
  const keep = new Set([...document.views.map((v) => v.id), ...protectedViews]);
  for (const c of [...cx.views.values()]) if (c.view.id !== "settings" && !keep.has(c.view.id)) cx.view.remove(c);
  for (const view of document.views) {
    let c = cx.views.get(view.id);
    // Graph content is owned by its existing source; layout only positions its pins.
    if (view.layout.type === "graph") {
      if (!c) { c = cx.view.build({ id: view.id, name: view.name, layout: "graph", cols: [], nodes: [], graphPins: view.layout.pinned, x: view.cell.x * CELL, y: view.cell.y * CELL }); cx.views.set(view.id, c); }
      else if (JSON.stringify(c.view.graphPins) !== JSON.stringify(view.layout.pinned)) { c.view.graphPins = view.layout.pinned; cx.mesh?.refreshLayout(c); }
      place(c, view);
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
        const relabel = rec.model.host !== model.host || rec.model.user !== model.user || rec.model.session !== model.session;
        const sameHost = rec.model.hostId === model.hostId && rec.model.host === model.host;
        const retargeted = rec.model.sessionId !== model.sessionId || rec.model.hostId !== model.hostId;
        rec.model.host = model.host;
        for (const k of ["sessionId", "session", "hostId", "user", "address", "os"] as const) { if (model[k] === undefined) delete rec.model[k]; else Object.assign(rec.model, { [k]: model[k] }); }
        if (retargeted && (!sameHost || !rec.binding?.retarget?.(rec.model))) { rec.binding?.dispose(); makeBody(cx, rec); rec.binding?.setActive(cx.state.activeWin === rec); }
        if (relabel) rec.card.setTitle({ host: rec.model.host, ...(rec.model.user ? { user: rec.model.user } : {}), ...(rec.model.session ? { session: rec.model.session } : {}) });
        for (const k of ["h", "span", "rows", "row"] as const) { if (model[k] === undefined) delete rec.model[k]; else rec.model[k] = model[k]; } }
    }
    // Bindings keep the original model object. Columns must share it so asynchronous reference
    // completion reaches the next document instead of reopening the same shell on every paint.
    for (const col of columns) col.wins = col.wins.map((model) => c.wins.get(model.id)?.model ?? model);
    grouped.applyCols(cx, c, columns);
    c.view.cols = columns;
    place(c, view);
    cx.view.geometry(c); cx.view.paintEmpty(c);
  }
  if (!cx.state.activeWin) { const first = cx.views.get(cx.state.currentView)?.wins.values().next().value; if (first) cx.win.setActive(first); }
  cx.store.reset(protectedIds, new Set([...protectedViews].filter((id) => !document.views.some((v) => v.id === id))));
  cx.adapters.inventory?.setLayout?.(document);
  if (protectedIds.size || protectedViews.size) cx.store.changed();
  cx.tree.render(); cx.pill.paint(); cx.toolbar.update(); cx.visibility.lodChanged();
}
