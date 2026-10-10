/**
 * Views: building a view's elements, sizing it on the grid, pushing neighbours aside, and the view's own
 * interactions (hover summary when zoomed out, dragging a view by its label).
 *
 * A view is a labelled region on the canvas. A tiled view holds columns of windows; a graph view (Mesh) hands
 * its content to the mesh module. Which kinds of view exist is the registry's business (`registry.ts`); this
 * module draws whatever model it is given.
 *
 * Invariants:
 * - Committed positions (`view.x/y`) feed layouts; animated positions (`c.x/y`) are on their way and never do.
 * - Columns are the truth for a tiled view: `geometry` reads their widths and order back from the DOM, so a
 *   drag or a resize persists into the model without a second bookkeeping path.
 * - Views sit on the cell grid and never overlap (`resolve`).
 */
import { Spring } from "../../../../../packages/ui/src/spring";
import { clamp } from "../camera/camera";
import type { Ctx, ViewRec } from "../context";
import { MARGIN, boxOf, contentSize, resolve, snapToGrid, type Box, type Rect } from "../layout/geometry";
import type { ColumnModel, ViewId, ViewModel, WindowModel } from "../model/types";
import { el } from "../dom";
import { restPx } from "../springs";
import { viewIcon } from "./icons";
import { windowLabel } from "../windows/label";
import { endActivity, setActivity } from "../../perf-activity";
import { arrange, readColumns } from "./tracks";

export interface ViewsModule {
  contentRect(c: ViewRec): Rect;
  /** The region's frame: the content plus the 16 px the region draws around it. */
  frameOf(c: ViewRec): Rect;
  /** Committed boxes of every view. */
  boxes(): Box[];
  newCol(col: ColumnModel): HTMLElement;
  /** Builds a view's elements and puts them in the world. */
  build(view: ViewModel): ViewRec;
  /** Writes a view's size from its content and keeps its label and region in step. */
  geometry(c: ViewRec): void;
  /** After a view changed size: push neighbours aside (never the changed one). */
  settle(fixedId: ViewId, at?: { x: number; y: number }): void;
  paintEmpty(c: ViewRec): void;
  /** Rebuilds a view from its model, in place in the order. */
  replace(id: ViewId): void;
  /** Adds a view next to the others (right, or below on a phone) before `beforeId`, never over anything. */
  addBeside(view: ViewModel, beforeId?: ViewId): ViewRec;
  /** Removes a view and everything in it. */
  remove(c: ViewRec): void;
  /** Removes every view. */
  clear(): void;
  hideSummary(): void;
  /** True while a view is being dragged by its label. */
  dragging(): boolean;
  dispose(): void;
}

export function createViews(cx: Ctx): ViewsModule {
  const { viewport, world, overlay, signal, camera, state, views } = cx;
  const cam = camera.cam;
  const summary = el("div", "cl-summary ui-overlay-surface");
  summary.hidden = true;
  document.body.append(summary);
  let summaryTimer = 0, summaryFor: ViewId | undefined;

  const contentRect = (c: ViewRec): Rect => ({ x: c.x + MARGIN.l, y: c.y + MARGIN.t, ...contentSize(c.view, state.metrics) });
  const boxes = (): Box[] => [...views.values()].map((c) => boxOf(c.view, state.metrics));
  const frameOf = (c: ViewRec): Rect => {
    const r = contentRect(c);
    return { x: r.x - 16, y: r.y - 16, w: r.w + 32, h: r.h + 32 };
  };

  const newCol = (col: ColumnModel): HTMLElement => {
    const colEl = el("div", "cl-col");
    colEl.dataset.id = col.id;
    colEl.dataset.w = String(col.w);
    colEl.style.setProperty("--w", `${col.w}px`);
    return colEl;
  };

  // ---- the hover card (zoomed out, pointer devices) --------------------------------------------------
  const hideSummary = (): void => {
    window.clearTimeout(summaryTimer);
    if (summary.hidden) return;
    summary.dataset.open = "false";
    summaryFor = undefined;
    window.setTimeout(() => { if (summary.dataset.open === "false") summary.hidden = true; }, 170);
  };
  const showSummary = (c: ViewRec): void => {
    if (camera.band !== "out" || !matchMedia("(hover: hover) and (pointer: fine)").matches || clusterDrag || state.movingWindow) return;
    window.clearTimeout(summaryTimer);
    if (summaryFor === c.view.id && !summary.hidden) return;
    summaryFor = c.view.id;
    const rows = c.view.layout === "graph"
      ? (cx.mesh?.summaryRows(c) ?? [["Hosts", String(c.view.nodes.filter((v) => v.kind === "host").length)]])
      : [...c.wins.values()].map((w) => windowLabel(w.model));
    summary.innerHTML = `<div class="cl-summary-head"><span class="cl-summary-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${viewIcon(c.view.id)}</svg></span><span class="cl-summary-name"></span></div><div class="cl-summary-rows"></div>`;
    (summary.querySelector(".cl-summary-name") as HTMLElement).textContent = c.view.name;
    const list = summary.querySelector(".cl-summary-rows") as HTMLElement;
    if (!rows.length) rows.push(["No windows", ""]);
    for (const [k, v] of rows) {
      const row = el("div", "cl-summary-row");
      row.append(el("span", "cl-summary-k", k!), el("span", "cl-summary-v", v!));
      list.append(row);
    }
    summary.hidden = false;
    const r = c.label.getBoundingClientRect();
    const w = summary.offsetWidth;
    const left = clamp(r.left, 12, innerWidth - w - 12);
    summary.style.left = `${left}px`;
    summary.style.top = `${r.bottom + 8}px`;
    summary.style.transformOrigin = `${Math.max(14, r.left - left + 14)}px 0`;
    summary.dataset.open = "false";
    requestAnimationFrame(() => { if (summaryFor === c.view.id) summary.dataset.open = "true"; });
  };

  // ---- dragging a view by its label ------------------------------------------------------------------
  let clusterDrag: { c: ViewRec; id: number; x0: number; y0: number; fx: number; fy: number; moved: boolean; snapX: number; snapY: number } | undefined;
  const ghost = el("div", "cl-ghost");
  let ghostX: Spring, ghostY: Spring;
  const paintGhost = (): void => { if (ghostX && ghostY) ghost.style.transform = `translate(${ghostX.value}px, ${ghostY.value}px)`; };
  ghostX = restPx(new Spring(0, () => paintGhost(), { visualDuration: 0.3, bounce: 0.12 }));
  ghostY = restPx(new Spring(0, () => paintGhost(), { visualDuration: 0.3, bounce: 0.12 }));
  world.append(ghost);

  const wireView = (c: ViewRec): void => {
    c.label.addEventListener("pointerenter", () => showSummary(c), { signal });
    c.label.addEventListener("pointerleave", () => { summaryTimer = window.setTimeout(hideSummary, 90); }, { signal });
    c.region.addEventListener("pointerenter", () => showSummary(c), { signal });
    c.region.addEventListener("pointerleave", () => { summaryTimer = window.setTimeout(hideSummary, 90); }, { signal });
    c.label.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      c.label.setPointerCapture(e.pointerId);
      clusterDrag = { c, id: e.pointerId, x0: e.clientX, y0: e.clientY, fx: c.x, fy: c.y, moved: false, snapX: c.x, snapY: c.y };
    }, { signal });
    c.label.addEventListener("pointermove", (e) => {
      const d = clusterDrag;
      if (!d || d.c !== c || e.pointerId !== d.id) return;
      const dx = (e.clientX - d.x0) / cam.z, dy = (e.clientY - d.y0) / cam.z;
      if (!d.moved) {
        if (Math.hypot(e.clientX - d.x0, e.clientY - d.y0) < 6) return;
        d.moved = true;
        setActivity("drag");
        hideSummary();
        camera.stop();
        c.el.dataset.lifted = "";
        const f = frameOf(c);
        ghost.style.cssText = `left:${MARGIN.l - 16}px;top:${MARGIN.t - 16}px;width:${f.w}px;height:${f.h}px`;
        ghostX.set(c.x, true); ghostY.set(c.y, true);
        ghost.dataset.on = "";
      }
      // The view follows the pointer freely; the outline shows where it will land on the grid.
      c.sx.set(d.fx + dx, true); c.sy.set(d.fy + dy, true);
      const sx = snapToGrid(d.fx + dx), sy = snapToGrid(d.fy + dy);
      if (sx !== d.snapX || sy !== d.snapY) {
        d.snapX = sx; d.snapY = sy;
        ghostX.set(sx); ghostY.set(sy);
        const trial = boxes().map((b) => (b.id === c.view.id ? { ...b, x: sx, y: sy } : b));
        const next = resolve(trial, c.view.id);
        for (const other of views.values()) {
          if (other === c) continue;
          const p = next.get(other.view.id)!;
          other.sx.set(p.x); other.sy.set(p.y);
        }
      }
    }, { signal });
    const end = (e: PointerEvent): void => {
      const d = clusterDrag;
      if (!d || d.c !== c || e.pointerId !== d.id) return;
      clusterDrag = undefined;
      endActivity("drag");
      delete c.el.dataset.lifted;
      delete ghost.dataset.on;
      if (!d.moved) { cx.nav.flyView(c.view.id); return; }
      // Commit: the dragged view lands on the grid and the others settle where it pushed them.
      c.sx.set(d.snapX); c.sy.set(d.snapY);
      c.view.x = d.snapX; c.view.y = d.snapY;
      settle(c.view.id);
      cx.store.changed();
    };
    c.label.addEventListener("pointerup", end, { signal });
    c.label.addEventListener("pointercancel", end, { signal });
  };

  // ---- building --------------------------------------------------------------------------------------
  const build = (view: ViewModel): ViewRec => {
    const root = el("section", "cl");
    root.dataset.view = view.id;
    const region = el("div", "cl-region");
    const label = el("button", "cl-label ui-pill");
    label.type = "button";
    label.style.setProperty("--label-inv", camera.labelScale);
    const menu = cx.sharing ? '<span class="cl-label-menu" role="button" tabindex="0" aria-label="View menu" data-tip="Share layout…"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12h.01M12 12h.01M19 12h.01"/></svg></span>' : "";
    label.innerHTML = `<span class="cl-label-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${viewIcon(view.id)}</svg></span><span class="cl-label-name"></span><span class="cl-label-meta"></span>${view.team ? '<span class="ui-ts-tag cl-team">team</span>' : ""}${menu}`;
    (label.querySelector(".cl-label-name") as HTMLElement).textContent = view.name;
    const menuEl = label.querySelector(".cl-label-menu");
    menuEl?.addEventListener("pointerdown", (e) => e.stopPropagation());
    menuEl?.addEventListener("click", (e) => { e.stopPropagation(); void cx.sharing?.open([view.id]); });
    const content = el("div", "cl-content");
    const colsEl = el("div", "cl-cols");
    const lift = el("div", "cl-lift");
    content.append(colsEl, lift);
    root.append(region, label, content);
    const c: ViewRec = {
      view, el: root, region, label, labelMeta: label.querySelector(".cl-label-meta") as HTMLElement, content, colsEl, lift,
      wins: new Map(), x: view.x, y: view.y,
      sx: undefined as unknown as Spring, sy: undefined as unknown as Spring,
    };
    const place = (): void => { root.style.transform = `translate(${c.x}px, ${c.y}px)`; cx.invalidate(); cx.memory?.cull(); };
    const POS = { visualDuration: 0.5, bounce: 0.2 };
    c.sx = restPx(new Spring(view.x, (v) => { c.x = v; place(); }, POS));
    c.sy = restPx(new Spring(view.y, (v) => { c.y = v; place(); }, POS));
    if (view.layout === "tiled") {
      for (const col of view.cols) {
        const colEl = newCol(col);
        for (const m of col.wins) {
          const rec = cx.win.make(c, m);
          c.wins.set(m.id, rec);
          colEl.append(rec.card.root);
        }
        colsEl.append(colEl);
      }
    } else {
      cx.mesh?.buildGraph(c);
    }
    wireView(c);
    geometry(c);
    paintEmpty(c);
    world.insertBefore(root, overlay);
    place();
    return c;
  };

  function geometry(c: ViewRec): void {
    // Columns are the truth: read them back from the DOM so drags, resizes and moves persist, then make the DOM agree with
    // what was read (a group's grid, its bands and placements; D212).
    if (c.view.layout === "tiled" && c.colsEl.querySelector(".cl-group")) {
      c.view.cols = readColumns(cx, c);
      arrange(cx, c, c.view.cols);
    } else if (c.view.layout === "tiled") {
      // No group in the view: the plain read the product always did, with no style reads (plain columns pay nothing for
      // the grid, D212). A group that a change has just dissolved was already taken apart by `arrange` in that change.
      c.view.cols = [...c.colsEl.querySelectorAll<HTMLElement>(":scope > .cl-col")].map((colEl) => ({
        id: colEl.dataset.id ?? `c${++state.serial}`,
        w: Number(colEl.dataset.w) || state.metrics.colW,
        wins: [...colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")].map((n) => c.wins.get(n.dataset.windowId ?? "")?.model).filter((m): m is WindowModel => !!m),
      })).filter((col) => col.wins.length > 0 || c.colsEl.querySelector(".cl-slot"));
    }
    const size = contentSize(c.view, state.metrics);
    const box = boxOf(c.view, state.metrics);
    c.el.style.width = `${box.w}px`;
    c.el.style.height = `${box.h}px`;
    c.content.style.cssText = `left:${MARGIN.l}px;top:${MARGIN.t}px;width:${size.w}px;height:${size.h}px`;
    c.region.style.cssText = `left:${MARGIN.l - 16}px;top:${MARGIN.t - 16}px;width:${size.w + 32}px;height:${size.h + 32}px`;
    c.label.style.left = `${MARGIN.l - 16}px`;
    c.label.style.top = `${MARGIN.t - 16}px`;
    const count = c.view.layout === "graph" ? (cx.mesh?.countText(c) ?? `${c.view.nodes.filter((v) => v.kind === "host").length} hosts`) : `${c.wins.size} window${c.wins.size === 1 ? "" : "s"}`;
    c.labelMeta.textContent = c.wins.size || c.view.layout === "graph" ? `· ${count}` : "· empty";
    c.label.setAttribute("aria-label", `${c.view.name}, ${count}. Fly to this view`);
    if (c.view.published) cx.sharing?.schedulePublish(c);
  }

  function settle(fixedId: ViewId, at?: { x: number; y: number }): void {
    const trial = boxes().map((b) => (at && b.id === fixedId ? { ...b, x: at.x, y: at.y } : b));
    const next = resolve(trial, fixedId);
    for (const c of views.values()) {
      const p = next.get(c.view.id);
      if (!p || (p.x === c.view.x && p.y === c.view.y)) continue;
      c.view.x = p.x; c.view.y = p.y;
      c.sx.set(p.x); c.sy.set(p.y);
    }
  }

  function paintEmpty(c: ViewRec): void {
    const isEmpty = c.view.layout === "tiled" && c.wins.size === 0;
    if (!isEmpty) { c.empty?.remove(); delete c.empty; return; }
    if (c.empty) return;
    const box = el("div", "cl-empty");
    box.innerHTML = `<div class="cl-empty-slot" aria-hidden="true"></div><p class="cl-empty-title">No hosts yet</p><p class="cl-empty-hint">Add a host and its shell opens here.</p>`;
    const addHost = cx.adapters.addHost;
    if (addHost) {
      const add = el("button", "ui-pill cl-empty-add");
      add.type = "button";
      add.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg><span>Add host</span>';
      add.addEventListener("click", () => addHost(), { signal });
      box.append(add);
    }
    c.content.append(box);
    c.empty = box;
  }

  const disposeRec = (c: ViewRec): void => {
    for (const w of c.wins.values()) { w.stopResize?.(); cx.visibility.unwatch(w); w.binding?.dispose(); w.cleanup?.(); w.card.dispose(); }
    c.el.remove();
  };

  return {
    contentRect, frameOf, boxes, newCol, build, geometry, settle, paintEmpty, hideSummary,
    dragging: () => Boolean(clusterDrag),
    replace(id) {
      const old = views.get(id);
      if (!old) return;
      const view = old.view;
      disposeRec(old);
      const entries = [...views.entries()];
      views.clear();
      for (const [k, v] of entries) views.set(k, k === id ? build(view) : v);
      cx.tree.render();
      cx.pill.paint();
    },
    addBeside(view, beforeId) {
      const others = [...views.values()].filter((c) => c.view.id !== beforeId);
      const boxesNow = others.map((c) => boxOf(c.view, state.metrics));
      view.x = state.metrics.narrow ? 0 : Math.max(0, ...boxesNow.map((b) => b.x + b.w));
      view.y = state.metrics.narrow ? Math.max(0, ...boxesNow.map((b) => b.y + b.h)) : 0;
      const rec = build(view);
      const entries = [...views.entries()];
      views.clear();
      for (const [k, v] of entries) { if (k === beforeId) views.set(view.id, rec); views.set(k, v); }
      if (!views.has(view.id)) views.set(view.id, rec);
      settle(view.id);
      cx.tree.render();
      return rec;
    },
    remove(c) { disposeRec(c); views.delete(c.view.id); },
    clear() {
      hideSummary();
      for (const c of views.values()) disposeRec(c);
      views.clear();
      state.activeWin = undefined;
    },
    dispose() {
      window.clearTimeout(summaryTimer);
      summary.remove();
      ghost.remove();
    },
  };
}

