// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What a view does under the pointer: the hover card that lists its windows when the canvas is zoomed out, and dragging a
 * view by its label to a new place on the grid. Both are person-driven and none is needed before the first
 * pointer reaches a label, so they load on demand (D188, #322); `world.ts` keeps the label's tap (fly to the view) and
 * hands everything else to this module once it has arrived (it is fetched when the browser is idle after the canvas is up).
 *
 * Invariants:
 * - A drag the hook already began (the press came before this module) continues from the pointer's latest position: `press`
 *   takes the press and applies the position the pointer has now, so the view does not jump back to where the press was.
 * - Nothing outside on-demand code imports this file (see split.on-demand.ts): a static import would link it into the
 *   deferred chunk again.
 */
import { Spring } from "../../../../../packages/ui/src/spring";
import { keyCaps, PALETTE_KEYS } from "../../../../../packages/ui/src/shortcuts";
import { clamp } from "../camera/camera";
import type { Ctx, ViewRec, WinRec } from "../context";
import { MARGIN, resolve, snapToGrid, type Box, type Rect } from "../layout/geometry";
import type { ViewId } from "../model/types";
import { el } from "../dom";
import { restPx } from "../springs";
import { ICON, viewIcon } from "./icons";
import { windowLabel } from "../windows/label";
import { viewRecentWindows, viewWindowEntries } from "../toolbar/view-windows";
import { endActivity, setActivity } from "../../perf-activity";

/** Rows the view's hover card lists before its "All" row (TASTE: lists stay short). */
const SUMMARY_ROWS = 5;

/** A press the hook saw before this module arrived: where it began and where the pointer is now. */
export interface EarlyPress { id: number; x0: number; y0: number; x: number; y: number }

export interface ViewPointer {
  /** Gives a view's label and region their hover card and drag. */
  wire(c: ViewRec): void;
  /** Shows a view's card, when the canvas is zoomed out and the device hovers: the pointer was already over it as this module arrived. */
  hover(c: ViewRec): void;
  /** Continues a press that began before the module arrived, from the pointer's latest position. */
  press(c: ViewRec, press: EarlyPress): void;
  /** `instant`: another surface takes over (the palette), so the card goes at once instead of fading under it. */
  hideSummary(instant?: boolean): void;
  dispose(): void;
}

/** What the module needs of the views it serves: where a view's frame is, the committed boxes, and the push-aside after a drop. */
export interface ViewPointerHost {
  frameOf(c: ViewRec): Rect;
  boxes(): Box[];
  settle(fixedId: ViewId, at?: { x: number; y: number }): void;
}

export function createViewPointer(cx: Ctx, host: ViewPointerHost): ViewPointer {
  const { world, signal, camera, state, views } = cx;
  const cam = camera.cam;
  const { frameOf, boxes, settle } = host;
  const summary = el("div", "cl-summary ui-overlay-surface");
  summary.hidden = true;
  document.body.append(summary);
  let summaryTimer = 0, summaryFor: ViewId | undefined;

  // ---- the hover card (zoomed out, pointer devices) --------------------------------------------------
  /** `instant`: another surface takes over (the palette), so the card goes at once instead of fading under it. */
  const hideSummary = (instant = false): void => {
    window.clearTimeout(summaryTimer);
    if (summary.hidden) return;
    summary.dataset.open = "false";
    summaryFor = undefined;
    if (instant) { summary.hidden = true; return; }
    window.setTimeout(() => { if (summary.dataset.open === "false") summary.hidden = true; }, 170);
  };
  // The card is a popover while it shows: the pointer can cross the gap into it, and its rows can be pressed.
  summary.addEventListener("pointerenter", () => window.clearTimeout(summaryTimer), { signal });
  summary.addEventListener("pointerleave", () => { summaryTimer = window.setTimeout(hideSummary, 90); }, { signal });
  const summaryRow = (k: string, v: string): HTMLElement => {
    const row = el("div", "cl-summary-row");
    row.append(el("span", "cl-summary-k", k), el("span", "cl-summary-v", v));
    return row;
  };
  /** A window the card lists: the same row as the view list, pressed to fly to it. */
  const windowPick = (c: ViewRec, rec: WinRec): HTMLElement => {
    const [name, detail] = windowLabel(rec.model, cx.adapters.inventory);
    const b = el("button", "cl-viewrow cl-summary-pick");
    b.type = "button";
    b.dataset.window = rec.model.id;
    b.innerHTML = `<span class="cl-viewrow-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${rec.model.kind === "terminal" ? ICON.terminal : viewIcon(c.view.id)}</svg></span><span class="cl-viewrow-name"></span><span class="cl-viewrow-meta"></span>`;
    (b.querySelector(".cl-viewrow-name") as HTMLElement).textContent = name;
    (b.querySelector(".cl-viewrow-meta") as HTMLElement).textContent = detail;
    b.addEventListener("click", () => { hideSummary(); cx.win.setActive(rec); cx.nav.focusWindow(rec); });
    return b;
  };
  /** The quiet last row: the rest of the view is one step away in ⌘K, filtered to its windows. */
  const allRow = (c: ViewRec, total: number): HTMLElement => {
    const b = el("button", "cl-viewrow cl-viewrow-search cl-summary-all");
    b.type = "button";
    b.innerHTML = `<span class="cl-viewrow-name"></span><span class="cl-viewrow-keys"></span>`;
    (b.querySelector(".cl-viewrow-name") as HTMLElement).textContent = `All ${total} windows`;
    const keys = b.querySelector(".cl-viewrow-keys") as HTMLElement;
    for (const cap of keyCaps(PALETTE_KEYS)) keys.append(el("kbd", "", cap));
    b.addEventListener("click", () => { hideSummary(true); cx.core.showPalette(viewWindowEntries(cx, c)); });
    return b;
  };
  const showSummary = (c: ViewRec): void => {
    if (camera.band !== "out" || !matchMedia("(hover: hover) and (pointer: fine)").matches || clusterDrag || state.movingWindow) return;
    window.clearTimeout(summaryTimer);
    if (summaryFor === c.view.id && !summary.hidden) return;
    summaryFor = c.view.id;
    summary.innerHTML = `<div class="cl-summary-head"><span class="cl-summary-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${viewIcon(c.view.id)}</svg></span><span class="cl-summary-name"></span></div><div class="cl-summary-rows"></div>`;
    (summary.querySelector(".cl-summary-name") as HTMLElement).textContent = c.view.name;
    const list = summary.querySelector(".cl-summary-rows") as HTMLElement;
    if (c.view.layout === "graph") {
      const rows = cx.mesh?.summaryRows(c) ?? [["Hosts", String(c.view.nodes.filter((v) => v.kind === "host").length)]];
      if (!rows.length) rows.push(["No windows", ""]);
      for (const [k, v] of rows) list.append(summaryRow(k!, v!));
    } else {
      // Lists stay short (TASTE): the five windows used most recently, then one row for the rest of the view.
      const total = c.wins.size;
      if (!total) list.append(summaryRow("No windows", ""));
      for (const rec of viewRecentWindows(cx, c, SUMMARY_ROWS)) list.append(windowPick(c, rec));
      if (total > SUMMARY_ROWS) list.append(allRow(c, total));
    }
    // Never taller than the space under the label: it scrolls rather than leave the viewport.
    summary.hidden = false;
    const r = c.label.getBoundingClientRect();
    summary.style.maxHeight = `${Math.max(120, innerHeight - r.bottom - 8 - 12)}px`;
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
  ghostX = restPx(new Spring(0, () => paintGhost(), { visualDuration: 0.3 }));
  ghostY = restPx(new Spring(0, () => paintGhost(), { visualDuration: 0.3 }));
  world.append(ghost);

  const beginDrag = (c: ViewRec, id: number, x0: number, y0: number): void => {
    clusterDrag = { c, id, x0, y0, fx: c.x, fy: c.y, moved: false, snapX: c.x, snapY: c.y };
  };
  const moveDrag = (c: ViewRec, id: number, clientX: number, clientY: number): void => {
    const d = clusterDrag;
    if (!d || d.c !== c || id !== d.id) return;
    const dx = (clientX - d.x0) / cam.z, dy = (clientY - d.y0) / cam.z;
    if (!d.moved) {
      if (Math.hypot(clientX - d.x0, clientY - d.y0) < 6) return;
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
  };

  const wireView = (c: ViewRec): void => {
    c.label.addEventListener("pointerenter", () => showSummary(c), { signal });
    c.label.addEventListener("pointerleave", () => { summaryTimer = window.setTimeout(hideSummary, 90); }, { signal });
    c.region.addEventListener("pointerenter", () => showSummary(c), { signal });
    c.region.addEventListener("pointerleave", () => { summaryTimer = window.setTimeout(hideSummary, 90); }, { signal });
    c.label.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      c.label.setPointerCapture(e.pointerId);
      beginDrag(c, e.pointerId, e.clientX, e.clientY);
    }, { signal });
    c.label.addEventListener("pointermove", (e) => moveDrag(c, e.pointerId, e.clientX, e.clientY), { signal });
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
      // `at` makes the dragged view the one that stays, on a touch screen too. A person placed it, so it and what it pushed
      // are saved where they are: no view keeps a `home` from before.
      settle(c.view.id, { x: d.snapX, y: d.snapY });
      for (const other of views.values()) delete other.view.home;
      cx.store.changed();
    };
    c.label.addEventListener("pointerup", end, { signal });
    c.label.addEventListener("pointercancel", end, { signal });
  };

  return {
    wire: wireView,
    hover: showSummary,
    press(c, p) {
      beginDrag(c, p.id, p.x0, p.y0);
      moveDrag(c, p.id, p.x, p.y);
    },
    hideSummary,
    dispose() {
      window.clearTimeout(summaryTimer);
      summary.remove();
      ghost.remove();
    },
  };
}
