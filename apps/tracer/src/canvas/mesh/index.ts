/**
 * The Mesh (D164, D180): who may reach what, drawn two ways.
 *
 * - **Arrows on demand** in Console: hovering a terminal's pill (a long press on touch) shows where its host
 *   can reach, as quiet arrows to the other windows, with an edge marker that names where an off-screen target
 *   is. Dragging from the connector next to the pill onto another terminal asks to allow access.
 * - **The Mesh view**: a graph of node cards (hosts and tags) joined by access arrows; solid is direct, dashed
 *   goes through a named relay. Dragging an arrow's head or tail onto another node moves the grant; dropping it on
 *   empty canvas offers to remove it. Edges carry the grant's name only, never its rules (D180).
 *
 * All data and all edits go through a MeshSource (source.ts). Today a test double fills it; the API of #108
 * will fill it in the product, and the Mesh view is offered only when a source exists.
 *
 * The Mesh view's own code (graph-view.ts: node cards, grant arrows and their editing, layout, levels of detail) loads
 * the first time the view is on screen, and shows a quiet loading card until then. Everything here stays small: reach
 * arrows between terminals, the connector on a pill, and the rules for who sees what.
 *
 * Arrow geometry is the only per-frame geometry on the canvas, and it is redrawn on the next animation frame
 * after the camera or a window moves (updateOverlay, coalesced by the context's invalidate).
 */
import { mountConfirmTip } from "../../../../../packages/ui/src/tooltip";
import { createSpinner } from "../../../../../packages/ui/src/spinner";
import { onDemand } from "../../on-demand";
import { clamp } from "../camera/camera";
import type { Ctx, ViewRec, WinRec } from "../context";
import { SVG_NS, coarse, el } from "../dom";
import type { Pt, Rect } from "../layout/geometry";
import type { Grant } from "../model/types";
import { ICON } from "../views/icons";
import { Arrow, DragArrow, anchors } from "./arrows";
import type { GraphViewModule } from "./graph-view";
import { reach } from "./grants";
import type { MeshSource } from "./source";

export interface MeshModule {
  /** Fills a graph view with its node cards and arrows. */
  buildGraph(c: ViewRec): void;
  /** The camera came to rest: arrows redraw when the zoom changed enough to change their head size. */
  redraw(): void;
  /** Redraws the arrows that follow the camera or a moving window (called on the next frame). */
  updateOverlay(): void;
  wireTerminal(rec: WinRec): void;
  showReach(rec: WinRec, pinned?: boolean): void;
  hideReach(instant?: boolean): void;
  /** The window whose reach arrows are showing. */
  reachFor(): WinRec | undefined;
  reachCount(): number;
  /** True while an arrow is being dragged from a port. */
  dragging(): boolean;
  /** True while the pinned reach arrows should be dismissed by a press elsewhere. */
  reachPinned(): boolean;
  summaryRows(c: ViewRec): string[][];
  countText(c: ViewRec): string;
  /** The grants as they are now (a copy). */
  grants(): Grant[];
  /** What the Mesh view has on screen right now (specs and the frame-time benchmark read this). */
  graphStats(): ReturnType<GraphViewModule["stats"]>;
  dispose(): void;
}

export function createMesh(cx: Ctx, source: MeshSource): MeshModule {
  const { viewport, overlay, edges, signal, camera, state, views } = cx;
  const cam = camera.cam;
  const toWorld = (x: number, y: number): Pt => camera.toWorld(x, y);
  const toClient = (p: Pt): Pt => camera.toClient(p);
  const worldRect = (n: Element): Rect => camera.worldRect(n);
  const winOfEl = (node: Element | undefined): WinRec | undefined => {
    const id = (node as HTMLElement | undefined)?.dataset.windowId;
    return id ? [...views.values()].flatMap((v) => [...v.wins.values()]).find((w) => w.model.id === id) : undefined;
  };
  interface ReachItem { arrow: Arrow; host: string; via?: string; target: Element; marker?: HTMLButtonElement; node?: boolean }
  let reachFor: WinRec | undefined;
  let reachItems: ReachItem[] = [];
  let reachPinned = false;
  const reachLayer = document.createElementNS(SVG_NS, "g");
  reachLayer.setAttribute("class", "cl-reach");
  overlay.append(reachLayer);
  let drag: { arrow: DragArrow; source: WinRec; over?: HTMLElement | undefined } | undefined;
  const headSize = (): number => clamp(7 / cam.z, 7, 16);

  const updateOverlay = (): void => {
    if (gv) gv.cull(); else wantGraph();
    if (reachFor && reachItems.length) {
      const src = worldRect(reachFor.card.root);
      const vp = viewport.getBoundingClientRect();
      const inset = 30;
      reachItems.forEach((item, index) => {
        const dst = worldRect(item.target);
        const sc = toClient({ x: dst.x + dst.w / 2, y: dst.y + dst.h / 2 });
        const inside = sc.x > vp.left + inset && sc.x < vp.right - inset && sc.y > vp.top + inset && sc.y < vp.bottom - inset;
        if (inside) {
          item.arrow.between(src, dst, headSize(), (index % 3) - 1);
          item.marker?.removeAttribute("data-on");
          return;
        }
        // Off screen: the arrow runs to the viewport edge and a marker names where it leads.
        // On a phone the bottom edge keeps clear of the test-double badge.
        const ex = clamp(sc.x, vp.left + inset, vp.right - inset), ey = clamp(sc.y, vp.top + inset, vp.bottom - inset - (coarse.matches ? 56 : 0));
        const end = toWorld(ex, ey);
        const n = anchors(src, { x: end.x, y: end.y, w: 0, h: 0 }, 0);
        const dx = end.x - n.p0.x, dy = end.y - n.p0.y, len = Math.hypot(dx, dy) || 1;
        item.arrow.draw(n.p0, n.t0, end, { x: dx / len, y: dy / len }, headSize());
        if (item.marker) {
          item.marker.dataset.on = "";
          const w = item.marker.offsetWidth, h = item.marker.offsetHeight;
          const px = clamp(ex - vp.left - w / 2, 8, vp.width - w - 8), py = clamp(ey - vp.top - h / 2, 8, vp.height - h - 8);
          item.marker.style.translate = `${px}px ${py}px`;
          const angle = Math.atan2(sc.y - (vp.top + vp.height / 2), sc.x - (vp.left + vp.width / 2));
          (item.marker.querySelector(".cl-edge-arrow") as HTMLElement).style.transform = `rotate(${angle}rad)`;
        }
      });
    }
  };

  const hideReach = (instant = false): void => {
    if (!reachFor) return;
    const rec = reachFor;
    const items = reachItems;
    reachFor = undefined; reachItems = []; reachPinned = false;
    rec.card.root.removeAttribute("data-reach");
    const done = (): void => { for (const i of items) { i.arrow.remove(); i.marker?.remove(); } };
    if (instant) { done(); return; }
    reachLayer.dataset.open = "false";
    window.setTimeout(() => { if (!reachFor) done(); }, 200);
  };
  const showReach = (rec: WinRec, pinned = false): void => {
    if (!source.canView()) return;
    if (reachFor === rec) { reachPinned ||= pinned; return; }
    hideReach(true);
    reachFor = rec; reachPinned = pinned;
    rec.card.root.dataset.reach = "";
    const items: ReachItem[] = [];
    const topo = views.get("mesh");
    for (const r of reach(rec.model.host, source.grants(), source.tags())) {
      const target = [...(views.get("console")?.wins.values() ?? [])].find((w) => w.model.kind === "terminal" && w.model.host === r.host)?.card.root;
      if (!target) continue;
      const arrow = new Arrow({ ...(r.via ? { dashed: true } : {}), tone: "quiet" });
      items.push({ arrow, host: r.host, ...(r.via ? { via: r.via } : {}), target });
    }
    const node = topo?.wins.get(`n-${rec.model.host}`)?.card.root;
    if (node && topo) {
      const arrow = new Arrow({ tone: "quiet" });
      const marker = el("button", "cl-edge ui-pill");
      marker.type = "button";
      marker.innerHTML = `<span class="cl-edge-arrow"><svg viewBox="0 0 24 24" aria-hidden="true">${ICON.chevron}</svg></span><span>Mesh</span>`;
      marker.setAttribute("aria-label", `${rec.model.host} in Mesh`);
      marker.addEventListener("click", () => { hideReach(true); cx.nav.flyView("mesh"); });
      edges.append(marker);
      items.push({ arrow, host: rec.model.host, target: node, marker, node: true });
    }
    reachItems = items;
    items.forEach((item, i) => { item.arrow.g.style.setProperty("--i", String(i)); reachLayer.append(item.arrow.g); });
    reachLayer.dataset.open = "false";
    updateOverlay();
    requestAnimationFrame(() => { reachLayer.dataset.open = "true"; });
  };

  // ---- granting access: drag a live arrow from the port to another terminal ---------------------------------------------
  const beginLink = (rec: WinRec, e: PointerEvent): void => {
    if (!rec.port) return;
    showReach(rec, true);
    const port = rec.port;
    port.setPointerCapture(e.pointerId);
    const src = worldRect(rec.card.root);
    const p0 = toWorld(e.clientX, e.clientY);
    const arrow = new DragArrow(src, p0, cx.invalidate);
    overlay.append(arrow.arrow.g);
    drag = { arrow, source: rec };
    rec.card.root.dataset.linking = "";
    const reachable = new Set(reach(rec.model.host, source.grants(), source.tags()).map((r) => r.host));
    const move = (ev: PointerEvent): void => {
      if (!drag) return;
      const w = toWorld(ev.clientX, ev.clientY);
      drag.arrow.move(w, headSize());
      const under = document.elementsFromPoint(ev.clientX, ev.clientY).find((n): n is HTMLElement => n instanceof HTMLElement && n.matches('.ui-window[data-kind="terminal"]'));
      const ok = under && under !== rec.card.root && !reachable.has(winOfEl(under)?.model.host ?? "") && under.closest('[data-view="console"]');
      const next = ok ? under : undefined;
      if (next !== drag.over) {
        drag.over?.removeAttribute("data-drop");
        next?.setAttribute("data-drop", "");
        drag.over = next;
        drag.arrow.setTarget(next ? worldRect(next) : undefined);
      }
    };
    const up = (ev: PointerEvent): void => {
      port.removeEventListener("pointermove", move);
      port.removeEventListener("pointerup", up);
      port.removeEventListener("pointercancel", up);
      const d = drag;
      if (!d) return;
      delete rec.card.root.dataset.linking;
      d.over?.removeAttribute("data-drop");
      if (!d.over || ev.type === "pointercancel") { retract(d); return; }
      askGrant(rec, d.over, d);
    };
    port.addEventListener("pointermove", move);
    port.addEventListener("pointerup", up);
    port.addEventListener("pointercancel", up);
    move(e);
  };
  const retract = (d: NonNullable<typeof drag>): void => {
    d.arrow.retract();
    d.arrow.arrow.g.dataset.leaving = "";
    drag = undefined;
    window.setTimeout(() => d.arrow.dispose(), 320);
  };
  const askGrant = (srcRec: WinRec, dstEl: HTMLElement, d: NonNullable<typeof drag>): void => {
    const from = srcRec.model.host;
    const to = winOfEl(dstEl)?.model.host ?? "";
    const anchorPt = toClient(d.arrow.end());
    const tipAnchor = el("div", "cl-tip-anchor");
    tipAnchor.style.cssText = `position:fixed;left:${anchorPt.x}px;top:${anchorPt.y}px;width:1px;height:1px;pointer-events:none`;
    document.body.append(tipAnchor);
    const cleanup = (): void => { window.setTimeout(() => tipAnchor.remove(), 260); };
    mountConfirmTip(tipAnchor, {
      label: `Allow ${from} to reach ${to}`,
      message: `Let ${from} reach ${to}?`,
      detail: "It can then open connections to it.",
      confirmLabel: "Allow access",
      cancelLabel: "Cancel",
      onConfirm: () => {
        cleanup();
        const g = source.addGrant(from, to);
        
        drag = undefined;
        d.arrow.dispose();
        // The reach arrows are rebuilt from the source.grants(), so the new arrow is one of them.
        const keep = srcRec;
        hideReach(true);
        showReach(keep, true);
        const topo = views.get("mesh");
        if (topo) { gv?.refresh(topo); gv?.pulseNew(topo, g); cx.view.geometry(topo); }
        for (const cl of views.values()) cx.view.geometry(cl);
        cx.toast.show({ message: `${from} can now reach ${to}`, ...(topo ? { action: { label: "Show in Mesh", onSelect: () => cx.nav.flyView("mesh") } } : {}) });
      },
      onCancel: () => { cleanup(); retract(d); },
    });
  };

  /** The connectors next to terminal pills; shown while the person may change grants. */
  const ports = new Set<HTMLButtonElement>();
  const wireTerminal = (rec: WinRec): void => {
    const pill = rec.card.pill;
    // Arrows on demand: hovering the pill (long-press on touch) shows where this window's host can reach.
    let hoverTimer = 0, leaveTimer = 0;
    const enter = (e: PointerEvent): void => {
      if (e.pointerType !== "mouse" || camera.lod === "thumb") return;
      window.clearTimeout(leaveTimer);
      hoverTimer = window.setTimeout(() => showReach(rec), 110);
    };
    const leave = (e: PointerEvent): void => {
      if (e.pointerType !== "mouse") return;
      window.clearTimeout(hoverTimer);
      leaveTimer = window.setTimeout(() => { if (reachFor === rec && !reachPinned && !drag) hideReach(); }, 160);
    };
    const port = el("button", "cl-port");
    port.type = "button";
    port.dataset.tip = "Drag to another window to allow access";
    port.setAttribute("aria-label", "Allow access to another window");
    port.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON.port}</svg>`;
    port.style.touchAction = "none";
    port.hidden = !source.canEdit(); // the connector exists only for people who may grant access (D187)
    ports.add(port);
    rec.card.pill.after(port);
    rec.port = port;
    for (const t of [pill, port]) { t.addEventListener("pointerenter", enter, { signal }); t.addEventListener("pointerleave", leave, { signal }); }
    port.addEventListener("pointerdown", (e) => { if (e.button === 0) { e.preventDefault(); beginLink(rec, e); } }, { signal });
    rec.card.pill.addEventListener("keydown", (e) => { if (e.key === "ArrowRight" && e.altKey) showReach(rec, true); }, { signal });
  };
  // ---- the Mesh view: its code loads when it is first on screen --------------------------------------------------------
  let gv: GraphViewModule | undefined;
  let loading = false, disposed = false;
  const pending = new Set<ViewRec>();
  const quiet = new Map<ViewRec, HTMLElement>();
  const onScreen = (c: ViewRec): boolean => {
    const f = cx.view.frameOf(c);
    const w = camera.vw / cam.z, h = camera.vh / cam.z;
    return f.x < cam.cx + w / 2 && f.x + f.w > cam.cx - w / 2 && f.y < cam.cy + h / 2 && f.y + f.h > cam.cy - h / 2;
  };
  /** The loading card shows only when the code takes longer than a frame; it is the loading state of the view (same card, same rhythm). */
  const showQuiet = (c: ViewRec): void => {
    requestAnimationFrame(() => {
      if (gv || disposed || quiet.has(c) || !pending.has(c)) return;
      const box = el("div", "cl-empty cl-meshstate");
      const mark = el("div", "cl-meshstate-mark");
      mark.append(createSpinner());
      box.append(mark, el("p", "cl-empty-title", "Loading the mesh"), el("p", "cl-empty-hint", "Asking the server for hosts and grants."));
      box.setAttribute("role", "status");
      box.dataset.open = "false";
      c.content.append(box);
      quiet.set(c, box);
      requestAnimationFrame(() => { box.dataset.open = "true"; });
    });
  };
  const wantGraph = (): void => {
    if (gv || loading || !pending.size || ![...pending].some(onScreen)) return;
    loading = true;
    for (const c of pending) showQuiet(c);
    void onDemand(() => import("./mesh.on-demand")).then((mod) => {
      if (disposed) return;
      gv = mod.createGraphView(cx, source);
      for (const box of quiet.values()) box.remove();
      quiet.clear();
      for (const c of pending) gv.buildGraph(c);
      pending.clear();
    }, () => {
      // The code did not arrive (the network dropped, a new build replaced the chunk): try again at the next frame on screen.
      loading = false;
    });
  };
  const buildGraph = (c: ViewRec): void => {
    c.colsEl.classList.add("cl-graph");
    if (gv) { gv.buildGraph(c); return; }
    pending.add(c);
    wantGraph();
  };
  const redraw = (): void => { gv?.rest(); if (!gv) wantGraph(); };

  let canEdit = source.canEdit();
  const offChange = source.onChange(() => {
    const rights = source.canEdit() !== canEdit;
    canEdit = source.canEdit();
    gv?.changed(rights);
    for (const port of ports) { if (port.isConnected) port.hidden = !canEdit; else ports.delete(port); } // a closed window's connector goes with it
  });
  const offFailure = source.onFailure((message) => cx.toast.show({ message }));
  const nodeCount = (): number => { const d = source.data(); return d.nodes.size + Object.keys(d.tags).length; };
  return {
    buildGraph, redraw, updateOverlay, wireTerminal, showReach, hideReach,
    reachFor: () => reachFor,
    reachCount: () => reachItems.length,
    dragging: () => Boolean(drag),
    reachPinned: () => reachPinned,
    summaryRows: () => [["Nodes", String(nodeCount())], ["Grants", String(source.grants().length)], ["Via relay", String(source.grants().filter((g) => g.via).length)]],
    countText: () => `${nodeCount()} nodes · ${source.grants().length} grants`,
    grants: () => source.grants().map((g) => ({ ...g })),
    graphStats: () => gv?.stats(),
    dispose() { disposed = true; offChange(); offFailure(); reachLayer.remove(); for (const box of quiet.values()) box.remove(); },
  };
}
