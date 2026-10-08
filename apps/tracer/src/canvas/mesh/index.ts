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
 * Arrow geometry is the only per-frame geometry on the canvas, and it is redrawn on the next animation frame
 * after the camera or a window moves (updateOverlay, coalesced by the context's invalidate).
 */
import { Spring } from "../../../../../packages/ui/src/spring";
import { mountConfirmTip } from "../../../../../packages/ui/src/tooltip";
import { createWindowCard } from "../../../../../packages/ui/src/window-card";
import { hostIconMarkup } from "../../../../../packages/ui/src/host-icons";
import { clamp } from "../camera/camera";
import type { Ctx, ViewRec, WinRec } from "../context";
import { SVG_NS, coarse, el } from "../dom";
import { contentSize, type Pt, type Rect } from "../layout/geometry";
import type { Grant, NodeModel, WindowModel } from "../model/types";
import { ICON, lineIcon } from "../views/icons";
import { Arrow, DragArrow, anchors } from "./arrows";
import { reach } from "./grants";
import type { MeshSource } from "./source";
import { SCALE_REST, restAt } from "../springs";

interface TopoArrow { grant: Grant; arrow: Arrow; label?: SVGTextElement }

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
  /** A newly added grant: its arrow is added to the Mesh view with a pulse. */
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

  // ---- mesh arrows -----------------------------------------------------------------------------------
  const nodeRect = (c: ViewRec, id: string): Rect | undefined => {
    const n = c.view.nodes.find((v) => v.id === id);
    return n ? { x: n.x, y: n.y, w: state.metrics.nodeW, h: state.metrics.nodeH } : undefined;
  };
  /** A grant is shown by its name only: who may reach what ("ops→build-01"), never ports or ranges (D180). */
  const grantName = (g: Grant): string => `${g.from.replace(/^tag:/, "")}→${g.to}`;
  const addTopoArrow = (c: ViewRec, g: Grant, animate: boolean): void => {
    if (!c.graphSvg) return;
    const arrow = new Arrow({ ...(g.via ? { dashed: true } : {}), tone: "accent", editable: source.canEdit() });
    arrow.g.dataset.grant = g.id;
    arrow.g.dataset.tip = grantName(g); // hover names the grant (warm tooltip); D180: edges carry grant names only
    const entry: TopoArrow = { grant: g, arrow };
    if (g.via) {
      const t = document.createElementNS(SVG_NS, "text");
      t.setAttribute("class", "cl-arrow-label");
      t.textContent = `via ${g.via}`;
      entry.label = t;
      arrow.g.append(t);
    }
    c.graphSvg.append(arrow.g);
    topoOf(c).push(entry);
    drawTopoArrow(c, entry);
    if (animate) {
      arrow.g.dataset.fresh = "";
      requestAnimationFrame(() => requestAnimationFrame(() => arrow.g.removeAttribute("data-fresh")));
      const pulse = restAt(new Spring(1.9, (v) => arrow.setPulse(v), { visualDuration: 0.4, bounce: 0.45 }), SCALE_REST);
      pulse.set(1);
    }
  };
  const drawTopoArrow = (c: ViewRec, e: TopoArrow): void => {
    const a = nodeRect(c, e.grant.from), b = nodeRect(c, e.grant.to);
    if (!a || !b) return;
    // Arrows that end on the same card fan out along its edge instead of piling onto one point.
    const sharing = topoOf(c).filter((o) => o.grant.to === e.grant.to);
    const lane = sharing.indexOf(e) - (sharing.length - 1) / 2;
    e.arrow.between(a, b, headSize(), lane * Math.max(1, (headSize() * 1.5) / 14));
    if (e.label) {
      const n = anchors(a, b);
      e.label.setAttribute("x", String((n.p0.x + n.p1.x) / 2));
      e.label.setAttribute("y", String((n.p0.y + n.p1.y) / 2 - 8));
      e.label.setAttribute("text-anchor", "middle");
    }
  };
  let lastTopoZ = 0;
  const redrawMesh = (): void => {
    const c = views.get("mesh");
    if (!c || Math.abs(cam.z - lastTopoZ) / cam.z < 0.04) return;
    lastTopoZ = cam.z;
    for (const e of topoOf(c)) drawTopoArrow(c, e);
  };

  const makeNode = (c: ViewRec, n: NodeModel): WinRec => {
    const m: WindowModel = { id: `n-${n.id}`, kind: "node", host: n.label };
    const card = createWindowCard({ id: m.id, title: { host: n.label }, icon: n.kind === "tag" ? lineIcon(ICON.tag) : hostIconMarkup(n.os ?? "unknown", "ui-host-mark"), status: "none", label: `${n.label} node` });
    const rec: WinRec = { model: m, card, owner: c };
    card.root.dataset.kind = "node";
    card.root.style.cssText = `position:absolute;left:0;top:0;width:${state.metrics.nodeW}px;height:${state.metrics.nodeH}px;transform:translate(${n.x}px,${n.y}px)`;
    const meta = el("div", "cl-node-meta");
    meta.innerHTML = `<span class="cl-node-detail"></span><span class="cl-node-sub"></span>`;
    (meta.children[0] as HTMLElement).textContent = n.detail;
    (meta.children[1] as HTMLElement).textContent = n.sub;
    card.body.append(meta);
    wireNode(rec, n);
    return rec;
  };

  const wireNode = (rec: WinRec, n: NodeModel): void => {
    const pill = rec.card.pill;
    pill.style.touchAction = "none";
    pill.dataset.grab = "";
    let d: { id: number; x: number; y: number; nx: number; ny: number } | undefined;
    pill.addEventListener("pointerdown", (e) => {
      if (camera.lod === "thumb") return;
      pill.setPointerCapture(e.pointerId);
      d = { id: e.pointerId, x: e.clientX, y: e.clientY, nx: n.x, ny: n.y };
      rec.card.root.dataset.lifted = "";
    }, { signal });
    pill.addEventListener("pointermove", (e) => {
      if (!d || e.pointerId !== d.id) return;
      const size = contentSize(rec.owner.view, state.metrics);
      n.x = clamp(d.nx + (e.clientX - d.x) / cam.z, 0, size.w - state.metrics.nodeW);
      n.y = clamp(d.ny + (e.clientY - d.y) / cam.z, 0, size.h - state.metrics.nodeH);
      source.pin(n.id, n.x, n.y);
      rec.card.root.style.transform = `translate(${n.x}px, ${n.y}px)`;
      // Arrows stay attached to the card they belong to while it moves.
      for (const t of topoOf(rec.owner)) if (t.grant.from === n.id || t.grant.to === n.id) drawTopoArrow(rec.owner, t);
    }, { signal });
    const up = (e: PointerEvent): void => {
      if (!d || e.pointerId !== d.id) return;
      d = undefined;
      delete rec.card.root.dataset.lifted;
    };
    pill.addEventListener("pointerup", up, { signal });
    pill.addEventListener("pointercancel", up, { signal });
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
  // ---- editing a grant: grab an arrow's head or tail, unsnap it, snap it to another node or drop it on empty canvas ----------------
  /** Where a confirmation is anchored: a point on the screen, as a 1 px element. */
  const tipAt = (client: Pt): { anchor: HTMLElement; done(): void } => {
    const anchor = el("div", "cl-tip-anchor");
    anchor.style.cssText = `position:fixed;left:${client.x}px;top:${client.y}px;width:1px;height:1px;pointer-events:none`;
    document.body.append(anchor);
    return { anchor, done: () => { window.setTimeout(() => anchor.remove(), 260); } };
  };
  const redrawTopo = (c: ViewRec): void => { for (const e of topoOf(c)) drawTopoArrow(c, e); };
  const beginEdit = (c: ViewRec, entry: TopoArrow, end: "tail" | "head", e: PointerEvent, handle: SVGElement): void => {
    const g = entry.grant;
    const fixedId = end === "head" ? g.from : g.to;
    const homeId = end === "head" ? g.to : g.from;
    const fixed = nodeRect(c, fixedId), home = nodeRect(c, homeId);
    if (!fixed || !home) return;
    handle.setPointerCapture(e.pointerId);
    // The graph's arrows live in the view's own coordinates; the pointer comes in world coordinates.
    const origin = cx.view.contentRect(c);
    const toLocal = (clientX: number, clientY: number): Pt => { const w = toWorld(clientX, clientY); return { x: w.x - origin.x, y: w.y - origin.y }; };
    const live = new DragArrow(fixed, toLocal(e.clientX, e.clientY), cx.invalidate, end === "tail");
    if (g.via) live.arrow.g.dataset.dashed = "";
    c.graphSvg!.append(live.arrow.g);
    live.snapNow(home); // the end starts attached, so pulling it off is an unsnap
    entry.arrow.g.dataset.editing = "";
    let candidate: string | undefined = homeId;
    let over: HTMLElement | undefined;
    const taken = (id: string): boolean => source.grants().some((o) => o !== g && (end === "head" ? o.from === g.from && o.to === id : o.to === g.to && o.from === id));
    const move = (ev: PointerEvent): void => {
      const w = toLocal(ev.clientX, ev.clientY);
      live.move(w, headSize());
      // Graph nodes take no pointer events of their own, so the node under the pointer is found by geometry.
      let id = c.view.nodes.find((n) => { const r = nodeRect(c, n.id); return !!r && w.x >= r.x && w.x <= r.x + r.w && w.y >= r.y && w.y <= r.y + r.h; })?.id;
      // Near its own node the end stays attached: a short pull does not unsnap it.
      const slack = 28 / cam.z;
      const nearHome = w.x > home.x - slack && w.x < home.x + home.w + slack && w.y > home.y - slack && w.y < home.y + home.h + slack;
      if (nearHome && !id) id = homeId;
      if (id === fixedId || (id && id !== homeId && taken(id))) id = undefined;
      if (id !== candidate) {
        over?.removeAttribute("data-drop");
        over = id && id !== homeId ? c.wins.get(`n-${id}`)?.card.root : undefined;
        over?.setAttribute("data-drop", "");
        candidate = id;
        const r = id ? nodeRect(c, id) : undefined;
        live.setTarget(r);
      }
    };
    const finish = (): void => {
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", up);
      handle.removeEventListener("pointercancel", up);
      over?.removeAttribute("data-drop");
    };
    const springBack = (): void => {
      live.setTarget(home);
      entry.arrow.g.removeAttribute("data-editing");
      window.setTimeout(() => live.dispose(), 380);
    };
    const up = (ev: PointerEvent): void => {
      finish();
      const at = tipAt({ x: ev.clientX, y: ev.clientY });
      if (ev.type === "pointercancel" || candidate === homeId) { springBack(); at.done(); return; }
      if (candidate) {
        const next: Grant = end === "head" ? { ...g, to: candidate } : { ...g, from: candidate };
        const endTip = tipAt(toClient({ x: live.end().x + origin.x, y: live.end().y + origin.y }));
        mountConfirmTip(endTip.anchor, {
          label: `Move grant ${grantName(g)}`, message: `Move grant ${grantName(g)} to ${grantName(next)}?`,
          confirmLabel: "Move", cancelLabel: "Cancel",
          onConfirm: () => {
            source.moveGrant(g, end === "head" ? { to: next.to } : { from: next.from });
            entry.arrow.g.dataset.tip = grantName(g);
            entry.arrow.g.removeAttribute("data-editing");
            redrawTopo(c);
            const pulse = restAt(new Spring(1.9, (v) => entry.arrow.setPulse(v), { visualDuration: 0.4, bounce: 0.45 }), SCALE_REST);
            pulse.set(1);
            live.dispose();
            for (const cl of views.values()) cx.view.geometry(cl);
            cx.toast.show({ message: `Grant moved to ${grantName(g)}` });
            endTip.done();
          },
          onCancel: () => { springBack(); endTip.done(); },
        });
        at.done();
        return;
      }
      // Dropped on empty canvas: offer to remove the grant.
      mountConfirmTip(at.anchor, {
        label: `Remove grant ${grantName(g)}`, message: `Remove grant ${grantName(g)}?`,
        confirmLabel: "Remove", cancelLabel: "Keep",
        onConfirm: () => {
          source.removeGrant(g);
          topoOf(c).splice(topoOf(c).indexOf(entry), 1);
          entry.arrow.g.dataset.leaving = "";
          window.setTimeout(() => entry.arrow.remove(), 240);
          live.dispose();
          redrawTopo(c);
          for (const cl of views.values()) cx.view.geometry(cl);
          cx.toast.show({ message: `Grant ${grantName(g)} removed` });
        },
        onCancel: springBack,
      });
      at.done();
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up);
    handle.addEventListener("pointercancel", up);
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
        if (topo) { addTopoArrow(topo, g, true); cx.view.geometry(topo); }
        for (const cl of views.values()) cx.view.geometry(cl);
        cx.toast.show({ message: `${from} can now reach ${to}`, ...(topo ? { action: { label: "Show in Mesh", onSelect: () => cx.nav.flyView("mesh") } } : {}) });
      },
      onCancel: () => { cleanup(); retract(d); },
    });
  };

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
    rec.card.pill.after(port);
    rec.port = port;
    for (const t of [pill, port]) { t.addEventListener("pointerenter", enter, { signal }); t.addEventListener("pointerleave", leave, { signal }); }
    port.addEventListener("pointerdown", (e) => { if (e.button === 0) { e.preventDefault(); beginLink(rec, e); } }, { signal });
    rec.card.pill.addEventListener("keydown", (e) => { if (e.key === "ArrowRight" && e.altKey) showReach(rec, true); }, { signal });
  };

  // ---- the graph view ----------------------------------------------------------------------------------
  const topos = new WeakMap<ViewRec, TopoArrow[]>();
  const topoOf = (c: ViewRec): TopoArrow[] => { let t = topos.get(c); if (!t) { t = []; topos.set(c, t); } return t; };
  const buildGraph = (c: ViewRec): void => {
    c.colsEl.classList.add("cl-graph");
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "cl-graph-arrows");
    c.colsEl.append(svg);
    c.graphSvg = svg;
    svg.addEventListener("pointerdown", (e) => {
      const handle = (e.target as Element).closest<SVGElement>(".cl-arrow-handle");
      const entry = topoOf(c).find((t) => t.arrow.g === handle?.closest(".cl-arrow"));
      if (!handle || !entry || e.button !== 0) return;
      e.stopPropagation(); e.preventDefault();
      beginEdit(c, entry, handle.dataset.end === "tail" ? "tail" : "head", e, handle);
    }, { signal });
    for (const n of c.view.nodes) {
      const rec = makeNode(c, n);
      c.wins.set(rec.model.id, rec);
      c.colsEl.append(rec.card.root);
    }
    for (const g of source.grants()) addTopoArrow(c, g, false);
  };

  const offChange = source.onChange(() => { for (const c of views.values()) if (c.view.layout === "graph") cx.view.geometry(c); });
  return {
    buildGraph, redraw: redrawMesh, updateOverlay, wireTerminal, showReach, hideReach,
    reachFor: () => reachFor,
    reachCount: () => reachItems.length,
    dragging: () => Boolean(drag),
    reachPinned: () => reachPinned,
    summaryRows: (c) => [["Nodes", String(c.view.nodes.length)], ["Grants", String(source.grants().length)], ["Via relay", String(source.grants().filter((g) => g.via).length)]],
    countText: (c) => `${c.view.nodes.length} nodes · ${source.grants().length} grants`,
    grants: () => source.grants().map((g) => ({ ...g })),
    dispose() { offChange(); reachLayer.remove(); },
  };
}
