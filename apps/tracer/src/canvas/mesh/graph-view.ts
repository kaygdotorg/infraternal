/**
 * The Mesh view's own code: its node cards, the grant arrows and their editing (drag a head or tail, snap, confirm,
 * drop on empty canvas to remove), the layout and the levels of detail (graph.ts). Loaded on demand
 * (`mesh.on-demand.ts`): the first time the Mesh view is on screen. The rest of the canvas, which only needs to know
 * whether to offer the view and to draw reach arrows between terminals, lives in index.ts.
 *
 * Arrow geometry is the only per-frame geometry of the graph, and it is redrawn on the next animation frame after the
 * camera moves (`cull`, called by index.ts from the context's coalesced invalidate).
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
import { SCALE_REST, restAt } from "../springs";
import { Arrow, DragArrow, anchors } from "./arrows";
import { createGraph, type GraphController, type TopoArrow } from "./graph";
import { createLayoutModel } from "./layout-model";
import { endName, grantSentence, type MeshSource } from "./source";

export interface GraphViewModule {
  /** Fills a graph view with its node cards and arrows. */
  buildGraph(c: ViewRec): void;
  /** The mesh (or the person's rights) changed: read it again into every graph view. */
  changed(rightsChanged: boolean): void;
  /** Re-reads the mesh into one graph view (after an edit made elsewhere in the canvas). */
  refresh(c: ViewRec): void;
  /** A grant that was just made: its arrow fades in and its head pulses once. */
  pulseNew(c: ViewRec, g: Grant): void;
  /** The camera moved (the next frame after it). */
  cull(): void;
  /** The camera came to rest. */
  rest(): void;
  stats(): ({ level: string } & ReturnType<GraphController["stats"]>) | undefined;
}

export function createGraphView(cx: Ctx, source: MeshSource): GraphViewModule {
  const { signal, camera, state, views } = cx;
  const cam = camera.cam;
  const toWorld = (x: number, y: number): Pt => camera.toWorld(x, y);
  const toClient = (p: Pt): Pt => camera.toClient(p);
  const worldRect = (n: Element): Rect => camera.worldRect(n);
  const layoutOf = createLayoutModel(source);
  const headSize = (): number => clamp(7 / cam.z, 7, 16);
  // ---- mesh arrows -----------------------------------------------------------------------------------
  const nodeRect = (c: ViewRec, id: string): Rect | undefined => {
    const n = graphOf(c)?.node(id);
    return n ? { x: n.x, y: n.y, w: state.metrics.nodeW, h: state.metrics.nodeH } : undefined;
  };
  /** A grant is shown by its name only (a sentence for one nobody named), never ports or ranges (D180). */
  const grantName = grantSentence;
  /**
   * An arrow for a grant, not yet in the document: the graph module decides which arrows exist. Arrows are reused: one
   * that leaves the screen goes to a pool and comes back for the next grant that enters (making one is a handful of SVG
   * elements, and a pan brings dozens a second). The pool is per kind: with handles or without.
   */
  const arrowPool = new Map<boolean, TopoArrow[]>();
  const makeTopoArrow = (g: Grant): TopoArrow => {
    const editable = source.canEdit();
    const entry = arrowPool.get(editable)?.pop() ?? { grant: g, arrow: new Arrow({ tone: "accent", editable }) };
    entry.grant = g;
    const { arrow } = entry;
    arrow.g.dataset.grant = g.id;
    arrow.g.dataset.tip = grantName(g); // hover names the grant (warm tooltip); D180: edges carry grant names only
    arrow.g.toggleAttribute("data-dashed", Boolean(g.via));
    arrow.setPulse(1);
    for (const flag of ["data-fresh", "data-leaving", "data-editing", "data-cluster"]) arrow.g.removeAttribute(flag);
    if (g.via) {
      if (!entry.label) {
        const t = document.createElementNS(SVG_NS, "text");
        t.setAttribute("class", "cl-arrow-label");
        entry.label = t;
        arrow.g.append(t);
      }
      entry.label.textContent = `through ${g.via}`;
      entry.label.removeAttribute("display");
    } else entry.label?.setAttribute("display", "none");
    return entry;
  };
  const releaseArrow = (entry: TopoArrow): void => {
    entry.arrow.remove();
    const kind = entry.arrow.hit !== undefined;
    const pool = arrowPool.get(kind) ?? [];
    arrowPool.set(kind, pool);
    if (pool.length < 400) pool.push(entry);
  };
  /** A grant that was just made: its arrow fades in and its head pulses once. */
  const pulseNew = (c: ViewRec, g: Grant): void => {
    const entry = topoOf(c).find((t) => t.grant === g);
    if (!entry) return;
    const { arrow } = entry;
    arrow.g.dataset.fresh = "";
    requestAnimationFrame(() => requestAnimationFrame(() => arrow.g.removeAttribute("data-fresh")));
    const pulse = restAt(new Spring(1.9, (v) => arrow.setPulse(v), { visualDuration: 0.4, bounce: 0.45 }), SCALE_REST);
    pulse.set(1);
  };
  const drawTopoArrow = (c: ViewRec, e: TopoArrow): void => {
    const a = nodeRect(c, e.grant.from), b = nodeRect(c, e.grant.to);
    if (!a || !b) return;
    // Arrows that end on the same card fan out along its edge instead of piling onto one point.
    const lane = graphOf(c)?.lane(e.grant) ?? 0;
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
    if (!c) return;
    graphOf(c)?.rest();
    if (Math.abs(cam.z - lastTopoZ) / cam.z < 0.04) return;
    lastTopoZ = cam.z;
    graphOf(c)?.redraw();
  };

  /**
   * Node cards are reused like arrows: a card that scrolls out of range goes to a pool and is rebound to the node that
   * scrolls in (its texts, icon, status, place and name), so a pan makes no DOM and the handlers are made once. The
   * handlers read the node a card is bound to now (`boundTo`), never the one it was made for.
   */
  const cardPool: WinRec[] = [];
  const boundTo = new WeakMap<WinRec, NodeModel>();
  const nodeStatus = (n: NodeModel): "none" | "offline" | "connecting" | "live" => (n.kind === "tag" ? "none" : n.state === "offline" ? "offline" : n.state === "behind" ? "connecting" : "live");
  const bindNode = (rec: WinRec, n: NodeModel): void => {
    boundTo.set(rec, n);
    rec.model.id = `n-${n.id}`;
    rec.model.host = n.label;
    const { card } = rec;
    card.root.dataset.windowId = rec.model.id;
    card.setTitle({ host: n.label });
    card.setIcon(n.kind === "tag" ? lineIcon(ICON.tag) : hostIconMarkup(n.os ?? "unknown", "ui-host-mark"));
    card.setStatus(nodeStatus(n));
    card.root.style.transform = `translate(${n.x}px,${n.y}px)`;
    const meta = card.body.firstElementChild as HTMLElement;
    (meta.children[0] as HTMLElement).textContent = n.detail;
    (meta.children[1] as HTMLElement).textContent = n.sub;
    const port = card.pill.nextElementSibling as HTMLElement | null;
    if (port?.classList.contains("cl-port")) { port.dataset.tip = `Drag onto another card to let ${endName(n.id)} reach it`; port.setAttribute("aria-label", `Let ${endName(n.id)} reach another card`); }
  };
  const makeNode = (c: ViewRec, n: NodeModel): WinRec => {
    const pooled = cardPool.pop();
    if (pooled) { bindNode(pooled, n); return pooled; }
    const m: WindowModel = { id: `n-${n.id}`, kind: "node", host: n.label };
    const card = createWindowCard({ id: m.id, title: { host: n.label }, status: nodeStatus(n), lockable: false, label: `${n.label} node` });
    const rec: WinRec = { model: m, card, owner: c };
    card.root.dataset.kind = "node";
    card.root.style.cssText = `position:absolute;left:0;top:0;width:${state.metrics.nodeW}px;height:${state.metrics.nodeH}px`;
    const meta = el("div", "cl-node-meta");
    meta.innerHTML = `<span class="cl-node-detail"></span><span class="cl-node-sub"></span>`;
    card.body.append(meta);
    wireNode(rec);
    wireLink(c, rec);
    bindNode(rec, n);
    return rec;
  };
  const dropNode = (rec: WinRec): void => {
    rec.card.root.remove();
    for (const flag of ["data-lifted", "data-drop", "data-linking", "data-active"]) rec.card.root.removeAttribute(flag);
    boundTo.delete(rec);
    if (cardPool.length < 120) cardPool.push(rec); else rec.card.dispose();
  };

  const wireNode = (rec: WinRec): void => {
    const pill = rec.card.pill;
    pill.style.touchAction = "none";
    pill.dataset.grab = "";
    let d: { id: number; x: number; y: number; nx: number; ny: number; n: NodeModel; at?: { x: number; y: number }; frame: number } | undefined;
    // A drag is applied once per frame, from the last pointer position: a pointer that reports faster than the screen
    // draws would move the card and redraw its arrows several times for one frame.
    const apply = (): void => {
      if (!d) return;
      d.frame = 0;
      if (!d.at) return;
      const { n } = d;
      const size = contentSize(rec.owner.view, state.metrics);
      n.x = clamp(d.nx + (d.at.x - d.x) / cam.z, 0, size.w - state.metrics.nodeW);
      n.y = clamp(d.ny + (d.at.y - d.y) / cam.z, 0, size.h - state.metrics.nodeH);
      n.pinned = true; // a node the person moved stays where it is (D180); the canvas document keeps it
      source.pin(n.id, n.x, n.y);
      rec.card.root.style.transform = `translate(${n.x}px, ${n.y}px)`;
      // Arrows stay attached to the card they belong to while it moves.
      for (const t of topoOf(rec.owner)) if (t.grant.from === n.id || t.grant.to === n.id) drawTopoArrow(rec.owner, t);
    };
    pill.addEventListener("pointerdown", (e) => {
      const n = boundTo.get(rec);
      if (camera.lod === "thumb" || !n) return;
      pill.setPointerCapture(e.pointerId);
      d = { id: e.pointerId, x: e.clientX, y: e.clientY, nx: n.x, ny: n.y, n, frame: 0 };
      rec.card.root.dataset.lifted = "";
    }, { signal });
    pill.addEventListener("pointermove", (e) => {
      if (!d || e.pointerId !== d.id) return;
      d.at = { x: e.clientX, y: e.clientY };
      if (!d.frame) d.frame = requestAnimationFrame(apply);
    }, { signal });
    const up = (e: PointerEvent): void => {
      if (!d || e.pointerId !== d.id) return;
      cancelAnimationFrame(d.frame);
      apply();
      const { n } = d;
      const moved = d.nx !== n.x || d.ny !== n.y;
      d = undefined;
      delete rec.card.root.dataset.lifted;
      if (moved) cx.store.changed();
    };
    pill.addEventListener("pointerup", up, { signal });
    pill.addEventListener("pointercancel", up, { signal });
  };

  // ---- allowing access: drag the connector on a card onto another card (D194: drawn only here) ----------------------
  /** The connectors on the cards; shown while the person may change who can reach what (D187). */
  const ports = new Set<HTMLButtonElement>();
  const wireLink = (c: ViewRec, rec: WinRec): void => {
    const port = el("button", "cl-port");
    port.type = "button";
    port.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON.port}</svg>`;
    port.style.touchAction = "none";
    port.hidden = !source.canEdit();
    ports.add(port);
    rec.card.pill.after(port);
    port.addEventListener("pointerdown", (e) => { const n = boundTo.get(rec); if (n && e.button === 0 && camera.lod !== "thumb") { e.preventDefault(); e.stopPropagation(); beginLink(c, rec, n, port, e); } }, { signal });
  };
  const beginLink = (c: ViewRec, rec: WinRec, n: NodeModel, port: HTMLElement, e: PointerEvent): void => {
    const from = nodeRect(c, n.id);
    if (!from) return;
    port.setPointerCapture(e.pointerId);
    const origin = cx.view.contentRect(c);
    const toLocal = (clientX: number, clientY: number): Pt => { const w = toWorld(clientX, clientY); return { x: w.x - origin.x, y: w.y - origin.y }; };
    const live = new DragArrow(from, toLocal(e.clientX, e.clientY), cx.invalidate);
    c.graphSvg!.append(live.arrow.g);
    rec.card.root.dataset.linking = "";
    let candidate: string | undefined;
    let over: HTMLElement | undefined;
    const taken = (id: string): boolean => source.grants().some((o) => o.from === n.id && o.to === id);
    const move = (ev: PointerEvent): void => {
      const w = toLocal(ev.clientX, ev.clientY);
      live.move(w, headSize());
      const radius = (coarse.matches ? 48 : 32) / cam.z;
      const gap = (r: Rect): number => Math.hypot(Math.max(r.x - w.x, 0, w.x - (r.x + r.w)), Math.max(r.y - w.y, 0, w.y - (r.y + r.h)));
      let id: string | undefined, best = Infinity;
      for (const o of c.view.nodes) {
        const r = nodeRect(c, o.id);
        if (!r || o.id === n.id || taken(o.id)) continue;
        const d = gap(r), limit = o.id === candidate ? radius * 1.25 : radius;
        if (d <= limit && d < best) { best = d; id = o.id; }
      }
      if (id !== candidate) {
        over?.removeAttribute("data-drop");
        over = id ? c.wins.get(`n-${id}`)?.card.root : undefined;
        over?.setAttribute("data-drop", "");
        candidate = id;
        live.setTarget(id ? nodeRect(c, id) : undefined);
      }
    };
    const retract = (): void => { live.retract(); live.arrow.g.dataset.leaving = ""; window.setTimeout(() => live.dispose(), 320); };
    const up = (ev: PointerEvent): void => {
      port.removeEventListener("pointermove", move);
      port.removeEventListener("pointerup", up);
      port.removeEventListener("pointercancel", up);
      delete rec.card.root.dataset.linking;
      over?.removeAttribute("data-drop");
      if (!candidate || ev.type === "pointercancel") { retract(); return; }
      const to = candidate;
      const at = tipAt(toClient({ x: live.end().x + origin.x, y: live.end().y + origin.y }));
      mountConfirmTip(at.anchor, {
        label: `Let ${endName(n.id)} reach ${endName(to)}`,
        title: `Let ${endName(n.id)} reach ${endName(to)}?`,
        effect: `${endName(n.id)} will be able to connect to ${endName(to)}. You can stop it any time.`,
        confirmLabel: "Allow access", cancelLabel: "Cancel", named: true,
        onConfirm: () => {
          const g = source.addGrant(n.id, to);
          live.dispose();
          refreshGraph(c);
          pulseNew(c, g);
          for (const cl of views.values()) cx.view.geometry(cl);
          cx.toast.show({ message: `${endName(n.id)} can now reach ${endName(to)}` });
          at.done();
        },
        onCancel: () => { retract(); at.done(); },
      });
    };
    port.addEventListener("pointermove", move);
    port.addEventListener("pointerup", up);
    port.addEventListener("pointercancel", up);
    move(e);
  };

  // ---- editing a grant: grab an arrow's head or tail, unsnap it, snap it to another node or drop it on empty canvas ----------------
  /** Where a confirmation is anchored: a point on the screen, as a 1 px element. */
  const tipAt = (client: Pt): { anchor: HTMLElement; done(): void } => {
    const anchor = el("div", "cl-tip-anchor");
    anchor.style.cssText = `position:fixed;left:${client.x}px;top:${client.y}px;width:1px;height:1px;pointer-events:none`;
    document.body.append(anchor);
    return { anchor, done: () => { window.setTimeout(() => anchor.remove(), 260); } };
  };
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
      // Snap: the nearest node whose edge is within the snap radius of the pointer (about 32 px, larger on touch).
      // Once snapped the radius is a quarter wider before it lets go, so the arrow does not flicker at the edge.
      const radius = (coarse.matches ? 48 : 32) / cam.z;
      const gap = (r: Rect): number => Math.hypot(Math.max(r.x - w.x, 0, w.x - (r.x + r.w)), Math.max(r.y - w.y, 0, w.y - (r.y + r.h)));
      let id: string | undefined, best = Infinity;
      for (const n of c.view.nodes) {
        const r = nodeRect(c, n.id);
        if (!r || n.id === fixedId) continue;
        const d = gap(r), limit = n.id === candidate ? radius * 1.25 : radius;
        if (d <= limit && d < best) { best = d; id = n.id; }
      }
      if (id && id !== homeId && taken(id)) id = undefined;
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
        // What changes for the person, in the words of the cards: who reaches what now, and who will not any more.
        const [who, was, now] = end === "head" ? [g.from, g.to, candidate] : [candidate, g.to, g.to];
        const moveTitle = end === "head" ? `Let ${endName(who)} reach ${endName(now)} instead of ${endName(was)}?` : `Let ${endName(candidate)} reach ${endName(g.to)} instead of ${endName(g.from)}?`;
        const moveEffect = end === "head"
          ? `${endName(g.from)} will lose its connection to ${endName(g.to)} and gain one to ${endName(candidate)}. You can change it back any time.`
          : `${endName(g.from)} will lose its connection to ${endName(g.to)}, and ${endName(candidate)} will gain one. You can change it back any time.`;
        const endTip = tipAt(toClient({ x: live.end().x + origin.x, y: live.end().y + origin.y }));
        mountConfirmTip(endTip.anchor, {
          label: moveTitle, title: moveTitle, effect: moveEffect,
          confirmLabel: "Change access", cancelLabel: "Cancel", named: true,
          onConfirm: () => {
            source.moveGrant(g, end === "head" ? { to: next.to } : { from: next.from });
            entry.arrow.g.dataset.tip = grantName(g);
            entry.arrow.g.removeAttribute("data-editing");
            refreshGraph(c);
            const pulse = restAt(new Spring(1.9, (v) => entry.arrow.setPulse(v), { visualDuration: 0.4, bounce: 0.45 }), SCALE_REST);
            pulse.set(1);
            live.dispose();
            for (const cl of views.values()) cx.view.geometry(cl);
            cx.toast.show({ message: `${endName(g.from)} can now reach ${endName(g.to)}` });
            endTip.done();
          },
          onCancel: () => { springBack(); endTip.done(); },
        });
        at.done();
        return;
      }
      // Dropped on empty canvas: offer to remove the grant.
      mountConfirmTip(at.anchor, {
        label: `Stop ${endName(g.from)} reaching ${endName(g.to)}`, title: `Stop ${endName(g.from)} reaching ${endName(g.to)}?`,
        effect: `${endName(g.from)} will lose its connection to ${endName(g.to)}. You can allow it again any time.`,
        confirmLabel: "Stop access", cancelLabel: "Keep it", named: true,
        onConfirm: () => {
          source.removeGrant(g);
          live.dispose();
          refreshGraph(c); // the arrow fades out; the grants listed in the graph are the source's
          for (const cl of views.values()) cx.view.geometry(cl);
          cx.toast.show({ message: `${endName(g.from)} can no longer reach ${endName(g.to)}` });
        },
        onCancel: springBack,
      });
      at.done();
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", up);
    handle.addEventListener("pointercancel", up);
  };
  // ---- the graph view ----------------------------------------------------------------------------------
  const graphs = new WeakMap<ViewRec, GraphController>();
  const graphOf = (c: ViewRec): GraphController | undefined => graphs.get(c);
  const topoOf = (c: ViewRec): TopoArrow[] => graphOf(c)?.arrows() ?? [];
  /** Re-reads the mesh into a graph view: its nodes, its size, what is drawn, what the sidebar counts. */
  let sized = "";
  const refreshGraph = (c: ViewRec): void => {
    const graph = graphOf(c);
    if (!graph) return;
    const layout = layoutOf(state.metrics);
    c.view.nodes = layout.nodes;
    c.view.graph = layout.size;
    graph.sync();
    cx.view.geometry(c);
    const size = `${layout.size.w}x${layout.size.h}`;
    if (size !== sized) { sized = size; cx.view.settle(c.view.id); }
    cx.tree.render();
    cx.pill.paint(); // the top pill counts the nodes
  };
  const buildGraph = (c: ViewRec): void => {
    c.colsEl.classList.add("cl-graph");
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.setAttribute("class", "cl-graph-arrows");
    c.colsEl.append(svg);
    c.graphSvg = svg;
    svg.addEventListener("pointerdown", (e) => {
      // Touch: a tap on an arrow selects it (its handles show); a tap on another arrow moves the selection.
      const hitEl = (e.target as Element).closest(".cl-arrow-hit, .cl-arrow-handle")?.closest(".cl-arrow");
      for (const t of topoOf(c)) t.arrow.g.toggleAttribute("data-selected", t.arrow.g === hitEl);
      const handle = (e.target as Element).closest<SVGElement>(".cl-arrow-handle");
      const entry = topoOf(c).find((t) => t.arrow.g === handle?.closest(".cl-arrow"));
      if (!handle || !entry || e.button !== 0) return;
      e.stopPropagation(); e.preventDefault();
      beginEdit(c, entry, handle.dataset.end === "tail" ? "tail" : "head", e, handle);
    }, { signal });
    const graph = createGraph(cx, c, source, layoutOf, {
      makeCard: (n) => makeNode(c, n),
      dropCard: dropNode,
      makeArrow: makeTopoArrow,
      dropArrow: (entry, fade) => {
        if (!fade) { releaseArrow(entry); return; }
        entry.arrow.g.dataset.leaving = "";
        window.setTimeout(() => releaseArrow(entry), 240);
      },
      drawArrow: (entry) => drawTopoArrow(c, entry),
      headSize,
    });
    graphs.set(c, graph);
    refreshGraph(c);
    // The view was built empty and the camera may already be framing it: now that it has its size (and, if it is
    // big, no stops and a free canvas) the camera goes to where the view really rests. Only while the canvas is locked
    // to this view: in the overview (the lock is off) the person is looking at every view, and a graph that fills in
    // late (the Mesh answers after a terminal attached) must not pull the camera into itself.
    if (state.canvasLock && state.currentView === c.view.id && cx.camera.target) cx.nav.flyView(c.view.id);
  };

  return {
    buildGraph,
    refresh: refreshGraph,
    pulseNew,
    changed(rightsChanged) {
      for (const port of ports) { if (port.isConnected) port.hidden = !source.canEdit(); else ports.delete(port); } // a dropped card's connector goes with it
      // Handles on arrows exist only for people who may use them (D187): arrows are made again when that changes.
      if (rightsChanged) for (const c of views.values()) graphOf(c)?.reset();
      for (const c of views.values()) if (c.view.layout === "graph") refreshGraph(c);
    },
    cull() { const c = views.get("mesh"); if (c) graphOf(c)?.cull(); },
    rest() { redrawMesh(); },
    stats() { const c = views.get("mesh"); const g = c && graphOf(c); if (!g) return undefined; return { level: g.level(), ...g.stats() }; },
  };
}
