/**
 * The Mesh view's own code: its node cards, the grant arrows and their editing (drag a head or tail, snap, confirm,
 * drop on empty canvas to remove), the layout and the levels of detail (graph.ts). Loaded on demand
 * (`mesh.on-demand.ts`): the first time the Mesh view is on screen. The rest of the canvas, which only needs to know
 * whether to offer the view and to draw reach arrows between terminals, lives in index.ts.
 *
 * Arrow geometry is the only per-frame geometry of the graph, and it is redrawn on the next animation frame after the
 * camera moves (`cull`, called by index.ts from the context's coalesced invalidate).
 */
import { mountConfirmTip } from "../../../../../packages/ui/src/tooltip";
import { createWindowCard } from "../../../../../packages/ui/src/window-card";
import { renameHost, takePendingRename } from "./rename.on-demand";
import { onDoubleActivate } from "../../../../../packages/ui/src/double-activate";
import { beginInlineRename, placeOverName, type InlineRename } from "../../../../../packages/ui/src/inline-rename.on-demand";
import { hostIconMarkup } from "../../../../../packages/ui/src/host-icons";
import { clamp } from "../camera/camera";
import type { Ctx, ViewRec, WinRec } from "../context";
import { SVG_NS, coarse, el } from "../dom";
import { type Pt, type Rect } from "../layout/geometry";
import type { Grant, NodeModel, WindowModel } from "../model/types";
import { ICON, lineIcon } from "../views/icons";
import { Arrow, DragArrow, anchors } from "./arrows";
import { createGraph, type GraphController, type TopoArrow } from "./graph";
import { createLayoutModel } from "./layout-model";
import { createSay, tagChips } from "./entities";
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
  /** Opens the name field on a host's card (waits for the card if it is not drawn yet). */
  beginRename(id: string): void;
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
  const layouts = new WeakMap<ViewRec, ReturnType<typeof createLayoutModel>>();
  const layoutOf = (c: ViewRec, metrics: Ctx["state"]["metrics"]) => {
    let model = layouts.get(c);
    if (!model) { model = createLayoutModel(source, () => c.view.graphPins); layouts.set(c, model); }
    return model(metrics);
  };
  const headSize = (): number => clamp(7 / cam.z, 7, 16);
  // ---- mesh arrows -----------------------------------------------------------------------------------
  const nodeRect = (c: ViewRec, id: string): Rect | undefined => {
    const n = graphOf(c)?.node(id);
    return n ? { x: n.x, y: n.y, w: state.metrics.nodeW, h: state.metrics.nodeH } : undefined;
  };
  /** A grant is shown by its name only (a sentence for one nobody named), never ports or ranges (D180). */
  const say = createSay(source);
  const grantName = (g: Grant): string => grantSentence(g) + (g.via ? `, through ${g.via}` : "");
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
    arrow.rest();
    for (const flag of ["data-fresh", "data-leaving", "data-editing", "data-cluster"]) arrow.g.removeAttribute(flag);
    if (g.via) {
      if (!entry.label) {
        const t = document.createElementNS(SVG_NS, "text");
        t.setAttribute("class", "cl-arrow-label");
        entry.label = t;
        arrow.g.append(t);
      }
      entry.label.textContent = `via ${g.via}`;
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
    arrow.press();
  };
  const drawTopoArrow = (c: ViewRec, e: TopoArrow): void => {
    const a = nodeRect(c, e.grant.from), b = nodeRect(c, e.grant.to);
    if (!a || !b) return;
    // Arrows that end on the same card fan out along its edge instead of piling onto one point.
    const lane = graphOf(c)?.lane(e.grant) ?? 0;
    e.arrow.between(a, b, headSize(), lane * Math.max(1, (headSize() * 1.5) / 14));
    if (e.label) placeLabel(c, e);
  };
  /**
   * The label of an arrow that goes through another host sits on the curve, at the place nearest its middle where the
   * words clear every card; if there is none (cards all along it) the label is left out, and the hover says the same.
   * Its size follows the zoom (about 11 screen pixels), so it reads at every zoom and is quiet at every one.
   */
  const placeLabel = (c: ViewRec, e: TopoArrow): void => {
    const label = e.label!;
    const fs = clamp(11 / cam.z, 9, 40);
    const w = label.textContent!.length * fs * 0.62 + fs * 0.6, h = fs * 1.3;
    const graph = graphOf(c);
    for (const t of [0.5, 0.42, 0.58, 0.34, 0.66, 0.26, 0.74, 0.18, 0.82]) {
      const p = e.arrow.pointAt(t);
      if (!p) break;
      // The words sit just above the curve, centred on it.
      const box = { x: p.x - w / 2, y: p.y - h - fs * 0.25, w, h };
      const hit = graph?.nodesIn(box) ?? [];
      if (hit.length) continue;
      label.style.fontSize = `${fs.toFixed(1)}px`;
      label.setAttribute("x", p.x.toFixed(1));
      label.setAttribute("y", (p.y - fs * 0.4).toFixed(1));
      label.setAttribute("text-anchor", "middle");
      label.removeAttribute("display");
      return;
    }
    label.setAttribute("display", "none");
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
  /** Ends a card's open drag without writing anything: set by `wireNode`, called when the card stops being that node's. */
  const endDrag = new WeakMap<WinRec, () => void>();
  const bindNode = (rec: WinRec, n: NodeModel): void => {
    // A drag belongs to a node, not to a card: a card rebound to another node (the pool reuses cards) must not carry it.
    // The same id with a new model (a refresh) keeps the drag.
    if (boundTo.get(rec)?.id !== n.id) { endDrag.get(rec)?.(); renaming.get(rec)?.finish(false); }
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
    const detail = meta.children[0] as HTMLElement;
    // Tags are chips (the colour of a tag is the same everywhere); rebuilt only when the list changes, never on a pan.
    const tagKey = n.tagList?.join(" ") ?? "";
    if (n.tagList) { if (detail.dataset.tags !== tagKey) { detail.replaceChildren(tagChips(n.tagList)); detail.dataset.tags = tagKey; } }
    else { if (detail.dataset.tags !== undefined) delete detail.dataset.tags; detail.textContent = n.detail; }
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
    endDrag.get(rec)?.();
    renaming.get(rec)?.finish(false); // a card that leaves the screen takes an open name field with it
    rec.card.root.remove();
    for (const flag of ["data-lifted", "data-drop", "data-linking", "data-active"]) rec.card.root.removeAttribute(flag);
    boundTo.delete(rec);
    if (cardPool.length < 120) cardPool.push(rec); else rec.card.dispose();
  };

  /** Where each graph view's cards are drawn from, in pin coordinates (`MeshLayout.origin`), as of the last refresh. */
  const origins = new WeakMap<ViewRec, Pt>();
  const ZERO: Pt = { x: 0, y: 0 };
  /**
   * Fits the view to its nodes once a card is dropped. Only the dropped card's pin was written (while it moved): pins
   * may be negative, and the layout model draws the graph shifted by `origin` so the leftmost/topmost card is at or
   * past zero. When a drop changes that shift, the view's own place moves the opposite way, so no card moves on the
   * canvas, and no pin of another card is ever rewritten (a shift would write every pin, and the server keeps at most 256
   * per view). The re-read then grows or shrinks the view (neighbours are pushed by `settle`, as with any size change).
   */
  const fitAfterDrag = (c: ViewRec, dropped: NodeModel): void => {
    // A fresh object: the layout cache is keyed by the identity of the pins, and the drag changed them in place.
    c.view.graphPins = { ...(c.view.graphPins ?? Object.fromEntries(source.data().pins)) };
    const before = origins.get(c) ?? { x: 0, y: 0 };
    const after = layoutOf(c, state.metrics).origin;
    const dx = after.x - before.x, dy = after.y - before.y;
    if (dx || dy) {
      c.view.x -= dx; c.view.y -= dy;
      c.sx.set(c.view.x, true); c.sy.set(c.view.y, true);
    }
    refreshGraph(c);
    // Locked to this view, the camera rests at the stop that frames the card just dropped: the view grew, and a card
    // put beyond the stop that was on screen would otherwise be out of reach.
    if (state.canvasLock && state.currentView === c.view.id) {
      cx.nav.goStop(c, cx.nav.nearestStop(c, cx.view.contentRect(c).x + dropped.x + state.metrics.nodeW / 2));
    }
  };
  // ---- renaming a host: double click or double tap on its name, or the palette -----------------------------------------
  const renaming = new WeakMap<WinRec, InlineRename>();
  /** The card's name field is open, so the card does not drag from it and a refresh does not rebuild the title under it. */
  const nameOf = (rec: WinRec): HTMLElement => rec.card.pill.querySelector<HTMLElement>(".ui-window-host")!;
  const beginRenameOn = (rec: WinRec): boolean => {
    const n = boundTo.get(rec);
    // Tags are renamed elsewhere (a tag is not a host); far zoom shows no card to rename.
    if (!n || n.kind !== "host" || renaming.has(rec) || camera.lod === "thumb") return false;
    endDrag.get(rec)?.();
    const name = nameOf(rec);
    let restore = (): void => undefined;
    renaming.set(rec, beginInlineRename({
      value: n.label,
      label: "Host name",
      className: "cl-node-rename",
      place: (input) => { restore = placeOverName(name, rec.card.header, input, cam.z); },
      commit: (value) => {
        const next = value.trim();
        if (!next || next === n.label) return;
        // The new name shows at once and the card says it is waiting; a refusal puts the old one back (the toast says why).
        rec.card.setTitle({ host: next });
        rec.card.root.dataset.renaming = "pending";
        const settle = (): void => { if (rec.card.root.dataset.renaming === "pending") delete rec.card.root.dataset.renaming; };
        void renameHost(cx, n.id, next).then(settle, () => { if (boundTo.get(rec)?.id === n.id) rec.card.setTitle({ host: n.label }); settle(); });
      },
      close: () => { restore(); renaming.delete(rec); },
    }));
    return true;
  };
  /** A rename asked for before its card was drawn: tried again as cards come and go, until it opens or the host is gone. */
  let wanted: string | undefined;
  const tryWanted = (): void => {
    if (wanted === undefined) return;
    for (const c of views.values()) {
      const rec = c.view.layout === "graph" ? graphOf(c)?.card(wanted) : undefined;
      if (rec) { wanted = undefined; beginRenameOn(rec); return; }
    }
    if (![...views.values()].some((c) => c.view.layout === "graph" && c.view.nodes.some((n) => n.id === wanted))) wanted = undefined;
  };
  const wireNode = (rec: WinRec): void => {
    const pill = rec.card.pill;
    onDoubleActivate(pill, () => { beginRenameOn(rec); }, signal);
    pill.style.touchAction = "none";
    pill.dataset.grab = "";
    // The drag is anchored in pin space (`px`,`py`: the pin at pointerdown), not in drawn coordinates: the drawn shift
    // (`origins`) can change while a finger is down (a remote pin moves it), and a captured shift would make the card jump.
    let d: { id: number; x: number; y: number; px: number; py: number; n: NodeModel; moved: boolean; at?: { x: number; y: number }; frame: number } | undefined;
    // A drag is applied once per frame, from the last pointer position: a pointer that reports faster than the screen
    // draws would move the card and redraw its arrows several times for one frame.
    const cancel = (): void => {
      if (!d) return;
      cancelAnimationFrame(d.frame);
      if (pill.hasPointerCapture(d.id)) pill.releasePointerCapture(d.id);
      d = undefined;
      delete rec.card.root.dataset.lifted;
    };
    endDrag.set(rec, cancel);
    const apply = (): void => {
      if (!d) return;
      d.frame = 0;
      if (!d.at) return;
      // A refresh during the drag may have rebound the card to a new model of the same node: follow it, so the model
      // drawn is the one moved. A card that is no longer this node's (removed) ends the drag and writes no pin.
      const n = boundTo.get(rec);
      if (!n || n.id !== d.n.id) { cancel(); return; }
      d.n = n;
      // No wall: the view is as big as its nodes as placed, so a card can go anywhere; the view is fitted once, on drop
      // (`fitAfterDrag`), because a resize per pointer move would re-frame the camera under the finger.
      const o = origins.get(rec.owner) ?? ZERO; // the shift as drawn now: one WeakMap read per frame
      const px = d.px + (d.at.x - d.x) / cam.z, py = d.py + (d.at.y - d.y) / cam.z;
      if (px !== d.px || py !== d.py) d.moved = true;
      n.x = px + o.x;
      n.y = py + o.y;
      n.pinned = true; // a node the person moved stays where it is (D180); the canvas document keeps it
      const pins = rec.owner.view.graphPins ??= Object.fromEntries(source.data().pins);
      // The pin is where the card is minus the shift the graph is drawn with (it may be negative).
      pins[n.id] = { x: Math.round(px), y: Math.round(py) };
      if (rec.owner.view.id === "mesh") source.pin(n.id, px, py);
      rec.card.root.style.transform = `translate(${n.x}px, ${n.y}px)`;
      // Arrows stay attached to the card they belong to while it moves.
      for (const t of topoOf(rec.owner)) if (t.grant.from === n.id || t.grant.to === n.id) drawTopoArrow(rec.owner, t);
    };
    pill.addEventListener("pointerdown", (e) => {
      const n = boundTo.get(rec);
      if (d || camera.lod === "thumb" || !n) return; // a second finger must not reset or steal the drag
      pill.setPointerCapture(e.pointerId);
      const o = origins.get(rec.owner) ?? ZERO;
      d = { id: e.pointerId, x: e.clientX, y: e.clientY, px: n.x - o.x, py: n.y - o.y, n, moved: false, frame: 0 };
      rec.card.root.dataset.lifted = "";
    }, { signal });
    pill.addEventListener("pointermove", (e) => {
      if (!d || e.pointerId !== d.id) return;
      if (e.buttons === 0) { up(e); return; } // the release was missed: a stale drag must not follow a bare pointer
      d.at = { x: e.clientX, y: e.clientY };
      if (!d.frame) d.frame = requestAnimationFrame(apply);
    }, { signal });
    const up = (e: PointerEvent): void => {
      if (!d || e.pointerId !== d.id) return;
      cancelAnimationFrame(d.frame);
      apply(); // may end the drag (node gone)
      if (!d) return;
      const n = d.n;
      const moved = d.moved;
      cancel();
      if (moved) { fitAfterDrag(rec.owner, n); cx.store.changed(); }
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
      const ids = { a: n.id, b: to };
      const title = say("Let {a} reach {b}?", ids), effect = say("{a} will be able to connect to {b}. You can stop it any time.", ids);
      mountConfirmTip(at.anchor, {
        label: say("Let {a} reach {b}", ids).plain,
        title: title.plain, titleNode: title.node, effect: effect.plain, effectNode: effect.node,
        confirmLabel: "Allow access", cancelLabel: "Cancel",
        onConfirm: () => {
          const g = source.addGrant(n.id, to);
          live.dispose();
          refreshGraph(c);
          pulseNew(c, g);
          for (const cl of views.values()) cx.view.geometry(cl);
          const done = say("{a} can now reach {b}", ids);
          cx.toast.show({ message: done.plain, messageNode: done.node });
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
    /** Not changed: the end returns to where it came from, quickly and without overshoot, then the original arrow is back. */
    const putBack = (): void => {
      entry.arrow.g.removeAttribute("data-editing"); // the original fades back while the live arrow arrives on top of it
      live.glideTo(home, 150, () => live.dispose());
    };
    const up = (ev: PointerEvent): void => {
      finish();
      const at = tipAt({ x: ev.clientX, y: ev.clientY });
      if (ev.type === "pointercancel" || candidate === homeId) { putBack(); at.done(); return; }
      if (candidate) {
        const next: Grant = end === "head" ? { ...g, to: candidate } : { ...g, from: candidate };
        // What changes for the person, in the words of the cards: who reaches what now, and who will not any more.
        const ids = { from: g.from, to: g.to, cand: candidate };
        const moveTitle = say(end === "head" ? "Let {from} reach {cand} instead of {to}?" : "Let {cand} reach {to} instead of {from}?", ids);
        const moveEffect = say(end === "head"
          ? "{from} will lose its connection to {to} and gain one to {cand}. You can change it back any time."
          : "{from} will lose its connection to {to}, and {cand} will gain one. You can change it back any time.", ids);
        const endTip = tipAt(toClient({ x: live.end().x + origin.x, y: live.end().y + origin.y }));
        mountConfirmTip(endTip.anchor, {
          label: moveTitle.plain, title: moveTitle.plain, titleNode: moveTitle.node, effect: moveEffect.plain, effectNode: moveEffect.node,
          confirmLabel: "Change access", cancelLabel: "Cancel",
          onConfirm: () => {
            source.moveGrant(g, end === "head" ? { to: next.to } : { from: next.from });
            entry.arrow.g.dataset.tip = grantName(g);
            entry.arrow.g.removeAttribute("data-editing");
            refreshGraph(c);
            entry.arrow.press();
            live.dispose();
            for (const cl of views.values()) cx.view.geometry(cl);
            const done = say("{from} can now reach {to}", { from: g.from, to: g.to });
            cx.toast.show({ message: done.plain, messageNode: done.node });
            endTip.done();
          },
          onCancel: () => { putBack(); endTip.done(); },
        });
        at.done();
        return;
      }
      // Dropped on empty canvas: offer to remove the grant.
      const stopIds = { from: g.from, to: g.to };
      const stopTitle = say("Stop {from} reaching {to}?", stopIds), stopEffect = say("{from} will lose its connection to {to}. You can allow it again any time.", stopIds);
      mountConfirmTip(at.anchor, {
        label: stopTitle.plain.replace(/\?$/, ""), title: stopTitle.plain, titleNode: stopTitle.node, effect: stopEffect.plain, effectNode: stopEffect.node,
        confirmLabel: "Stop access", cancelLabel: "Keep it",
        onConfirm: () => {
          source.removeGrant(g);
          live.dispose();
          refreshGraph(c); // the arrow fades out; the grants listed in the graph are the source's
          for (const cl of views.values()) cx.view.geometry(cl);
          const gone = say("{from} can no longer reach {to}", stopIds);
          cx.toast.show({ message: gone.plain, messageNode: gone.node });
        },
        onCancel: putBack,
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
  const sizes = new WeakMap<ViewRec, string>();
  const refreshGraph = (c: ViewRec): void => {
    const graph = graphOf(c);
    if (!graph) return;
    const layout = layoutOf(c, state.metrics);
    origins.set(c, layout.origin);
    c.view.nodes = layout.nodes;
    c.view.graph = layout.size;
    graph.sync();
    cx.view.geometry(c);
    const size = `${layout.size.w}x${layout.size.h}`;
    if (size !== sizes.get(c)) { sizes.set(c, size); cx.view.settle(c.view.id); }
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
    const graph = createGraph(cx, c, source, (metrics) => layoutOf(c, metrics), {
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

  // A name field the palette asked for before this code had loaded opens once the card is on screen.
  queueMicrotask(() => { const early = takePendingRename(); if (early) api.beginRename(early); });
  const api: GraphViewModule = {
    buildGraph,
    refresh: refreshGraph,
    pulseNew,
    changed(rightsChanged) {
      for (const port of ports) { if (port.isConnected) port.hidden = !source.canEdit(); else ports.delete(port); } // a dropped card's connector goes with it
      // Handles on arrows exist only for people who may use them (D187): arrows are made again when that changes.
      if (rightsChanged) for (const c of views.values()) graphOf(c)?.reset();
      for (const c of views.values()) if (c.view.layout === "graph") refreshGraph(c);
      tryWanted();
    },
    beginRename(id) { wanted = id; tryWanted(); },
    cull() { for (const c of views.values()) if (c.view.layout === "graph") graphOf(c)?.cull(); tryWanted(); },
    rest() { redrawMesh(); },
    stats() { const c = views.get("mesh"); const g = c && graphOf(c); if (!g) return undefined; return { level: g.level(), ...g.stats() }; },
  };
  return api;
}
