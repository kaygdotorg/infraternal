/**
 * What is on screen of the Mesh graph, and how much of it (priority 1: 60 fps at 1,000 nodes).
 *
 * The graph can hold a thousand hosts and a few thousand grants, but a screen shows a few dozen cards. This module
 * keeps the DOM to what the camera can see:
 *
 * - **Cards level** (zoomed in): only the node cards whose frame is near the viewport are in the DOM, and only
 *   the arrows that touch one of them (at most `MAX_ARROWS`, the ones with both ends in view first). In a big graph
 *   the cards' soft shadow is a plain hairline one: a dozen tiles of blur per card is what a frame cannot afford. Moving the
 *   camera mounts the cards that come into view, a few per frame, and drops the ones far behind.
 * - **Clusters level** (zoomed out, below about 62 %: the cards would be thumbnails whose text cannot be read): no cards and no host arrows at all. One frame per cluster
 *   (a tag and its hosts) with its name, its host count and how many are online, and one arrow per pair of
 *   clusters that have grants between them. Clicking a frame flies into it.
 * - **Small meshes** (up to `SMALL`) are always drawn whole as cards: culling them would only add motion.
 *
 * Invariants:
 * - A frame of camera movement does a comparison per node and per grant (microseconds) and a DOM change only for
 *   what crossed the edge, at most `MOUNTS_PER_FRAME` cards. It writes no style on elements that stay.
 * - The arrows are one SVG: any change inside it repaints all of it, so arrows are mounted and dropped in batches
 *   (the camera moved a quarter of a screen, the zoom changed, the data changed, or it came to rest), never one
 *   by one while the camera moves. The set is chosen for a third of a screen more on every side, so a batch is
 *   enough for the next stretch of movement. Cluster frames and their arrows change only with the data or the level.
 * - The level changes with hysteresis (below 0.62 enters clusters, above 0.7 leaves), so a zoom does not flicker.
 * - Objects are identified by identity: the source keeps the same `NodeModel` and `Grant` objects for the same
 *   node and grant, so cards and arrows follow their values without being rebuilt.
 * - Cards and arrows are made by the mesh module (`hooks`); this module only decides which exist.
 */
import type { Ctx, ViewRec, WinRec } from "../context";
import { el } from "../dom";
import { createSpinner } from "../../../../../packages/ui/src/spinner";
import { ICON, lineIcon } from "../views/icons";
import type { Metrics, Rect } from "../layout/geometry";
import type { Grant, NodeModel } from "../model/types";
import { Arrow } from "./arrows";
import type { Cluster } from "./layout";
import { grantSentence, type MeshLayout, type MeshSource } from "./source";

/** One mounted arrow: its grant, the drawn `Arrow`, and its name label if it has one. */
export interface TopoArrow { grant: Grant; arrow: Arrow; label?: SVGTextElement }

/**
 * What the mesh module lends the graph: making and dropping cards and arrows, drawing an arrow, and the head size. The graph decides
 * which exist; these make them.
 */
export interface GraphHooks {
  makeCard(n: NodeModel): WinRec;
  dropCard(rec: WinRec): void;
  makeArrow(g: Grant): TopoArrow;
  dropArrow(entry: TopoArrow, fade: boolean): void;
  drawArrow(entry: TopoArrow): void;
  headSize(): number;
}

/** The graph's level of detail: node `cards` when zoomed in, or one frame per tag `clusters` when zoomed out. */
export type Level = "cards" | "clusters";
/** What the mesh module can ask of the graph: sync it, cull it after the camera moved, redraw it, and look things up. Made by `createGraph`. */
export interface GraphController {
  /** The mesh changed: nodes, grants, status or layout. */
  sync(): void;
  /** The camera moved (called on the next frame after it). */
  cull(): void;
  /** The camera came to rest: what was held back while it moved is done now (arrows for where it stopped). */
  rest(): void;
  level(): Level;
  stats(): { cards: number; arrows: number; chips: number; clusterArrows: number; passes: number; passMs: number; mounted: number };
  /** The mounted host arrows, in the order they were mounted (the mesh module edits these). */
  arrows(): TopoArrow[];
  /** A node of the graph by id. */
  node(id: string): NodeModel | undefined;
  /** The card a node is drawn with right now, if it has one (a card far off screen is not in the DOM). */
  card(id: string): WinRec | undefined;
  /** The nodes whose cards meet a rectangle (the graph's own coordinates). */
  nodesIn(r: Rect): NodeModel[];
  /** The zoom changed enough to change arrow heads: draw the arrows again. */
  redraw(): void;
  /** Arrows are made again (the person's rights changed, so handles appear or go). */
  reset(): void;
  /** The lane an arrow takes along the card it ends on (arrows that end on one card fan out). */
  lane(g: Grant): number;
  dispose(): void;
}

/**
 * The limits that keep a large graph cheap. `SMALL`: a mesh of up to this many nodes is always drawn whole. `MAX_ARROWS`: most host arrows
 * mounted at once. `ARROWS_PER_FRAME` and `MOUNTS_PER_FRAME`: most arrows and cards mounted in one frame. `ENTER_CLUSTERS` and
 * `LEAVE_CLUSTERS`: the zoom below and above which the clusters level starts and ends (different on purpose, so a zoom does not
 * flicker). `MAX_CLUSTER_ARROWS`: most arrows between clusters.
 */
const SMALL = 40, MAX_ARROWS = 150, ARROWS_PER_FRAME = 40, MOUNTS_PER_FRAME = 24, ENTER_CLUSTERS = 0.62, LEAVE_CLUSTERS = 0.7, MAX_CLUSTER_ARROWS = 400;

/**
 * Makes the graph controller for view `c`. `layoutOf` gives the automatic layout for the current metrics; `hooks` make the cards and
 * arrows. The controller keeps in the DOM only what the camera can see (see the module comment for the rules).
 */
export function createGraph(cx: Ctx, c: ViewRec, source: MeshSource, layoutOf: (m: Metrics) => MeshLayout, hooks: GraphHooks): GraphController {
  const { camera, state } = cx;
  const cam = camera.cam;
  let level: Level = "cards";
  let nodes = new Map<string, NodeModel>();
  let clusters: Cluster[] = [];
  let clusterOf = new Map<string, string>();
  const cards = new Map<NodeModel, WinRec>();
  const arrows = new Map<Grant, TopoArrow>();
  const mounted: TopoArrow[] = [];
  const lanes = new Map<Grant, number>();
  const chips = new Map<string, HTMLElement>();
  const clusterArrows = new Map<string, Arrow>();
  let dataKey = 0, lastKey = "", lastInv = 0, chipTimer = 0, cardTimer = 0, clusterKey = -1;
  /** Where (and at what zoom) the arrows were last chosen; the next batch is due when the camera has left it. */
  let cardsAt: { x: number; y: number; data: number } | undefined;
  let arrowAt: { x: number; y: number; z: number; data: number } | undefined;
  // What the passes cost (read by the specs that measure frame times): the time inside passes, and cards made.
  let passes = 0, passMs = 0, mounted_ = 0;
  let needsAnotherFrame = false;
  let lastZ = 0;

  // The chip layer sits under the cards, over the dotted canvas. The cards live in one layer of their own so that a
  // change of level fades one element, not a hundred (each fading card would be a layer to paint).
  const chipLayer = el("div", "cl-chips");
  chipLayer.dataset.on = "false";
  c.colsEl.prepend(chipLayer);
  const cardLayer = el("div", "cl-cards");
  c.colsEl.append(cardLayer);

  const small = (): boolean => nodes.size <= SMALL;

  // ---- what the camera sees, in the graph's own coordinates -------------------------------------------------------
  const view = (grow: number): Rect => {
    const o = cx.view.contentRect(c);
    const w = camera.vw / cam.z, h = camera.vh / cam.z;
    return { x: cam.cx - w / 2 - o.x - w * grow, y: cam.cy - h / 2 - o.y - h * grow, w: w * (1 + 2 * grow), h: h * (1 + 2 * grow) };
  };
  const hits = (r: Rect, v: Rect): boolean => r.x < v.x + v.w && v.x < r.x + r.w && r.y < v.y + v.h && v.y < r.y + r.h;
  const nodeBox = (n: NodeModel): Rect => ({ x: n.x, y: n.y, w: state.metrics.nodeW, h: state.metrics.nodeH });
  /** Whether a node's card meets a rectangle: no object is made, this runs for every node near the view on every frame. */
  const meets = (n: NodeModel, v: Rect): boolean => n.x < v.x + v.w && v.x < n.x + state.metrics.nodeW && n.y < v.y + v.h && v.y < n.y + state.metrics.nodeH;
  // The nodes by place, in cells of 512 px: a pass looks at the cells the view covers, not at every node.
  const CELL = 512;
  let grid = new Map<number, NodeModel[]>();
  const cellKey = (i: number, j: number): number => (i + 4096) * 8192 + (j + 4096);
  const buildGrid = (): void => {
    grid = new Map();
    for (const n of nodes.values()) {
      const k = cellKey(Math.floor(n.x / CELL), Math.floor(n.y / CELL));
      const list = grid.get(k);
      if (list) list.push(n); else grid.set(k, [n]);
    }
  };
  const inRect = (v: Rect, visit: (n: NodeModel) => void): void => {
    // A node is in the cell of its top left corner and reaches at most one card width right and down of it.
    const i0 = Math.floor((v.x - state.metrics.nodeW) / CELL), i1 = Math.floor((v.x + v.w) / CELL);
    const j0 = Math.floor((v.y - state.metrics.nodeH) / CELL), j1 = Math.floor((v.y + v.h) / CELL);
    for (let i = i0; i <= i1; i++) for (let j = j0; j <= j1; j++) { const list = grid.get(cellKey(i, j)); if (list) for (const n of list) visit(n); }
  };

  // ---- cards and arrows ------------------------------------------------------------------------------------------
  const mountCard = (n: NodeModel): void => {
    const rec = hooks.makeCard(n);
    mounted_ += 1;
    cards.set(n, rec);
    c.wins.set(rec.model.id, rec);
    cardLayer.append(rec.card.root);
  };
  const unmountCard = (n: NodeModel): void => {
    const rec = cards.get(n);
    if (!rec) return;
    cards.delete(n);
    c.wins.delete(rec.model.id);
    if (state.activeWin === rec) state.activeWin = undefined;
    hooks.dropCard(rec);
  };
  const mountArrow = (g: Grant): void => {
    const entry = hooks.makeArrow(g);
    arrows.set(g, entry);
    mounted.push(entry);
    c.graphSvg!.append(entry.arrow.g);
    hooks.drawArrow(entry);
  };
  const unmountArrow = (g: Grant, fade = false): void => {
    const entry = arrows.get(g);
    if (!entry) return;
    arrows.delete(g);
    mounted.splice(mounted.indexOf(entry), 1);
    hooks.dropArrow(entry, fade);
  };

  const rebuildLanes = (): void => {
    lanes.clear();
    const byTo = new Map<string, Grant[]>();
    for (const g of source.grants()) (byTo.get(g.to) ?? byTo.set(g.to, []).get(g.to)!).push(g);
    for (const list of byTo.values()) list.forEach((g, i) => lanes.set(g, i - (list.length - 1) / 2));
  };

  // ---- clusters ---------------------------------------------------------------------------------------------------
  const chipSummary = (cl: Cluster): { total: number; online: number } => {
    let online = 0;
    for (const id of cl.hosts) if (nodes.get(id)?.state === "online") online++;
    return { total: cl.hosts.length, online };
  };
  const paintChip = (cl: Cluster, chip: HTMLElement): void => {
    const { total, online } = chipSummary(cl);
    chip.style.cssText = `left:${cl.x}px;top:${cl.y}px;width:${cl.w}px;height:${cl.h}px`;
    const name = chip.querySelector<HTMLElement>(".cl-chip-name")!;
    const meta = chip.querySelector<HTMLElement>(".cl-chip-meta")!;
    if (name.textContent !== cl.label) name.textContent = cl.label;
    const hostsText = total === 0 ? "no hosts" : `${total} host${total === 1 ? "" : "s"}`;
    const onlineText = total === 0 ? "" : `${online} online`;
    const text = onlineText ? `${hostsText} · ${onlineText}` : hostsText;
    // Two parts the label wraps between (never inside one, never an ellipsis): see `.cl-chip-meta` in mesh.css.
    if (meta.dataset.text !== text) {
      meta.dataset.text = text;
      const head = el("span", "cl-chip-part", hostsText);
      meta.replaceChildren(...(onlineText ? [head, el("span", "cl-chip-part cl-chip-part-after", onlineText)] : [head]));
    }
    if (total === 0 || online === total) chip.removeAttribute("data-degraded"); else chip.dataset.degraded = "";
    chip.setAttribute("aria-label", `${cl.label}, ${text}. Zoom in`);
  };
  const mountChips = (): void => {
    const live = new Set(clusters.map((cl) => cl.id));
    for (const [id, chip] of chips) if (!live.has(id)) { chip.remove(); chips.delete(id); }
    for (const cl of clusters) {
      let chip = chips.get(cl.id);
      if (!chip) {
        chip = el("button", "cl-chip");
        (chip as HTMLButtonElement).type = "button";
        chip.dataset.cluster = cl.id;
        chip.innerHTML = '<span class="cl-chip-label"><span class="cl-chip-name"></span><span class="cl-chip-meta"></span></span>';
        chip.addEventListener("click", (e) => { e.stopPropagation(); flyInto(cl.id); }, { signal: cx.signal }); // not the thumbnail tap that flies to the whole view
        chips.set(cl.id, chip);
        chipLayer.append(chip);
      }
      paintChip(cl, chip);
    }
  };
  const flyInto = (id: string): void => {
    const cl = clusters.find((o) => o.id === id);
    if (!cl) return;
    const o = cx.view.contentRect(c);
    // Frame the cluster so its cards are live (above the cards threshold) and the whole frame fits the screen.
    const z = Math.min(1, Math.max(0.78, Math.min(camera.vw / (cl.w + 120), camera.vh / (cl.h + 120))));
    cx.nav.applyCanvasLock(false);
    camera.flyTo(() => ({ cx: o.x + cl.x + cl.w / 2, cy: o.y + cl.y + cl.h / 2, z }));
  };
  const clusterEdges = (): Array<{ key: string; from: string; to: string; count: number }> => {
    const counts = new Map<string, { from: string; to: string; count: number }>();
    for (const g of source.grants()) {
      const a = clusterOf.get(g.from), b = clusterOf.get(g.to);
      if (!a || !b || a === b) continue;
      const key = `${a}\u0000${b}`;
      const have = counts.get(key);
      if (have) have.count++; else counts.set(key, { from: a, to: b, count: 1 });
    }
    return [...counts.entries()].map(([key, v]) => ({ key, ...v })).sort((p, q) => q.count - p.count).slice(0, MAX_CLUSTER_ARROWS);
  };
  /** Heads of the far zoom are drawn larger in the graph so they still read at the thumbnail scale. */
  const clusterHead = (): number => Math.min(64, Math.max(hooks.headSize(), 9 / cam.z));
  const paintClusterArrows = (): void => {
    const edges = clusterEdges();
    const live = new Set(edges.map((e) => e.key));
    for (const [key, a] of clusterArrows) if (!live.has(key)) { a.remove(); clusterArrows.delete(key); }
    const by = new Map(clusters.map((cl) => [cl.id, cl]));
    for (const e of edges) {
      const a = by.get(e.from), b = by.get(e.to);
      if (!a || !b) continue;
      let arrow = clusterArrows.get(e.key);
      if (!arrow) {
        arrow = new Arrow({ tone: "accent" });
        arrow.g.dataset.cluster = ""; // quieter than a grant's own arrow (mesh.css)
        arrow.g.dataset.fresh = "";
        const fresh = arrow;
        requestAnimationFrame(() => requestAnimationFrame(() => fresh.g.removeAttribute("data-fresh")));
        c.graphSvg!.append(arrow.g);
        clusterArrows.set(e.key, arrow);
      }
      arrow.g.dataset.tip = `${a.label} can reach ${b.label}`;
      arrow.between(a, b, clusterHead());
    }
  };
  /** Leaving the clusters level: the frames and their arrows fade out, then go. */
  const clearClusterLevel = (): void => {
    chipLayer.dataset.on = "false";
    const gone = [...clusterArrows.values()];
    clusterArrows.clear();
    for (const a of gone) a.g.dataset.leaving = "";
    window.clearTimeout(chipTimer);
    chipTimer = window.setTimeout(() => {
      for (const a of gone) a.remove();
      if (level === "cards") { for (const chip of chips.values()) chip.remove(); chips.clear(); }
    }, 240);
  };
  /** Entering the clusters level: the cards and host arrows fade out (a short animation) and are then taken out of the DOM. */
  const leaveCards = (): void => {
    cardLayer.dataset.leaving = "";
    for (const e of mounted) e.arrow.g.dataset.leaving = "";
    window.clearTimeout(cardTimer);
    cardTimer = window.setTimeout(() => {
      if (level !== "clusters") return;
      for (const n of [...cards.keys()]) unmountCard(n);
      for (const g of [...arrows.keys()]) unmountArrow(g);
    }, 200);
  };

  // ---- one pass ----------------------------------------------------------------------------------------------------
  /**
   * The representation changes at rest, or well past the threshold while the camera still moves: a zoom gesture that
   * crosses the threshold keeps drawing what it has (frames stay frames, cards stay cards) and swaps where it stops,
   * so no frame of the gesture pays for the swap. A long zoom still gets the right one once it is clearly past.
   */
  const pickLevel = (atRest: boolean): Level => {
    if (small()) return "cards";
    const enter = atRest ? ENTER_CLUSTERS : ENTER_CLUSTERS * 0.72, leave = atRest ? LEAVE_CLUSTERS : LEAVE_CLUSTERS * 1.3;
    return level === "cards" ? (cam.z < enter ? "clusters" : "cards") : (cam.z > leave ? "cards" : "clusters");
  };

  const passCards = (full: boolean): void => {
    const whole = small();
    // While the camera pans, cards are made in batches: the pass runs when the view has moved a tenth of a screen from where
    // the last one ran, so the frames in between change nothing but the world's transform. Each batch is one change of the
    // page's paint, however many cards it brings (the margin around the view covers the distance until the next one).
    if (!full && !whole && !needsAnotherFrame && cardsAt && cardsAt.data === dataKey) {
      const w = camera.vw / cam.z, h = camera.vh / cam.z;
      if (Math.abs(cam.cx - cardsAt.x) < w * 0.1 && Math.abs(cam.cy - cardsAt.y) < h * 0.1) return;
    }
    cardsAt = { x: cam.cx, y: cam.cy, data: dataKey };
    const near = whole ? undefined : view(0.2);
    const far = whole ? undefined : view(0.4);
    let budget = MOUNTS_PER_FRAME;
    const wanted: NodeModel[] = [];
    if (far) for (const n of [...cards.keys()]) if (!meets(n, far)) unmountCard(n);
    if (!near) { for (const n of nodes.values()) if (!cards.has(n)) wanted.push(n); }
    else inRect(near, (n) => { if (!cards.has(n) && meets(n, near)) wanted.push(n); });
    // The ones nearest the middle of the screen come first, so a fast pan fills the centre before the edges.
    if (wanted.length > budget && near) {
      const mx = near.x + near.w / 2, my = near.y + near.h / 2;
      wanted.sort((p, q) => Math.hypot(p.x - mx, p.y - my) - Math.hypot(q.x - mx, q.y - my));
    }
    for (const n of wanted) { if (budget-- <= 0) { needsAnotherFrame = true; break; } mountCard(n); }

    if (!arrowsDue(full)) return;
    // Arrows that touch a node near the screen (a third of a screen more on every side); the ones with both ends there first.
    arrowAt = { x: cam.cx, y: cam.cy, z: cam.z, data: dataKey };
    const reach = whole ? undefined : view(0.35);
    const want = new Set<Grant>();
    const both: Grant[] = [], one: Grant[] = [];
    const touches = (id: string): boolean => { const n = nodes.get(id); return !!n && (!reach || meets(n, reach)); };
    for (const g of source.grants()) {
      if (!nodes.has(g.from) || !nodes.has(g.to)) continue;
      const a = touches(g.from), b = touches(g.to);
      if (a && b) both.push(g); else if (a || b) one.push(g);
    }
    for (const g of both) { if (want.size >= MAX_ARROWS) break; want.add(g); }
    for (const g of one) { if (want.size >= MAX_ARROWS) break; want.add(g); }
    for (const g of [...arrows.keys()]) if (!want.has(g)) unmountArrow(g);
    // A big batch is made over a few frames: each arrow is a handful of SVG elements.
    let arrowBudget = ARROWS_PER_FRAME;
    for (const g of want) {
      if (arrows.has(g)) continue;
      if (arrowBudget-- <= 0) { arrowAt = undefined; needsAnotherFrame = true; break; }
      mountArrow(g);
    }
  };
  /** Whether the arrows should be chosen again now (see the invariants above). */
  const arrowsDue = (full: boolean): boolean => {
    if (full || !arrowAt || arrowAt.data !== dataKey) return true;
    if (small()) return false; // a small graph draws every arrow once
    const w = camera.vw / cam.z, h = camera.vh / cam.z;
    return Math.abs(cam.cx - arrowAt.x) > w * 0.25 || Math.abs(cam.cy - arrowAt.y) > h * 0.25 || Math.abs(Math.log(cam.z / arrowAt.z)) > 0.12;
  };

  const passClusters = (): void => {
    mountChips();
    paintClusterArrows();
    chipLayer.dataset.on = "true";
  };

  /** The world width of one screen pixel for strokes (see mesh.css): written at rest and when the data changes, never per frame. */
  let lastK = 0;
  const strokeScale = (): void => {
    const k = Math.min(8, Math.max(0.5, 1 / cam.z));
    if (lastK && Math.abs(k - lastK) / k < 0.04) return;
    lastK = k;
    c.graphSvg?.style.setProperty("--k", k.toFixed(2));
  };
  /** The label counter-scale of the chips: written in coarse steps, never per frame. */
  const scaleChips = (): void => {
    const inv = Math.min(10, Math.max(1, 1 / cam.z));
    if (Math.abs(inv - lastInv) / inv < 0.06 && lastInv !== 0) return;
    lastInv = inv;
    chipLayer.style.setProperty("--inv", inv.toFixed(2));
  };

  const run = (force: boolean): void => {
    const next = pickLevel(force);
    const key = `${dataKey}|${next}|${Math.round(cam.cx / 48)}|${Math.round(cam.cy / 48)}|${cam.z.toFixed(3)}`;
    if (!force && key === lastKey && !needsAnotherFrame) return;
    lastKey = key;
    needsAnotherFrame = false;
    const levelChanged = next !== level;
    // A zoom is only the world's transform: no card or arrow is made or dropped while the scale changes, and what is
    // missing at the edges is made where the zoom stops.
    if (!force && !levelChanged && c.colsEl.dataset.zooming !== undefined) return;
    if (levelChanged) {
      level = next;
      c.colsEl.dataset.level = level;
      if (level === "cards") clearClusterLevel(); else leaveCards();
      if (level === "cards") {
        window.clearTimeout(cardTimer);
        delete cardLayer.dataset.leaving;
        cardLayer.dataset.enter = "";
        cardLayer.addEventListener("animationend", () => cardLayer.removeAttribute("data-enter"), { once: true });
      }
    }
    const t0 = performance.now();
    if (level === "clusters") {
      scaleChips();
      // The frames and their arrows depend on the data and the level only: nothing is rewritten while the camera moves.
      if (force || levelChanged || clusterKey !== dataKey) { clusterKey = dataKey; passClusters(); }
    } else passCards(force || levelChanged);
    passes += 1; passMs += performance.now() - t0;
    if (needsAnotherFrame) cx.invalidate();
  };

  // ---- states: loading, unreachable, empty ----------------------------------------------------------------------------
  // They reuse the empty view's card (`cl-empty`), so every state has the same rhythm: title, one line, one action.
  let stateEl: HTMLElement | undefined, stateKind = "";
  const paintState = (): void => {
    const status = source.status();
    const kind = status === "loading" ? "loading" : status === "error" ? (nodes.size ? "stale" : "error") : nodes.size ? "" : "empty";
    if (kind === stateKind) return;
    stateKind = kind;
    const old = stateEl;
    stateEl = undefined;
    if (old) { old.dataset.open = "false"; window.setTimeout(() => old.remove(), 200); }
    if (!kind) return;
    // The last known mesh stays on screen; the connection's state is one small icon with motion and a tooltip (TASTE),
    // and selecting it asks again. A mesh with nothing to show gets the empty view's card instead.
    const box = el(kind === "stale" ? "button" : "div", kind === "stale" ? "cl-meshnote ui-pill ui-pill-icon" : "cl-empty cl-meshstate");
    const retry = (label: string): HTMLButtonElement => {
      const b = el("button", "ui-pill cl-empty-add");
      b.type = "button";
      b.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON.retry}</svg><span>${label}</span>`;
      b.addEventListener("click", () => source.retry(), { signal: cx.signal });
      return b;
    };
    if (kind === "loading") {
      const spin = el("div", "cl-meshstate-mark");
      spin.append(createSpinner());
      box.append(spin, el("p", "cl-empty-title", "Loading the mesh"), el("p", "cl-empty-hint", "Getting your hosts and who can reach what."));
      box.setAttribute("role", "status");
    } else if (kind === "error") {
      const mark = el("div", "cl-meshstate-mark");
      mark.innerHTML = lineIcon(ICON.offline);
      box.append(mark, el("p", "cl-empty-title", "Could not reach the mesh"), el("p", "cl-empty-hint", "Check your connection. It will try again on its own."), retry("Try again"));
      box.setAttribute("role", "alert");
    } else if (kind === "stale") {
      const note = box as HTMLButtonElement;
      note.type = "button";
      note.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON.offline}</svg>`;
      note.dataset.tip = "Showing what was last known. Select to try again.";
      note.setAttribute("aria-label", "Showing what was last known. Try again");
      note.addEventListener("click", () => source.retry(), { signal: cx.signal });
    } else {
      const mark = el("div", "cl-meshstate-mark");
      mark.innerHTML = lineIcon(ICON.node);
      box.append(mark, el("p", "cl-empty-title", "No hosts in the mesh yet"), el("p", "cl-empty-hint", "Hosts join the mesh as they are added."));
      const addHost = cx.adapters.addHost;
      if (addHost) {
        const add = el("button", "ui-pill cl-empty-add");
        add.type = "button";
        add.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON.plus}</svg><span>Add host</span>`;
        add.addEventListener("click", () => addHost(), { signal: cx.signal });
        box.append(add);
      }
    }
    box.dataset.open = "false";
    c.content.append(box);
    stateEl = box;
    requestAnimationFrame(() => { box.dataset.open = "true"; });
  };

  // ---- data ---------------------------------------------------------------------------------------------------------
  const sync = (): void => {
    const layout = layoutOf(state.metrics);
    nodes = new Map(layout.nodes.map((n) => [n.id, n]));
    buildGrid();
    clusters = layout.clusters;
    clusterOf = new Map();
    for (const cl of clusters) { for (const id of cl.hosts) clusterOf.set(id, cl.id); if (cl.tagNode) clusterOf.set(cl.tagNode, cl.id); }
    // Cards of nodes that are gone, and arrows of grants that are gone, leave; the rest follow their objects.
    for (const n of [...cards.keys()]) if (nodes.get(n.id) !== n) unmountCard(n);
    const live = new Set(source.grants());
    for (const g of [...arrows.keys()]) if (!live.has(g)) unmountArrow(g, true);
    rebuildLanes();
    for (const [n, rec] of cards) {
      rec.card.setStatus(n.kind === "tag" ? "none" : n.state === "offline" ? "offline" : n.state === "behind" ? "connecting" : "live");
      const [detail, sub] = rec.card.body.querySelectorAll<HTMLElement>(".cl-node-detail, .cl-node-sub");
      if (detail && detail.textContent !== n.detail) detail.textContent = n.detail;
      if (sub && sub.textContent !== n.sub) sub.textContent = n.sub;
      rec.card.root.style.transform = `translate(${n.x}px,${n.y}px)`;
    }
    for (const e of mounted) {
      e.arrow.g.dataset.tip = grantSentence(e.grant); // a rename or a move shows on the next hover
      e.arrow.g.dataset.grant = e.grant.id;
      hooks.drawArrow(e);
    }
    dataKey += 1;
    strokeScale();
    c.colsEl.toggleAttribute("data-big", !small());
    paintState();
    run(true);
    if (level === "clusters") { mountChips(); paintClusterArrows(); }
  };

  return {
    sync,
    cull() {
      // Zooming scales every stroke of the arrow layer, and a software rasteriser draws all of them again on every
      // frame: while the zoom changes the arrows wait, and they fade back in where the camera stops (TASTE: costly
      // paint is held during motion and refreshed at rest). Panning leaves them: a pan does not repaint them.
      if (lastZ && Math.abs(Math.log(cam.z / lastZ)) > 0.003 && !small() && c.colsEl.dataset.zooming === undefined) c.colsEl.dataset.zooming = "";
      lastZ = cam.z;
      run(false);
    },
    rest() {
      lastZ = 0;
      if (c.colsEl.dataset.zooming !== undefined) {
        delete c.colsEl.dataset.zooming;
        const svg = c.graphSvg;
        if (svg) { svg.dataset.in = ""; svg.addEventListener("animationend", () => svg.removeAttribute("data-in"), { once: true }); }
      }
      run(true);
    },
    level: () => level,
    stats: () => ({ cards: cards.size, arrows: arrows.size, chips: chips.size && level === "clusters" ? chips.size : 0, clusterArrows: clusterArrows.size, passes, passMs: Math.round(passMs * 10) / 10, mounted: mounted_ }),
    arrows: () => mounted,
    node: (id) => nodes.get(id),
    card: (id) => { const n = nodes.get(id); return n ? cards.get(n) : undefined; },
    nodesIn(r) { const out: NodeModel[] = []; inRect(r, (n) => { if (meets(n, r)) out.push(n); }); return out; },
    redraw() {
      strokeScale();
      for (const e of mounted) hooks.drawArrow(e);
      if (level === "clusters") paintClusterArrows();
    },
    reset() { for (const g of [...arrows.keys()]) unmountArrow(g); dataKey += 1; run(true); },
    lane: (g) => lanes.get(g) ?? 0,
    dispose() {
      for (const n of [...cards.keys()]) unmountCard(n);
      for (const g of [...arrows.keys()]) unmountArrow(g);
      for (const a of clusterArrows.values()) a.remove();
      window.clearTimeout(chipTimer); window.clearTimeout(cardTimer);
      chipLayer.remove();
      cardLayer.remove();
      stateEl?.remove();
    },
  };
}
