/**
 * The clusters concept mockup (`?mock=1&proto=clusters`, issue #89, D119, D159, D164).
 *
 * One infinite canvas holds *views*. Each view is a tidy tiled group of windows (columns
 * side by side, every column a vertical stack that scrolls by itself), or, for Topology, a
 * graph of small node cards joined by mesh access arrows. Views are placed on a coarse grid
 * and push each other aside; they never overlap (clusters-model.ts).
 *
 * This file is the view layer:
 * - a camera (centre + zoom, three springs) that flies between views and is always
 *   interruptible; below 60 % zoom windows become read-only thumbnails and every view shows as a
 *   labelled region (a hover card on desktop, always-visible labels on touch);
 * - the windows, built from the shared window card; the window's *kind* decides which header
 *   actions it has (only terminals can split);
 * - the interactions the owner's open questions are about: arrows on demand, structure
 *   (drag a pill, drag a view), where a new session opens, and the droplet split.
 *
 * Scenes and the "mockup" stepper are scaffolding for the review round and live in
 * clusters-stepper.ts; nothing here is meant to ship as is. Motion is transform and opacity
 * only (arrow geometry excepted), every spring comes from packages/ui spring.ts, and reduced
 * motion jumps instead.
 */
import { Spring } from "../../../packages/ui/src/spring";
import { createWindowCard, type WindowAction, type WindowCard } from "../../../packages/ui/src/window-card";
import { hostIconMarkup, type HostPlatform } from "../../../packages/ui/src/host-icons";
import { mountConfirmTip } from "../../../packages/ui/src/tooltip";
import { mountToast, type ToastController } from "../../../packages/ui/src/toast";
import { keyCaps, registerShortcuts } from "../../../packages/ui/src/shortcuts";
import { isMacPlatform, shortcutLabel } from "../../../packages/ui/src/platform";
import { createPillMorph, type PillMorph } from "../../../packages/ui/src/pill-morph";
import { aspectFrame, aspectRange, attachWindowResize, settleResize, type ResizeFrame, type ResizeStart, type WindowResizeHost } from "../../../packages/ui/src/window-resize";
import type { BranchSection } from "../../../packages/ui/src/branched";
import type { CoreScreen } from "./core-screen";
import { previewLine } from "./canvas";
import {
  CELL, COLUMN_GAP, CONTAINERS, INITIAL_GRANTS, MARGIN, boxOf, buildViews, contentSize, metricsFor, reach, resolve, shellLines, snapToGrid,
  type Box, type ColumnModel, type Grant, type Metrics, type NodeModel, type Role, type ViewId, type ViewModel, type WindowModel,
} from "./clusters-model";
import { Arrow, DragArrow, anchors, type Pt, type Rect } from "./clusters-arrows";
import { dropletSplit } from "./clusters-split";
import { mountStepper, type Stepper } from "./clusters-stepper";

const reduced = matchMedia("(prefers-reduced-motion: reduce)");
const coarse = matchMedia("(pointer: coarse)");
const clamp = (v: number, lo: number, hi: number): number => Math.max(lo, Math.min(hi, v));

const el = <K extends keyof HTMLElementTagNameMap>(tag: K, cls = "", text?: string): HTMLElementTagNameMap[K] => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
};
const SVG_NS = "http://www.w3.org/2000/svg";

const ICON = {
  close: '<path d="m7 7 10 10M17 7 7 17"/>',
  split: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M4 12h16"/>',
  terminal: '<path d="m5 8 4 4-4 4M12 16h7"/>',
  containers: '<path d="M12 3 4 7v10l8 4 8-4V7z"/><path d="m4 7 8 4 8-4M12 11v10"/>',
  logs: '<path d="M5 6h14M5 10h10M5 14h14M5 18h8"/>',
  node: '<circle cx="12" cy="12" r="2.6"/><circle cx="5.5" cy="6" r="1.8"/><circle cx="18.5" cy="7" r="1.8"/><circle cx="17.5" cy="18" r="1.8"/><path d="m10 10.4-3-3M14.4 11l2.6-2.7M13.8 13.9l2.6 2.8"/>',
  tag: '<path d="M4 4h7l9 9-7 7-9-9z"/><circle cx="8" cy="8" r="1.2"/>',
  console: '<rect x="3" y="4" width="18" height="16" rx="3"/><path d="m7 10 3 2-3 2M13 14h4"/>',
  chevron: '<path d="m9 6 6 6-6 6"/>',
  port: '<path d="M6 12h10m-4-4 4 4-4 4"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
} as const;
const lineIcon = (path: string): string => `<svg viewBox="0 0 24 24" class="is-line" aria-hidden="true">${path}</svg>`;
const VIEW_ICON: Record<ViewId, string> = { console: ICON.console, containers: ICON.containers, topology: ICON.node };

interface Cam { cx: number; cy: number; z: number }

interface WinRec {
  model: WindowModel;
  card: WindowCard;
  cluster: ClusterRec;
  /** Header connector (terminals only): drag from it to another terminal to grant access. */
  port?: HTMLButtonElement;
  stopResize?: () => void;
  stream?: HTMLElement;
}

interface TopoArrow { grant: Grant; arrow: Arrow; label?: SVGTextElement }

interface ClusterRec {
  view: ViewModel;
  el: HTMLElement;
  region: HTMLElement;
  label: HTMLButtonElement;
  labelMeta: HTMLElement;
  content: HTMLElement;
  colsEl: HTMLElement;
  lift: HTMLElement;
  wins: Map<string, WinRec>;
  sx: Spring;
  sy: Spring;
  x: number;
  y: number;
  empty?: HTMLElement;
  graphSvg?: SVGSVGElement;
  topo: TopoArrow[];
}

export interface ClustersOptions {
  scene?: number;
  role?: Role;
}

export interface ClustersController {
  dispose(): void;
}

interface Fixture { hosts?: Array<{ name: string; user: string; os: HostPlatform; sessions: Array<{ screen: string[] }> }> }

/** Mounts the clusters mockup into the core screen's pane area. */
export async function mountClusters(core: CoreScreen, options: ClustersOptions = {}): Promise<ClustersController> {
  const stage = core.stage;
  stage.dataset.canvas = "on";
  stage.dataset.clusters = "";
  core.panes.querySelector(".pane-card")?.remove();
  const viewport = el("div", "cl-viewport");
  viewport.setAttribute("aria-label", "Canvas of views");
  const world = el("div", "cl-world");
  const overlay = document.createElementNS(SVG_NS, "svg");
  overlay.setAttribute("class", "cl-overlay");
  overlay.setAttribute("aria-hidden", "true");
  world.append(overlay);
  world.dataset.lod = "live";
  world.dataset.zoom = "in";
  const edges = el("div", "cl-edges");
  const summary = el("div", "cl-summary ui-overlay-surface");
  summary.hidden = true;
  viewport.append(world, edges);
  core.panes.append(viewport);
  document.body.append(summary);
  const events = new AbortController();
  const signal = events.signal;

  // ---- test double data -------------------------------------------------------------------------
  const screens = new Map<string, { os: HostPlatform; user: string; screen: string[] }>();
  try {
    const data = await fetch("/__mock/proto/windows", { credentials: "same-origin" }).then((r) => (r.ok ? (r.json() as Promise<Fixture>) : undefined));
    for (const h of data?.hosts ?? []) screens.set(h.name, { os: h.os, user: h.user, screen: h.sessions[0]?.screen ?? [] });
  } catch { /* the mock fixture is optional: windows then show an empty prompt */ }

  // ---- state ------------------------------------------------------------------------------------
  let metrics: Metrics = metricsFor(viewport.clientWidth || innerWidth, coarse.matches);
  let role: Role = options.role ?? "operator";
  let sceneIndex = 0;
  let omit: string[] = [];
  let grants: Grant[] = INITIAL_GRANTS.map((g) => ({ ...g }));
  const clusters = new Map<ViewId, ClusterRec>();
  let activeWin: WinRec | undefined;
  let currentView: ViewId = "console";
  let serial = 0;
  const toast: ToastController = mountToast(stage);
  const cam: Cam = { cx: 0, cy: 0, z: 1 };
  let tx = 0, ty = 0, vw = 0, vh = 0;
  let camTarget: (() => Cam) | undefined;
  let lod: "live" | "thumb" = "live";
  let zoomBand: "in" | "out" = "in";

  // ---- camera -----------------------------------------------------------------------------------
  const FLIGHT = { visualDuration: 0.8, bounce: 0 };
  let restTimer = 0;
  const dpr = (): number => devicePixelRatio || 1;
  const snapPx = (v: number): number => Math.round(v * dpr()) / dpr();
  let camMoving = false;
  const applyCam = (atRest = false): void => {
    vw = viewport.clientWidth; vh = viewport.clientHeight;
    tx = vw / 2 - cam.cx * cam.z;
    ty = vh / 2 - cam.cy * cam.z;
    // At rest the translation lands on whole device pixels, so text is as crisp as it can be.
    if (atRest) { tx = snapPx(tx); ty = snapPx(ty); }
    world.style.transform = `translate3d(${tx}px, ${ty}px, 0) scale(${cam.z})`;
    world.style.setProperty("--z", String(cam.z));
    world.style.setProperty("--inv", String(clamp(1 / cam.z, 1, 3.2)));
    const nextLod = lod === "live" ? (cam.z < 0.58 ? "thumb" : "live") : (cam.z > 0.62 ? "live" : "thumb");
    if (nextLod !== lod) { lod = nextLod; world.dataset.lod = lod; paintCapsule(); }
    const nextBand = zoomBand === "in" ? (cam.z < 0.76 ? "out" : "in") : (cam.z > 0.82 ? "in" : "out");
    if (nextBand !== zoomBand) { zoomBand = nextBand; world.dataset.zoom = zoomBand; hideSummary(); }
    if (!atRest) {
      if (!camMoving) { camMoving = true; world.style.willChange = "transform"; }
      window.clearTimeout(restTimer);
      restTimer = window.setTimeout(restCam, 140);
    }
    invalidate();
  };
  const restCam = (): void => {
    window.clearTimeout(restTimer);
    camMoving = false;
    world.style.willChange = "";
    applyCam(true);
    redrawTopology();
    updateCurrentView();
  };
  const stopCam = (): void => {
    springCx.set(cam.cx, true); springCy.set(cam.cy, true); springLz.set(Math.log(cam.z), true);
  };
  const setCam = (next: Cam): void => {
    cam.cx = next.cx; cam.cy = next.cy; cam.z = next.z;
    springCx.value = next.cx; springCy.value = next.cy; springLz.value = Math.log(next.z);
    stopCam();
    applyCam();
    restCam();
  };
  /** Flies the camera (interruptible: a new target keeps the current velocity). */
  const flyTo = (target: () => Cam, instant = false): void => {
    camTarget = target;
    hideSummary();
    const t = target();
    if (instant) { setCam(t); return; }
    if (reduced.matches) {
      world.animate([{ opacity: 1 }, { opacity: 0.15 }, { opacity: 1 }], { duration: 240, easing: "ease-out" });
      setCam(t);
      return;
    }
    springCx.value = cam.cx; springCy.value = cam.cy; springLz.value = Math.log(cam.z);
    springCx.set(t.cx); springCy.set(t.cy); springLz.set(Math.log(t.z));
  };
  const toWorld = (clientX: number, clientY: number): Pt => {
    const r = viewport.getBoundingClientRect();
    return { x: (clientX - r.left - tx) / cam.z, y: (clientY - r.top - ty) / cam.z };
  };
  const toClient = (p: Pt): Pt => {
    const r = viewport.getBoundingClientRect();
    return { x: r.left + tx + p.x * cam.z, y: r.top + ty + p.y * cam.z };
  };
  const worldRect = (node: Element): Rect => {
    const r = node.getBoundingClientRect();
    const a = toWorld(r.left, r.top);
    return { x: a.x, y: a.y, w: r.width / cam.z, h: r.height / cam.z };
  };

  // ---- geometry of a view -----------------------------------------------------------------------
  const contentRect = (c: ClusterRec): Rect => ({ x: c.x + MARGIN.l, y: c.y + MARGIN.t, ...contentSize(c.view, metrics) });
  /** Committed positions only: animated positions (c.x, c.y) are on their way and must never feed a layout. */
  const boxes = (): Box[] => [...clusters.values()].map((c) => boxOf(c.view, metrics));
  const frameOf = (c: ClusterRec): Rect => {
    const r = contentRect(c);
    return { x: r.x - 16, y: r.y - 16, w: r.w + 32, h: r.h + 32 };
  };
  const bounds = (list: Rect[]): Rect => {
    const x0 = Math.min(...list.map((r) => r.x)), y0 = Math.min(...list.map((r) => r.y));
    const x1 = Math.max(...list.map((r) => r.x + r.w)), y1 = Math.max(...list.map((r) => r.y + r.h));
    return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
  };
  const fitRect = (r: Rect, pad = 0.9, maxZ = 1): Cam => {
    const z = clamp(Math.min((vw * pad) / r.w, (vh * pad) / r.h), 0.05, maxZ);
    return { cx: r.x + r.w / 2, cy: r.y + r.h / 2, z };
  };
  const overviewCam = (): Cam => fitRect(bounds([...clusters.values()].map(frameOf)).w ? bounds([...clusters.values()].map((c) => { const f = frameOf(c); return { x: f.x, y: f.y - 70, w: f.w, h: f.h + 70 }; })) : { x: 0, y: 0, w: 1, h: 1 }, 0.92, 1);
  const viewCam = (id: ViewId): Cam => {
    const c = clusters.get(id);
    if (!c) return overviewCam();
    const r = contentRect(c);
    if (metrics.narrow) {
      // A phone shows one column and the edge of the next; the camera starts at the first column.
      const z = Math.min(1, (vw - 40) / Math.max(1, c.view.cols[0]?.w ?? r.w));
      return { cx: r.x - 20 / z + vw / (2 * z), cy: r.y - 12 / z + vh / (2 * z), z };
    }
    return fitRect({ x: r.x, y: r.y - 40, w: r.w, h: r.h + 40 }, 0.94, 1);
  };
  const windowCam = (rec: WinRec): Cam => {
    const r = worldRect(rec.card.root);
    const z = clamp(Math.min((vw * 0.88) / r.w, (vh * 0.9) / r.h), 0.62, 1);
    return { cx: r.x + r.w / 2, cy: r.y + r.h / 2, z };
  };

  const updateCurrentView = (): void => {
    let best: ClusterRec | undefined, bestD = Infinity;
    for (const c of clusters.values()) {
      const f = frameOf(c);
      const d = Math.hypot(f.x + f.w / 2 - cam.cx, f.y + f.h / 2 - cam.cy);
      if (d < bestD) { best = c; bestD = d; }
    }
    if (best && best.view.id !== currentView) { currentView = best.view.id; paintCapsule(); }
  };
  const paintCapsule = (): void => {
    const c = clusters.get(currentView);
    const host = stage.querySelector<HTMLElement>("#capsule-host");
    // Zoomed all the way out no single view is current.
    if (host) host.textContent = lod === "thumb" ? "All views" : (c?.view.name ?? "");
    stage.querySelector<HTMLElement>("#capsule")?.setAttribute("data-flow", "");
  };

  // ---- overlay: arrows on demand, trails and edge markers --------------------------------------------
  let frameQueued = 0;
  const invalidate = (): void => {
    if (frameQueued) return;
    frameQueued = requestAnimationFrame(() => { frameQueued = 0; updateOverlay(); });
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
        const ex = clamp(sc.x, vp.left + inset, vp.right - inset), ey = clamp(sc.y, vp.top + inset, vp.bottom - inset);
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
    const topo = clusters.get("topology");
    for (const r of reach(rec.model.host, grants)) {
      const target = clusters.get("console")?.wins.get(`w-${r.host}`)?.card.root;
      if (!target) continue;
      const arrow = new Arrow({ ...(r.via ? { dashed: true } : {}), tone: "quiet" });
      items.push({ arrow, host: r.host, ...(r.via ? { via: r.via } : {}), target });
    }
    const node = topo?.wins.get(`n-${rec.model.host}`)?.card.root;
    if (node && topo) {
      const arrow = new Arrow({ tone: "quiet" });
      const marker = el("button", "cl-edge ui-pill");
      marker.type = "button";
      marker.innerHTML = `<span class="cl-edge-arrow"><svg viewBox="0 0 24 24" aria-hidden="true">${ICON.chevron}</svg></span><span>Topology</span>`;
      marker.setAttribute("aria-label", `${rec.model.host} in Topology`);
      marker.addEventListener("click", () => { hideReach(true); flyView("topology"); });
      edges.append(marker);
      items.push({ arrow, host: rec.model.host, target: node, marker, node: true });
    }
    reachItems = items;
    items.forEach((item, i) => { item.arrow.g.style.setProperty("--i", String(i)); reachLayer.append(item.arrow.g); });
    reachLayer.dataset.open = "false";
    updateOverlay();
    requestAnimationFrame(() => { reachLayer.dataset.open = "true"; });
  };

  // ---- FLIP helper: reflows animate on one spring each -------------------------------------------
  const flips = new WeakMap<HTMLElement, Spring>();
  const flipMeasure = (nodes: Iterable<HTMLElement>): Map<HTMLElement, DOMRect> => {
    const out = new Map<HTMLElement, DOMRect>();
    for (const n of nodes) {
      out.set(n, n.getBoundingClientRect());
      flips.get(n)?.set(0, true);
    }
    return out;
  };
  const flipPlay = (first: Map<HTMLElement, DOMRect>, scale = false, cfg = { visualDuration: 0.5, bounce: 0.22 }): void => {
    if (reduced.matches) return;
    for (const [n, a] of first) {
      if (!n.isConnected) continue;
      const b = n.getBoundingClientRect();
      const dx = (a.left - b.left) / cam.z, dy = (a.top - b.top) / cam.z;
      const sw = scale && b.width ? a.width / b.width : 1, sh = scale && b.height ? a.height / b.height : 1;
      if (Math.abs(dx) < 0.5 && Math.abs(dy) < 0.5 && Math.abs(sw - 1) < 0.01 && Math.abs(sh - 1) < 0.01) continue;
      n.style.transformOrigin = "0 0";
      const spring = new Spring(1, (p) => {
        if (p === 0) { n.style.transform = ""; n.style.transformOrigin = ""; invalidate(); return; }
        n.style.transform = `translate(${dx * p}px, ${dy * p}px)${scale ? ` scale(${1 + (sw - 1) * p}, ${1 + (sh - 1) * p})` : ""}`;
        invalidate();
      }, cfg);
      flips.set(n, spring);
      spring.set(0);
    }
  };
  const flipTargets = (c: ClusterRec): HTMLElement[] => [...c.colsEl.querySelectorAll<HTMLElement>(".ui-window, .cl-slot, .cl-col")];

  // ---- building the world ------------------------------------------------------------------------------
  const iconFor = (m: WindowModel): string =>
    m.kind === "terminal" ? (m.os ? hostIconMarkup(m.os, "ui-host-mark") : lineIcon(ICON.terminal))
      : m.kind === "containers" ? lineIcon(ICON.containers) : m.kind === "logs" ? lineIcon(ICON.logs) : lineIcon(ICON.node);

  const makeBody = (rec: WinRec): void => {
    const m = rec.model;
    const body = rec.card.body;
    body.replaceChildren();
    if (m.kind === "terminal") {
      const pre = el("pre", "canvas-preview cl-preview");
      const lines = m.lines ?? [];
      pre.innerHTML = `${lines.map(previewLine).join("\n")}<span class="cl-cursor" aria-hidden="true"></span>`;
      body.append(pre);
    } else if (m.kind === "logs") {
      const pre = el("pre", "canvas-preview cl-preview cl-logs");
      const paint = (): void => {
        pre.innerHTML = (m.lines ?? []).map((l) => {
          const [time, src, ...msg] = l.split("  ");
          return `<span class="cl-log-time">${time}</span>  <span class="cl-log-src">${src}</span>  ${msg.join("  ")}`;
        }).join("\n");
        pre.scrollTop = pre.scrollHeight;
      };
      paint();
      rec.stream = pre;
      body.append(pre);
    } else if (m.kind === "containers") {
      const list = el("div", "cl-list");
      list.setAttribute("role", "list");
      for (const row of CONTAINERS) {
        const b = el("button", "cl-row");
        b.type = "button";
        b.dataset.name = row.name;
        b.dataset.state = row.state;
        b.setAttribute("role", "listitem");
        b.setAttribute("aria-label", `${row.name}, ${row.state}. Open a shell`);
        b.innerHTML = `<span class="cl-state" aria-hidden="true"></span><span class="cl-name"></span><span class="cl-image"></span><span class="cl-cpu"></span>`;
        (b.querySelector(".cl-name") as HTMLElement).textContent = row.name;
        (b.querySelector(".cl-image") as HTMLElement).textContent = row.image;
        (b.querySelector(".cl-cpu") as HTMLElement).textContent = row.cpu;
        b.addEventListener("click", () => openSession("build-01", row.name), { signal });
        list.append(b);
      }
      body.append(list);
    }
  };

  const makeWindow = (c: ClusterRec, m: WindowModel): WinRec => {
    const actions: WindowAction[] = [];
    const rec: WinRec = {} as WinRec;
    // The window's kind decides what it can do: only a terminal has a split control.
    if (m.kind === "terminal") actions.push({ id: "split", label: "Split", icon: ICON.split, onSelect: () => { void splitWindow(rec); } });
    if (m.kind !== "node") actions.push({ id: "close", label: "Close", icon: ICON.close, onSelect: () => closeWindow(rec) });
    const title = { host: m.host, ...(m.user ? { user: m.user } : {}), ...(m.session ? { session: m.session } : {}) };
    const card = createWindowCard({ id: m.id, title, icon: iconFor(m), status: m.kind === "terminal" ? "live" : "none", actions, label: `${m.host} ${m.session ?? m.kind}` });
    Object.assign(rec, { model: m, card, cluster: c });
    card.root.dataset.kind = m.kind;
    if (m.h) { card.root.style.height = `${m.h}px`; card.root.style.flex = "none"; }
    makeBody(rec);
    wireWindow(rec);
    return rec;
  };

  const makeNode = (c: ClusterRec, n: NodeModel): WinRec => {
    const m: WindowModel = { id: `n-${n.id}`, kind: "node", host: n.label };
    const card = createWindowCard({ id: m.id, title: { host: n.label }, icon: n.kind === "tag" ? lineIcon(ICON.tag) : hostIconMarkup(n.os ?? "unknown", "ui-host-mark"), status: "none", label: `${n.label} node` });
    const rec: WinRec = { model: m, card, cluster: c };
    card.root.dataset.kind = "node";
    card.root.style.cssText = `position:absolute;left:0;top:0;width:${metrics.nodeW}px;height:${metrics.nodeH}px;transform:translate(${n.x}px,${n.y}px)`;
    const meta = el("div", "cl-node-meta");
    meta.innerHTML = `<span class="cl-node-detail"></span><span class="cl-node-sub"></span>`;
    (meta.children[0] as HTMLElement).textContent = n.detail;
    (meta.children[1] as HTMLElement).textContent = n.sub;
    card.body.append(meta);
    wireNode(rec, n);
    return rec;
  };

  const newCol = (c: ClusterRec, col: ColumnModel): HTMLElement => {
    const colEl = el("div", "cl-col");
    colEl.dataset.id = col.id;
    colEl.dataset.w = String(col.w);
    colEl.style.setProperty("--w", `${col.w}px`);
    return colEl;
  };

  const buildCluster = (view: ViewModel): ClusterRec => {
    const root = el("section", "cl");
    root.dataset.view = view.id;
    const region = el("div", "cl-region");
    const label = el("button", "cl-label ui-pill");
    label.type = "button";
    label.innerHTML = `<span class="cl-label-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${VIEW_ICON[view.id]}</svg></span><span class="cl-label-name"></span><span class="cl-label-meta"></span>`;
    (label.querySelector(".cl-label-name") as HTMLElement).textContent = view.name;
    const content = el("div", "cl-content");
    const colsEl = el("div", "cl-cols");
    const lift = el("div", "cl-lift");
    content.append(colsEl, lift);
    root.append(region, label, content);
    const c: ClusterRec = {
      view, el: root, region, label, labelMeta: label.querySelector(".cl-label-meta") as HTMLElement, content, colsEl, lift,
      wins: new Map(), x: view.x, y: view.y, topo: [],
      sx: undefined as unknown as Spring, sy: undefined as unknown as Spring,
    };
    const place = (): void => { root.style.transform = `translate(${c.x}px, ${c.y}px)`; invalidate(); };
    const POS = { visualDuration: 0.5, bounce: 0.2 };
    c.sx = new Spring(view.x, (v) => { c.x = v; place(); }, POS);
    c.sy = new Spring(view.y, (v) => { c.y = v; place(); }, POS);
    if (view.layout === "tiled") {
      for (const col of view.cols) {
        const colEl = newCol(c, col);
        for (const m of col.wins) {
          const rec = makeWindow(c, m);
          c.wins.set(m.id, rec);
          colEl.append(rec.card.root);
        }
        colsEl.append(colEl);
      }
    } else {
      colsEl.classList.add("cl-graph");
      const svg = document.createElementNS(SVG_NS, "svg");
      svg.setAttribute("class", "cl-graph-arrows");
      colsEl.append(svg);
      c.graphSvg = svg;
      for (const n of view.nodes) {
        const rec = makeNode(c, n);
        c.wins.set(rec.model.id, rec);
        colsEl.append(rec.card.root);
      }
      for (const g of grants) addTopoArrow(c, g, false);
    }
    wireCluster(c);
    geometry(c);
    paintEmpty(c);
    world.insertBefore(root, overlay);
    place();
    return c;
  };

  /** Writes a view's size from its content and keeps its label and region in step. */
  const geometry = (c: ClusterRec): void => {
    // Columns are the truth: read their widths back from the DOM so drags and resizes persist.
    if (c.view.layout === "tiled") {
      c.view.cols = [...c.colsEl.querySelectorAll<HTMLElement>(":scope > .cl-col")].map((colEl) => ({
        id: colEl.dataset.id ?? `c${++serial}`,
        w: Number(colEl.dataset.w) || metrics.colW,
        wins: [...colEl.querySelectorAll<HTMLElement>(":scope > .ui-window")].map((n) => c.wins.get(n.dataset.windowId ?? "")?.model).filter((m): m is WindowModel => !!m),
      })).filter((col) => col.wins.length > 0 || c.colsEl.querySelector(".cl-slot"));
    }
    const size = contentSize(c.view, metrics);
    const box = boxOf(c.view, metrics);
    c.el.style.width = `${box.w}px`;
    c.el.style.height = `${box.h}px`;
    c.content.style.cssText = `left:${MARGIN.l}px;top:${MARGIN.t}px;width:${size.w}px;height:${size.h}px`;
    c.region.style.cssText = `left:${MARGIN.l - 16}px;top:${MARGIN.t - 16}px;width:${size.w + 32}px;height:${size.h + 32}px`;
    c.label.style.left = `${MARGIN.l - 16}px`;
    c.label.style.top = `${MARGIN.t - 16}px`;
    const count = c.view.layout === "graph" ? `${c.view.nodes.length} nodes · ${grants.length} grants` : `${c.wins.size} window${c.wins.size === 1 ? "" : "s"}`;
    c.labelMeta.textContent = c.wins.size || c.view.layout === "graph" ? `· ${count}` : "· empty";
    c.label.setAttribute("aria-label", `${c.view.name}, ${count}. Fly to this view`);
  };

  /** After a view changed size: push neighbours aside (never the changed one). */
  const settle = (fixedId: ViewId, at?: { x: number; y: number }): void => {
    const trial = boxes().map((b) => (at && b.id === fixedId ? { ...b, x: at.x, y: at.y } : b));
    const next = resolve(trial, fixedId);
    for (const c of clusters.values()) {
      const p = next.get(c.view.id);
      if (!p || (p.x === c.view.x && p.y === c.view.y)) continue;
      c.view.x = p.x; c.view.y = p.y;
      c.sx.set(p.x); c.sy.set(p.y);
    }
  };

  const paintEmpty = (c: ClusterRec): void => {
    const isEmpty = c.view.layout === "tiled" && c.wins.size === 0;
    if (!isEmpty) { c.empty?.remove(); delete c.empty; return; }
    if (c.empty) return;
    const box = el("div", "cl-empty");
    box.innerHTML = `<div class="cl-empty-slot" aria-hidden="true"></div><p class="cl-empty-title">No hosts yet</p><p class="cl-empty-hint">Add a host and its shell opens here.</p>`;
    const add = el("button", "ui-pill cl-empty-add");
    add.type = "button";
    add.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${ICON.plus}</svg><span>Add host</span>`;
    add.addEventListener("click", () => toast.show({ message: "Add host is its own mockup (proto=addhost)." }), { signal });
    box.append(add);
    c.content.append(box);
    c.empty = box;
  };

  // ---- topology arrows -----------------------------------------------------------------------------------
  const nodeRect = (c: ClusterRec, id: string): Rect | undefined => {
    const n = c.view.nodes.find((v) => v.id === id);
    return n ? { x: n.x, y: n.y, w: metrics.nodeW, h: metrics.nodeH } : undefined;
  };
  const addTopoArrow = (c: ClusterRec, g: Grant, animate: boolean): void => {
    if (!c.graphSvg) return;
    const arrow = new Arrow({ ...(g.via ? { dashed: true } : {}), tone: "accent" });
    arrow.g.dataset.grant = g.id;
    const entry: TopoArrow = { grant: g, arrow };
    if (g.via) {
      const t = document.createElementNS(SVG_NS, "text");
      t.setAttribute("class", "cl-arrow-label");
      t.textContent = `via ${g.via}`;
      entry.label = t;
      arrow.g.append(t);
    }
    c.graphSvg.append(arrow.g);
    c.topo.push(entry);
    drawTopoArrow(c, entry);
    if (animate) {
      arrow.g.dataset.fresh = "";
      requestAnimationFrame(() => requestAnimationFrame(() => arrow.g.removeAttribute("data-fresh")));
      const pulse = new Spring(1.9, (v) => arrow.setPulse(v), { visualDuration: 0.4, bounce: 0.45 });
      pulse.set(1);
    }
  };
  const drawTopoArrow = (c: ClusterRec, e: TopoArrow): void => {
    const a = nodeRect(c, e.grant.from), b = nodeRect(c, e.grant.to);
    if (!a || !b) return;
    // Arrows that end on the same card fan out along its edge instead of piling onto one point.
    const sharing = c.topo.filter((o) => o.grant.to === e.grant.to);
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
  const redrawTopology = (): void => {
    const c = clusters.get("topology");
    if (!c || Math.abs(cam.z - lastTopoZ) / cam.z < 0.04) return;
    lastTopoZ = cam.z;
    for (const e of c.topo) drawTopoArrow(c, e);
  };

  // ---- wiring: cluster ---------------------------------------------------------------------------------------
  let summaryTimer = 0, summaryFor: ViewId | undefined;
  const hideSummary = (): void => {
    window.clearTimeout(summaryTimer);
    if (summary.hidden) return;
    summary.dataset.open = "false";
    summaryFor = undefined;
    window.setTimeout(() => { if (summary.dataset.open === "false") summary.hidden = true; }, 170);
  };
  const showSummary = (c: ClusterRec): void => {
    if (zoomBand !== "out" || !matchMedia("(hover: hover) and (pointer: fine)").matches || drag || clusterDrag) return;
    window.clearTimeout(summaryTimer);
    if (summaryFor === c.view.id && !summary.hidden) return;
    summaryFor = c.view.id;
    const rows = c.view.layout === "graph"
      ? [["Nodes", String(c.view.nodes.length)], ["Grants", String(grants.length)], ["Via relay", String(grants.filter((g) => g.via).length)]]
      : [...c.wins.values()].map((w) => [w.model.kind === "terminal" ? w.model.host : (w.model.session ?? w.model.kind), w.model.kind === "terminal" ? "shell" : w.model.kind]);
    summary.innerHTML = `<div class="cl-summary-head"><span class="cl-summary-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${VIEW_ICON[c.view.id]}</svg></span><span class="cl-summary-name"></span></div><div class="cl-summary-rows"></div>`;
    (summary.querySelector(".cl-summary-name") as HTMLElement).textContent = c.view.name;
    const list = summary.querySelector(".cl-summary-rows") as HTMLElement;
    if (!rows.length) rows.push(["No windows", ""]);
    for (const [k, v] of rows) {
      const row = el("div", "cl-summary-row");
      row.append(el("span", "cl-summary-k", k), el("span", "cl-summary-v", v));
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

  let clusterDrag: { c: ClusterRec; id: number; x0: number; y0: number; fx: number; fy: number; moved: boolean; snapX: number; snapY: number } | undefined;
  const ghost = el("div", "cl-ghost");
  let ghostX: Spring, ghostY: Spring;
  const paintGhost = (): void => { if (ghostX && ghostY) ghost.style.transform = `translate(${ghostX.value}px, ${ghostY.value}px)`; };
  ghostX = new Spring(0, () => paintGhost(), { visualDuration: 0.3, bounce: 0.12 });
  ghostY = new Spring(0, () => paintGhost(), { visualDuration: 0.3, bounce: 0.12 });
  world.append(ghost);

  const flyView = (id: ViewId, instant = false): void => {
    const c = clusters.get(id);
    if (!c) return;
    currentView = id;
    paintCapsule();
    flyTo(() => viewCam(id), instant);
  };

  const wireCluster = (c: ClusterRec): void => {
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
        hideSummary();
        stopCam();
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
        for (const other of clusters.values()) {
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
      delete c.el.dataset.lifted;
      delete ghost.dataset.on;
      if (!d.moved) { flyView(c.view.id); return; }
      // Commit: the dragged view lands on the grid and the others settle where it pushed them.
      c.sx.set(d.snapX); c.sy.set(d.snapY);
      c.view.x = d.snapX; c.view.y = d.snapY;
      settle(c.view.id);
    };
    c.label.addEventListener("pointerup", end, { signal });
    c.label.addEventListener("pointercancel", end, { signal });
  };

  // ---- wiring: windows -------------------------------------------------------------------------------------
  const setActive = (rec: WinRec | undefined): void => {
    if (activeWin === rec) return;
    activeWin?.card.setActive(false);
    activeWin = rec;
    rec?.card.setActive(true);
    renderTree();
  };

  const wireWindow = (rec: WinRec): void => {
    const root = rec.card.root;
    const pill = rec.card.pill;
    root.addEventListener("pointerdown", () => setActive(rec), { signal, capture: true });
    // The pill moves the window; it never opens anything in this mockup (the details popover is a separate mockup).
    pill.addEventListener("click", (e) => e.preventDefault(), { signal });
    pill.style.touchAction = "none";
    pill.dataset.grab = "";
    let press: { id: number; x: number; y: number; timer: number; touch: boolean } | undefined;
    pill.addEventListener("pointerdown", (e) => {
      if (e.button !== 0 || lod === "thumb") return;
      const touch = e.pointerType !== "mouse";
      press = { id: e.pointerId, x: e.clientX, y: e.clientY, touch, timer: 0 };
      if (touch && rec.model.kind === "terminal") {
        press.timer = window.setTimeout(() => { if (press) { showReach(rec, true); press = undefined; } }, 450);
      }
      pill.setPointerCapture(e.pointerId);
    }, { signal });
    pill.addEventListener("pointermove", (e) => {
      if (!press || e.pointerId !== press.id) return;
      if (Math.hypot(e.clientX - press.x, e.clientY - press.y) < 6) return;
      window.clearTimeout(press.timer);
      const start = press;
      press = undefined;
      beginMove(rec, e, start);
    }, { signal });
    const release = (e: PointerEvent): void => {
      if (press && e.pointerId === press.id) { window.clearTimeout(press.timer); press = undefined; }
    };
    pill.addEventListener("pointerup", release, { signal });
    pill.addEventListener("pointercancel", release, { signal });
    if (rec.model.kind !== "terminal") return;

    // Arrows on demand: hovering the pill (long-press on touch) shows where this window's host can reach.
    let hoverTimer = 0, leaveTimer = 0;
    const enter = (e: PointerEvent): void => {
      if (e.pointerType !== "mouse" || lod === "thumb") return;
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
    if (rec.model.kind === "terminal" && !rec.model.id.includes("-s")) {
      // Resizing is shared with the product canvas (window-resize.ts); here it sets the column width and the window height.
      rec.stopResize = attachWindowResize(rec.card, resizeHost(rec)).dispose;
    }
  };

  const resizeHost = (rec: WinRec): WindowResizeHost => ({
    begin(): ResizeStart {
      const colEl = rec.card.root.parentElement as HTMLElement;
      return { width: colEl.offsetWidth * cam.z - 28 * cam.z, height: rec.card.root.offsetHeight * cam.z, top: 0, minWidth: 300 * cam.z, minHeight: 160 * cam.z, maxWidth: 900 * cam.z, areaHeight: 4000 };
    },
    apply(f: ResizeFrame): void {
      const colEl = rec.card.root.parentElement as HTMLElement;
      const w = Math.round(f.width / cam.z);
      colEl.dataset.w = String(w);
      colEl.style.setProperty("--w", `${w}px`);
      rec.card.root.style.height = `${Math.round(f.height / cam.z)}px`;
      rec.card.root.style.flex = "none";
      geometry(rec.cluster);
      invalidate();
    },
    end(): void { settle(rec.cluster.view.id); },
  });

  const wireNode = (rec: WinRec, n: NodeModel): void => {
    const pill = rec.card.pill;
    pill.style.touchAction = "none";
    pill.dataset.grab = "";
    let d: { id: number; x: number; y: number; nx: number; ny: number } | undefined;
    pill.addEventListener("pointerdown", (e) => {
      if (lod === "thumb") return;
      pill.setPointerCapture(e.pointerId);
      d = { id: e.pointerId, x: e.clientX, y: e.clientY, nx: n.x, ny: n.y };
      rec.card.root.dataset.lifted = "";
    }, { signal });
    pill.addEventListener("pointermove", (e) => {
      if (!d || e.pointerId !== d.id) return;
      const size = contentSize(rec.cluster.view, metrics);
      n.x = clamp(d.nx + (e.clientX - d.x) / cam.z, 0, size.w - metrics.nodeW);
      n.y = clamp(d.ny + (e.clientY - d.y) / cam.z, 0, size.h - metrics.nodeH);
      rec.card.root.style.transform = `translate(${n.x}px, ${n.y}px)`;
      // Arrows stay attached to the card they belong to while it moves.
      for (const t of rec.cluster.topo) if (t.grant.from === n.id || t.grant.to === n.id) drawTopoArrow(rec.cluster, t);
    }, { signal });
    const up = (e: PointerEvent): void => {
      if (!d || e.pointerId !== d.id) return;
      d = undefined;
      delete rec.card.root.dataset.lifted;
    };
    pill.addEventListener("pointerup", up, { signal });
    pill.addEventListener("pointercancel", up, { signal });
  };

  // ---- structure: moving a window by its pill ----------------------------------------------------------------
  const beginMove = (rec: WinRec, first: PointerEvent, start: { x: number; y: number }): void => {
    const c = rec.cluster;
    if (c.view.layout !== "tiled") return;
    hideReach(true);
    const root = rec.card.root;
    const rect0 = root.getBoundingClientRect();
    const contentBox = c.content.getBoundingClientRect();
    const slot = el("div", "cl-slot");
    slot.style.height = `${rect0.height / cam.z}px`;
    slot.style.flex = "none";
    const colEl = root.parentElement as HTMLElement;
    colEl.insertBefore(slot, root);
    const fixedH = root.style.height;
    root.classList.add("is-lifted");
    root.style.cssText = `position:absolute;left:${(rect0.left - contentBox.left) / cam.z}px;top:${(rect0.top - contentBox.top) / cam.z}px;width:${rect0.width / cam.z}px;height:${rect0.height / cam.z}px;margin:0`;
    c.lift.append(root);
    let dx = 0, dy = 0;
    const applyMoveTransform = (): void => { root.style.transform = `translate(${dx}px, ${dy}px) scale(${root.style.getPropertyValue("--lift") || 1})`; invalidate(); };
    const lift = new Spring(1, (s) => { root.style.setProperty("--lift", String(s)); applyMoveTransform(); }, { visualDuration: 0.3, bounce: 0.3 });
    lift.set(1.025);
    const target = { col: colEl as HTMLElement | undefined, index: 0, fresh: false };
    const place = (clientX: number, clientY: number): void => {
      const cols = [...c.colsEl.querySelectorAll<HTMLElement>(":scope > .cl-col")];
      const rects = cols.map((x) => x.getBoundingClientRect());
      let nextCol: HTMLElement | undefined, fresh = false;
      if (rects.length && clientX < rects[0]!.left - 20 * cam.z) fresh = true;
      else if (rects.length && clientX > rects[rects.length - 1]!.right + 20 * cam.z) fresh = true;
      if (!fresh) {
        let best = Infinity;
        cols.forEach((x, i) => { const r = rects[i]!; const d = clientX < r.left ? r.left - clientX : clientX > r.right ? clientX - r.right : 0; if (d < best) { best = d; nextCol = x; } });
      }
      const before = flipMeasure(flipTargets(c));
      let slotCol: HTMLElement;
      if (fresh || !nextCol) {
        const atStart = rects.length > 0 && clientX < rects[0]!.left;
        slotCol = newCol(c, { id: `c${++serial}`, w: Number((colEl as HTMLElement).dataset.w) || metrics.colW, wins: [] });
        if (atStart) c.colsEl.prepend(slotCol); else c.colsEl.append(slotCol);
        slotCol.append(slot);
      } else {
        slotCol = nextCol;
        const wins = [...slotCol.querySelectorAll<HTMLElement>(":scope > .ui-window")].filter((w) => w !== root);
        const index = wins.filter((w) => { const r = w.getBoundingClientRect(); return r.top + r.height / 2 < clientY; }).length;
        const ref = wins[index] ?? null;
        if (slot.parentElement === slotCol && slot.nextElementSibling === ref) return;
        slotCol.insertBefore(slot, ref);
      }
      // Columns left empty collapse; the ones to their right glide over.
      for (const x of c.colsEl.querySelectorAll<HTMLElement>(":scope > .cl-col")) if (!x.children.length) x.remove();
      target.col = slotCol;
      geometry(c);
      flipPlay(before);
    };
    const move = (e: PointerEvent): void => {
      if (e.pointerId !== first.pointerId) return;
      dx = (e.clientX - start.x) / cam.z; dy = (e.clientY - start.y) / cam.z;
      applyMoveTransform();
      place(e.clientX, e.clientY);
    };
    const finish = (e: PointerEvent): void => {
      if (e.pointerId !== first.pointerId) return;
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", finish);
      window.removeEventListener("pointercancel", finish);
      const slotRect = slot.getBoundingClientRect();
      const now = root.getBoundingClientRect();
      // Land: the window springs from where it is to the slot (a little overshoot), then joins the column.
      const gx = (now.left - slotRect.left) / cam.z, gy = (now.top - slotRect.top) / cam.z;
      const contentNow = c.content.getBoundingClientRect();
      root.style.left = `${(slotRect.left - contentNow.left) / cam.z}px`;
      root.style.top = `${(slotRect.top - contentNow.top) / cam.z}px`;
      root.style.width = `${slotRect.width / cam.z}px`;
      root.style.height = `${slotRect.height / cam.z}px`;
      const land = new Spring(1, (p) => {
        const s = 1 + 0.025 * Math.max(0, p);
        root.style.transform = `translate(${gx * p}px, ${gy * p}px) scale(${s})`;
        invalidate();
        if (p !== 0) return;
        root.style.cssText = fixedH ? `height:${fixedH}` : "";
        root.classList.remove("is-lifted");
        slot.replaceWith(root);
        geometry(c);
        settle(c.view.id);
        renderTree();
      }, { visualDuration: 0.42, bounce: 0.3 });
      land.set(0);
    };
    // Re-parenting the card into the lift layer drops its pointer capture, so the gesture listens on the window.
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", finish);
    window.addEventListener("pointercancel", finish);
    move(first);
  };

  // ---- granting access: drag a live arrow from the port to another terminal ---------------------------------------------
  const beginLink = (rec: WinRec, e: PointerEvent): void => {
    if (!rec.port) return;
    showReach(rec, true);
    const port = rec.port;
    port.setPointerCapture(e.pointerId);
    const src = worldRect(rec.card.root);
    const p0 = toWorld(e.clientX, e.clientY);
    const arrow = new DragArrow(src, p0, invalidate);
    overlay.append(arrow.arrow.g);
    drag = { arrow, source: rec };
    rec.card.root.dataset.linking = "";
    const reachable = new Set(reach(rec.model.host, grants).map((r) => r.host));
    const move = (ev: PointerEvent): void => {
      if (!drag) return;
      const w = toWorld(ev.clientX, ev.clientY);
      drag.arrow.move(w, headSize());
      const under = document.elementsFromPoint(ev.clientX, ev.clientY).find((n): n is HTMLElement => n instanceof HTMLElement && n.matches('.ui-window[data-kind="terminal"]'));
      const ok = under && under !== rec.card.root && !reachable.has(under.dataset.windowId?.replace(/^w-/, "") ?? "") && under.closest('[data-view="console"]');
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
    const to = dstEl.dataset.windowId?.replace(/^w-/, "") ?? "";
    const anchorPt = toClient(d.arrow.end());
    const tipAnchor = el("div", "cl-tip-anchor");
    tipAnchor.style.cssText = `position:fixed;left:${anchorPt.x}px;top:${anchorPt.y}px;width:1px;height:1px;pointer-events:none`;
    document.body.append(tipAnchor);
    const cleanup = (): void => { window.setTimeout(() => tipAnchor.remove(), 260); };
    mountConfirmTip(tipAnchor, {
      label: `Allow ${from} to reach ${to}`,
      message: `Let ${from} reach ${to}?`,
      detail: "All ports, direct when possible.",
      confirmLabel: "Allow access",
      cancelLabel: "Cancel",
      onConfirm: () => {
        cleanup();
        const g: Grant = { id: `g${++serial + 100}`, from, to };
        grants.push(g);
        drag = undefined;
        d.arrow.dispose();
        // The reach arrows are rebuilt from the grants, so the new arrow is one of them.
        const keep = srcRec;
        hideReach(true);
        showReach(keep, true);
        const topo = clusters.get("topology");
        if (topo) { addTopoArrow(topo, g, true); geometry(topo); }
        for (const cl of clusters.values()) geometry(cl);
        toast.show({ message: `${from} can now reach ${to}`, ...(topo ? { action: { label: "Show in Topology", onSelect: () => flyView("topology") } } : {}) });
      },
      onCancel: () => { cleanup(); retract(d); },
    });
  };

  // ---- window lifecycle: open beside, close, split --------------------------------------------------------------------
  const enterAnimation = (rec: WinRec, from?: DOMRect): void => {
    if (reduced.matches) { rec.card.root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160 }); return; }
    const root = rec.card.root;
    const spring = new Spring(1, (p) => {
      if (p === 0) { root.style.transform = ""; root.style.opacity = ""; root.style.transformOrigin = ""; return; }
      if (from) {
        const to = root.getBoundingClientRect();
        void to;
      }
      root.style.transformOrigin = "0 50%";
      root.style.transform = `scale(${1 - 0.06 * p})`;
      root.style.opacity = String(clamp(1 - p * 1.4, 0, 1));
      invalidate();
    }, { visualDuration: 0.5, bounce: 0.28 });
    spring.set(0);
    void from;
  };

  /** Adds a window in a new column at `index` of a tiled view; the others glide aside. */
  const addColumn = (c: ClusterRec, m: WindowModel, index: number, w = metrics.colW, silent = false): WinRec => {
    const before = flipMeasure(flipTargets(c));
    const rec = makeWindow(c, m);
    c.wins.set(m.id, rec);
    const colEl = newCol(c, { id: `c${++serial}`, w, wins: [m] });
    colEl.append(rec.card.root);
    const kids = c.colsEl.querySelectorAll<HTMLElement>(":scope > .cl-col");
    c.colsEl.insertBefore(colEl, kids[index] ?? null);
    c.empty?.remove(); delete c.empty;
    geometry(c);
    settle(c.view.id);
    flipPlay(before);
    if (!silent) enterAnimation(rec);
    renderTree();
    invalidate();
    return rec;
  };

  const closeWindow = (rec: WinRec): void => {
    const c = rec.cluster;
    if (activeWin === rec) setActive(undefined);
    if (reachFor === rec) hideReach(true);
    const root = rec.card.root;
    const finish = (): void => {
      const before = flipMeasure(flipTargets(c));
      c.wins.delete(rec.model.id);
      const colEl = root.parentElement;
      rec.stopResize?.();
      root.remove();
      if (colEl && !colEl.children.length) colEl.remove();
      geometry(c);
      paintEmpty(c);
      settle(c.view.id);
      flipPlay(before, true);
      renderTree();
    };
    if (reduced.matches) { finish(); return; }
    root.style.pointerEvents = "none";
    const spring = new Spring(0, (p) => {
      root.style.transform = `scale(${1 - 0.04 * p})`;
      root.style.opacity = String(1 - p);
      if (p >= 1) finish();
    }, { visualDuration: 0.22, bounce: 0 });
    spring.set(1);
  };

  const splitWindow = async (rec: WinRec): Promise<void> => {
    const c = rec.cluster;
    const root = rec.card.root;
    const colEl = root.parentElement as HTMLElement;
    const m = rec.model;
    const h = root.offsetHeight;
    const half = Math.round((h - COLUMN_GAP) / 2);
    const nm: WindowModel = { ...m, id: `${m.id}-s${++serial}`, session: `split ${serial}`, lines: shellLines(m.user ?? "kayg", m.host, "echo ready") };
    const b = makeWindow(c, nm);
    c.wins.set(nm.id, b);
    root.style.height = `${half}px`; root.style.flex = "none";
    b.card.root.style.height = `${half}px`; b.card.root.style.flex = "none";
    root.after(b.card.root);
    geometry(c);
    renderTree();
    colEl.dataset.split = "";
    await dropletSplit(root, b.card.root);
    delete colEl.dataset.split;
  };

  const consoleView = (): ClusterRec | undefined => clusters.get("console");

  const pulse = (rec: WinRec): void => {
    rec.card.root.animate([{ transform: "scale(1)" }, { transform: "scale(1.012)" }, { transform: "scale(1)" }], { duration: 360, easing: "cubic-bezier(0.23, 1, 0.32, 1)" });
  };

  /**
   * Opens a session (a host's shell, or a container's) as a window in Console. The session
   * exists in Console from this moment. Where you are decides what you see: in Console (or
   * zoomed out) the camera flies to the window; anywhere else the camera stays put and the
   * top pill morphs into a floating terminal that is a view of that same Console window.
   */
  const openSession = (host: string, container?: string): void => {
    const c = consoleView();
    if (!c) return;
    const id = container ? `w-shell-${container}` : `w-${host}`;
    let rec = c.wins.get(id);
    const s = screens.get(host);
    const here = currentView === "console" || zoomBand === "out";
    if (!rec) {
      const model: WindowModel = container
        ? { id, kind: "terminal", host, user: "root", os: s?.os ?? "ubuntu", session: `${container} · sh`, lines: shellLines("root", container, "sh") }
        : { id, kind: "terminal", host, user: s?.user ?? "kayg", os: s?.os ?? "unknown", lines: s?.screen ?? [`kayg@${host}:~$ `] };
      rec = addColumn(c, model, c.view.cols.length, metrics.colW, !here);
    } else if (here) pulse(rec);
    setActive(rec);
    if (here) { const target = rec; flyTo(() => windowCam(target)); } else openFloat(rec);
  };

  // ---- the floating terminal: a view of a Console session, morphed out of the top pill -------------------------------
  interface Float { rec: WinRec; morph: PillMorph; card: WindowCard; expanding: boolean; stopResize: () => void; cells: { cols: number; rows: number } }
  let float: Float | undefined;
  const capsule = stage.querySelector<HTMLElement>("#capsule")!;
  const badge = el("div", "cl-badge ui-overlay-surface");
  badge.hidden = true;
  stage.append(badge);
  let badgeTimer = 0;
  const showBadge = (): void => {
    const n = [...(clusters.get("console")?.wins.keys() ?? [])].filter((k) => k.startsWith("w-shell")).length || 1;
    badge.textContent = `${n} session${n === 1 ? "" : "s"} in Console`;
    badge.hidden = false;
    badge.dataset.open = "false";
    const r = capsule.getBoundingClientRect(), s = stage.getBoundingClientRect();
    badge.style.left = `${r.left - s.left + r.width / 2}px`;
    badge.style.top = `${r.bottom - s.top + 8}px`;
    requestAnimationFrame(() => { badge.dataset.open = "true"; });
    window.clearTimeout(badgeTimer);
    badgeTimer = window.setTimeout(() => { badge.dataset.open = "false"; window.setTimeout(() => { badge.hidden = true; }, 220); }, 2600);
  };
  const FULL = '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>';
  const dropFloat = (f: Float): void => { f.stopResize(); f.card.dispose(); if (float === f) float = undefined; };
  const closeFloat = (instant = false): void => {
    const f = float;
    if (!f || f.expanding) return;
    f.morph.close(instant);
    if (instant) dropFloat(f); else showBadge();
  };
  const openFloat = (rec: WinRec): void => {
    closeViewList(true);
    if (float) { float.morph.close(true); dropFloat(float); }
    const m = rec.model;
    const card = createWindowCard({
      id: `f-${m.id}`, title: { host: m.host, ...(m.user ? { user: m.user } : {}), ...(m.session ? { session: m.session } : {}) }, icon: iconFor(m), status: "live",
      actions: [
        { id: "expand", label: "Open in Console", icon: FULL, onSelect: () => expandFloat() },
        { id: "close", label: "Close", icon: ICON.close, onSelect: () => closeFloat() },
      ],
      label: `${m.host} ${m.session ?? "shell"}, floating`,
    });
    card.root.dataset.kind = "terminal";
    const pre = el("pre", "canvas-preview cl-preview");
    pre.innerHTML = `${(m.lines ?? []).map(previewLine).join("\n")}<span class="cl-cursor" aria-hidden="true"></span>`;
    card.body.append(pre);
    const panel = el("section", "cl-float ui-overlay-surface");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", `${m.host} terminal, floating`);
    panel.append(card.root);
    // The float is the top part of the Console window it shows; it keeps that window's width.
    const W0 = Math.min(rec.card.root.offsetWidth || metrics.colW, stage.clientWidth - 24);
    const H0 = metrics.narrow ? 300 : 330;
    panel.style.height = `${H0}px`;
    const morph = createPillMorph({
      pill: capsule, stage, panel, content: [card.root], width: W0,
      onClosed: () => { const f = float; if (f && f.card === card) dropFloat(f); },
    });
    // Resizing is the shared engine (window-resize.ts) with the aspect locked, anchored at the top
    // centre. The terminal's cells are re-measured from the new box; text is never scaled.
    const cellW = (() => { const probe = el("span", "", "0000000000"); probe.style.cssText = "position:absolute;visibility:hidden;font:inherit"; pre.append(probe); const w = probe.offsetWidth / 10 || 8.4; probe.remove(); return w; })();
    const measure = (): void => {
      const cols = Math.max(20, Math.floor((card.body.clientWidth - 32) / cellW));
      const rows = Math.max(4, Math.floor((card.body.clientHeight - 28) / (14 * 1.2857)));
      panel.dataset.cols = String(cols); panel.dataset.rows = String(rows);
      if (float) float.cells = { cols, rows };
    };
    const limits = (): ResizeStart => ({
      width: panel.offsetWidth, height: panel.offsetHeight, top: 0,
      minWidth: W0 * 0.78, minHeight: H0 * 0.78, maxWidth: Math.min(W0 * 1.7, stage.clientWidth - 24), areaHeight: Math.min(H0 * 1.7, stage.clientHeight - 90),
    });
    const host: WindowResizeHost = {
      aspect: W0 / H0, centered: true, rubber: true,
      begin: limits,
      apply: (f) => { morph.setBox(f.width, f.height, f.height); },
      snap: (f) => (Math.abs(f.width / W0 - 1) < 0.06 ? { width: W0, height: H0, top: 0, shiftX: 0 } : f),
      end: measure,
    };
    const resize = attachWindowResize(card, host);
    // Touch: pinch inside the float resizes it too, with the same rubber band and settle.
    const fingers = new Map<number, Pt>();
    let pinchStart: { d0: number; start: ResizeStart; frame: ResizeFrame; cancel?: () => void } | undefined;
    const onDown = (e: PointerEvent): void => {
      if (e.pointerType !== "touch") return;
      fingers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (fingers.size === 2) {
        const [a, b] = [...fingers.values()] as [Pt, Pt];
        pinchStart = { d0: Math.hypot(a.x - b.x, a.y - b.y), start: limits(), frame: { width: panel.offsetWidth, height: panel.offsetHeight, top: 0, shiftX: 0 } };
      }
    };
    const onMove = (e: PointerEvent): void => {
      if (!fingers.has(e.pointerId)) return;
      fingers.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (!pinchStart || fingers.size < 2) return;
      const [a, b] = [...fingers.values()] as [Pt, Pt];
      pinchStart.frame = aspectFrame(pinchStart.start, W0 / H0, Math.hypot(a.x - b.x, a.y - b.y) / pinchStart.d0, true);
      host.apply(pinchStart.frame);
    };
    const onUp = (e: PointerEvent): void => {
      fingers.delete(e.pointerId);
      if (!pinchStart || fingers.size >= 2) return;
      const ps = pinchStart;
      pinchStart = undefined;
      const range = aspectRange(ps.start, W0 / H0);
      let rest = aspectFrame(ps.start, W0 / H0, Math.min(range.max, Math.max(range.min, ps.frame.width / ps.start.width)), false);
      rest = host.snap!(rest);
      settleResize((fr) => host.apply(fr), ps.frame, rest, measure);
    };
    panel.addEventListener("pointerdown", onDown, true);
    panel.addEventListener("pointermove", onMove, true);
    panel.addEventListener("pointerup", onUp, true);
    panel.addEventListener("pointercancel", onUp, true);
    panel.style.touchAction = "none";
    const stopResize = (): void => { resize.dispose(); };
    float = { rec, morph, card, expanding: false, stopResize, cells: { cols: 0, rows: 0 } };
    morph.open();
    requestAnimationFrame(measure);
  };
  /** The float flies into its Console slot while the camera follows, one continuous motion. */
  const expandFloat = (): void => {
    const f = float;
    if (!f || f.expanding) return;
    f.expanding = true;
    f.stopResize();
    const root = f.rec.card.root;
    const panel = f.morph.panel;
    // Lay the panel out at the Console window's own width and full height, and scale it back down to
    // the size it has now, so nothing visibly changes before the flight starts.
    const rect0 = panel.getBoundingClientRect();
    const w0 = panel.offsetWidth, shown0 = panel.offsetHeight;
    const wc = root.offsetWidth || w0, fullH = root.offsetHeight;
    const s0 = w0 / wc;
    f.morph.setBox(wc, fullH, shown0 / s0);
    panel.style.transformOrigin = "0 0";
    panel.style.pointerEvents = "none";
    const rest0 = f.morph.restRect();
    const x0 = rect0.left - rest0.left, y0 = rect0.top - rest0.top;
    panel.style.transform = `translate(${x0}px, ${y0}px) scale(${s0})`;
    root.style.opacity = "0";
    flyTo(() => windowCam(f.rec));
    const done = (): void => {
      root.style.opacity = "";
      panel.style.transform = "";
      f.morph.close(true);
      dropFloat(f);
      setActive(f.rec);
    };
    if (reduced.matches) { done(); return; }
    const progress = new Spring(0, (v) => {
      f.morph.setReveal(v);
      const rest = f.morph.restRect();
      const target = root.getBoundingClientRect();
      const sT = target.width / rest.width;
      const s = s0 + (sT - s0) * v;
      panel.style.transform = `translate(${x0 + (target.left - rest.left - x0) * v}px, ${y0 + (target.top - rest.top - y0) * v}px) scale(${s})`;
      // The last stretch crossfades float material into the window's own, so there is no pop.
      const fade = clamp((v - 0.88) / 0.12, 0, 1);
      panel.style.opacity = String(1 - fade);
      root.style.opacity = String(fade);
      if (v === 1) done();
    }, { visualDuration: 0.85, bounce: 0.05 });
    progress.set(1);
  };

  // ---- the view list: tapping the capsule lists the views, with the same morph ------------------------------------------
  let viewList: PillMorph | undefined;
  let viewListAbort: AbortController | undefined;
  const closeViewList = (instant = false): void => {
    viewListAbort?.abort(); viewListAbort = undefined;
    viewList?.close(instant);
  };
  const viewKeys = (index: number) => ({ mac: `⌘${index + 1}`, other: `Ctrl+${index + 1}` });
  const toggleViewList = (): void => {
    if (viewList?.isOpen) { closeViewList(); return; }
    if (float) closeFloat(true);
    const panel = el("section", "cl-viewlist ui-overlay-surface");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "Views");
    const list = el("ul", "cl-viewlist-rows");
    [...clusters.values()].forEach((c, i) => {
      const li = el("li");
      const b = el("button", "cl-viewrow");
      b.type = "button";
      b.dataset.view = c.view.id;
      if (c.view.id === currentView) b.setAttribute("aria-current", "true");
      b.innerHTML = `<span class="cl-viewrow-icon"><svg viewBox="0 0 24 24" aria-hidden="true">${VIEW_ICON[c.view.id]}</svg></span><span class="cl-viewrow-name"></span><span class="cl-viewrow-meta"></span><span class="cl-viewrow-keys"></span>`;
      (b.querySelector(".cl-viewrow-name") as HTMLElement).textContent = c.view.name;
      (b.querySelector(".cl-viewrow-meta") as HTMLElement).textContent = c.view.layout === "graph" ? `${c.view.nodes.length} nodes` : `${c.wins.size} windows`;
      const keys = b.querySelector(".cl-viewrow-keys") as HTMLElement;
      for (const cap of keyCaps(viewKeys(i))) keys.append(el("kbd", "", cap));
      b.addEventListener("click", () => { closeViewList(); flyView(c.view.id); });
      li.append(b);
      list.append(li);
    });
    const foot = el("button", "cl-viewrow cl-viewrow-search");
    foot.type = "button";
    foot.innerHTML = `<span class="cl-viewrow-icon"><svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="9" cy="9" r="5.5"/><path d="m13 13 3.5 3.5"/></svg></span><span class="cl-viewrow-name">Search everything</span><span class="cl-viewrow-keys"></span>`;
    for (const cap of keyCaps({ mac: "⌘K", other: "Ctrl+K" })) (foot.querySelector(".cl-viewrow-keys") as HTMLElement).append(el("kbd", "", cap));
    foot.addEventListener("click", () => { closeViewList(true); document.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: isMacPlatform(), ctrlKey: !isMacPlatform(), bubbles: true })); });
    panel.append(list, foot);
    viewList = createPillMorph({ pill: capsule, stage, panel, content: [list, foot], width: 340, onClosed: () => { viewListAbort?.abort(); } });
    viewListAbort = new AbortController();
    const sig = viewListAbort.signal;
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closeViewList(); } }, { capture: true, signal: sig });
    document.addEventListener("pointerdown", (e) => { if (!panel.contains(e.target as Node) && !capsule.contains(e.target as Node)) closeViewList(); }, { capture: true, signal: sig });
    viewList.open();
  };
  capsule.addEventListener("click", (e) => { e.preventDefault(); e.stopImmediatePropagation(); toggleViewList(); }, { capture: true, signal });

  // ---- sidebar tree and palette ----------------------------------------------------------------------------------
  const treeSections = (): BranchSection[] => [...clusters.values()].map((c) => {
    const graph = c.view.layout === "graph";
    return {
      id: `view:${c.view.id}`,
      label: c.view.name,
      meta: graph ? `${c.view.nodes.length} nodes` : `${c.wins.size}`,
      open: true,
      leaves: graph
        ? c.view.nodes.map((n) => ({ id: `n-${n.id}`, label: n.label, glyph: n.kind === "tag" ? "#" : "◦" }))
        : [...c.wins.values()].map((w) => ({ id: w.model.id, label: w.model.kind === "terminal" ? `${w.model.host}${w.model.session ? ` · ${w.model.session}` : ""}` : (w.model.session ?? w.model.kind), glyph: w.model.kind === "terminal" ? "›_" : "▤" })),
    };
  });
  let treeQueued = false;
  const renderTree = (): void => {
    if (treeQueued) return;
    treeQueued = true;
    queueMicrotask(() => {
      treeQueued = false;
      core.setHostTree(treeSections(), activeWin?.model.id ?? "", (id) => {
        const target = [...clusters.values()].flatMap((c) => [...c.wins.values()]).find((w) => w.model.id === id);
        if (!target) return;
        setActive(target);
        if (target.model.kind === "node") flyView("topology"); else flyTo(() => windowCam(target));
        if (coarse.matches) stage.querySelector<HTMLButtonElement>("#sidebar-toggle[aria-expanded='true']")?.click();
      });
    });
  };
  const tree = stage.querySelector<HTMLElement>("#tree");
  tree?.addEventListener("click", (e) => {
    const head = (e.target as Element).closest(".bm-head");
    const id = head?.parentElement?.dataset.id?.replace(/^view:/, "") as ViewId | undefined;
    if (id && clusters.has(id)) flyView(id);
  }, { signal });
  const sideTitle = stage.querySelector<HTMLElement>(".sidebar-title");
  if (sideTitle) sideTitle.textContent = "Views";

  const visibleHosts = (): string[] => [...(consoleView()?.wins.values() ?? [])].filter((w) => w.model.kind === "terminal" && !w.model.id.includes("-s") && !w.model.id.startsWith("w-shell")).map((w) => w.model.host);
  const allowedHosts = (): string[] => (role === "viewer" ? ["build-01", "nix-cache"] : role === "new" ? [] : ["build-01", "edge-arm", "nix-cache", "studio-mac"]);
  const removeProvider = core.addPaletteProvider(() => {
    const out: import("./core-screen").PaletteEntry[] = [];
    [...clusters.values()].forEach((c, i) => {
      out.push({ group: "Views", glyph: "▦", icon: VIEW_ICON[c.view.id], label: `Go to ${c.view.name}`, hint: `view · ${shortcutLabel(viewKeys(i))}`, action: `proto:view:${c.view.id}` });
    });
    out.push({ group: "Views", glyph: "▦", label: "Zoom out to all views", hint: "Esc", action: "proto:overview" });
    // Any session by name. Keywords ride in the hint so "ssh", "terminal", "console", "vnc" and "rdp" find them.
    for (const host of allowedHosts()) {
      out.push({ group: "Console", glyph: "›_", icon: ICON.terminal, label: `Open shell on ${host}`, hint: "terminal · ssh · console", action: `proto:open:${host}` });
      out.push({ group: "Console", glyph: "▭", label: `Open remote desktop on ${host}`, hint: "vnc · rdp · arrives later", action: "proto:later" });
    }
    if (role === "operator") for (const row of CONTAINERS) out.push({ group: "Console", glyph: "›_", icon: ICON.terminal, label: `Open shell on ${row.name}`, hint: "container · terminal · console", action: `proto:ctr:${row.name}` });
    return out;
  });
  window.addEventListener("tracer:proto-action", (event) => {
    const action = (event as CustomEvent<{ action?: string }>).detail?.action ?? "";
    const [, kind, value] = action.split(":");
    if (kind === "view" && value) flyView(value as ViewId);
    else if (kind === "overview") flyTo(overviewCam);
    else if (kind === "open" && value) openSession(value);
    else if (kind === "ctr" && value) {
      openSession("build-01", value);
    } else if (kind === "later") toast.show({ message: "Remote desktop arrives later.", tone: "ok" });
    else if (kind === "addhost") toast.show({ message: "Add host is its own mockup (proto=addhost)." });
  }, { signal });
  const removeShortcuts = registerShortcuts({ id: "clusters", title: "Canvas", area: "canvas", shortcuts: [
    { id: "overview", label: "Zoom out to all views", keys: "Esc" },
    { id: "zoom", label: "Zoom", keys: { mac: "⌘+Scroll", other: "Ctrl+Scroll" } },
    { id: "pan", label: "Pan the canvas", keys: "Scroll" },
    { id: "views", label: "Go to view 1 to 3", keys: { mac: "⌘1–3", other: "Ctrl+1–3" } },
  ] });
  window.addEventListener("keydown", (e) => {
    if (e.key !== "Escape" || e.defaultPrevented || stage.querySelector(".palette:not([hidden])") || document.querySelector(".ui-confirm-tip[data-open='true']")) return;
    if (float && !float.expanding) { closeFloat(); return; }
    flyTo(overviewCam);
  }, { signal });
  // Every jump is the same camera spring: Command or Ctrl with 1 to 9.
  window.addEventListener("keydown", (e) => {
    const mod = isMacPlatform() ? e.metaKey : e.ctrlKey;
    if (!mod || e.altKey || e.shiftKey || !/^[1-9]$/.test(e.key)) return;
    const id = [...clusters.keys()][Number(e.key) - 1];
    if (!id) return;
    e.preventDefault(); e.stopPropagation();
    closeViewList(true);
    flyView(id);
  }, { signal, capture: true });

  // ---- gestures on the canvas ---------------------------------------------------------------------------------------------
  const touches = new Map<number, Pt>();
  let pinch: { d0: number; z0: number; wp: Pt } | undefined;
  let pan: { id: number; x: number; y: number; cx: number; cy: number; moved: boolean; target: Element } | undefined;
  const interactive = (t: EventTarget | null): boolean => !!(t as Element | null)?.closest?.(".ui-window, .cl-label, .cl-edge, .cl-port, .cl-empty-add");
  const zoomAt = (cx: number, cy: number, z: number): void => {
    const r = viewport.getBoundingClientRect();
    const wp = toWorld(cx, cy);
    cam.z = clamp(z, 0.08, 2);
    cam.cx = wp.x - (cx - r.left - vw / 2) / cam.z;
    cam.cy = wp.y - (cy - r.top - vh / 2) / cam.z;
    springCx.value = cam.cx; springCy.value = cam.cy; springLz.value = Math.log(cam.z);
    applyCam();
  };
  viewport.addEventListener("wheel", (e) => {
    const inCol = (e.target as Element).closest(".cl-col");
    if (!(e.ctrlKey || e.metaKey) && inCol && Math.abs(e.deltaY) > Math.abs(e.deltaX) && lod === "live") {
      const colEl = inCol as HTMLElement;
      const canScroll = colEl.scrollHeight > colEl.clientHeight + 1 && (e.deltaY < 0 ? colEl.scrollTop > 0 : colEl.scrollTop + colEl.clientHeight < colEl.scrollHeight - 1);
      if (canScroll) return;
    }
    e.preventDefault();
    stopCam();
    camTarget = undefined;
    if (e.ctrlKey || e.metaKey) { zoomAt(e.clientX, e.clientY, cam.z * Math.exp(-e.deltaY * (e.ctrlKey ? 0.01 : 0.0025))); return; }
    const dx = e.shiftKey && !e.deltaX ? e.deltaY : e.deltaX, dy = e.shiftKey ? 0 : e.deltaY;
    cam.cx += dx / cam.z; cam.cy += dy / cam.z;
    springCx.value = cam.cx; springCy.value = cam.cy;
    applyCam();
  }, { passive: false, signal });
  viewport.addEventListener("pointerdown", (e) => {
    if (e.pointerType === "touch") {
      touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (touches.size === 2) {
        const [a, b] = [...touches.values()] as [Pt, Pt];
        stopCam();
        camTarget = undefined;
        pan = undefined;
        pinch = { d0: Math.hypot(a.x - b.x, a.y - b.y), z0: cam.z, wp: toWorld((a.x + b.x) / 2, (a.y + b.y) / 2) };
        return;
      }
    }
    if (interactive(e.target) || e.button === 2) return;
    const target = e.target as Element;
    pan = { id: e.pointerId, x: e.clientX, y: e.clientY, cx: cam.cx, cy: cam.cy, moved: false, target };
    viewport.setPointerCapture(e.pointerId);
  }, { signal, capture: true });
  viewport.addEventListener("pointermove", (e) => {
    if (e.pointerType === "touch" && touches.has(e.pointerId)) touches.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pinch && touches.size >= 2) {
      const [a, b] = [...touches.values()] as [Pt, Pt];
      const z = clamp(pinch.z0 * (Math.hypot(a.x - b.x, a.y - b.y) / pinch.d0), 0.08, 2);
      const r = viewport.getBoundingClientRect();
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      cam.z = z;
      cam.cx = pinch.wp.x - (mx - r.left - vw / 2) / z;
      cam.cy = pinch.wp.y - (my - r.top - vh / 2) / z;
      springCx.value = cam.cx; springCy.value = cam.cy; springLz.value = Math.log(z);
      applyCam();
      return;
    }
    if (!pan || e.pointerId !== pan.id) return;
    if (!pan.moved && Math.hypot(e.clientX - pan.x, e.clientY - pan.y) < 6) return;
    if (!pan.moved) { pan.moved = true; stopCam(); camTarget = undefined; viewport.dataset.panning = ""; hideSummary(); }
    cam.cx = pan.cx - (e.clientX - pan.x) / cam.z;
    cam.cy = pan.cy - (e.clientY - pan.y) / cam.z;
    springCx.value = cam.cx; springCy.value = cam.cy;
    applyCam();
  }, { signal });
  const pointerEnd = (e: PointerEvent): void => {
    touches.delete(e.pointerId);
    if (touches.size < 2) pinch = undefined;
    if (!pan || e.pointerId !== pan.id) return;
    const p = pan;
    pan = undefined;
    delete viewport.dataset.panning;
    if (p.moved) return;
    // A tap: on a view's region it flies in; on empty canvas it clears the active window.
    const region = p.target.closest?.(".cl-region");
    const c = [...clusters.values()].find((x) => x.region === region);
    if (c && (zoomBand === "out" || lod === "thumb")) flyView(c.view.id);
    else if (!region) setActive(undefined);
  };
  viewport.addEventListener("pointerup", pointerEnd, { signal });
  viewport.addEventListener("pointercancel", pointerEnd, { signal });
  // A thumbnail window is read-only: a tap on it flies into its view.
  world.addEventListener("click", (e) => {
    if (lod !== "thumb") return;
    const cl = (e.target as Element).closest<HTMLElement>(".cl");
    if (cl?.dataset.view && !(e.target as Element).closest(".cl-label") && !pan) flyView(cl.dataset.view as ViewId);
  }, { signal });
  document.addEventListener("pointerdown", (e) => {
    if (reachPinned && !(e.target as Element).closest(".cl-port, .ui-window-pill, .ui-confirm-tip, .cl-edge")) hideReach();
  }, { signal, capture: true });

  // ---- live streams (a logs window keeps moving, so thumbnails are visibly live) ---------------------------------------------------
  const streamTimer = window.setInterval(() => {
    for (const c of clusters.values()) for (const w of c.wins.values()) {
      if (!w.stream || !w.model.lines) continue;
      const now = new Date();
      const t = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}`;
      w.model.lines = [...w.model.lines.slice(-14), `${t}  web-api  GET /healthz 200 1ms`];
      w.stream.innerHTML = w.model.lines.map((l) => { const [time, src, ...msg] = l.split("  "); return `<span class="cl-log-time">${time}</span>  <span class="cl-log-src">${src}</span>  ${msg.join("  ")}`; }).join("\n");
      w.stream.scrollTop = w.stream.scrollHeight;
    }
  }, 1600);

  // The camera springs start last: their first update paints the world, which needs everything above.
  const springCx = new Spring(0, (v) => { cam.cx = v; applyCam(); }, FLIGHT);
  const springCy = new Spring(0, (v) => { cam.cy = v; applyCam(); }, FLIGHT);
  const springLz = new Spring(0, (v) => { cam.z = Math.exp(v); applyCam(); }, FLIGHT);

  // ---- scenes ---------------------------------------------------------------------------------------------------------------
  const clear = (): void => {
    hideReach(true);
    hideSummary();
    drag?.arrow.dispose(); drag = undefined;
    for (const c of clusters.values()) { for (const w of c.wins.values()) { w.stopResize?.(); w.card.dispose(); } c.el.remove(); }
    clusters.clear();
    activeWin = undefined;
  };
  const build = (): void => {
    clear();
    grants = INITIAL_GRANTS.map((g) => ({ ...g }));
    metrics = metricsFor(viewport.clientWidth || innerWidth, coarse.matches);
    vw = viewport.clientWidth; vh = viewport.clientHeight;
    for (const v of buildViews(role, metrics, screens, omit)) clusters.set(v.id, buildCluster(v));
    world.dataset.lod = lod;
    renderTree();
  };

  interface SceneDef { name: string; hint: string; options?: () => { label: string; tabs: Array<{ id: string; label: string }>; selected: string; onChange(id: string): void } }
  const scenes: Array<SceneDef & { enter(): void }> = [
    { name: "Overview", hint: "Three views on one canvas. Hover a region for its summary; click one to fly in. The sidebar and the command palette list the views.",
      enter() { role = "operator"; omit = []; build(); flyTo(overviewCam, true); } },
    { name: "Fly in", hint: "The camera springs into Console; windows go live above 60 % zoom. Press Esc to fly out. In the command palette, type build and open a shell on build-01.",
      enter() { role = "operator"; omit = ["build-01"]; build(); flyTo(overviewCam, true); window.setTimeout(() => { if (sceneIndex === 1 && camTarget === overviewCam) flyView("console"); }, 650); } },
    { name: "Arrows on demand", hint: "Hover a terminal's pill (long-press on touch) to see where it can reach. Drag from the connector next to the pill onto another terminal to allow access.",
      enter() { role = "operator"; omit = []; build(); flyView("console", true); } },
    { name: "Open from a container", hint: "Click a container: the top pill morphs into a floating terminal; the camera stays here. Expand it to fly into Console, or close it. The terminal has Split; the list does not.",
      enter() { role = "operator"; omit = []; build(); flyView("containers", true); } },
    { name: "Access by grants", hint: "The views a person sees come from their grants. Switch who is signed in.",
      options: () => ({ label: "Signed in as", tabs: [{ id: "viewer", label: "viewer" }, { id: "operator", label: "operator" }, { id: "new", label: "new user" }], selected: role, onChange: (id) => { role = id as Role; scenes[4]!.enter(); } }),
      enter() { omit = []; if (role === "operator" && sceneIndex !== 4) role = "viewer"; build(); if (role === "operator") flyTo(overviewCam, true); else flyView("console", true); } },
    { name: "Structure", hint: "Drag a window by its pill: the others reflow and it lands with a bounce. Drag a view by its label: it snaps to the grid and pushes a neighbour aside.",
      enter() { role = "operator"; omit = []; build(); const c = clusters.get("console")!; const r = contentRect(c); flyTo(() => ({ cx: r.x + r.w / 2 + (metrics.narrow ? 0 : 180), cy: r.y + r.h / 2 + (metrics.narrow ? 120 : 200), z: 0.62 }), true); } },
  ];
  let stepper: Stepper | undefined;
  const goScene = (i: number): void => {
    sceneIndex = (i + scenes.length) % scenes.length;
    const def = scenes[sceneIndex]!;
    if (sceneIndex === 4 && role === "operator" && !new URLSearchParams(location.search).has("role")) role = "viewer";
    def.enter();
    stepper?.set(sceneIndex, def.name, def.hint, def.options?.());
    const url = new URL(location.href);
    url.searchParams.set("scene", String(sceneIndex + 1));
    history.replaceState(null, "", url);
    paintCapsule();
  };
  stepper = mountStepper(stage, { count: scenes.length, onStep: (delta) => goScene(sceneIndex + delta) });

  // Refit when the pane changes size (sidebar docks, rotation) so the framing holds.
  let lastW = 0, lastH = 0;
  const ro = new ResizeObserver(() => {
    const w = viewport.clientWidth, h = viewport.clientHeight;
    if (w === lastW && h === lastH) return;
    lastW = w; lastH = h;
    vw = w; vh = h;
    if (camTarget && clusters.size) setCam(camTarget()); else applyCam(true);
  });
  ro.observe(viewport);
  applyCam(true);
  const startScene = clamp(((options.scene ?? 1) | 0) - 1, 0, scenes.length - 1);
  if (options.role) role = options.role;
  goScene(startScene);

  const probe = {
    scene: () => sceneIndex + 1,
    setScene: (n: number) => goScene(n - 1),
    camera: () => ({ ...cam, lod, zoomBand, tx, ty }),
    views: () => [...clusters.values()].map((c) => ({ id: c.view.id, name: c.view.name, x: c.x, y: c.y, w: boxOf(c.view, metrics).w, h: boxOf(c.view, metrics).h, windows: [...c.wins.keys()] })),
    grants: () => grants.map((g) => ({ ...g })),
    flyView: (id: ViewId) => flyView(id),
    overview: () => flyTo(overviewCam),
    openSession,
    float: () => (float ? { cols: float.cells.cols, rows: float.cells.rows, width: float.morph.panel.offsetWidth, height: float.morph.panel.offsetHeight } : undefined),
    setRole: (r: Role) => { role = r; scenes[4]!.enter(); stepper?.set(4, scenes[4]!.name, scenes[4]!.hint, scenes[4]!.options?.()); },
    reachFor: () => reachFor?.model.id,
    reachCount: () => reachItems.length,
  };
  (window as unknown as { __tracerClusters?: typeof probe }).__tracerClusters = probe;

  return {
    dispose() {
      events.abort();
      window.clearInterval(streamTimer);
      window.clearTimeout(restTimer);
      ro.disconnect();
      removeProvider();
      removeShortcuts();
      closeViewList(true);
      if (float) { float.morph.close(true); dropFloat(float); }
      badge.remove();
      clear();
      stepper?.dispose();
      toast.dispose();
      summary.remove();
      viewport.remove();
      delete (window as unknown as { __tracerClusters?: unknown }).__tracerClusters;
      delete stage.dataset.clusters;
    },
  };
}
