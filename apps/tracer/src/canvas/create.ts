/**
 * The composition root of the canvas: builds the context, wires the modules in dependency order and returns the
 * controller. Product code and mockups both come through here; they differ only in the adapters and flags they
 * pass (mockups also add their scaffolding from `mock/`).
 *
 * Order matters only for construction, never for behaviour: modules call each other through the context at event
 * time. Construction order is: elements, camera, layout helpers, then navigation, views, windows, the top pill and
 * its lists, the toolbar, the optional mesh and sharing, then gestures, shortcuts and the palette.
 *
 * The 60 fps rule lives in the camera; the instant-work rule here: every handler does at most a layout read and a
 * transform write, and everything else (saving, the tree, arrows) is coalesced to a microtask, a frame or a timer.
 */
import { mountToast } from "../../../../packages/ui/src/toast";
import type { CoreScreen } from "../core-screen";
import { createMemory } from "./memory";
import { createBackdrop, type Backdrop } from "./backdrop";
import { Camera } from "./camera/camera";
import { installGestures } from "./camera/gestures";
import { createNav } from "./camera/lock";
import type { Adapters, CanvasState, Ctx } from "./context";
import { SVG_NS, coarse, el } from "./dom";
import { createFlip } from "./layout/flip";
import { metricsFor, type Metrics } from "./layout/geometry";
import { createMesh } from "./mesh";
import { createDocumentSync } from "./model/sync";
import type { ViewModel } from "./model/types";
import { createSharing } from "./sharing";
import { createPill } from "./toolbar/pill";
import { installPalette } from "./toolbar/palette";
import { createToolbar } from "./toolbar/row";
import { installShortcuts } from "./toolbar/shortcuts";
import { createTree } from "./toolbar/tree";
import { createViews } from "./views/world";
import { createViewList } from "./toolbar/viewlist";
import { createFloat } from "./windows/float";
import { createInputLock } from "./windows/input-lock";
import { createWindows } from "./windows/lifecycle";
import { createSessionUi } from "./windows/session-ui";
import { createVisibility } from "./windows/visibility";

export interface CanvasOptions {
  adapters: Adapters;
  /** The floating terminal; off until a session binding can mirror itself. */
  float?: boolean;
  /** Draw the dotted backdrop (default true). */
  dots?: boolean;
  /** Views that are saved to the document (default: all of them). */
  persisted?: (viewId: string) => boolean;
}

export interface CanvasController {
  readonly cx: Ctx;
  /** Replaces every view with these models and re-aims the camera. */
  setViews(models: ViewModel[] | ((m: Metrics) => ViewModel[])): void;
  /** Flushes pending saves; call when the page is hidden. */
  flush(): void;
  dispose(): void;
}

export function createCanvas(core: CoreScreen, options: CanvasOptions): CanvasController {
  const { stage } = core;
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
  const edges = el("div", "cl-edges");
  viewport.append(world, edges);
  core.panes.append(viewport);
  const backdrop: Backdrop | undefined = options.dots === false ? undefined : createBackdrop(stage, viewport);
  backdrop?.measure();
  const events = new AbortController();

  const state: CanvasState = {
    metrics: metricsFor(viewport.clientWidth || innerWidth, viewport.clientHeight || innerHeight, coarse.matches),
    activeWin: undefined, currentView: "console", canvasLock: true, snapIdx: 0, movingWindow: false, serial: 0,
  };
  let frameQueued = 0;
  const cx = {
    core, stage, viewport, world, overlay, edges, signal: events.signal, toast: core.toast ?? mountToast(stage),
    adapters: options.adapters, state, flags: { float: options.float ?? false }, views: new Map(),
    invalidate() {
      if (frameQueued) return;
      frameQueued = requestAnimationFrame(() => { frameQueued = 0; cx.mesh?.updateOverlay(); });
    },
  } as unknown as Ctx;
  (cx as { camera: Camera }).camera = new Camera(viewport, world, {
    onTransform: (t) => backdrop?.update(t),
    onLabelScale: (inv) => { for (const c of cx.views.values()) c.label.style.setProperty("--inv", inv); },
    onLod: () => { cx.pill.paint(); cx.visibility.lodChanged(); },
    onBand: () => cx.view.hideSummary(),
    onFrame: () => { cx.invalidate(); cx.memory.cull(); },
    onRest: () => { cx.mesh?.redraw(); cx.nav.updateCurrentView(); },
    onFlight: () => cx.view.hideSummary(),
  });
  (cx as { flip: Ctx["flip"] }).flip = createFlip(() => cx.camera.cam.z, () => cx.invalidate());

  cx.memory = createMemory(cx, backdrop);
  cx.store = createDocumentSync(cx, options.persisted);
  cx.nav = createNav(cx);
  cx.view = createViews(cx);
  cx.win = createWindows(cx);
  cx.float = createFloat(cx);
  cx.inputLock = createInputLock(cx);
  if (options.adapters.inventory) cx.sessionUi = createSessionUi(cx);
  cx.visibility = createVisibility(cx);
  cx.pill = createPill(cx);
  cx.viewList = createViewList(cx);
  cx.tree = createTree(cx);
  if (options.adapters.mesh) cx.mesh = createMesh(cx, options.adapters.mesh);
  if (options.adapters.sharing) cx.sharing = createSharing(cx, options.adapters.sharing);
  cx.toolbar = createToolbar(cx);
  installGestures(cx);
  const removeShortcuts = installShortcuts(cx);
  const removePalette = installPalette(cx);

  // Refit when the pane changes size (sidebar docks, rotation) so the framing holds. Views are as tall as the
  // viewport, so a resize (the keyboard, the URL bar, a rotation) refits them.
  let lastW = 0, lastH = 0;
  const ro = new ResizeObserver(() => {
    const w = viewport.clientWidth, h = viewport.clientHeight;
    if (w === lastW && h === lastH) return;
    lastW = w; lastH = h;
    cx.camera.resized();
    backdrop?.measure();
    state.metrics = metricsFor(w, h, coarse.matches);
    world.style.setProperty("--clh", `${state.metrics.clh}px`);
    for (const c of cx.views.values()) cx.view.geometry(c);
    for (const c of cx.views.values()) for (const rec of c.wins.values()) rec.binding?.refit();
    if (cx.camera.target && cx.views.size) cx.camera.set(cx.camera.target()); else cx.camera.apply(true);
  });
  ro.observe(viewport);
  cx.camera.start();

  // A hidden page also releases its big surfaces (memory.ts) and must not lose the last edit.
  const onHide = (): void => { if (document.hidden) cx.store.flush(); };
  document.addEventListener("visibilitychange", onHide, { signal: events.signal });
  window.addEventListener("pagehide", () => cx.store.flush(), { signal: events.signal });

  return {
    cx,
    setViews(models) {
      cx.inputLock.reset();
      cx.mesh?.hideReach(true);
      cx.view.clear();
      state.metrics = metricsFor(viewport.clientWidth || innerWidth, viewport.clientHeight || innerHeight, coarse.matches);
      cx.camera.resized();
      world.style.setProperty("--clh", `${state.metrics.clh}px`);
      for (const v of typeof models === "function" ? models(state.metrics) : models) cx.views.set(v.id, cx.view.build(v));
      cx.tree.render();
      cx.pill.paint();
      cx.toolbar.update();
    },
    flush: () => cx.store.flush(),
    dispose() {
      events.abort();
      ro.disconnect();
      removePalette();
      removeShortcuts();
      cx.store.dispose();
      cx.toolbar.dispose();
      cx.tree.dispose();
      cx.sessionUi?.dispose();
      cx.pill.dispose();
      cx.sharing?.dispose();
      cx.mesh?.dispose();
      cx.float.dispose();
      cx.visibility.dispose();
      cx.view.clear();
      cx.view.dispose();
      cx.camera.dispose();
      backdrop?.dispose();
      viewport.remove();
      delete stage.dataset.clusters;
    },
  };
}

