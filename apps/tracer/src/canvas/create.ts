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
import { onDemand, whenIdle } from "../on-demand";
import type { AppWindowsHook } from "./appwin/hook.on-demand";
import { mountToast } from "../../../../packages/ui/src/toast";
import type { CoreScreen } from "../core-screen";
import { createMemory } from "./memory";
import { warmSplit } from "./windows/split-handle";
import { createBackdrop, type Backdrop } from "./backdrop";
import { Camera } from "./camera/camera";
import { installGestures } from "./camera/gestures";
import { createNav } from "./camera/lock";
import type { Adapters, CanvasState, Ctx } from "./context";
import { SVG_NS, coarse, el } from "./dom";
import { createFlip } from "./layout/flip";
import { metricsFor, type Metrics } from "./layout/geometry";
import { columnEls } from "./layout/columns";
import { SIZE_EVENT, edgeToEdge, readSizes } from "./window-sizes";
import { UI_SIZE_EVENT, currentUiScale } from "../../../../packages/ui/src/ui-scale";
import { createMesh } from "./mesh";
import { createDocumentSync } from "./model/sync";
import type { ViewModel } from "./model/types";
import { createPill } from "./toolbar/pill";
import { installPalette } from "./toolbar/palette";
import { createToolbar } from "./toolbar/row";
import { installShortcuts } from "./toolbar/shortcuts";
import { createTree } from "./toolbar/tree";
import { createViews } from "./views/world";
import { createViewList } from "./toolbar/viewlist";
import { createFloatHandle } from "./windows/float-handle";
import { createDetailsHandle } from "./windows/details-handle";
import { createSharingHandle } from "./sharing";
import { hideTips } from "../../../../packages/ui/src/tooltip";
import { createInputLock } from "./windows/input-lock";
import { createWindows } from "./windows/lifecycle";
import { createSessionHooks } from "./windows/session-hooks";
import { setPerfProbe } from "../perf-activity";
import { loadGroups } from "./layout/groups-handle";
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
  // The grouped layout's chunk starts at mount, for every canvas (the product and the test double both come through here).
  // A key press that splits a stacked window must act at once, and an idle callback does not come on a busy canvas (D212).
  void loadGroups().catch(() => undefined);
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
  const setEdge = (sizes: ReturnType<typeof readSizes>): void => { stage.toggleAttribute("data-window-edge", edgeToEdge(coarse.matches || innerWidth < 720, sizes)); };
  setEdge(readSizes());
  const backdrop: Backdrop | undefined = options.dots === false ? undefined : createBackdrop(stage, viewport);
  backdrop?.measure();
  const events = new AbortController();

  const state: CanvasState = {
    metrics: metricsFor(viewport.clientWidth || innerWidth, viewport.clientHeight || innerHeight, coarse.matches, readSizes(), currentUiScale()),
    activeWin: undefined, currentView: "console", canvasLock: true, snapIdx: 0, movingWindow: false, serial: 0, recent: new Map(),
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
  // While the camera moves at a thumbnail scale the terminals hold their drawing (terminal.ts `setFrozen`).
  let terminalsFrozen = false;
  const freezeTerminals = (frozen: boolean): void => { if (frozen === terminalsFrozen) return; terminalsFrozen = frozen; options.adapters.sessions.freeze?.(frozen); };
  (cx as { camera: Camera }).camera = new Camera(viewport, world, {
    onTransform: (t) => backdrop?.update(t),
    onLabelScale: (inv) => { for (const c of cx.views.values()) c.label.style.setProperty("--label-inv", inv); },
    onLod: () => { cx.pill.paint(); cx.visibility.lodChanged(); },
    onBand: () => cx.view.hideSummary(),
    onFrame: () => { cx.invalidate(); cx.memory.cull(); if (cx.details?.isOpen()) cx.details.close(true); if (cx.camera.isMoving && cx.camera.lod === "thumb") freezeTerminals(true); },
    onRest: () => { cx.mesh?.redraw(); cx.nav.updateCurrentView(); freezeTerminals(false); cx.pill.settled(); cx.nav.settled(); },
    onFlight: () => { cx.view.hideSummary(); hideTips(); },
  });
  (cx as { flip: Ctx["flip"] }).flip = createFlip(() => cx.camera.cam.z, () => cx.invalidate());

  cx.memory = createMemory(cx, backdrop);
  // The Docs view is the server's, never the person's layout (views/docs.ts): it is not part of the saved document.
  cx.store = createDocumentSync(cx, (id) => id !== "docs" && (options.persisted?.(id) ?? true));
  cx.nav = createNav(cx);
  cx.view = createViews(cx);
  cx.win = createWindows(cx);
  cx.float = createFloatHandle(cx);
  if (options.adapters.details) cx.details = createDetailsHandle(cx, options.adapters.details);
  cx.inputLock = createInputLock(cx);
  if (options.adapters.inventory) cx.sessionUi = createSessionHooks(cx);
  cx.visibility = createVisibility(cx);
  cx.pill = createPill(cx);
  cx.viewList = createViewList(cx);
  cx.tree = createTree(cx);
  if (options.adapters.mesh) cx.mesh = createMesh(cx, options.adapters.mesh);
  if (options.adapters.sharing) cx.sharing = createSharingHandle(cx, options.adapters.sharing);
  const appWindowsAdapter = options.adapters.appWindows;
  let appWindowsLoading: Promise<AppWindowsHook | undefined> | undefined;
  // Keep this bridge small in the deferred canvas; the picker, inventory, body and frame shaping stay on demand.
  const loadAppWindows = (): Promise<AppWindowsHook | undefined> => {
    if (!appWindowsAdapter || cx.signal.aborted || !appWindowsAdapter.available()) return Promise.resolve(undefined);
    if (!appWindowsLoading) {
      appWindowsLoading = onDemand(() => import("./appwin/hook.on-demand")).then((module) => {
        if (cx.signal.aborted) return undefined;
        return module.installAppWindowsRuntime(cx, appWindowsAdapter);
      }).catch(() => {
        appWindowsLoading = undefined;
        if (!cx.signal.aborted && appWindowsAdapter.available()) {
          cx.toast.show({ message: "Could not load app windows. Try again.", tone: "error", duration: 5000 });
        }
        return undefined;
      });
    }
    return appWindowsLoading;
  };
  const warmAppWindows = (): void => {
    if (appWindowsAdapter?.available()) whenIdle(() => { void loadAppWindows(); });
  };
  const offAppWindows = appWindowsAdapter?.onChange(() => {
    if (cx.signal.aborted) return;
    if (appWindowsAdapter.available()) warmAppWindows();
  });
  if (appWindowsAdapter) {
    cx.appWindows = {
      load: loadAppWindows,
      dispose() {
        offAppWindows?.();
        void appWindowsLoading?.then((runtime) => runtime?.dispose());
      },
    };
    warmAppWindows();
  }
  cx.toolbar = createToolbar(cx);
  installGestures(cx);
  const removeShortcuts = installShortcuts(cx);
  const removePalette = installPalette(cx);

  // Relayout: the canvas area changed size (a rotation, the keyboard, a window resize) or the window-size setting did
  // (Settings -> Window Sizes, applied live with the layout spring). Views are as tall as the area, and a column the
  // person never resized follows the default width. The keyboard changes only the height: the width, and so the
  // columns of every terminal, stay (D191).
  let lastW = 0, lastH = 0, animatingUntil = 0;
  const relayout = (animate: boolean): void => {
    const sizes = readSizes();
    setEdge(sizes);
    const w = viewport.clientWidth, h = viewport.clientHeight;
    lastW = w; lastH = h;
    cx.camera.resized();
    backdrop?.measure();
    const previous = state.metrics;
    const next = metricsFor(w, h, coarse.matches, sizes, currentUiScale());
    if (next.colW === previous.colW && next.peekW === previous.peekW && next.clh === previous.clh && next.narrow === previous.narrow && next.minW === previous.minW && next.maxW === previous.maxW && next.scale === previous.scale) {
      // Nothing about the windows changed (the area did): keep the framing centred, unless a flight is under way.
      if (performance.now() >= animatingUntil) { if (cx.camera.target && cx.views.size) cx.camera.set(cx.camera.target()); else cx.camera.apply(true); }
      return;
    }
    const first = animate ? [...cx.views.values()].map((c) => cx.flip.measure(cx.flip.targets(c.colsEl))) : [];
    state.metrics = next;
    world.style.setProperty("--clh", `${next.clh}px`);
    for (const c of cx.views.values()) cx.view.fitWidths(c, previous);
    for (const c of cx.views.values()) cx.view.geometry(c);
    for (const c of cx.views.values()) for (const rec of c.wins.values()) rec.binding?.refit();
    // Reflow changes each view's drawn footprint; settle the display geometry before framing the canvas. This keeps
    // saved shared cells intact while preventing width changes from leaving overlapping views (D178, D309).
    const anchor = cx.views.has(state.currentView) ? state.currentView : cx.views.keys().next().value;
    if (anchor) cx.view.settle(anchor, undefined, true);
    if (animate) {
      first.forEach((m) => cx.flip.play(m, true));
      animatingUntil = performance.now() + 700;
      const target = cx.camera.target;
      if (target) cx.camera.flyTo(target);
    } else if (cx.camera.target && cx.views.size) cx.camera.set(cx.camera.target()); else cx.camera.apply(true);
    // A new layout (wider windows) must not leave the window the person is on out of view: frame it again.
    const on = state.activeWin;
    if (on && on.owner.view.id === state.currentView && on.owner.view.cols.some((col) => col.group !== undefined)) cx.nav.focusWindow(on, !animate);
  };
  const ro = new ResizeObserver(() => {
    if (viewport.clientWidth === lastW && viewport.clientHeight === lastH) return;
    relayout(false);
  });
  window.addEventListener(SIZE_EVENT, () => relayout(true), { signal: events.signal });
  // The UI size: windows grow with it, live, with the same layout spring as a change of Window Sizes (#283).
  window.addEventListener(UI_SIZE_EVENT, () => relayout(true), { signal: events.signal });
  // Attaching or removing a trackpad or mouse flips the pointer kind without a resize; the touch minimum
  // column (D309) must follow it, or a fine pointer keeps the wide touch columns.
  coarse.addEventListener("change", () => relayout(true), { signal: events.signal });
  ro.observe(viewport);
  cx.camera.start();
  warmSplit(cx);

  // A hidden page also releases its big surfaces (memory.ts) and must not lose the last edit.
  const onHide = (): void => { if (document.hidden) cx.store.flush(); };
  document.addEventListener("visibilitychange", onHide, { signal: events.signal });
  window.addEventListener("pagehide", () => cx.store.flush(), { signal: events.signal });

  // What the frame meter records when a frame drops (counts and names only; read at drop time, never per frame).
  setPerfProbe(() => {
    let windows = 0;
    for (const c of cx.views.values()) windows += c.wins.size;
    return { view: state.currentView, zoom: Math.round(cx.camera.cam.z * 1000) / 1000, lod: cx.camera.lod, band: cx.camera.band, windows, windowsInView: cx.views.get(state.currentView)?.wins.size ?? 0, canvasLock: state.canvasLock };
  });

  return {
    cx,
    setViews(models) {
      cx.inputLock.reset();
      cx.view.clear();
      state.metrics = metricsFor(viewport.clientWidth || innerWidth, viewport.clientHeight || innerHeight, coarse.matches, readSizes(), currentUiScale());
      cx.camera.resized();
      world.style.setProperty("--clh", `${state.metrics.clh}px`);
      for (const v of typeof models === "function" ? models(state.metrics) : models) cx.views.set(v.id, cx.view.build(v));
      cx.tree.render();
      cx.pill.paint();
      cx.toolbar.update();
      // Views that are not the scene's own (the Docs view) come back after the scene replaced every view.
      window.dispatchEvent(new CustomEvent("tracer:canvas-views"));
    },
    flush: () => cx.store.flush(),
    dispose() {
      events.abort();
      setPerfProbe(undefined);
      ro.disconnect();
      removePalette();
      removeShortcuts();
      cx.store.dispose();
      cx.toolbar.dispose();
      cx.tree.dispose();
      cx.sessionUi?.dispose();
      cx.appWindows?.dispose();
      cx.pill.dispose();
      cx.sharing?.dispose();
      cx.mesh?.dispose();
      cx.float.dispose();
      cx.details?.dispose();
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
