/**
 * Views: building a view's elements, sizing it on the grid, pushing neighbours aside, and the tap on a view's label. The
 * view's other interactions under the pointer (the hover card when zoomed out, dragging a view by its label) are
 * `view-pointer.on-demand.ts` (D188, #322).
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
import { triggeredByKeyboard } from "../../../../../packages/ui/src/input-source";
import type { Ctx, ViewRec } from "../context";
import { columnEls, setColumnWidth } from "../layout/column-els";
import { MARGIN, boxOf, contentSize, defaultWidth, isDefaultWidth, resolve, type Box, type Metrics, type Rect } from "../layout/geometry";
import type { ColumnModel, ViewId, ViewModel, WindowModel } from "../model/types";
import { el } from "../dom";
import { hostNote, LOCKED_NOTE } from "../host-note";
import { onDemand, whenIdle } from "../../on-demand";
import type { EarlyPress, ViewPointer } from "./view-pointer.on-demand";
import { restPx } from "../springs";
import { viewIcon } from "./icons";
import { groupsLoaded, loadGroups, type Groups } from "../layout/groups-handle";


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
  /**
   * Gives the columns the person never resized the default width for how many columns the view has: the full phone width
   * alone, narrower with neighbours so a slice of each peeks in at the screen edge (TASTE). `was` is the metrics the columns'
   * widths came from (a resize or a setting changed them), the current ones by default. Callers animate the change with a
   * FLIP around it, as they do for any other reflow.
   */
  fitWidths(c: ViewRec, was?: Metrics): void;
  /** After a view changed size: push neighbours aside; display-only placement keeps saved cells intact. */
  settle(fixedId: ViewId, at?: { x: number; y: number }, displayOnly?: boolean): void;
  paintEmpty(c: ViewRec): void;
  /** Rebuilds a view from its model, in place in the order. */
  replace(id: ViewId): void;
  /** Adds a view next to the others (right, or below on a phone) before `beforeId`, never over anything. */
  addBeside(view: ViewModel, beforeId?: ViewId): ViewRec;
  /** Removes a view and everything in it. */
  remove(c: ViewRec): void;
  /** Removes every view. */
  clear(): void;
  /** Takes the hover card down (a no-op until the pointer module has loaded: there is no card before it). */
  hideSummary(instant?: boolean): void;
  dispose(): void;
}

/**
 * Makes the views module for the canvas `cx`: builds each view, lays them out in the world and keeps them from overlapping.
 * A view that moves glides to its new place on the ease-out curve in 280 ms.
 */
export function createViews(cx: Ctx): ViewsModule {
  const { viewport, world, overlay, signal, camera, state, views } = cx;

  const contentRect = (c: ViewRec): Rect => ({ x: c.x + MARGIN.l, y: c.y + MARGIN.t, ...contentSize(c.view, state.metrics) });
  const boxes = (): Box[] => [...views.values()].map((c) => boxOf(c.view, state.metrics));
  const frameOf = (c: ViewRec): Rect => {
    const r = contentRect(c);
    return { x: r.x - 16, y: r.y - 16, w: r.w + 32, h: r.h + 32 };
  };

  const newCol = (col: ColumnModel): HTMLElement => {
    const colEl = el("div", "cl-col");
    colEl.dataset.id = col.id;
    setColumnWidth(colEl, col.w, state.metrics);
    return colEl;
  };


  // ---- what a view does under the pointer (view-pointer.on-demand.ts) -------------------------------------------------
  // The module is fetched when the browser is idle after the canvas is up, and when a pointer first reaches a label. Until
  // it has arrived a tap on a label still flies to the view (decided here, with no wait), and a press that turns into a drag
  // is handed over when the module comes, to continue from the pointer's latest position. A press released before it came
  // starts no drag. A hover has no card to show before the module is there; the pointer still over a label when it arrives gets it then.
  let pointer: ViewPointer | undefined;
  let pointerLoading: Promise<void> | undefined;
  let gone = false;
  const early = new Set<ViewRec>();
  let press: (EarlyPress & { c: ViewRec }) | undefined;
  const loadPointer = (): Promise<void> => pointerLoading ??= onDemand(() => import("./view-pointer.on-demand")).then((m) => {
    if (gone) return;
    const ready = m.createViewPointer(cx, { frameOf, boxes, settle });
    for (const c of early) ready.wire(c);
    pointer = ready;
    // A pointer that was already over a label as the module arrived gets its card now, not on its next entry.
    for (const c of early) if (c.label.matches(":hover") || c.region.matches(":hover")) ready.hover(c);
    early.clear();
    if (press) { const { c, ...began } = press; press = undefined; ready.press(c, began); }
  }, (error: unknown) => { pointerLoading = undefined; throw error; });
  const warmPointer = (): void => { void loadPointer().catch(() => undefined); };
  const wireView = (c: ViewRec): void => {
    if (pointer) { pointer.wire(c); return; }
    early.add(c);
    c.label.addEventListener("pointerenter", warmPointer, { signal });
    c.region.addEventListener("pointerenter", warmPointer, { signal });
    c.label.addEventListener("pointerdown", (e) => {
      if (pointer || e.button !== 0) return;
      e.preventDefault();
      c.label.setPointerCapture(e.pointerId);
      press = { c, id: e.pointerId, x0: e.clientX, y0: e.clientY, x: e.clientX, y: e.clientY };
      warmPointer();
    }, { signal });
    c.label.addEventListener("pointermove", (e) => { if (!pointer && press?.id === e.pointerId) { press.x = e.clientX; press.y = e.clientY; } }, { signal });
    const end = (e: PointerEvent): void => {
      if (pointer || press?.id !== e.pointerId) return;
      const began = press;
      press = undefined;
      if (Math.hypot(began.x - began.x0, began.y - began.y0) < 6) cx.nav.flyView(c.view.id);
    };
    c.label.addEventListener("pointerup", end, { signal });
    c.label.addEventListener("pointercancel", end, { signal });
  };
  whenIdle(warmPointer, 500);

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
    const POS = { visualDuration: 0.28 } as const;
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
      // An already-loaded graph lays out synchronously and may settle this view.
      // Its identity must be registered before layout resolves the fixed view.
      views.set(view.id, c);
      cx.mesh?.buildGraph(c);
    }
    // A view that declares row groups (D212: Settings, one row of windows for each component) is arranged as its model says, as a saved layout with
    // groups is: at once when the grouped module is already here, and when it arrives otherwise. Until then it shows as plain columns.
    // (The first `geometry` below reads the plain columns back into `view.cols`, which has no groups yet: the declared ones are kept here.)
    const declared = view.cols;
    const rows = view.layout === "tiled" && declared.some((col) => col.group !== undefined);
    const arrangeRows = (g: Groups): void => { g.applyCols(cx, c, declared); geometry(c); settle(view.id, undefined, true); cx.tree.render(); };
    const here = rows ? groupsLoaded() : undefined;
    if (here) here.applyCols(cx, c, declared);
    else if (rows) void loadGroups().then((g) => { if (views.get(view.id) === c) arrangeRows(g); });
    wireView(c);
    geometry(c);
    paintEmpty(c);
    world.insertBefore(root, overlay);
    place();
    return c;
  };

  function fitWidths(c: ViewRec, was: Metrics = state.metrics): void {
    if (c.view.layout !== "tiled") return;
    const cols = columnEls(c.colsEl);
    const target = defaultWidth(state.metrics, cols.length);
    // The UI size changed (and nothing else decides this): a column the person widened keeps its proportion to the default, so it
    // is as many times wider as the default became. Any other change of metrics leaves such a column at the width it has.
    const k = state.metrics.scale / (was.scale || 1);
    for (const colEl of cols) {
      // A column the person resized keeps its width (`user`), and so does one whose width is none of the defaults.
      if (!colEl.dataset.user && isDefaultWidth(Number(colEl.dataset.w), was) && !colEl.dataset.half) { setColumnWidth(colEl, target, state.metrics); continue; }
      // The floor can change with the screen (rotation, a keyboard) while the saved width stays: redraw at the new floor.
      if (Number(colEl.dataset.w)) setColumnWidth(colEl, k === 1 ? Number(colEl.dataset.w) : Math.round(Number(colEl.dataset.w) * k), state.metrics);
    }
  }

  function geometry(c: ViewRec): void {
    fitWidths(c);
    // Columns are the truth: read them back from the DOM so drags, resizes and moves persist, then make the DOM agree with
    // what was read (a group's grid, its bands and placements; D212).
    const grouped = groupsLoaded();
    if (c.view.layout === "tiled" && grouped && c.colsEl.querySelector(".cl-group")) {
      // A group's DOM exists only once the grouped module has run (layout/groups.on-demand.ts), so `groupsLoaded` is set.
      c.view.cols = grouped.readColumns(cx, c);
      grouped.arrange(cx, c, c.view.cols);
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

  /**
   * Pushes the views that overlap the one that stays put clear of it, along the axis of least travel (D119).
   *
   * A touch screen draws columns wider than the layout saved (D309), so a console that grew past its saved footprint can sit
   * under a neighbour that a desktop placed right beside it. There the view on screen stays put (the camera is looking at it)
   * and the others move, at once and never animated: this runs when a layout arrives, and a view must not slide in from
   * where the desktop had it. How this device draws is not what the layout says. The saved position stays in `home`, which
   * is what a save writes (`toDocument`), so a phone never moves a view in the shared layout.
   * Incoming snapshots use the same display-only settlement on desktop: cached geometry and generated Settings
   * can also overlap newly restored content, without the person having moved a shared view.
   */
  function settle(fixedId: ViewId, at?: { x: number; y: number }, displayOnly = state.metrics.minW > 0): void {
    const local = displayOnly && !at;
    const trial = boxes().map((b) => (at && b.id === fixedId ? { ...b, x: at.x, y: at.y } : b));
    // On touch, the current view stays fixed as wider drawn columns push neighbours. Desktop display settlement visits
    // every overlap group in one resolver pass, keeping only the camera's current view fixed.
    const root = local && state.metrics.minW > 0 && views.has(state.currentView) ? state.currentView : fixedId;
    const next = resolve(trial, root, displayOnly);
    for (const c of views.values()) {
      const p = next.get(c.view.id);
      if (!p || (p.x === c.view.x && p.y === c.view.y)) continue;
      if (local) {
        c.view.home ??= { x: c.view.x, y: c.view.y };
        if (c.view.home.x === p.x && c.view.home.y === p.y) delete c.view.home;
      }
      c.view.x = p.x; c.view.y = p.y;
      // A key (a window opened by a chord or a palette row widens its view) moves the neighbours at once; a drag or a tap glides them (#427).
      const jump = local || triggeredByKeyboard();
      c.sx.set(p.x, jump); c.sy.set(p.y, jump);
    }
  }

  /**
   * The placeholder of a tiled view with no windows. It tells the truth about why and offers what can be done now: with no host
   * at all it says so and offers Add host; with a host but no window (the last shell ended) it says no window is open and offers
   * Open shell; a host that cannot connect only because the CA is locked is named, with the one tap that unlocks it.
   *
   * The server's own host is always one of `hosts` (an account with one added host has two), so Open shell is offered whenever a
   * host can be reached: it opens that host's shell when it is the only one, and otherwise the palette limited to "Open shell on
   * <host>" rows, so no host is ever out of reach because another exists (#500, J539). `mode` records which placeholder is on
   * screen, and the placeholder is rebuilt when it changes (a host is added, removed, locked or unlocked).
   */
  function paintEmpty(c: ViewRec): void {
    const isEmpty = c.view.layout === "tiled" && c.wins.size === 0;
    if (!isEmpty) { c.empty?.remove(); delete c.empty; return; }
    const hosts = cx.adapters.sessions.hosts().filter((host) => !host.state);
    const only = hosts.length === 1 ? hosts[0] : undefined;
    // Hosts that cannot connect only because the CA is locked (#500, J528): they stay listed, and this says why and offers the one tap.
    const locked = hosts.filter((host) => hostNote(cx, host) === "locked").map((host) => host.name);
    const canOpen = hosts.some((host) => host.online !== false);
    const mode = hosts.length === 0 ? "no-hosts" : `windows:${only?.id ?? "many"}:${canOpen ? "open" : "closed"}${locked.length ? `:locked:${locked.join(",")}` : ""}`;
    if (c.empty?.dataset.mode === mode) return;
    c.empty?.remove();
    const box = el("div", "cl-empty");
    box.dataset.mode = mode;
    const title = hosts.length === 0 ? "No hosts yet" : "No windows open";
    const hint = hosts.length === 0 ? "Add a host and its shell opens here."
      : locked.length ? `${locked.join(", ")} ${locked.length === 1 ? "is" : "are"} ${LOCKED_NOTE}.`
      : only ? `Open a shell on ${only.name} to pick up where you left off.` : "Open a shell on one of your hosts to pick up where you left off.";
    box.innerHTML = `<div class="cl-empty-slot" aria-hidden="true"></div><p class="cl-empty-title"></p><p class="cl-empty-hint"></p>`;
    box.querySelector(".cl-empty-title")!.textContent = title;
    box.querySelector(".cl-empty-hint")!.textContent = hint;
    const addHost = cx.adapters.addHost;
    const pill = (label: string, icon: string, run: () => void): HTMLButtonElement => {
      const button = el("button", "ui-pill cl-empty-add");
      button.type = "button";
      button.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${icon}</svg><span>${label}</span>`;
      button.addEventListener("click", run, { signal });
      box.append(button);
      return button;
    };
    if (canOpen) {
      pill("Open shell", '<path d="m5 8 4 4-4 4M12 16h7"/>', () => {
        if (only) cx.win.open(only.id);
        else void onDemand(() => import("../toolbar/palette-rows.on-demand")).then((m) => { if (!signal.aborted) cx.core.showPalette(m.openShellEntries(cx)); });
      });
    }
    if (locked.length) {
      pill("Unlock host connections", '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 7.5-2"/>', () => { void cx.adapters.authority?.unlock(); }).dataset.action = "unlock";
    } else if (hosts.length === 0 && addHost) {
      pill("Add host", '<path d="M12 5v14M5 12h14"/>', () => addHost());
    }
    c.content.append(box);
    c.empty = box;
  }

  // A host that joins or leaves while a view is empty changes what the placeholder should say.
  const offHosts = cx.adapters.sessions.onChange(() => { for (const c of views.values()) paintEmpty(c); });
  // The lock changes the same placeholder (a locked host says so and offers Unlock; unlocked, it offers a shell again).
  const offLock = cx.adapters.authority?.onChange(() => { for (const c of views.values()) paintEmpty(c); });
  signal.addEventListener("abort", () => { offHosts(); offLock?.(); }, { once: true });

  const disposeRec = (c: ViewRec): void => {
    for (const w of c.wins.values()) { w.stopResize?.(); cx.visibility.unwatch(w); w.binding?.dispose(); w.cleanup?.(); w.card.dispose(); }
    c.el.remove();
  };

  return {
    contentRect, frameOf, boxes, newCol, build, geometry, fitWidths, settle, paintEmpty,
    hideSummary: (instant) => pointer?.hideSummary(instant),
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
      pointer?.hideSummary();
      for (const c of views.values()) disposeRec(c);
      views.clear();
      state.activeWin = undefined;
    },
    dispose() {
      gone = true;
      pointer?.dispose();
    },
  };
}

