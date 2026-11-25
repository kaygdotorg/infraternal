// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Finds what is under every glass surface and makes its text readable there (D365), with one mechanism for all of them.
 *
 * The theme knows the colours of its own page, but not what a card really sits over: a remote app window's picture, a
 * video, an image, or a terminal whose screen has a bright status bar under the card. {@link watchGlassSurfaces}, started
 * once from `applyTheme`, watches the document for glass surfaces (the same elements the glass rules in `themes.ts` style:
 * popovers, menus, cards, the palette, toasts, tooltips, the sidebar, pills) as they appear, show and move, and looks at
 * what is under each. Nothing has to opt in, and a surface mounted anywhere in the document is covered.
 *
 * What it does with the answer:
 *  - over a picture (a `video`, an `img` of 64 px or more, the app-window stream canvas `canvas.aw-surface`, or anything
 *    marked `data-glass-picture`): the surface takes the static floor at once (`data-glass-under="picture"`), which is
 *    correct over any picture, and the sampler (`glass-adapt.on-demand.ts`) lightens it where the sampled picture allows;
 *  - over a registered terminal grid ({@link registerGlassGrid}): the surface takes the static floor at once
 *    (`data-glass-under="terminal"`), and the tracker (same chunk) reads the real cell colours under the card, blurs them
 *    the way the glass does, and gives the surface exactly the opacity and text colours that content needs;
 *  - over neither: the themed set applies and the surface carries no mark.
 *
 * Where it looks. At the corners, edge midpoints and centre of the surface's box, below it in paint order, by hit
 * test. The test does not depend on the surface being hit-testable itself: a card that is `pointer-events: none` while it
 * opens is still found (it is skipped by identity, not by position in the stack). A picture with `pointer-events: none`
 * is not seen by a hit test and is not covered.
 *
 * When. In the animation-frame step after the mutation callback saw the surface (before that frame's style, layout and first
 * paint, and never inside an input handler's own task), when it is shown (`hidden`, `data-open`), and every 250 ms while the page is changing, but only re-evaluated when its box moved or resized. That
 * is a handful of box reads a few times a second, never per frame, and never in an input handler. An idle page keeps no
 * timer (the motion audit holds an idle screen to none): the checks stop after {@link QUIET_ROUNDS} rounds in which nothing
 * moved, and start again on a DOM change, input, scroll, resize or the end of an animation, which is everything that can move a
 * card. A card that moves with none of those would be missed until the next one; none does.
 *
 * This module is an on-demand chunk (D188), requested by the first `applyTheme` (the start of boot, in parallel with the first
 * paint) and by each terminal as it opens, so none of the glass code is on the critical path. It starts by scanning the surfaces
 * already in the document, so one that appeared before it arrived is covered when it does. The adaptive code (with the contrast
 * solver and the rules, requested by `applyTheme`) and the terminal's cell reader are chunks of their own.
 * A surface marked here before they arrive is covered as soon as they do: the rules in `glass-rules.on-demand.ts` are keyed on
 * the mark, not on when it was written.
 */
import { TINT_USERS } from "./themes";

/** What counts as a picture; see the module note. */
const PICTURE = "video, img, canvas.aw-surface, [data-glass-picture]";
/** Everything a surface could be over and care about: a picture, or a registered terminal screen. */
const CANDIDATES = `${PICTURE}, [data-glass-grid]`;
/**
 * The box a surface is given while nothing it could be over exists: not a real box, so the first {@link recheck} reads the
 * surface's true box (after a frame has laid it out, when the read costs nothing) and looks under it then.
 */
const PENDING = "pending";
/** The smallest side of an image that counts as a picture, so icons do not. */
const MIN_SIDE = 64;
/** How often an on-screen surface is checked for having moved, in milliseconds. */
const WATCH_MS = 250;
/** How many checks in a row may find nothing moved before the checking stops until something wakes it (one second). */
const QUIET_ROUNDS = 4;

/**
 * The cells of a terminal under one rectangle, as the colour each cell shows to the glass: its background (the
 * foreground when inverted), with a share of its text colour mixed in for cells that hold a character.
 */
export interface GlassGridRead {
  /** Client position of the top left corner of the first cell, in px. */
  x: number; y: number;
  /** One cell's size in px. */
  cellW: number; cellH: number;
  /** Cells across and down. */
  cols: number; rows: number;
  /** `rows * cols * 3` bytes, red green blue per cell, row by row. */
  rgb: Uint8Array;
}

/** A screen of cells the glass can read (a terminal), registered with {@link registerGlassGrid}. */
export interface GlassGrid {
  /** The element that holds the screen; a surface over it is over the grid. */
  element: HTMLElement;
  /** The cells under `rect` (client px), or `null` when the screen cannot be read now. `base` is what a default-background cell stands for. */
  read(rect: DOMRect, base: readonly [number, number, number]): GlassGridRead | null;
  /** Calls `listener` after the screen changes (each render pass); returns the way to stop. Called only while a card is open over it. */
  subscribe(listener: () => void): () => void;
}

/** The grid registered on an element. */
const grids = new WeakMap<Element, GlassGrid>();

/**
 * Registers a terminal's screen so glass over it is solved from its real cells. Returns the way to unregister. The first
 * registration starts loading the adaptive chunk when the page is idle, so the first card over a terminal has it.
 */
export function registerGlassGrid(grid: GlassGrid): () => void {
  grids.set(grid.element, grid);
  grid.element.dataset.glassGrid = "";
  const idle = (window as { requestIdleCallback?: (cb: () => void) => void }).requestIdleCallback ?? ((cb: () => void) => window.setTimeout(cb, 2000));
  // A failed load is harmless here: the same import is made, and caught, when a card first needs the trackers.
  idle(() => void import("./glass-adapt.on-demand").catch(() => undefined));
  // A card that opened before this screen registered (a terminal that mounts or reconnects under an open card) looks again now,
  // instead of waiting for it to move.
  queueMicrotask(() => { const near = candidates(); for (const [surface, box] of watched) if (box) evaluate(surface, near); });
  return () => {
    grids.delete(grid.element);
    delete grid.element.dataset.glassGrid;
    // Cards that were tracking this screen look again: with the grid gone they fall back to the themed set or another thing under them.
    { const near = candidates(); for (const [surface, box] of watched) if (box && tracking.get(surface)?.key === grid.element) evaluate(surface, near); }
  };
}

/**
 * Every element in the document that a surface could be over: a picture or a terminal screen. One query by selector, which
 * reads no layout, so it is safe inside an input handler's task. Callers that look under several surfaces ask once and share it.
 */
const candidates = (): Element[] => [...document.querySelectorAll(CANDIDATES)];

/** What is under a surface. */
interface Found { picture?: HTMLElement; grid?: GlassGrid }

/**
 * Finds a picture or a registered grid under `surface` (see the module note for where and how). `near` is every candidate
 * in the document ({@link candidates}). A picture or a screen paints inside its own box, so when no candidate's box touches the
 * surface's box nothing can be under it, and the nine hit tests (about 3 ms in the Mesh view's confirm click, #580) are skipped.
 */
function whatIsUnder(surface: HTMLElement, near: readonly Element[]): Found {
  const r = surface.getBoundingClientRect();
  if (r.width < 8 || r.height < 8) return {};
  const touches = near.some((c) => { const b = c.getBoundingClientRect(); return b.right > r.left && b.left < r.right && b.bottom > r.top && b.top < r.bottom; });
  if (!touches) return {};
  const found: Found = {};
  for (const fx of [0.02, 0.5, 0.98]) for (const fy of [0.02, 0.5, 0.98]) {
    const x = r.left + Math.min(r.width - 2, Math.max(2, r.width * fx)), y = r.top + Math.min(r.height - 2, Math.max(2, r.height * fy));
    for (const el of document.elementsFromPoint(x, y)) {
      // Skipped by identity, not by position: a surface that is not hit-testable yet is simply absent from the stack.
      if (el === surface || surface.contains(el) || el.classList.contains("ui-glass-bed")) continue;
      const picture = el.closest<HTMLElement>(PICTURE);
      if (picture && !(picture.matches("img") && (picture.clientWidth < MIN_SIDE || picture.clientHeight < MIN_SIDE))) return { picture };
      const host = el.closest<HTMLElement>("[data-glass-grid]");
      const grid = host && grids.get(host);
      if (grid) found.grid = grid;
    }
  }
  return found;
}

/** Whether the failed tracker load has been reported already. */
let trackerWarned = false;

/** What a surface is tracking: the thing it is over, how to nudge the tracker, how to stop it, and its last box. */
interface Tracked { key: Element; refresh(): void; stop(): void }
/** What each evaluated surface is over. */
const tracking = new WeakMap<HTMLElement, Tracked>();
/** Every glass surface seen and not yet gone, with its last box as text. */
const watched = new Map<HTMLElement, string>();
/** The timer that rechecks on-screen surfaces; zero while the page is idle. */
let timer = 0;
/** Checks in a row that found no surface moved; {@link recheck} stops at {@link QUIET_ROUNDS}. */
let quiet = 0;

/** The box of `surface` as a comparable string, or an empty string when it is not on screen. */
function boxOf(surface: HTMLElement): string {
  if (!surface.isConnected || surface.hidden) return "";
  const r = surface.getBoundingClientRect();
  return r.width < 8 || r.height < 8 ? "" : `${Math.round(r.left)},${Math.round(r.top)},${Math.round(r.width)},${Math.round(r.height)}`;
}

/** Stops whatever `surface` is tracking and clears its mark. */
function release(surface: HTMLElement): void {
  tracking.get(surface)?.stop();
  tracking.delete(surface);
  delete surface.dataset.glassUnder;
}

/** Looks under `surface` and starts, keeps or stops its tracking to match. */
function evaluate(surface: HTMLElement, near: readonly Element[]): void {
  const { picture, grid } = whatIsUnder(surface, near);
  const key = picture ?? grid?.element;
  const before = tracking.get(surface);
  if (!key) { release(surface); return; }
  surface.dataset.glassUnder = picture ? "picture" : "terminal";
  if (before && before.key === key) { before.refresh(); return; }
  before?.stop();
  // The adaptive chunk loads on first use; `cancelled` covers a surface that moved off, closed or was replaced while it loaded.
  let cancelled = false;
  let inner: { refresh(): void; stop(): void } | undefined;
  tracking.set(surface, { key, refresh: () => inner?.refresh(), stop: () => { cancelled = true; inner?.stop(); } });
  void import("./glass-adapt.on-demand").then((m) => {
    if (cancelled || !surface.isConnected) return;
    inner = picture ? m.trackPicture(surface, picture) : m.trackGrid(surface, grid!);
    inner?.refresh();
    // Without the trackers the surface stays on the static floor, which is correct over anything; say so once and do not retry.
  }).catch((error: unknown) => { if (!trackerWarned) { trackerWarned = true; console.warn("infraternal: the glass trackers did not load; glass uses its static floor", error); } });
}

/** Rechecks every watched surface that moved; drops those that are gone; stops itself when none are on screen. */
function recheck(): void {
  timer = 0;
  let moved = false;
  const near = candidates();
  for (const [surface, last] of watched) {
    const box = boxOf(surface);
    if (!surface.isConnected) { release(surface); watched.delete(surface); continue; }
    if (box === last) continue;
    moved = true;
    watched.set(surface, box);
    if (box) evaluate(surface, near); else release(surface);
  }
  quiet = moved ? 0 : quiet + 1;
  if (watched.size && quiet < QUIET_ROUNDS) timer = window.setTimeout(recheck, WATCH_MS);
}

/** Starts the checks if they are stopped, and counts the quiet rounds afresh; the one place that arms {@link timer}. */
function wake(): void {
  quiet = 0;
  if (!timer && watched.size) timer = window.setTimeout(recheck, WATCH_MS);
}

/**
 * Starts watching one glass surface: looks under it now and keeps it checked. `near` is {@link candidates}; with none in the
 * document the surface is only noted (its box is read by the next recheck), so a surface that appears inside an input
 * handler's task forces no layout there.
 */
function watch(surface: HTMLElement, near: readonly Element[]): void {
  if (!near.length) {
    if (!watched.has(surface)) watched.set(surface, PENDING);
    wake();
    return;
  }
  const box = boxOf(surface);
  if (!watched.has(surface) || watched.get(surface) !== box) {
    watched.set(surface, box);
    if (box) evaluate(surface, near); else release(surface);
  }
  wake();
}

/** Whether the watcher has been started. */
let started = false;

/**
 * Starts the one watcher for every glass surface in the document (see the module note). Safe to call again; `applyTheme`
 * requests it. It does nothing where there is no document. Sets `data-glass-watching` on the root once it is looking, which the specs wait for.
 */
export function watchGlassSurfaces(): void {
  if (started || typeof MutationObserver === "undefined" || !document.body) return;
  started = true;
  document.documentElement.setAttribute("data-glass-watching", "");
  /**
   * The nodes the observer has seen and the frame has not looked at yet. The callback only notes them: the looking reads
   * layout (the box of each surface, then the boxes of its candidates), and a callback runs as a microtask of the task that
   * changed the DOM, so inside an input handler's task it would pay for every pending style and layout change at once (about 9
   * ms on the Mesh view's confirm click, #580). {@link drain} looks in the next animation frame's callbacks, which still
   * run before that frame's style, layout and first paint, so a surface that a handler or a timer shows is marked before
   * it is first drawn. The one case that is a frame late: a surface shown inside another animation-frame callback (the
   * frame is already past the callbacks when the observer reports it), which is almost always a fade-in from invisible.
   */
  const noted = new Set<Node>();
  let frame = 0;
  /** Watches `node` if it is a glass surface, and every surface inside it; `near` gives the candidates when the first one needs them. */
  const consider = (node: Node, near: () => readonly Element[]): void => {
    if (!(node instanceof Element) || !node.isConnected) return;
    if (node.matches(TINT_USERS)) watch(node as HTMLElement, near());
    for (const inner of node.querySelectorAll<HTMLElement>(TINT_USERS)) watch(inner, near());
  };
  /** Looks at every noted node once; the candidates are asked for at the first surface and shared by the rest. */
  const drain = (): void => {
    frame = 0;
    let found: readonly Element[] | undefined;
    const near = (): readonly Element[] => (found ??= candidates());
    const nodes = [...noted];
    noted.clear();
    for (const node of nodes) consider(node, near);
  };
  new MutationObserver((records) => {
    for (const record of records) {
      if (record.type === "childList") record.addedNodes.forEach((node) => { if (node instanceof Element) noted.add(node); });
      else noted.add(record.target);
    }
    if (noted.size && !frame) frame = requestAnimationFrame(drain);
  }).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ["hidden", "data-open"] });
  consider(document.body, candidates);
  // Whatever can move a card without touching the DOM: input and scrolling (a drag, a pan), a resize, and a transition or animation
  // ending (a fly settles). Each only arms the check timer if it is stopped; passive and in the capture phase, so it sees them all
  // and never delays one.
  const options = { capture: true, passive: true } as const;
  for (const type of ["pointerdown", "pointermove", "pointerup", "wheel", "keydown", "scroll", "transitionend", "animationend"]) document.addEventListener(type, wake, options);
  window.addEventListener("resize", wake, { passive: true });
}
