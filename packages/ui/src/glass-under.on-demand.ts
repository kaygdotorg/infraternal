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
 * When. In the mutation callback that sees the surface (a microtask, before the first paint), when it is shown (`hidden`,
 * `data-open`), and every 250 ms for as long as it is on screen, but only re-evaluated when its box moved or resized. That
 * is a handful of box reads a few times a second, never per frame, and never in an input handler.
 *
 * This module is an on-demand chunk (D188), requested by the first `applyTheme` (the start of boot, in parallel with the first
 * paint) and by each terminal as it opens, so none of the glass code is on the critical path. It starts by scanning the surfaces
 * already in the document, so one that appeared before it arrived is covered when it does. The adaptive code, the contrast
 * solver and the terminal's cell reader are chunks of their own (the adaptive one is prefetched when the first terminal registers).
 * A surface marked here before they arrive is covered as soon as they do: the rules in `glass-rules.on-demand.ts` are keyed on
 * the mark, not on when it was written.
 */
import { TINT_USERS } from "./themes";

/** What counts as a picture; see the module note. */
const PICTURE = "video, img, canvas.aw-surface, [data-glass-picture]";
/** The smallest side of an image that counts as a picture, so icons do not. */
const MIN_SIDE = 64;
/** How often an on-screen surface is checked for having moved, in milliseconds. */
const WATCH_MS = 250;

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
  idle(() => void import("./glass-adapt.on-demand"));
  // A card that opened before this screen registered (a terminal that mounts or reconnects under an open card) looks again now,
  // instead of waiting for it to move.
  queueMicrotask(() => { for (const [surface, box] of watched) if (box) evaluate(surface); });
  return () => {
    grids.delete(grid.element);
    delete grid.element.dataset.glassGrid;
    // Cards that were tracking this screen look again: with the grid gone they fall back to the themed set or another thing under them.
    for (const [surface, box] of watched) if (box && tracking.get(surface)?.key === grid.element) evaluate(surface);
  };
}

/** What is under a surface. */
interface Found { picture?: HTMLElement; grid?: GlassGrid }

/** Finds a picture or a registered grid under `surface` (see the module note for where and how). */
function whatIsUnder(surface: HTMLElement): Found {
  const r = surface.getBoundingClientRect();
  if (r.width < 8 || r.height < 8) return {};
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

/** What a surface is tracking: the thing it is over, how to nudge the tracker, how to stop it, and its last box. */
interface Tracked { key: Element; refresh(): void; stop(): void }
/** What each evaluated surface is over. */
const tracking = new WeakMap<HTMLElement, Tracked>();
/** Every glass surface seen and not yet gone, with its last box as text. */
const watched = new Map<HTMLElement, string>();
/** The timer that rechecks on-screen surfaces. */
let timer = 0;

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
function evaluate(surface: HTMLElement): void {
  const { picture, grid } = whatIsUnder(surface);
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
  });
}

/** Rechecks every watched surface that moved; drops those that are gone; stops itself when none are on screen. */
function recheck(): void {
  timer = 0;
  for (const [surface, last] of watched) {
    const box = boxOf(surface);
    if (!surface.isConnected) { release(surface); watched.delete(surface); continue; }
    if (box === last) continue;
    watched.set(surface, box);
    if (box) evaluate(surface); else release(surface);
  }
  if (watched.size) timer = window.setTimeout(recheck, WATCH_MS);
}

/** Starts watching one glass surface: looks under it now and keeps it checked. */
function watch(surface: HTMLElement): void {
  const box = boxOf(surface);
  if (!watched.has(surface) || watched.get(surface) !== box) {
    watched.set(surface, box);
    if (box) evaluate(surface); else release(surface);
  }
  if (!timer) timer = window.setTimeout(recheck, WATCH_MS);
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
  const consider = (node: Node): void => {
    if (!(node instanceof Element)) return;
    if (node.matches(TINT_USERS)) watch(node as HTMLElement);
    for (const inner of node.querySelectorAll<HTMLElement>(TINT_USERS)) watch(inner);
  };
  new MutationObserver((records) => {
    for (const record of records) {
      if (record.type === "childList") record.addedNodes.forEach(consider);
      else consider(record.target);
    }
  }).observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ["hidden", "data-open"] });
  consider(document.body);
}
