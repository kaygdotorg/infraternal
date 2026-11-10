/**
 * Direct resizing for a window card (D160): the one gesture engine every window on the canvas
 * shares. It owns the handles and pointer maths; the consumer owns the geometry.
 *
 * - Desktop (mouse, pen): eight invisible hit strips along the edges and corners of the card
 *   carry the platform's resize cursors. Dragging any of them resizes the window.
 * - Touch: a deliberate press-and-hold (450 ms) on the header reveals an outline and four
 *   corner grips; dragging a grip resizes, and a tap anywhere else (or Escape) ends the mode.
 *   Nothing is drawn until then, so a window at rest looks exactly like one without this.
 *
 * The engine does no layout of its own. For every gesture it asks the consumer for the start
 * geometry and limits once (`begin`), then hands over at most one frame per animation frame
 * (`apply`), computed from the pointer's total travel since the press, never from the last
 * move, so a missed frame cannot drift. `end` runs once on release: that is where a terminal
 * refits, never while the pointer moves.
 *
 * Edges map to geometry like this. A window sits at the top of its row with `top` of free
 * space above it. East and south change the size; west changes the width and reports
 * `shiftX` (the negative of the growth) so the consumer can hold the window's right edge
 * still on screen; north moves `top` and changes the height so the bottom edge stays put.
 *
 *   const resize = attachWindowResize(card, { begin, apply, end });
 *   resize.dispose();
 */
import type { WindowCard } from "./window-card";
import { Spring } from "./spring";
import { EASE_OUT } from "./motion";

/** An edge or corner handle: compass points, "n" for north (top). */
export type ResizeEdge = "n" | "e" | "s" | "w" | "ne" | "nw" | "se" | "sw";

/** Geometry and limits at the moment a gesture starts, in CSS pixels. */
export interface ResizeStart {
  width: number;
  height: number;
  /** Free space above the window in its row. */
  top: number;
  minWidth: number;
  minHeight: number;
  maxWidth: number;
  /** The row's full height: `top + height` may never exceed it. */
  areaHeight: number;
}

/** The geometry a gesture asks the host to apply. */
export interface ResizeFrame {
  width: number;
  height: number;
  top: number;
  /** How far the row must shift horizontally to keep the window's right edge still (west edges). */
  shiftX: number;
}

/**
 * What the consumer provides to {@link attachWindowResize}: the options in the first group, then `begin`, `apply` and `end`.
 * The engine only calls back; it never lays out the window itself.
 */
export interface WindowResizeHost {
  /**
   * Locks width / height to this ratio. A gesture then moves the window by one measure (the
   * scale), not by two independent sizes. Needs `centered` or the default left/top anchoring.
   */
  aspect?: number;
  /**
   * The window is anchored at its top centre and grows symmetrically: an east or west edge
   * follows the pointer 1:1, so the width changes by twice the pointer's travel. North edges
   * do nothing (the top is fixed).
   */
  centered?: boolean;
  /**
   * Past the minimum or maximum the size resists like rubber instead of stopping, and on release
   * it springs back to the limit without overshoot. Release always springs to rest;
   * with `snap` it rests on the nearest snap point.
   */
  rubber?: boolean;
  /**
   * Whether the touch press-and-hold also starts on the header's pill (default true). A host that
   * gives the pill its own long-press says false: the hold then starts only on the rest of the header.
   */
  holdOnPill?: boolean;
  /** Where a released size rests, within the limits (for example a default size it clings to). */
  snap?(frame: ResizeFrame): ResizeFrame;
  begin(): ResizeStart;
  /** Called at most once per animation frame while dragging; make one layout write. */
  apply(frame: ResizeFrame): void;
  /** Called once on release (or cancel). */
  end(): void;
  /** Called when the touch resize mode starts, so the consumer can drop competing gestures. */
  onTouchMode?(active: boolean): void;
}

/** The handle returned by {@link attachWindowResize}. `exitTouchMode()` hides the touch handles; `dispose()` removes the handles and listeners. */
export interface WindowResize {
  /** True while the touch handles are showing. */
  readonly touchMode: boolean;
  exitTouchMode(): void;
  dispose(): void;
}


/** Rubber-band resistance: past a limit the overshoot is damped and never exceeds `range` * 0.55. */
const damp = (over: number, range: number): number => (over * range * 0.55) / (range + 0.55 * Math.abs(over)) ;

/** The scale range an aspect-locked window may rest in: width and height limits together. */
export function aspectRange(start: ResizeStart, aspect: number): { min: number; max: number } {
  const maxHeight = start.areaHeight - start.top;
  return {
    min: Math.max(start.minWidth / start.width, start.minHeight / start.height),
    max: Math.min(start.maxWidth / start.width, maxHeight / start.height, start.maxWidth / aspect / start.height),
  };
}

/**
 * The frame for scale `k` of the start size, aspect locked. With `rubber`, a scale beyond the range
 * resists like rubber (shown past the limit, never past a fraction of it); without, it is clamped.
 */
export function aspectFrame(start: ResizeStart, aspect: number, k: number, rubber: boolean): ResizeFrame {
  const range = aspectRange(start, aspect);
  let scale = k;
  if (k > range.max) scale = rubber ? range.max + damp(k - range.max, 0.5) : range.max;
  else if (k < range.min) scale = rubber ? range.min - damp(range.min - k, 0.5) : range.min;
  const width = start.width * scale;
  return { width, height: width / aspect, top: start.top, shiftX: 0 };
}

/**
 * Springs from the frame a gesture ended on to its resting frame (the limit, a snap point, or
 * where it was let go), with a slight settle, calling `apply` each tick and `done` once at rest.
 * Interruptible by the next gesture through the returned cancel.
 */
export function settleResize(apply: (frame: ResizeFrame) => void, from: ResizeFrame, to: ResizeFrame, done: () => void): () => void {
  if (Math.abs(from.width - to.width) < 0.5 && Math.abs(from.height - to.height) < 0.5) { apply(to); done(); return () => undefined; }
  let cancelled = false;
  const spring = new Spring(0, (p) => {
    if (cancelled) return;
    const l = (a: number, b: number): number => a + (b - a) * p;
    if (p === 1) { apply(to); done(); return; }
    apply({ width: l(from.width, to.width), height: l(from.height, to.height), top: l(from.top, to.top), shiftX: l(from.shiftX, to.shiftX) });
  }, { visualDuration: 0.28 });
  spring.set(1);
  return () => { cancelled = true; spring.set(spring.value, true); };
}

const EDGES: ResizeEdge[] = ["n", "e", "s", "w", "ne", "nw", "se", "sw"];
/** How long (ms) a touch must be held on the header to start touch resizing. */
const HOLD_MS = 450;
/** How far (px) the finger may move during the hold before it counts as a scroll and cancels it. */
const HOLD_SLOP = 8;

/** Adds the resize handles to `card` and wires the gestures. */
export function attachWindowResize(card: WindowCard, host: WindowResizeHost): WindowResize {
  const root = card.root;
  const events = new AbortController();
  const signal = events.signal;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");

  for (const edge of EDGES) {
    const handle = document.createElement("div");
    handle.className = "ui-window-resize";
    handle.dataset.edge = edge;
    handle.setAttribute("aria-hidden", "true");
    root.append(handle);
  }

  let touchMode = false;
  const setTouchMode = (on: boolean): void => {
    if (touchMode === on) return;
    touchMode = on;
    if (on) root.dataset.resize = "touch"; else delete root.dataset.resize;
    host.onTouchMode?.(on);
  };

  // ---- the drag ----------------------------------------------------------------------------
  const drag = (event: PointerEvent, handle: HTMLElement): void => {
    const edge = handle.dataset.edge as ResizeEdge;
    const start = host.begin();
    const originX = event.clientX, originY = event.clientY;
    const bottom = start.top + start.height;
    handle.setPointerCapture(event.pointerId);
    root.dataset.resizing = edge;
    let latest = { x: originX, y: originY };
    let queued = 0;
    let latestFrame: ResizeFrame = { width: start.width, height: start.height, top: start.top, shiftX: 0 };
    // Aspect-locked, centred and rubber-band gestures: one scale, from how far the edge moved.
    const shaped = (dx: number, dy: number): ResizeFrame => {
      const side = edge.includes("e") ? 1 : edge.includes("w") ? -1 : 0;
      const down = edge.includes("s") ? 1 : 0;
      const sx = side ? (start.width + side * dx * (host.centered ? 2 : 1)) / start.width : 1;
      const sy = down ? (start.height + dy) / start.height : 1;
      if (host.aspect) {
        // One measure: whichever axis the pointer has moved further along drives the scale.
        const k = !side ? sy : !down ? sx : Math.abs(sx - 1) > Math.abs(sy - 1) ? sx : sy;
        return aspectFrame(start, host.aspect, k, !!host.rubber);
      }
      const width = clamp(start.width * sx, start.minWidth, start.maxWidth);
      const height = clamp(start.height * sy, start.minHeight, start.areaHeight - start.top);
      return { width, height, top: start.top, shiftX: 0 };
    };
    const clamp = (value: number, min: number, max: number): number => Math.min(max, Math.max(min, value));
    const flush = (): void => {
      queued = 0;
      const dx = latest.x - originX, dy = latest.y - originY;
      if (host.aspect || host.centered || host.rubber) { latestFrame = shaped(dx, dy); host.apply(latestFrame); return; }
      let width = start.width, height = start.height, top = start.top;
      if (edge.includes("e")) width = clamp(start.width + dx, start.minWidth, start.maxWidth);
      if (edge.includes("w")) width = clamp(start.width - dx, start.minWidth, start.maxWidth);
      if (edge.includes("s")) height = clamp(start.height + dy, start.minHeight, start.areaHeight - start.top);
      if (edge.includes("n")) {
        top = clamp(start.top + dy, Math.max(0, bottom - start.areaHeight), bottom - start.minHeight);
        height = bottom - top;
      }
      host.apply({ width, height, top, shiftX: edge.includes("w") ? start.width - width : 0 });
    };
    const move = (next: PointerEvent): void => {
      if (next.pointerId !== event.pointerId) return;
      latest = { x: next.clientX, y: next.clientY };
      if (!queued) queued = requestAnimationFrame(flush);
    };
    const finish = (next: PointerEvent): void => {
      if (next.pointerId !== event.pointerId) return;
      handle.removeEventListener("pointermove", move);
      handle.removeEventListener("pointerup", finish);
      handle.removeEventListener("pointercancel", finish);
      if (queued) { cancelAnimationFrame(queued); flush(); }
      delete root.dataset.resizing;
      if (!(host.aspect || host.centered || host.rubber)) { host.end(); return; }
      // Release: spring from where the pointer left it to where the window rests.
      let rest = latestFrame;
      if (host.aspect) {
        const range = aspectRange(start, host.aspect);
        rest = aspectFrame(start, host.aspect, Math.min(range.max, Math.max(range.min, latestFrame.width / start.width)), false);
      } else {
        rest = { ...latestFrame, width: clamp(latestFrame.width, start.minWidth, start.maxWidth), height: clamp(latestFrame.height, start.minHeight, start.areaHeight - start.top) };
      }
      if (host.snap) rest = host.snap(rest);
      if (reduced.matches) { host.apply(rest); host.end(); return; }
      settleResize((frame) => host.apply(frame), latestFrame, rest, () => host.end());
    };
    handle.addEventListener("pointermove", move);
    handle.addEventListener("pointerup", finish);
    handle.addEventListener("pointercancel", finish);
  };

  root.addEventListener("pointerdown", (event) => {
    const handle = (event.target as Element).closest<HTMLElement>(".ui-window-resize");
    if (!handle || event.button !== 0) return;
    // A finger only resizes through the grips the hold revealed.
    if (event.pointerType === "touch" && !touchMode) return;
    event.preventDefault();
    event.stopPropagation();
    drag(event, handle);
  }, { capture: true, signal });

  // ---- press and hold on the header (touch) ------------------------------------------------
  let hold: { id: number; x: number; y: number; timer: number; cue?: Animation | undefined } | undefined;
  const cancelHold = (): void => {
    if (!hold) return;
    window.clearTimeout(hold.timer);
    hold.cue?.cancel();
    hold = undefined;
  };
  let swallowClick = false;
  card.header.addEventListener("pointerdown", (event) => {
    if (event.pointerType !== "touch" || touchMode || hold) return;
    if (host.holdOnPill === false && (event.target as Element).closest(".ui-window-pill, .cl-port")) return;
    const press = { id: event.pointerId, x: event.clientX, y: event.clientY, timer: 0, cue: undefined as Animation | undefined };
    // The window leans in a little while the finger rests, so the hold reads as deliberate;
    // it settles back when the handles appear. Composited transform only, no fill.
    if (!reduced.matches) {
      press.cue = root.animate([{ transform: "none" }, { transform: "scale(0.985)" }],
        { duration: HOLD_MS, delay: 120, easing: EASE_OUT, fill: "forwards" });
    }
    press.timer = window.setTimeout(() => {
      hold = undefined;
      press.cue?.cancel();
      if (!reduced.matches) root.animate([{ transform: "scale(0.985)" }, { transform: "none" }], { duration: 220, easing: EASE_OUT });
      navigator.vibrate?.(8);
      swallowClick = true;
      setTouchMode(true);
    }, HOLD_MS);
    hold = press;
  }, { signal });
  card.header.addEventListener("pointermove", (event) => {
    if (hold && event.pointerId === hold.id && Math.hypot(event.clientX - hold.x, event.clientY - hold.y) > HOLD_SLOP) cancelHold();
  }, { signal });
  for (const type of ["pointerup", "pointercancel"] as const) {
    card.header.addEventListener(type, (event) => { if (hold && event.pointerId === hold.id) cancelHold(); }, { signal });
  }
  // The release that follows a hold must not also press the pill underneath it.
  root.addEventListener("click", (event) => {
    if (!swallowClick) return;
    swallowClick = false;
    event.preventDefault();
    event.stopPropagation();
  }, { capture: true, signal });
  card.header.addEventListener("contextmenu", (event) => event.preventDefault(), { signal });

  // ---- leaving the mode ---------------------------------------------------------------------
  document.addEventListener("pointerdown", (event) => {
    if (!touchMode) return;
    if ((event.target as Element).closest(".ui-window-resize") && root.contains(event.target as Node)) return;
    setTouchMode(false);
  }, { capture: true, signal });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape") setTouchMode(false); }, { signal });

  return {
    get touchMode() { return touchMode; },
    exitTouchMode: () => setTouchMode(false),
    dispose() {
      cancelHold();
      events.abort();
      for (const handle of root.querySelectorAll(".ui-window-resize")) handle.remove();
      delete root.dataset.resize;
    },
  };
}
