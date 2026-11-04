/**
 * Mesh access arrows for the clusters mockup (D164: an arrow A -> B lets A open connections
 * to B; solid = direct, dashed = via a named relay).
 *
 * `Arrow` draws one curve and its head into an SVG group in world coordinates. It knows only
 * rectangles and points, so the same code serves the Mesh graph, the on-demand arrows in
 * the Console view, and the live arrow that follows a pointer.
 *
 * `DragArrow` is the live arrow. It is a snap-fit, not a spring: the free end follows the pointer 1:1, and the moment the
 * pointer is inside a target's snap zone the end sits on the target's anchor (no tween toward it); leaving the zone
 * un-snaps just as fast. The landing is confirmed by a cue (`Arrow.press`, a 120 ms press of the head, plus the target's
 * border, owned by the caller). The only motion is `glideTo`: after a release elsewhere the end returns to where it came
 * from in at most 180 ms, ease-out, no overshoot. Only path data and the head transform change; no layout is touched.
 */
import type { Pt, Rect } from "../layout/geometry";
export type { Pt, Rect };

/** The SVG namespace, needed to create SVG elements. */
const SVG_NS = "http://www.w3.org/2000/svg";
/** Creates an SVG element of tag `tag`, with the optional CSS class `cls`. */
const svgEl = <K extends keyof SVGElementTagNameMap>(tag: K, cls?: string): SVGElementTagNameMap[K] => {
  const node = document.createElementNS(SVG_NS, tag);
  if (cls) node.setAttribute("class", cls);
  return node;
};

/** Where an arrow leaves and arrives: the points `p0`, `p1` and the unit directions `t0`, `t1` it travels in there. */
interface Anchors { p0: Pt; t0: Pt; p1: Pt; t1: Pt }

/** Picks the facing sides of two rectangles; `lane` shifts the anchors so parallel arrows do not overlap. */
export function anchors(a: Rect, b: Rect, lane = 0): Anchors {
  const ax = a.x + a.w / 2, ay = a.y + a.h / 2, bx = b.x + b.w / 2, by = b.y + b.h / 2;
  const gapX = Math.max(a.x - (b.x + b.w), b.x - (a.x + a.w));
  const gapY = Math.max(a.y - (b.y + b.h), b.y - (a.y + a.h));
  const off = lane * 14;
  if (gapX > gapY) {
    const right = bx > ax;
    return { p0: { x: right ? a.x + a.w : a.x, y: ay + off }, t0: { x: right ? 1 : -1, y: 0 }, p1: { x: right ? b.x : b.x + b.w, y: by + off }, t1: { x: right ? 1 : -1, y: 0 } };
  }
  const down = by > ay;
  return { p0: { x: ax + off, y: down ? a.y + a.h : a.y }, t0: { x: 0, y: down ? 1 : -1 }, p1: { x: bx + off, y: down ? b.y : b.y + b.h }, t1: { x: 0, y: down ? 1 : -1 } };
}

/** The point of `rect` an arrow from `from` would attach to. */
export const anchorOn = (rect: Rect, from: Rect | Pt, lane = 0): Pt => {
  const r: Rect = "w" in from ? from : { x: from.x, y: from.y, w: 0, h: 0 };
  return anchors(r, rect, lane).p1;
};

/** How an arrow looks: dashed (via a relay), its tone, and whether it can be edited. */
export interface ArrowStyle { dashed?: boolean; tone?: "accent" | "quiet"; /** Adds a wide invisible hit line and a grab handle on each end (the Mesh edits grants with them). */ editable?: boolean }

/**
 * One arrow: a curve and a head in an SVG group (`g`) in world coordinates. Draw it with `draw` (exact points) or `between`
 * (two rectangles), read a point on it with `pointAt`, and remove it with `remove`. Editable arrows get a wide hit line and grab handles.
 */
export class Arrow {
  readonly g = svgEl("g", "cl-arrow");
  private readonly line = svgEl("path", "cl-arrow-line");
  private readonly head = svgEl("path", "cl-arrow-head");
  /**
   * Editable arrows only: a wide invisible line to hover, and a grab handle on each end. The handles are made when the
   * pointer first comes near (or at once on touch, where there is no hover): a graph holds hundreds of arrows and
   * almost none is ever grabbed, and each handle is an element to style and paint.
   */
  readonly hit: SVGPathElement | undefined;
  tailHandle: SVGCircleElement | undefined;
  headHandle: SVGCircleElement | undefined;
  private ends: { p0: Pt; p1: Pt; r: string } | undefined;
  /** Last tip, so the press of the head can pivot on it. */
  private tip: Pt = { x: 0, y: 0 };
  private pressing: Animation | undefined;

  constructor(style: ArrowStyle = {}) {
    if (style.editable) {
      this.hit = svgEl("path", "cl-arrow-hit");
      this.g.append(this.hit, this.line, this.head);
      this.hit.addEventListener("pointerenter", () => this.ensureHandles());
      if (matchMedia("(pointer: coarse)").matches) queueMicrotask(() => this.ensureHandles());
    } else this.g.append(this.line, this.head);
    this.g.dataset.tone = style.tone ?? "accent";
    if (style.dashed) this.g.dataset.dashed = "";
  }

  private curve: { p0: Pt; c0: Pt; c1: Pt; p1: Pt } | undefined;
  /** A point of the curve last drawn, `t` from 0 (tail) to 1 (head), and the direction there. */
  pointAt(t: number): { x: number; y: number; dx: number; dy: number } | undefined {
    const c = this.curve;
    if (!c) return undefined;
    const u = 1 - t;
    const x = u * u * u * c.p0.x + 3 * u * u * t * c.c0.x + 3 * u * t * t * c.c1.x + t * t * t * c.p1.x;
    const y = u * u * u * c.p0.y + 3 * u * u * t * c.c0.y + 3 * u * t * t * c.c1.y + t * t * t * c.p1.y;
    const dx = 3 * u * u * (c.c0.x - c.p0.x) + 6 * u * t * (c.c1.x - c.c0.x) + 3 * t * t * (c.p1.x - c.c1.x);
    const dy = 3 * u * u * (c.c0.y - c.p0.y) + 6 * u * t * (c.c1.y - c.c0.y) + 3 * t * t * (c.p1.y - c.c1.y);
    return { x, y, dx, dy };
  }

  /** Makes the grab handles if they are not there yet, at the ends last drawn. */
  ensureHandles(): void {
    if (!this.hit || this.tailHandle) return;
    this.tailHandle = svgEl("circle", "cl-arrow-handle");
    this.tailHandle.dataset.end = "tail";
    this.headHandle = svgEl("circle", "cl-arrow-handle");
    this.headHandle.dataset.end = "head";
    this.g.append(this.tailHandle, this.headHandle);
    if (this.ends) this.placeHandles(this.ends.p0, this.ends.p1, this.ends.r);
  }
  private placeHandles(p0: Pt, p1: Pt, r: string): void {
    if (!this.tailHandle || !this.headHandle) return;
    for (const [h, pt] of [[this.tailHandle, p0], [this.headHandle, p1]] as const) { h.setAttribute("cx", pt.x.toFixed(1)); h.setAttribute("cy", pt.y.toFixed(1)); h.setAttribute("r", r); }
  }

  /** Draws from `p0` (leaving along `t0`) to `p1` (arriving along `t1`). `size` is the head length in world px. */
  draw(p0: Pt, t0: Pt, p1: Pt, t1: Pt, size: number): void {
    const dist = Math.hypot(p1.x - p0.x, p1.y - p0.y);
    const k = Math.max(24, Math.min(240, dist * 0.42));
    const c0 = { x: p0.x + t0.x * k, y: p0.y + t0.y * k };
    const c1 = { x: p1.x - t1.x * k, y: p1.y - t1.y * k };
    // The head points along the curve's final tangent; the stroke stops inside the head.
    const dx = p1.x - c1.x, dy = p1.y - c1.y;
    const len = Math.hypot(dx, dy) || 1;
    const ux = dx / len, uy = dy / len;
    const end = { x: p1.x - ux * size * 0.7, y: p1.y - uy * size * 0.7 };
    const d = `M${p0.x.toFixed(1)} ${p0.y.toFixed(1)}C${c0.x.toFixed(1)} ${c0.y.toFixed(1)} ${c1.x.toFixed(1)} ${c1.y.toFixed(1)} ${end.x.toFixed(1)} ${end.y.toFixed(1)}`;
    this.line.setAttribute("d", d);
    this.curve = { p0, c0, c1, p1: end };
    if (this.hit) {
      this.hit.setAttribute("d", d);
      const r = (size * 0.85).toFixed(1);
      this.ends = { p0, p1, r };
      this.placeHandles(p0, p1, r);
    }
    const w = size * 0.55;
    const bx = p1.x - ux * size, by = p1.y - uy * size;
    this.head.setAttribute("d", `M${p1.x.toFixed(1)} ${p1.y.toFixed(1)}L${(bx - uy * w).toFixed(1)} ${(by + ux * w).toFixed(1)}L${(bx + uy * w).toFixed(1)} ${(by - ux * w).toFixed(1)}Z`);
    this.tip = p1;
  }

  /** Draws from rectangle `a` to rectangle `b`, on their facing sides. `lane` shifts the ends so parallel arrows do not overlap. */
  between(a: Rect, b: Rect, size: number, lane = 0): void {
    const n = anchors(a, b, lane);
    this.draw(n.p0, n.t0, n.p1, n.t1, size);
  }

  /**
   * The landing cue: the head presses in and out about its tip, 1 -> 0.92 -> 1 over 120 ms with a strong ease-out and no
   * overshoot. Transform only, run by the compositor-friendly Web Animations engine, and gone from the element at the end,
   * so the head is never left on a fractional scale. Reduced motion drops the press (the caller keeps its colour cue).
   */
  press(): void {
    this.pressing?.cancel();
    this.pressing = undefined;
    if (matchMedia("(prefers-reduced-motion: reduce)").matches || typeof this.head.animate !== "function") return;
    this.head.style.transformOrigin = `${this.tip.x}px ${this.tip.y}px`;
    this.pressing = this.head.animate([{ transform: "scale(1)" }, { transform: "scale(0.92)" }, { transform: "scale(1)" }], { duration: 120, easing: "cubic-bezier(0.23, 1, 0.32, 1)" });
  }
  /** Stops a press in flight (an arrow taken from the pool starts at rest). */
  rest(): void { this.pressing?.cancel(); this.pressing = undefined; }

  /** Hides or shows the arrow without removing it. */
  set hidden(value: boolean) { this.g.toggleAttribute("hidden", value); }
  remove(): void { this.g.remove(); }
}

/** Ease-out cubic: fast at first, settling without overshoot. */
const easeOut = (t: number): number => 1 - (1 - t) ** 3;

/** The arrow that follows a pointer and snaps onto a target rectangle. */
export class DragArrow {
  readonly arrow = new Arrow({ tone: "accent" });
  private pointer: Pt;
  private target: Rect | undefined;
  private lastSize = 8;
  /** A return in flight: the end runs from `from` to the target's anchor over `ms`, eased out. */
  private glide: { from: Pt; t0: number; ms: number; done: () => void } | undefined;
  private glideFrame = 0;
  private progress = 0;
  /** Called when the end moved, so the owner can keep a tip anchored to it. */
  onMove: ((end: Pt) => void) | undefined;

  /** `reverse`: the dragged end is the tail (the arrow still points at `source`). */
  constructor(private readonly source: Rect, start: Pt, private readonly onFrame: () => void, private readonly reverse = false) {
    this.pointer = start;
    this.render();
    this.arrow.g.dataset.live = "";
  }

  /** True while the free end sits on a target. */
  get snapped(): boolean { return this.target !== undefined; }

  /** Moves the free end to `pointer` (world coordinates). `size` is the head length in world pixels. */
  move(pointer: Pt, size: number): void {
    this.pointer = pointer;
    this.lastSize = size;
    this.render();
  }

  /** Snaps onto `rect` at once, or lets go when it is undefined. A new snap gets the landing cue. */
  setTarget(rect: Rect | undefined): void {
    const had = this.target !== undefined;
    this.cancelGlide();
    this.target = rect;
    if (rect) this.arrow.g.dataset.snapped = ""; else this.arrow.g.removeAttribute("data-snapped");
    this.render();
    if (rect && !had) this.land();
  }

  /** Starts out snapped on `rect` with no cue (an edit begins with the end still attached). */
  snapNow(rect: Rect): void {
    this.target = rect;
    this.arrow.g.dataset.snapped = "";
    this.render();
  }

  /** The landing cue: the head presses, and a touch screen that can tick does. */
  private land(): void {
    this.arrow.press();
    if (matchMedia("(pointer: coarse)").matches) navigator.vibrate?.(8);
  }

  /** Returns the end to `rect` in at most `ms` (ease-out, no overshoot), then calls `done`. Used after a release elsewhere. */
  glideTo(rect: Rect, ms: number, done: () => void): void {
    const from = this.end();
    this.cancelGlide();
    this.target = rect;
    this.arrow.g.dataset.snapped = "";
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) { this.render(); done(); return; }
    this.glide = { from, t0: performance.now(), ms, done };
    this.progress = 0;
    const step = (now: number): void => {
      const g = this.glide;
      if (!g) return;
      const t = Math.min(1, (now - g.t0) / g.ms);
      this.progress = easeOut(t);
      this.render();
      if (t < 1) this.glideFrame = requestAnimationFrame(step); else { this.glide = undefined; this.progress = 1; g.done(); }
    };
    this.glideFrame = requestAnimationFrame(step);
  }
  private cancelGlide(): void {
    if (this.glide) cancelAnimationFrame(this.glideFrame);
    this.glide = undefined;
    this.progress = 0;
  }

  /** How far the end is attached: 1 on a target, 0 on the pointer, in between only while gliding home. */
  private get attach(): number { return this.glide ? this.progress : this.target ? 1 : 0; }

  /** Where the far end is right now. */
  end(): Pt {
    if (!this.target) return this.pointer;
    const a = this.reverse ? anchors(this.target, this.source).p0 : anchorOn(this.target, this.source);
    const g = this.glide;
    if (!g) return a;
    const s = this.progress;
    return { x: g.from.x + (a.x - g.from.x) * s, y: g.from.y + (a.y - g.from.y) * s };
  }

  private render(): void {
    const near = this.target ?? { x: this.pointer.x, y: this.pointer.y, w: 0, h: 0 };
    const s = this.attach;
    if (this.reverse) {
      // The tail is the free end; the head stays on the source and arrives along its side normal.
      const m = anchors(near, this.source);
      const p0 = this.end();
      const dx0 = m.p1.x - p0.x, dy0 = m.p1.y - p0.y, l0 = Math.hypot(dx0, dy0) || 1;
      const t0 = this.target ? { x: m.t0.x * s + (dx0 / l0) * (1 - s), y: m.t0.y * s + (dy0 / l0) * (1 - s) } : { x: dx0 / l0, y: dy0 / l0 };
      this.arrow.draw(p0, t0, m.p1, m.t1, this.lastSize);
      this.onMove?.(p0);
      this.onFrame();
      return;
    }
    const n = anchors(this.source, near);
    const p1 = this.end();
    // Free end: arrive along the line of travel. Snapped: arrive along the target's side normal.
    const dx = p1.x - n.p0.x, dy = p1.y - n.p0.y, len = Math.hypot(dx, dy) || 1;
    const t1 = this.target ? { x: n.t1.x * s + (dx / len) * (1 - s), y: n.t1.y * s + (dy / len) * (1 - s) } : { x: dx / len, y: dy / len };
    this.arrow.draw(n.p0, n.t0, p1, t1, this.lastSize);
    this.onMove?.(p1);
    this.onFrame();
  }

  /** The live arrow lets go of its target; its owner fades it out. */
  retract(): void { this.setTarget(undefined); }
  dispose(): void { this.cancelGlide(); this.arrow.remove(); }
}
