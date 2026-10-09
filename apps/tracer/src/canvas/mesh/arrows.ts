/**
 * Mesh access arrows for the clusters mockup (D164: an arrow A -> B lets A open connections
 * to B; solid = direct, dashed = via a named relay).
 *
 * `Arrow` draws one curve and its head into an SVG group in world coordinates. It knows only
 * rectangles and points, so the same code serves the Mesh graph, the on-demand arrows in
 * the Console view, and the live arrow that follows a pointer.
 *
 * `DragArrow` is the live arrow. Its far end is `lerp(pointer, anchor, s)` where `s` is a
 * spring: setting a target runs `s` to 1 with a little overshoot (the end overshoots the
 * anchor and settles, the "snap"); clearing the target runs it back to 0 (the "unsnap"), so the
 * end is pulled off the window and rejoins the pointer. The head also gets a small scale pulse
 * on snap. Only the path data and the head transform change; no layout is touched.
 */
import { Spring } from "../../../../../packages/ui/src/spring";

import type { Pt, Rect } from "../layout/geometry";
import { SCALE_REST, restAt } from "../springs";
export type { Pt, Rect };

const SVG_NS = "http://www.w3.org/2000/svg";
const svgEl = <K extends keyof SVGElementTagNameMap>(tag: K, cls?: string): SVGElementTagNameMap[K] => {
  const node = document.createElementNS(SVG_NS, tag);
  if (cls) node.setAttribute("class", cls);
  return node;
};

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

export interface ArrowStyle { dashed?: boolean; tone?: "accent" | "quiet"; /** Adds a wide invisible hit line and a grab handle on each end (the Mesh edits grants with them). */ editable?: boolean }

export class Arrow {
  readonly g = svgEl("g", "cl-arrow");
  private readonly line = svgEl("path", "cl-arrow-line");
  private readonly head = svgEl("path", "cl-arrow-head");
  /** Editable arrows only: a wide invisible line to hover, and a grab handle on each end. */
  readonly hit: SVGPathElement | undefined;
  readonly tailHandle: SVGCircleElement | undefined;
  readonly headHandle: SVGCircleElement | undefined;
  /** Last tip and direction, so a scale pulse can pivot on the tip. */
  private tip: Pt = { x: 0, y: 0 };
  private pulse = 1;

  constructor(style: ArrowStyle = {}) {
    if (style.editable) {
      this.hit = svgEl("path", "cl-arrow-hit");
      this.tailHandle = svgEl("circle", "cl-arrow-handle");
      this.tailHandle.dataset.end = "tail";
      this.headHandle = svgEl("circle", "cl-arrow-handle");
      this.headHandle.dataset.end = "head";
      this.g.append(this.hit, this.line, this.head, this.tailHandle, this.headHandle);
    } else this.g.append(this.line, this.head);
    this.g.dataset.tone = style.tone ?? "accent";
    if (style.dashed) this.g.dataset.dashed = "";
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
    if (this.hit && this.tailHandle && this.headHandle) {
      this.hit.setAttribute("d", d);
      const r = (size * 0.85).toFixed(1);
      for (const [h, pt] of [[this.tailHandle, p0], [this.headHandle, p1]] as const) { h.setAttribute("cx", pt.x.toFixed(1)); h.setAttribute("cy", pt.y.toFixed(1)); h.setAttribute("r", r); }
    }
    const w = size * 0.55;
    const bx = p1.x - ux * size, by = p1.y - uy * size;
    this.head.setAttribute("d", `M${p1.x.toFixed(1)} ${p1.y.toFixed(1)}L${(bx - uy * w).toFixed(1)} ${(by + ux * w).toFixed(1)}L${(bx + uy * w).toFixed(1)} ${(by - ux * w).toFixed(1)}Z`);
    this.tip = p1;
    this.applyPulse();
  }

  between(a: Rect, b: Rect, size: number, lane = 0): void {
    const n = anchors(a, b, lane);
    this.draw(n.p0, n.t0, n.p1, n.t1, size);
  }

  /** Scales the head about its tip (1 = rest). Transform only. */
  setPulse(scale: number): void { this.pulse = scale; this.applyPulse(); }
  private applyPulse(): void {
    this.head.style.transformOrigin = `${this.tip.x}px ${this.tip.y}px`;
    this.head.style.transform = this.pulse === 1 ? "" : `scale(${this.pulse})`;
  }

  set hidden(value: boolean) { this.g.toggleAttribute("hidden", value); }
  remove(): void { this.g.remove(); }
}

/** The arrow that follows a pointer and snaps onto a target rectangle. */
export class DragArrow {
  readonly arrow = new Arrow({ tone: "accent" });
  private readonly snap: Spring;
  private readonly pulse: Spring;
  private pointer: Pt;
  private target: Rect | undefined;
  private lastSize = 8;
  /** Called when the end moved, so the owner can keep a tip anchored to it. */
  onMove: ((end: Pt) => void) | undefined;

  /** `reverse`: the dragged end is the tail (the arrow still points at `source`). */
  constructor(private readonly source: Rect, start: Pt, private readonly onFrame: () => void, private readonly reverse = false) {
    this.pointer = start;
    this.snap = new Spring(0, () => this.render(), { visualDuration: 0.34, bounce: 0.38 });
    this.pulse = new Spring(1, (v) => { this.arrow.setPulse(v); }, { visualDuration: 0.3, bounce: 0.45 });
    restAt(this.snap, SCALE_REST); restAt(this.pulse, SCALE_REST);
    this.render();
    this.arrow.g.dataset.live = "";
  }

  get snapped(): boolean { return this.target !== undefined; }

  move(pointer: Pt, size: number): void {
    this.pointer = pointer;
    this.lastSize = size;
    this.render();
  }

  /** Snaps onto `rect`, or lets go when it is undefined. */
  setTarget(rect: Rect | undefined): void {
    const had = this.target !== undefined;
    this.target = rect;
    this.snap.set(rect ? 1 : 0);
    if (rect && !had) { this.pulse.value = 1.7; this.pulse.set(1); }
    if (rect) this.arrow.g.dataset.snapped = ""; else this.arrow.g.removeAttribute("data-snapped");
  }

  /** Starts out snapped on `rect` with no animation (an edit begins with the end still attached). */
  snapNow(rect: Rect): void {
    this.target = rect;
    this.snap.set(1, true);
    this.arrow.g.dataset.snapped = "";
    this.render();
  }

  /** Where the far end is right now. */
  end(): Pt {
    const s = this.snap.value;
    if (!this.target) return this.pointer;
    const a = this.reverse ? anchors(this.target, this.source).p0 : anchorOn(this.target, this.source);
    return { x: this.pointer.x + (a.x - this.pointer.x) * s, y: this.pointer.y + (a.y - this.pointer.y) * s };
  }

  private render(): void {
    if (!this.snap || !this.pulse) return; // the springs report once while they are being constructed
    const near = this.target ?? { x: this.pointer.x, y: this.pointer.y, w: 0, h: 0 };
    if (this.reverse) {
      // The tail is the free end; the head stays on the source and arrives along its side normal.
      const m = anchors(near, this.source);
      const p0 = this.end();
      const s0 = Math.max(0, Math.min(1, this.snap.value));
      const dx0 = m.p1.x - p0.x, dy0 = m.p1.y - p0.y, l0 = Math.hypot(dx0, dy0) || 1;
      const t0 = this.target ? { x: m.t0.x * s0 + (dx0 / l0) * (1 - s0), y: m.t0.y * s0 + (dy0 / l0) * (1 - s0) } : { x: dx0 / l0, y: dy0 / l0 };
      this.arrow.draw(p0, t0, m.p1, m.t1, this.lastSize);
      this.onMove?.(p0);
      this.onFrame();
      return;
    }
    const n = anchors(this.source, near);
    const p1 = this.end();
    // Free end: arrive along the line of travel. Snapped: arrive along the target's side normal.
    const s = Math.max(0, Math.min(1, this.snap.value));
    const dx = p1.x - n.p0.x, dy = p1.y - n.p0.y, len = Math.hypot(dx, dy) || 1;
    const t1 = this.target ? { x: n.t1.x * s + (dx / len) * (1 - s), y: n.t1.y * s + (dy / len) * (1 - s) } : { x: dx / len, y: dy / len };
    this.arrow.draw(n.p0, n.t0, p1, t1, this.lastSize);
    this.onMove?.(p1);
    this.onFrame();
  }

  /** The live arrow settles where it is (confirm) or retracts to its source (cancel). */
  retract(): void { this.setTarget(undefined); }
  dispose(): void { this.arrow.remove(); }
}
