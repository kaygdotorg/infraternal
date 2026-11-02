/**
 * Icon morph (#280): one icon turning into its sibling as a single shape, driven by the shared spring. It is made for
 * the pair on a window's header that Option switches between, "split" and "new window" (ICONS.splitRight → newRight,
 * splitDown → newBelow). In both icons a rounded frame holds one bar; in the "new window" icon the frame shrinks to
 * the part of the screen the first window keeps and the bar becomes the upright of a plus whose second bar grows out
 * of it. So the morph is geometry, not a crossfade: the frame's size, its corner radius and the bars' end points all
 * move together with one number, `p` from 0 (split) to 1 (new window).
 *
 * - One spring per icon; it runs only while it moves (zero idle work, D81), retargets mid-flight with its velocity, so a
 *   key pressed and released quickly reverses from where the icon is. Reduced motion swaps at once.
 * - The spring is critically damped (TASTE §3: no overshoot, ever), so the geometry never leaves the range between
 *   the two icons.
 * - The endpoints are the shared icons exactly: `icon-morph.test.ts` parses ICONS and compares them with `geometryAt(spec, 0)`
 *   and `geometryAt(spec, 1)`, so editing an icon without its morph fails a test.
 */
import { Spring } from "./spring";

/** x, y, width, height, corner radius. */
export type FrameBox = readonly [number, number, number, number, number];
/** x1, y1, x2, y2. */
export type BarLine = readonly [number, number, number, number];

export interface MorphSpec {
  frame: { from: FrameBox; to: FrameBox };
  /** The bar both icons have: a divider in the split icon, the upright of the plus in the new-window icon. */
  a: { from: BarLine; to: BarLine };
  /** The plus's second bar: it grows out of its own centre as `p` rises, and is absent from the split icon. */
  b: { from: BarLine; to: BarLine };
}

/** Right: the divider is vertical and becomes the plus's upright. Down: the divider is horizontal and becomes its crossbar. */
export const SPLIT_MORPH: { right: MorphSpec; down: MorphSpec } = {
  right: {
    frame: { from: [4, 4, 16, 16, 3], to: [3.5, 4.5, 8, 15, 2.5] },
    a: { from: [12, 4, 12, 20], to: [17, 9.5, 17, 14.5] },
    b: { from: [17, 12, 17, 12], to: [14.5, 12, 19.5, 12] },
  },
  down: {
    frame: { from: [4, 4, 16, 16, 3], to: [4.5, 3.5, 15, 8, 2.5] },
    a: { from: [4, 12, 20, 12], to: [9.5, 19, 14.5, 19] },
    b: { from: [12, 19, 12, 19], to: [12, 16.5, 12, 21.5] },
  },
};

const lerp = (from: number, to: number, p: number): number => from + (to - from) * p;
const mix = <T extends readonly number[]>(from: T, to: T, p: number): number[] => from.map((v, i) => lerp(v, to[i]!, p));
const smooth = (edge0: number, edge1: number, x: number): number => { const t = Math.min(1, Math.max(0, (x - edge0) / (edge1 - edge0))); return t * t * (3 - 2 * t); };

export interface MorphGeometry { frame: number[]; a: number[]; b: number[]; bOpacity: number }

/** The icon's shapes at `p` (0 the split icon, 1 the new-window icon). Pure, so the endpoints can be tested. */
export function geometryAt(spec: MorphSpec, p: number): MorphGeometry {
  return {
    frame: mix(spec.frame.from, spec.frame.to, p),
    a: mix(spec.a.from, spec.a.to, p),
    b: mix(spec.b.from, spec.b.to, p),
    // The second bar appears over the second half of the morph, after the frame has mostly moved out of its way.
    bOpacity: smooth(0.35, 0.9, p),
  };
}

export interface IconMorph {
  /** Turns toward the new-window icon (`true`) or back. `instant` jumps (reduced motion does too). */
  set(alt: boolean, instant?: boolean): void;
  readonly alt: boolean;
  dispose(): void;
}

const n = (value: number): string => (Math.round(value * 100) / 100).toString();

/** Fills `svg` (a 24 px grid) with the morphing shapes, at rest as the split icon. */
export function createIconMorph(svg: SVGSVGElement, spec: MorphSpec): IconMorph {
  const NS = "http://www.w3.org/2000/svg";
  const frame = document.createElementNS(NS, "rect");
  const a = document.createElementNS(NS, "path");
  const b = document.createElementNS(NS, "path");
  svg.replaceChildren(frame, a, b);
  const line = (l: number[]): string => `M${n(l[0]!)} ${n(l[1]!)}L${n(l[2]!)} ${n(l[3]!)}`;
  const paint = (p: number): void => {
    const g = geometryAt(spec, p);
    frame.setAttribute("x", n(g.frame[0]!));
    frame.setAttribute("y", n(g.frame[1]!));
    frame.setAttribute("width", n(g.frame[2]!));
    frame.setAttribute("height", n(g.frame[3]!));
    frame.setAttribute("rx", n(Math.max(0, g.frame[4]!)));
    a.setAttribute("d", line(g.a));
    b.setAttribute("d", line(g.b));
    b.setAttribute("opacity", n(Math.min(1, Math.max(0, g.bOpacity))));
  };
  const spring = new Spring(0, paint, { visualDuration: 0.26 });
  let alt = false;
  return {
    set(next, instant = false) {
      if (next === alt) return;
      alt = next;
      spring.set(next ? 1 : 0, instant);
    },
    get alt() { return alt; },
    dispose() { spring.set(alt ? 1 : 0, true); },
  };
}
