// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Adaptive glass density (D365): when the app can see what is behind a glass card, the card asks for only as much tint
 * and text colour as that content needs, so the approved levels stay distinct whenever the backdrop allows it. When no glass reaches the line over what is behind (a light card over a dark picture, a dark one over a light picture) the card turns solid: the theme's opaque card colour, no blur, its own text colours; the solver never reaches for a glow behind the text.
 *
 * `glass-under.on-demand.ts` finds what a surface is over and starts one of two trackers here. Until the first value arrives the
 * surface is on the static floor (set by the CSS from `data-glass-under`), which is correct over anything, so this module
 * can only make the glass lighter where that is safe; it never makes a card less readable.
 *
 *  - {@link trackGrid}, over a terminal: reads the real cell colours under the card from the terminal's own grid (no pixel
 *    readback), blurs them the way the glass does ({@link rangeOfGrid}), and solves for that range. It runs once per
 *    frame at most, only after the screen changed or the card moved, and only while the card is open.
 *  - {@link trackPicture}, over a stream canvas, a video that fills its box or an image: {@link watchBackdrop} reads an 8x8
 *    average of the part of the picture under the card, at most every 250 ms, on a timer and never in an input handler.
 *    A card that straddles the picture and the page around it (a window's ⋯ menu hangs over the window's edge) is solved for
 *    both: the picture part is sampled, the part outside is read from the colours the page paints there ({@link outsideRange},
 *    cached per box and theme, so it never runs in the frame a theme switch lands in), and the two ranges are merged, so the
 *    worst contrast of either decides glass or solid.
 *
 * The cost of both is measured in `apps/tracer/test/glass-sample-cost.spec.ts` and `glass-terminal.spec.ts`; setting
 * `data-glass-stats` on the root makes this module count its updates in `globalThis.__glassStats`.
 */
import { activeGlass, glassTint, GLASS_ADAPT_VARS, type Theme } from "./themes";
import { clearSolution, glassSeen, nominalOpacity } from "./glass-rules.on-demand";
// The rules are written by the same chunk: `themes.ts` requests this module at the start of boot and calls `installGlassRules`.
export { installGlassRules } from "./glass-rules.on-demand";
import { hexToRgb, luminanceOf, type BackdropRange, type Rgb } from "./glass-contrast";
import type { GlassGrid, GlassGridRead } from "./glass-under.on-demand";

/** Cells per side of the sample. 8x8 is enough because the card's own blur averages finer detail away anyway. */
export const SAMPLE_CELLS = 8;
/** The least time between two samples of one card, in milliseconds. */
export const SAMPLE_INTERVAL_MS = 250;
/** Added around the sampled colours (0 to 255 per channel): detail finer than a cell, and a frame that changes before the next sample. */
const SAMPLE_PAD = 20;

/**
 * The darkest and lightest backdrop in a sample: per channel, the lowest and highest cell, widened by a small pad.
 * `rgba` is the 8x8 image as `getImageData` returns it.
 */
export function rangeOfSample(rgba: ArrayLike<number>): BackdropRange {
  const lo = [255, 255, 255], hi = [0, 0, 0];
  for (let i = 0; i + 3 < rgba.length; i += 4) {
    for (let c = 0; c < 3; c++) {
      const v = rgba[i + c]!;
      if (v < lo[c]!) lo[c] = v;
      if (v > hi[c]!) hi[c] = v;
    }
  }
  const pad = (v: number, sign: number): number => Math.min(255, Math.max(0, v + sign * SAMPLE_PAD));
  return { dark: lo.map((v) => pad(v, -1)) as unknown as Rgb, light: hi.map((v) => pad(v, 1)) as unknown as Rgb };
}

/** The range that covers both `a` and `b`: per channel the lower dark and the higher light, as {@link rangeOfSample} takes it. */
export function mergeRanges(a: BackdropRange, b: BackdropRange): BackdropRange {
  const pick = (x: Rgb, y: Rgb, f: (p: number, q: number) => number): Rgb => x.map((v, i) => f(v, y[i]!)) as unknown as Rgb;
  return { dark: pick(a.dark, b.dark, Math.min), light: pick(a.light, b.light, Math.max) };
}

/** What {@link watchBackdrop} needs to know about one card and the picture behind it. */
export interface BackdropWatch {
  /** The glass surface to adapt: it carries `data-glass-under` (set by `glass-under.on-demand.ts`) and is written the sampled opacity and colours. */
  marker: HTMLElement;
  /** The picture behind the card: a playing video, a canvas or an image. */
  source: HTMLVideoElement | HTMLCanvasElement | HTMLImageElement;
  /**
   * The part of `source` under the card, in the source's own pixels. Called on each sample, not on each frame. `outside` is the
   * backdrop range of the part of the card that is not over `source`, when the card straddles its edge.
   */
  region: () => { x: number; y: number; width: number; height: number; outside?: BackdropRange } | null;
  /** The active theme and the card level, read on each sample so a change is picked up. */
  theme: () => Theme;
  level: () => number;
}

/**
 * How much wider (0 to 255 per channel) the backdrop range is taken while a card is solid, before it may turn back to glass.
 * A card that went solid over a backdrop returns to glass only when the content is clearly easier than the line it crossed,
 * so text scrolling under the edge of the limit does not flicker the card between the two.
 */
export const SOLID_HYSTERESIS = 24;

/** Remembers solved ranges: a steady picture asks the solver once, not four times a second. Keyed by theme, level, the starting opacity (a look's tint moves it), range and whether the card is solid now. */
const solved = new Map<string, ReturnType<typeof glassSeen>>();
/**
 * The solved glass for a theme, level and sampled range, from the memo or the solver. `wasSolid` is whether the card is solid
 * now: then the range is widened by {@link SOLID_HYSTERESIS} first, so the card only goes back to glass with margin to spare.
 */
export const solveFor = (theme: Theme, level: number, range: BackdropRange, wasSolid = false): ReturnType<typeof glassSeen> => {
  // Quantised to 8/255 so a flicker of a few levels in a video reuses the answer.
  const q = (rgb: Rgb): string => rgb.map((v) => v >> 3).join(",");
  const nominal = nominalOpacity(theme, level);
  const key = `${theme.name}|${level}|${nominal}|${q(range.dark)}|${q(range.light)}|${wasSolid}`;
  let hit = solved.get(key);
  if (!hit) {
    if (solved.size > 256) solved.clear();
    const widen = (rgb: Rgb, sign: number): Rgb => rgb.map((v) => Math.min(255, Math.max(0, v + sign * SOLID_HYSTERESIS))) as unknown as Rgb;
    hit = glassSeen(theme, level, wasSolid ? { dark: widen(range.dark, -1), light: widen(range.light, 1) } : range, nominal);
    solved.set(key, hit);
  }
  return hit;
};

/** The one 8x8 canvas every sample is drawn into, created on first use. */
let scratch: { canvas: HTMLCanvasElement; ctx: CanvasRenderingContext2D } | undefined;

/** Reads the 8x8 average of `region` of `source`, or `null` if the source has nothing to draw yet. */
export function readSample(source: BackdropWatch["source"], region: { x: number; y: number; width: number; height: number }): Uint8ClampedArray | null {
  if (source instanceof HTMLVideoElement && (source.readyState < 2 || source.videoWidth === 0)) return null;
  if (source instanceof HTMLImageElement && (!source.complete || source.naturalWidth === 0)) return null;
  if (!scratch) {
    const canvas = document.createElement("canvas");
    canvas.width = canvas.height = SAMPLE_CELLS;
    const ctx = canvas.getContext("2d", { willReadFrequently: true });
    if (!ctx) return null;
    scratch = { canvas, ctx };
  }
  try {
    scratch.ctx.drawImage(source, region.x, region.y, Math.max(1, region.width), Math.max(1, region.height), 0, 0, SAMPLE_CELLS, SAMPLE_CELLS);
    return scratch.ctx.getImageData(0, 0, SAMPLE_CELLS, SAMPLE_CELLS).data;
  } catch {
    // A cross-origin or tainted source cannot be read: stay on the static floor.
    return null;
  }
}

/**
 * Starts adapting the glass under `watch.marker` to the picture behind it. The marker must already carry
 * `data-glass-under` (its owner sets it, so the static floor holds from the first paint). Returns a function that stops
 * sampling and clears what was written, which puts the glass back on the static floor. Call it when the card opens and
 * call the result when the card closes.
 */
export function watchBackdrop(watch: BackdropWatch): () => void {
  const { marker } = watch;
  let timer = 0;
  let last = "";
  let solid = false;
  const tick = (): void => {
    // The card is gone (closed, removed): stop for good, nobody will call the disposer.
    if (!marker.isConnected) return;
    timer = window.setTimeout(tick, SAMPLE_INTERVAL_MS);
    if (document.hidden) return;
    const region = watch.region();
    const rgba = region ? readSample(watch.source, region) : null;
    if (!rgba) return;
    const sampled = rangeOfSample(rgba);
    const sol = solveFor(watch.theme(), watch.level(), region!.outside ? mergeRanges(sampled, region!.outside) : sampled, solid);
    const signature = `${sol.solid}|${sol.alpha}|${Object.values(sol.colours).join()}`;
    if (signature === last) return;
    last = signature;
    solid = sol.solid;
    writeSolution(marker, sol, watch.theme());
  };
  // First sample off the current task, so opening the card never waits on it.
  timer = window.setTimeout(tick, 0);
  return () => {
    window.clearTimeout(timer);
    clearSolution(marker);
  };
}

/** How long the fill and blur take to cross-fade between glass and solid, in milliseconds. */
export const FADE_MS = 160;

/**
 * Runs `change` (which rewrites the glass custom properties on `surface`) and cross-fades the fill and the blur from what
 * the card showed to what it shows now, so glass turning solid (or back) never pops. It uses the Web Animations API, which
 * layers over whatever transitions the card already has (opening, hiding), so none of those is touched. Skipped for a
 * card that is not drawn yet and for reduced motion. Only text colours, which are a few percent apart, change at once.
 */
function crossFade(surface: HTMLElement, change: () => void): void {
  const drawn = surface.isConnected && !surface.hidden && typeof surface.animate === "function" && !matchMedia("(prefers-reduced-motion: reduce)").matches;
  const before = drawn ? getComputedStyle(surface) : undefined;
  // What the card shows now, read while any earlier fade is still running (so a change that lands mid-fade continues from where the eye is).
  const from = before && { backgroundColor: before.backgroundColor, backdropFilter: before.backdropFilter };
  // An earlier fade must end before the new value is read: a running animation overrides the computed style, so `after` would be the
  // earlier fade's value and the card would pop to the real one when that fade ended (J1020).
  const earlier = drawn ? surface.getAnimations().filter((a) => fades.has(a)) : [];
  for (const a of earlier) a.cancel();
  change();
  if (!from) return;
  const after = getComputedStyle(surface);
  if (after.backgroundColor === from.backgroundColor && after.backdropFilter === from.backdropFilter) return;
  const fade = surface.animate(
    [{ backgroundColor: from.backgroundColor, backdropFilter: from.backdropFilter, webkitBackdropFilter: from.backdropFilter }, { backgroundColor: after.backgroundColor, backdropFilter: after.backdropFilter, webkitBackdropFilter: after.backdropFilter }],
    { duration: FADE_MS, easing: "ease-out" },
  );
  fades.add(fade);
  fade.finished.then(() => fades.delete(fade), () => fades.delete(fade));
}

/** The cross-fades this module started and that are still running, so a later change can end them before it reads the new value. */
const fades = new WeakSet<Animation>();

/** Writes a solved opacity, blur and text colours onto `surface`, where the glass rules read them in place of the static floor. */
function writeSolution(surface: HTMLElement, sol: ReturnType<typeof glassSeen>, theme: Theme): void {
  crossFade(surface, () => {
    surface.style.setProperty(GLASS_ADAPT_VARS.overlay, `rgb(${hexToRgb(glassTint(theme)).join(" ")} / ${sol.alpha})`);
    // The answer, for the rules that drop the blur of a solid card and keep a glass card's own (see `installGlassRules`).
    surface.dataset.glassAnswer = sol.solid ? "solid" : "glass";
    for (const [role, colour] of Object.entries(sol.colours)) surface.style.setProperty(GLASS_ADAPT_VARS.role(role), colour);
  });
}

/** What a tracker hands back to `glass-under.on-demand.ts`: nudge it to look again, or stop it and restore the floor. */
export interface Tracker { refresh(): void; stop(): void }

/** Counts one update in `globalThis.__glassStats` when the root carries `data-glass-stats` (the cost specs set it). */
function stat(startedAt: number, readMs: number): void {
  if (!document.documentElement.hasAttribute("data-glass-stats")) return;
  const g = ((globalThis as { __glassStats?: { updates: number; totalMs: number; maxMs: number; readMs: number } }).__glassStats ??= { updates: 0, totalMs: 0, maxMs: 0, readMs: 0 });
  const ms = performance.now() - startedAt;
  g.updates += 1; g.totalMs += ms; g.readMs += readMs;
  if (ms > g.maxMs) g.maxMs = ms;
}

/**
 * How much sharper than a flat blur the card's own backdrop blur is, as a share of its radius. A card's blur fades at its
 * own box and lets the content near the edge through, so a thin bright band stays far brighter than a blur of the whole
 * screen would leave it (measured on rendered pixels: about 0.59 of the band's colour at 32 px where a flat blur gives
 * 0.20). 0.35 of the radius reproduces that, and leans toward the sharper answer.
 */
export const EDGE_SHARPNESS = 0.35;
/** Added around the blurred extremes (0 to 255 per channel): the card's colour saturation boost and eight-bit rounding. */
const GRID_PAD = 8;

/**
 * Blurs a grid of cell colours with a Gaussian of `sigma` px (cells are `cellW` by `cellH`), clamping at the grid's edges
 * as the card's own blur does at its box. Returns three floats per cell. A `sigma` under a third of a cell leaves it as is.
 */
export function blurCells(read: GlassGridRead, sigma: number): Float32Array<ArrayBuffer> {
  const { cols, rows, rgb } = read;
  let cur = new Float32Array(rgb);
  const pass = (src: Float32Array<ArrayBuffer>, along: "x" | "y"): Float32Array<ArrayBuffer> => {
    const s = (along === "x" ? sigma / read.cellW : sigma / read.cellH);
    if (s < 0.33) return src;
    const radius = Math.min(Math.ceil(s * 3), along === "x" ? cols : rows);
    const weights: number[] = [];
    let total = 0;
    for (let k = -radius; k <= radius; k++) { const w = Math.exp(-(k * k) / (2 * s * s)); weights.push(w); total += w; }
    const out = new Float32Array(src.length);
    for (let y = 0; y < rows; y++) for (let x = 0; x < cols; x++) for (let c = 0; c < 3; c++) {
      let sum = 0;
      for (let k = -radius; k <= radius; k++) {
        const xx = along === "x" ? Math.min(cols - 1, Math.max(0, x + k)) : x, yy = along === "y" ? Math.min(rows - 1, Math.max(0, y + k)) : y;
        sum += src[(yy * cols + xx) * 3 + c]! * weights[k + radius]!;
      }
      out[(y * cols + x) * 3 + c] = sum / total;
    }
    return out;
  };
  cur = pass(cur, "x");
  return pass(cur, "y");
}

/**
 * The darkest and the lightest colour the card can show text over: the blurred cells under it ({@link blurCells} with the
 * card's blur radius scaled by {@link EDGE_SHARPNESS}), taken by luminance and widened by a small pad.
 */
export function rangeOfGrid(read: GlassGridRead, blurPx: number): BackdropRange {
  const blurred = blurCells(read, blurPx * EDGE_SHARPNESS);
  let lo: Rgb = [255, 255, 255], hi: Rgb = [0, 0, 0], loL = Infinity, hiL = -Infinity;
  for (let i = 0; i + 2 < blurred.length; i += 3) {
    const c: Rgb = [blurred[i]!, blurred[i + 1]!, blurred[i + 2]!];
    const l = luminanceOf(c);
    if (l < loL) { loL = l; lo = c; }
    if (l > hiL) { hiL = l; hi = c; }
  }
  const pad = (c: Rgb, sign: number): Rgb => c.map((v) => Math.min(255, Math.max(0, v + sign * GRID_PAD))) as unknown as Rgb;
  return { dark: pad(lo, -1), light: pad(hi, 1) };
}

/** The blur radius of a glass surface in px, from its computed backdrop filter; 0 when it has none (Solid). */
function blurOf(surface: HTMLElement): number {
  return parseFloat(/blur\(([\d.]+)px\)/.exec(getComputedStyle(surface).backdropFilter)?.[1] ?? "0") || 0;
}

/**
 * Tracks a terminal under `surface`: reads the cells under the card, solves for what they need and writes it, once per
 * frame at most, after the screen changed (the grid calls back after each render pass) or the card moved (`refresh`).
 */
export function trackGrid(surface: HTMLElement, grid: GlassGrid): Tracker {
  let frame = 0;
  let last = "";
  let solid = false;
  const run = (): void => {
    frame = 0;
    if (!surface.isConnected || surface.hidden) return;
    const started = performance.now();
    const { theme, level } = activeGlass();
    const read = grid.read(surface.getBoundingClientRect(), hexToRgb(theme.bg));
    const readMs = performance.now() - started;
    if (!read) return;
    const sol = solveFor(theme, level, rangeOfGrid(read, blurOf(surface)), solid);
    const signature = `${sol.solid}|${sol.alpha}|${Object.values(sol.colours).join()}`;
    if (signature !== last) { last = signature; solid = sol.solid; writeSolution(surface, sol, theme); }
    stat(started, readMs);
  };
  const refresh = (): void => { if (!frame) frame = requestAnimationFrame(run); };
  const unsubscribe = grid.subscribe(refresh);
  return { refresh, stop(): void { cancelAnimationFrame(frame); unsubscribe(); clearSolution(surface); } };
}

/** A 1x1 canvas that does the colour maths for {@link paintedAt}: it parses any CSS colour and composites layers exactly as the page does. */
let swatch: CanvasRenderingContext2D | null | undefined;

/**
 * The colour the page paints at client point (`x`, `y`) outside `surface`: the background colours of the element there and
 * its ancestors, layered over the theme's page colour `base`. Returns `null` when the point is over something this cannot
 * read (another picture, a terminal screen), so the caller keeps the static floor rather than guess. Gradients and images
 * are not read: only plain background colours.
 */
function paintedAt(surface: HTMLElement, x: number, y: number, base: Rgb): Rgb | null {
  swatch ??= document.createElement("canvas").getContext("2d", { willReadFrequently: true }) ?? null;
  if (!swatch) return null;
  const hit = document.elementsFromPoint(x, y).find((el) => el !== surface && !surface.contains(el) && !el.classList.contains("ui-glass-bed"));
  const layers: string[] = [];
  for (let el: Element | null = hit ?? null; el; el = el.parentElement) {
    if (el.matches("video, img, canvas, [data-glass-picture], [data-glass-grid]")) return null;
    const bg = getComputedStyle(el).backgroundColor;
    if (bg && bg !== "rgba(0, 0, 0, 0)" && bg !== "transparent") layers.push(bg);
  }
  swatch.clearRect(0, 0, 1, 1);
  swatch.fillStyle = `rgb(${base.join(",")})`;
  swatch.fillRect(0, 0, 1, 1);
  for (const colour of layers.reverse()) { swatch.fillStyle = colour; swatch.fillRect(0, 0, 1, 1); }
  const d = swatch.getImageData(0, 0, 1, 1).data;
  return [d[0]!, d[1]!, d[2]!];
}

/** How many points per side of the card's box {@link outsideRange} looks at. */
const OUTSIDE_POINTS = 5;

/**
 * The backdrop range of the part of `surface` that lies outside `picture` (a card hanging over the picture's edge), from the
 * colours the page paints there, or `undefined` when the card is wholly inside the picture, `null` when some part cannot be read.
 */
export function outsideRange(surface: HTMLElement, picture: DOMRect, base: Rgb): BackdropRange | null | undefined {
  const s = surface.getBoundingClientRect();
  const colours: number[] = [];
  let any = false;
  for (let i = 0; i < OUTSIDE_POINTS; i++) for (let j = 0; j < OUTSIDE_POINTS; j++) {
    const x = s.left + 1 + (s.width - 2) * (i / (OUTSIDE_POINTS - 1)), y = s.top + 1 + (s.height - 2) * (j / (OUTSIDE_POINTS - 1));
    if (x >= picture.left && x <= picture.right && y >= picture.top && y <= picture.bottom) continue;
    any = true;
    const c = paintedAt(surface, x, y, base);
    if (!c) return null;
    colours.push(c[0], c[1], c[2], 255);
  }
  return any ? rangeOfSample(colours) : undefined;
}

/**
 * Tracks a picture under `surface` if it can be sampled faithfully: a stream canvas, an image or a video that fills its box.
 * A card wholly inside the picture is sampled there; one that straddles the picture's edge is sampled over the part inside
 * and read over the part outside ({@link outsideRange}), and the worst of the two decides. Otherwise (the card is not over
 * the picture, or the part outside cannot be read) returns a tracker that leaves the card on the static floor.
 */
export function trackPicture(surface: HTMLElement, picture: HTMLElement): Tracker | undefined {
  const ok = picture instanceof HTMLCanvasElement || ((picture instanceof HTMLVideoElement || picture instanceof HTMLImageElement) && getComputedStyle(picture).objectFit === "fill");
  if (!ok) return undefined;
  const source = picture as HTMLCanvasElement | HTMLVideoElement | HTMLImageElement;
  // The outside answer is kept while the two boxes and the theme stay as they were: it reads computed styles, which is work for a timer tick, not for every one.
  let cached: { key: string; range: BackdropRange | null | undefined } | undefined;
  const stop = watchBackdrop({
    marker: surface,
    source,
    region: () => {
      const p = picture.getBoundingClientRect(), s = surface.getBoundingClientRect();
      const left = Math.max(s.left, p.left), right = Math.min(s.right, p.right), top = Math.max(s.top, p.top), bottom = Math.min(s.bottom, p.bottom);
      if (right - left < 1 || bottom - top < 1) return null;
      let outside: BackdropRange | null | undefined;
      if (s.left < p.left || s.right > p.right || s.top < p.top || s.bottom > p.bottom) {
        const theme = activeGlass().theme;
        const key = `${theme.name}|${[s, p].map((r) => [r.left, r.top, r.width, r.height].map(Math.round).join(",")).join("|")}`;
        if (cached?.key !== key) cached = { key, range: outsideRange(surface, p, hexToRgb(theme.bg)) };
        outside = cached.range;
        // Something under the outside part that cannot be read: the floor stays.
        if (outside === null) return null;
      }
      const width = source instanceof HTMLVideoElement ? source.videoWidth : source instanceof HTMLImageElement ? source.naturalWidth : source.width;
      const height = source instanceof HTMLVideoElement ? source.videoHeight : source instanceof HTMLImageElement ? source.naturalHeight : source.height;
      const sx = width / p.width, sy = height / p.height;
      return { x: (left - p.left) * sx, y: (top - p.top) * sy, width: (right - left) * sx, height: (bottom - top) * sy, ...(outside ? { outside } : {}) };
    },
    theme: () => activeGlass().theme,
    level: () => activeGlass().level,
  });
  return { refresh(): void { /* sampled on its own timer */ }, stop };
}
