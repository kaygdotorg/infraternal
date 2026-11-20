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
 *
 * The cost of both is measured in `apps/tracer/test/glass-sample-cost.spec.ts` and `glass-terminal.spec.ts`; setting
 * `data-glass-stats` on the root makes this module count its updates in `globalThis.__glassStats`.
 */
import { activeGlass, glassTint, GLASS_ADAPT_VARS, type Theme } from "./themes";
import { glassSeen, nominalOpacity } from "./glass-rules.on-demand";
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

/** What {@link watchBackdrop} needs to know about one card and the picture behind it. */
export interface BackdropWatch {
  /** The glass surface to adapt: it carries `data-glass-under` (set by `glass-under.on-demand.ts`) and is written the sampled opacity and colours. */
  marker: HTMLElement;
  /** The picture behind the card: a playing video, a canvas or an image. */
  source: HTMLVideoElement | HTMLCanvasElement | HTMLImageElement;
  /** The part of `source` under the card, in the source's own pixels. Called on each sample, not on each frame. */
  region: () => { x: number; y: number; width: number; height: number } | null;
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
    const sol = solveFor(watch.theme(), watch.level(), rangeOfSample(rgba), solid);
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
  const from = before && { backgroundColor: before.backgroundColor, backdropFilter: before.backdropFilter };
  change();
  if (!from) return;
  const after = getComputedStyle(surface);
  if (after.backgroundColor === from.backgroundColor && after.backdropFilter === from.backdropFilter) return;
  surface.animate(
    [{ backgroundColor: from.backgroundColor, backdropFilter: from.backdropFilter, webkitBackdropFilter: from.backdropFilter }, { backgroundColor: after.backgroundColor, backdropFilter: after.backdropFilter, webkitBackdropFilter: after.backdropFilter }],
    { duration: FADE_MS, easing: "ease-out" },
  );
}

/** Writes a solved opacity, blur and text colours onto `surface`, where the glass rules read them in place of the static floor. */
function writeSolution(surface: HTMLElement, sol: ReturnType<typeof glassSeen>, theme: Theme): void {
  crossFade(surface, () => {
    surface.style.setProperty(GLASS_ADAPT_VARS.overlay, `rgb(${hexToRgb(glassTint(theme)).join(" ")} / ${sol.alpha})`);
    // The answer, for the rules that drop the blur of a solid card and keep a glass card's own (see `installGlassRules`).
    surface.dataset.glassAnswer = sol.solid ? "solid" : "glass";
    for (const [role, colour] of Object.entries(sol.colours)) surface.style.setProperty(GLASS_ADAPT_VARS.role(role), colour);
  });
}

/** Removes what {@link writeSolution} wrote, which puts the surface back on the static floor. */
function clearSolution(surface: HTMLElement): void {
  surface.style.removeProperty(GLASS_ADAPT_VARS.overlay);
  delete surface.dataset.glassAnswer;
  for (const role of ["fg", "fg2", "fg3", "secondary", "accent", "ok", "danger", "warn"]) surface.style.removeProperty(GLASS_ADAPT_VARS.role(role));
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

/**
 * Tracks a picture under `surface` if it can be sampled faithfully: a stream canvas, an image or a video that fills its box,
 * with the card wholly inside it. Otherwise returns `undefined` and the card stays on the static floor.
 */
export function trackPicture(surface: HTMLElement, picture: HTMLElement): Tracker | undefined {
  const ok = picture instanceof HTMLCanvasElement || ((picture instanceof HTMLVideoElement || picture instanceof HTMLImageElement) && getComputedStyle(picture).objectFit === "fill");
  if (!ok) return undefined;
  const source = picture as HTMLCanvasElement | HTMLVideoElement | HTMLImageElement;
  const stop = watchBackdrop({
    marker: surface,
    source,
    region: () => {
      const p = picture.getBoundingClientRect(), s = surface.getBoundingClientRect();
      // Wholly inside the picture, or the part outside is something else (bars, the page): then the floor stays.
      if (s.left < p.left || s.right > p.right || s.top < p.top || s.bottom > p.bottom) return null;
      const width = source instanceof HTMLVideoElement ? source.videoWidth : source instanceof HTMLImageElement ? source.naturalWidth : source.width;
      const height = source instanceof HTMLVideoElement ? source.videoHeight : source instanceof HTMLImageElement ? source.naturalHeight : source.height;
      const sx = width / p.width, sy = height / p.height;
      return { x: (s.left - p.left) * sx, y: (s.top - p.top) * sy, width: s.width * sx, height: s.height * sy };
    },
    theme: () => activeGlass().theme,
    level: () => activeGlass().level,
  });
  return { refresh(): void { /* sampled on its own timer */ }, stop };
}
