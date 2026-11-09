// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Adaptive glass density (D365): when the app can see what is behind a glass card, the card asks for only as much tint as
 * that needs, so a dark backdrop keeps its lightness instead of always getting the worst-case floor.
 *
 * Two kinds of backdrop are known:
 *  - a terminal's or the page's own colours: known from the theme alone, so the themed set in `themes.ts` already covers
 *    them and nothing here runs;
 *  - a remote app window's picture: unknown to the theme but visible in a `<video>` or `<canvas>`. {@link watchBackdrop}
 *    reads a tiny average of the part of that picture under a card, a few times a second while the card is open, and
 *    writes the matching opacity and text colours onto the element that carries `data-glass-under`.
 *
 * Until the first sample arrives, and whenever sampling is not possible (a hidden tab, a stream with no frame yet), that
 * element's glass uses the static floor, which is correct over anything. So sampling can only make the glass lighter
 * where it is safe to; it never makes a card less readable.
 *
 * Cost and the input path. Sampling is one `drawImage` of the source's region into an 8x8 canvas and one 256-byte read, on a
 * timer of at least 250 ms and only while the card is open. It never runs inside an input, pointer or key handler, and it
 * does nothing for a card that is closed. The cost is measured in `apps/tracer/test/glass-sample-cost.spec.ts`.
 */
import { glassFor, glassTint, GLASS_ADAPT_VARS, type Theme } from "./themes";
import { hexToRgb, type BackdropRange, type Rgb } from "./glass-contrast";

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
  /** The element that carries `data-glass-under` (the window card the picture and the glass surfaces live in). */
  marker: HTMLElement;
  /** The picture behind the card: a playing video or a canvas. */
  source: HTMLVideoElement | HTMLCanvasElement;
  /** The part of `source` under the card, in the source's own pixels. Called on each sample, not on each frame. */
  region: () => { x: number; y: number; width: number; height: number } | null;
  /** The active theme and the card level, read on each sample so a change is picked up. */
  theme: () => Theme;
  level: () => number;
}

/** Remembers solved ranges: a steady picture asks the solver once, not four times a second. Keyed by theme, level and range. */
const solved = new Map<string, ReturnType<typeof glassFor>>();
/** The solved glass for a theme, level and sampled range, from the memo or the solver. */
const solveFor = (theme: Theme, level: number, range: BackdropRange): ReturnType<typeof glassFor> => {
  // Quantised to 8/255 so a flicker of a few levels in a video reuses the answer.
  const q = (rgb: Rgb): string => rgb.map((v) => v >> 3).join(",");
  const key = `${theme.name}|${level}|${q(range.dark)}|${q(range.light)}`;
  let hit = solved.get(key);
  if (!hit) {
    if (solved.size > 256) solved.clear();
    hit = glassFor(theme, level, range);
    solved.set(key, hit);
  }
  return hit;
};

/** The one 8x8 canvas every sample is drawn into, created on first use. */
let scratch: { canvas: HTMLCanvasElement; ctx: CanvasRenderingContext2D } | undefined;

/** Reads the 8x8 average of `region` of `source`, or `null` if the source has nothing to draw yet. */
export function readSample(source: BackdropWatch["source"], region: { x: number; y: number; width: number; height: number }): Uint8ClampedArray | null {
  if (source instanceof HTMLVideoElement && (source.readyState < 2 || source.videoWidth === 0)) return null;
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
  const tick = (): void => {
    timer = window.setTimeout(tick, SAMPLE_INTERVAL_MS);
    if (document.hidden) return;
    const region = watch.region();
    const rgba = region ? readSample(watch.source, region) : null;
    if (!rgba) return;
    const sol = solveFor(watch.theme(), watch.level(), rangeOfSample(rgba));
    const signature = `${sol.alpha}|${Object.values(sol.colours).join()}`;
    if (signature === last) return;
    last = signature;
    marker.style.setProperty(GLASS_ADAPT_VARS.overlay, `rgb(${hexToRgb(glassTint(watch.theme())).join(" ")} / ${sol.alpha})`);
    for (const [role, colour] of Object.entries(sol.colours)) marker.style.setProperty(GLASS_ADAPT_VARS.role(role), colour);
  };
  // First sample off the current task, so opening the card never waits on it.
  timer = window.setTimeout(tick, 0);
  return () => {
    window.clearTimeout(timer);
    marker.style.removeProperty(GLASS_ADAPT_VARS.overlay);
    for (const role of ["fg", "fg2", "fg3", "secondary", "accent", "ok", "danger", "warn"]) marker.style.removeProperty(GLASS_ADAPT_VARS.role(role));
  };
}
