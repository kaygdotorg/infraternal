/**
 * The camera: one centre and one zoom, three springs, and the single transform they write (D119, D159, D177).
 *
 * Rules this module keeps (the 60 fps rule, TASTE sections 3 and 5):
 * - A frame writes `transform` on the world layer and nothing else that is per frame: the backdrop gets the new
 *   offset through `onTransform`, the labels' counter-scale is written only when it changes, and the level of
 *   detail and zoom band flip with hysteresis so a zoom does not flicker between them.
 * - `will-change` is set only while the camera moves and is cleared at rest, so text is raster-crisp at rest.
 * - At rest the translation is snapped to whole device pixels (crisp text).
 * - A flight is a spring per axis; a new target keeps the current velocity, so a flight is always interruptible.
 *   A flight a gesture drives may take its time; one a key triggers is the short version (`keyFlight`).
 *   Reduced motion jumps (with a short fade) instead of flying.
 * - Nothing runs while the camera is still: the springs and the rest timer stop on their own.
 *
 * The camera knows nothing about views, windows or sessions. The canvas hands it a viewport, a world layer and a
 * few hooks; everything that depends on where the camera is (labels, the thumbnail switch, the mesh arrows) hangs
 * on those hooks.
 */
import { Spring } from "../../../../../packages/ui/src/spring";

export interface Cam { cx: number; cy: number; z: number }
import type { Pt, Rect } from "../layout/geometry";
import { SCALE_REST, quarterDevicePx, restAt } from "../springs";

/** Below about 60 % zoom, windows become read-only thumbnails (`thumb`). */
export type Lod = "live" | "thumb";
/** Below about 78 % zoom, the canvas shows views as labelled regions (`out`). */
export type ZoomBand = "in" | "out";

export interface CameraHooks {
  /** The world transform changed: where the world origin is on screen (viewport pixels) and the zoom. */
  onTransform?(t: { tx: number; ty: number; z: number; vw: number; vh: number }): void;
  /** The counter-scale labels use to keep a readable size at any zoom (`--inv`); only called when it changes. */
  onLabelScale?(inv: string): void;
  onLod?(lod: Lod): void;
  onBand?(band: ZoomBand): void;
  /** Every applied frame: overlays that follow the camera redraw (coalesced by the caller). */
  onFrame?(): void;
  /** The camera came to rest (140 ms after the last frame). */
  onRest?(): void;
  /** A flight starts: transient cards that point at the old framing go away. */
  onFlight?(): void;
}

export const clamp = (v: number, lo: number, hi: number): number => Math.max(lo, Math.min(hi, v));

const FLIGHT = { visualDuration: 0.8, bounce: 0 };
const KEY_FLIGHT = { visualDuration: 0.2, bounce: 0 };
const REST_DELAY = 140;
export const MIN_ZOOM = 0.08;
export const MAX_ZOOM = 2;

export class Camera {
  readonly cam: Cam = { cx: 0, cy: 0, z: 1 };
  tx = 0;
  ty = 0;
  vw = 0;
  vh = 0;
  lod: Lod = "live";
  band: ZoomBand = "in";
  /** The framing a flight is heading for; recomputed on resize so a flight keeps its meaning. */
  target: (() => Cam) | undefined;
  /** The counter-scale labels currently use. New labels start from it. */
  labelScale = "1";

  private readonly reduced = matchMedia("(prefers-reduced-motion: reduce)");
  private readonly springCx: Spring;
  private readonly springCy: Spring;
  private readonly springLz: Spring;
  private restTimer = 0;
  private moving = false;
  private ready = false;
  private flightKind: "gesture" | "key" = "gesture";

  constructor(private readonly viewport: HTMLElement, private readonly world: HTMLElement, private readonly hooks: CameraHooks = {}) {
    world.dataset.lod = this.lod;
    world.dataset.zoom = this.band;
    // The springs paint nothing until `start()`: their first update would run the hooks before the canvas is built.
    this.springCx = new Spring(0, (v) => { this.cam.cx = v; this.apply(); }, FLIGHT);
    this.springCy = new Spring(0, (v) => { this.cam.cy = v; this.apply(); }, FLIGHT);
    this.springLz = new Spring(0, (v) => { this.cam.z = Math.exp(v); this.apply(); }, FLIGHT);
    this.restThresholds(1);
  }

  /** A flight ends when it is under a quarter of a device pixel (a zoom change under 0.05 %) from its target. */
  private restThresholds(zoom: number): void {
    restAt(this.springCx, quarterDevicePx() / zoom);
    restAt(this.springCy, quarterDevicePx() / zoom);
    restAt(this.springLz, SCALE_REST);
  }

  /** Paints the first frame, at rest. Call once the canvas around the camera exists. */
  start(): void {
    this.ready = true;
    this.apply(true);
  }

  private readonly dpr = (): number => devicePixelRatio || 1;
  private readonly snapPx = (v: number): number => Math.round(v * this.dpr()) / this.dpr();

  /** Writes the world transform for the current centre and zoom. */
  apply(atRest = false): void {
    if (!this.ready) return;
    const { cam, world } = this;
    this.vw = this.viewport.clientWidth; this.vh = this.viewport.clientHeight;
    this.tx = this.vw / 2 - cam.cx * cam.z;
    this.ty = this.vh / 2 - cam.cy * cam.z;
    // At rest the translation lands on whole device pixels, so text is as crisp as it can be.
    if (atRest) { this.tx = this.snapPx(this.tx); this.ty = this.snapPx(this.ty); }
    world.style.transform = `translate3d(${this.tx}px, ${this.ty}px, 0) scale(${cam.z})`;
    this.hooks.onTransform?.({ tx: this.tx, ty: this.ty, z: cam.z, vw: this.vw, vh: this.vh });
    // The labels keep a readable size at any zoom. Written on the labels themselves (by the hook), not on the
    // world: a custom property that changes on a root restyles every element below it, on every frame of every zoom.
    const inv = String(clamp(1 / cam.z, 1, 3.2));
    if (inv !== this.labelScale) { this.labelScale = inv; this.hooks.onLabelScale?.(inv); }
    const nextLod: Lod = this.lod === "live" ? (cam.z < 0.58 ? "thumb" : "live") : (cam.z > 0.62 ? "live" : "thumb");
    if (nextLod !== this.lod) { this.lod = nextLod; world.dataset.lod = nextLod; this.hooks.onLod?.(nextLod); }
    const nextBand: ZoomBand = this.band === "in" ? (cam.z < 0.76 ? "out" : "in") : (cam.z > 0.82 ? "in" : "out");
    if (nextBand !== this.band) { this.band = nextBand; world.dataset.zoom = nextBand; this.hooks.onBand?.(nextBand); }
    if (!atRest) {
      if (!this.moving) { this.moving = true; world.style.willChange = "transform"; }
      window.clearTimeout(this.restTimer);
      this.restTimer = window.setTimeout(() => this.rest(), REST_DELAY);
    }
    this.hooks.onFrame?.();
  }

  /** The camera came to rest: raster-crisp text, then the rest hook. */
  rest(): void {
    window.clearTimeout(this.restTimer);
    this.moving = false;
    this.world.style.willChange = "";
    this.apply(true);
    this.hooks.onRest?.();
  }

  /** Halts any flight where the camera is. */
  stop(): void {
    const { cam } = this;
    this.springCx.set(cam.cx, true); this.springCy.set(cam.cy, true); this.springLz.set(Math.log(cam.z), true);
  }

  /** Puts the camera at `next` without motion. */
  set(next: Cam): void {
    this.cam.cx = next.cx; this.cam.cy = next.cy; this.cam.z = next.z;
    this.springCx.value = next.cx; this.springCy.value = next.cy; this.springLz.value = Math.log(next.z);
    this.stop();
    this.apply();
    this.rest();
  }

  /**
   * Moves the camera directly (a wheel, a drag, a pinch): the springs follow so a later flight starts from
   * here, and a frame is written. The caller has already stopped any flight.
   */
  drive(patch: Partial<Cam>): void {
    const { cam } = this;
    if (patch.cx !== undefined) { cam.cx = patch.cx; this.springCx.value = patch.cx; }
    if (patch.cy !== undefined) { cam.cy = patch.cy; this.springCy.value = patch.cy; }
    if (patch.z !== undefined) { cam.z = patch.z; this.springLz.value = Math.log(patch.z); }
    this.apply();
  }

  /** Halts the flight and forgets its target: a gesture took over. */
  takeOver(): void {
    this.stop();
    this.target = undefined;
  }

  /**
   * Motion rule: a flight the user's gesture drives (a swipe, a tap, a drag) may take its time; one a key
   * triggers (Command or Ctrl with a digit, the palette by keyboard) is the short version.
   */
  keyFlight<T>(run: () => T): T {
    this.flightKind = "key";
    try { return run(); } finally { this.flightKind = "gesture"; }
  }

  /** Flies the camera (interruptible: a new target keeps the current velocity). */
  flyTo(target: () => Cam, instant = false): void {
    this.target = target;
    this.hooks.onFlight?.();
    const t = target();
    if (instant) { this.set(t); return; }
    if (this.reduced.matches) {
      this.world.animate([{ opacity: 1 }, { opacity: 0.15 }, { opacity: 1 }], { duration: 240, easing: "ease-out" });
      this.set(t);
      return;
    }
    this.restThresholds(Math.max(t.z, this.cam.z));
    const cfg = this.flightKind === "key" ? KEY_FLIGHT : FLIGHT;
    this.springCx.configure(cfg); this.springCy.configure(cfg); this.springLz.configure(cfg);
    const { cam } = this;
    this.springCx.value = cam.cx; this.springCy.value = cam.cy; this.springLz.value = Math.log(cam.z);
    this.springCx.set(t.cx); this.springCy.set(t.cy); this.springLz.set(Math.log(t.z));
  }

  /** Re-reads the viewport size and re-aims a flight in progress. Called by the canvas on every resize. */
  resized(): void {
    this.vw = this.viewport.clientWidth; this.vh = this.viewport.clientHeight;
  }

  /** A point of the screen as a point of the world. */
  toWorld(clientX: number, clientY: number): Pt {
    const r = this.viewport.getBoundingClientRect();
    return { x: (clientX - r.left - this.tx) / this.cam.z, y: (clientY - r.top - this.ty) / this.cam.z };
  }

  /** A point of the world as a point of the screen. */
  toClient(p: Pt): Pt {
    const r = this.viewport.getBoundingClientRect();
    return { x: r.left + this.tx + p.x * this.cam.z, y: r.top + this.ty + p.y * this.cam.z };
  }

  /** An element's box in world coordinates. */
  worldRect(node: Element): Rect {
    const r = node.getBoundingClientRect();
    const a = this.toWorld(r.left, r.top);
    return { x: a.x, y: a.y, w: r.width / this.cam.z, h: r.height / this.cam.z };
  }

  /** Zooms about a screen point (a pinch or ctrl-wheel): the world point under it stays under it. */
  zoomAt(clientX: number, clientY: number, z: number): void {
    const r = this.viewport.getBoundingClientRect();
    const wp = this.toWorld(clientX, clientY);
    const next = clamp(z, MIN_ZOOM, MAX_ZOOM);
    this.drive({ z: next, cx: wp.x - (clientX - r.left - this.vw / 2) / next, cy: wp.y - (clientY - r.top - this.vh / 2) / next });
  }

  /** The framing that fits `r` in the viewport with `pad` of it used (never zoomed past `maxZ`). */
  fit(r: Rect, pad = 0.9, maxZ = 1): Cam {
    const z = clamp(Math.min((this.vw * pad) / r.w, (this.vh * pad) / r.h), 0.05, maxZ);
    return { cx: r.x + r.w / 2, cy: r.y + r.h / 2, z };
  }

  dispose(): void {
    window.clearTimeout(this.restTimer);
    this.springCx.set(this.cam.cx, true); this.springCy.set(this.cam.cy, true); this.springLz.set(Math.log(this.cam.z), true);
    this.ready = false;
  }
}

/** The smallest rectangle that holds all of `list`. */
export function bounds(list: Rect[]): Rect {
  const x0 = Math.min(...list.map((r) => r.x)), y0 = Math.min(...list.map((r) => r.y));
  const x1 = Math.max(...list.map((r) => r.x + r.w)), y1 = Math.max(...list.map((r) => r.y + r.h));
  return { x: x0, y: y0, w: x1 - x0, h: y1 - y0 };
}
