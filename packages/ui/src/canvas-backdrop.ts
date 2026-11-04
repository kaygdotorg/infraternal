/**
 * The canvas backdrop (D160): the gradient behind everything is fixed to the screen and visible everywhere;
 * the dots sit on it as light marks and move with the camera, which gives depth.
 *
 * How, and why it is cheap. Bottom to top: the theme's plain base, one static gradient layer (the mesh
 * colours, or any image or gradient through `--ui-dot-fill`; it never moves or repaints), and one dot layer
 * per level of detail. A dot layer is ordinary background tiles (a repeating radial gradient of a brighter
 * tint of the gradient, at a low opacity), with no mask and no cover, so it needs no offscreen surface. The
 * camera only ever writes `transform` and `opacity` on a layer: no background-position animation, no canvas
 * redraw, nothing runs while the camera is still (`update` is called by the camera, never by a timer).
 *
 * Memory: a layer is one viewport (plus a tile of margin), never world sized. Its tile size is the dots' screen
 * spacing and its offset is the camera modulo one tile, so panning is a translate and the dots stay on world
 * multiples. At most two layers exist during a crossfade; the others are `hidden` and hold no surface.
 *
 * Zoom without repainting. A layer's tiles are painted at the zoom it was last "snapped" at (`z0`); while the camera
 * zooms, the layer is only scaled by `z / z0` on the compositor (transform), so a pinch or a wheel zoom repaints and
 * rasters nothing per frame (measured with 55 windows at DPR 2: a zoom frame cost about twice the main-thread time
 * and three times the raster time when `background-size` was rewritten every frame). The layer is made big enough to
 * still cover the screen when scaled down to `MIN_SCALE`; only the tiles on screen are ever rastered, so the bigger
 * box costs no memory. A layer is snapped again (one repaint) when it was scaled outside [MIN_SCALE, MAX_SCALE], when
 * the screen size changed, and when the camera comes to rest at another zoom, so a resting canvas has crisp dots.
 *
 * Level of detail: layer k has spacing `gap * 2^k`. Below 50 % zoom the next, sparser layer fades in while the
 * denser one fades out: the grid thins to every second dot with a crossfade and never becomes noise.
 *
 * Tokens (CSS custom properties, per instance or on a parent): `--ui-dot-size` (diameter, default 1.4px),
 * `--ui-dot-gap` (spacing at 100 % zoom, default 22px), `--ui-dot-color` (the tint), `--ui-dot-opacity`,
 * `--ui-gradient-opacity` (how strongly the gradient shows) and `--ui-dot-fill` (the gradient itself).
 */
/** Number of dot layers (levels of detail); layer k has spacing `gap * 2^k`. */
const LEVELS = 4;
/** The smallest scale a painted layer may be shown at before it is painted again; the layer box is sized to still cover the screen at this scale. */
const MIN_SCALE = 0.6;
/** The largest scale a painted layer may be shown at before it is painted again. */
const MAX_SCALE = 1.7;
/** At rest a layer within this of its painted zoom is left alone (a repaint for 1 % would only move dots by sub-pixels). */
const REST_TOLERANCE = 0.01;

/** What a layer was last painted for: the zoom (`z0`) and the viewport size. */
interface Snap { z0: number; vw: number; vh: number }

/**
 * The handle returned by {@link createCanvasBackdrop}. `root` is the element it added to the parent; `dispose()`
 * removes it. Call `update` from the camera, not from a timer.
 */
export interface CanvasBackdrop {
  readonly root: HTMLElement;
  /** Places the dots for a camera: `tx`, `ty` are the world origin on screen, `z` the zoom. */
  update(tx: number, ty: number, z: number, viewWidth: number, viewHeight: number, atRest?: boolean): void;
  /** Frees every layer's surface (a hidden page holds nothing); the next `update` brings them back. */
  release(): void;
  dispose(): void;
}

/**
 * Adds the backdrop as the first child of `parent` and returns its handle.
 * The element is decorative (`aria-hidden`). The dot spacing is read once, from `--ui-dot-gap`, on the first `update`.
 * @example
 * const dots = createCanvasBackdrop(stage); dots.update(tx, ty, zoom, stage.clientWidth, stage.clientHeight);
 */
export function createCanvasBackdrop(parent: HTMLElement): CanvasBackdrop {
  const root = document.createElement("div");
  root.className = "ui-canvas-backdrop";
  root.setAttribute("aria-hidden", "true");
  const fill = document.createElement("div");
  fill.className = "ui-canvas-backdrop-fill";
  root.append(fill);
  const layers = Array.from({ length: LEVELS }, (_, k) => {
    const layer = document.createElement("div");
    layer.className = "ui-canvas-backdrop-layer";
    layer.dataset.level = String(k);
    layer.hidden = true;
    layer.style.transformOrigin = "0 0";
    root.append(layer);
    return layer;
  });
  parent.prepend(root);

  let gap = 22;
  let measured = false;
  const snaps: Array<Snap | undefined> = Array.from({ length: LEVELS });
  const update = (tx: number, ty: number, z: number, viewWidth: number, viewHeight: number, atRest = false): void => {
    if (!measured) { measured = true; gap = Number.parseFloat(getComputedStyle(root).getPropertyValue("--ui-dot-gap")) || 22; }
    const level = Math.min(LEVELS - 1, Math.max(0, -Math.log2(z) - 1));
    const lo = Math.floor(level), hi = Math.min(LEVELS - 1, lo + 1), f = level - lo;
    layers.forEach((layer, k) => {
      // The denser layer fades out as the sparser one fades in (their shared dots keep the same strength).
      const weight = k === lo ? 1 - f : k === hi ? f : 0;
      if (weight === 0) { if (!layer.hidden) layer.hidden = true; return; }
      if (layer.hidden) layer.hidden = false;
      layer.style.opacity = String(weight);
      // Screen spacing of this level's dots. Its offset is the camera modulo one tile, so a pan is a translate and
      // the dots stay on world multiples (`gap * 2^k`), moving exactly with the windows.
      const spacing = gap * 2 ** k * z;
      let snap = snaps[k];
      const scale = snap ? z / snap.z0 : 0;
      if (!snap || scale < MIN_SCALE || scale > MAX_SCALE || snap.vw !== viewWidth || snap.vh !== viewHeight || (atRest && Math.abs(scale - 1) > REST_TOLERANCE)) {
        // Paint the tiles at this zoom. The box covers the screen at the smallest scale it may be shown at.
        snap = snaps[k] = { z0: z, vw: viewWidth, vh: viewHeight };
        layer.style.backgroundSize = `${spacing}px ${spacing}px`;
        layer.style.width = `${Math.ceil(viewWidth / MIN_SCALE + 2 * spacing)}px`;
        layer.style.height = `${Math.ceil(viewHeight / MIN_SCALE + 2 * spacing)}px`;
      }
      const ox = ((((tx - spacing / 2) % spacing) + spacing) % spacing) - spacing;
      const oy = ((((ty - spacing / 2) % spacing) + spacing) % spacing) - spacing;
      layer.style.transform = `translate3d(${ox}px, ${oy}px, 0) scale(${z / snap.z0})`;
    });
  };
  const release = (): void => { for (const layer of layers) { layer.hidden = true; layer.style.willChange = "auto"; } snaps.fill(undefined); };
  return { root, update, release, dispose() { root.remove(); } };
}
