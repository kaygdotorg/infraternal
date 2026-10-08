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
 * Level of detail: layer k has spacing `gap * 2^k`. Below 50 % zoom the next, sparser layer fades in while the
 * denser one fades out: the grid thins to every second dot with a crossfade and never becomes noise.
 *
 * Tokens (CSS custom properties, per instance or on a parent): `--ui-dot-size` (diameter, default 1.4px),
 * `--ui-dot-gap` (spacing at 100 % zoom, default 22px), `--ui-dot-color` (the tint), `--ui-dot-opacity`,
 * `--ui-gradient-opacity` (how strongly the gradient shows) and `--ui-dot-fill` (the gradient itself).
 */
const LEVELS = 4;

export interface CanvasBackdrop {
  readonly root: HTMLElement;
  /** Places the dots for a camera: `tx`, `ty` are the world origin on screen, `z` the zoom. */
  update(tx: number, ty: number, z: number, viewWidth: number, viewHeight: number): void;
  /** Frees every layer's surface (a hidden page holds nothing); the next `update` brings them back. */
  release(): void;
  dispose(): void;
}

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
    root.append(layer);
    return layer;
  });
  parent.prepend(root);

  let gap = 22;
  let measured = false;
  const update = (tx: number, ty: number, z: number, viewWidth: number, viewHeight: number): void => {
    if (!measured) { measured = true; gap = Number.parseFloat(getComputedStyle(root).getPropertyValue("--ui-dot-gap")) || 22; }
    const level = Math.min(LEVELS - 1, Math.max(0, -Math.log2(z) - 1));
    const lo = Math.floor(level), hi = Math.min(LEVELS - 1, lo + 1), f = level - lo;
    layers.forEach((layer, k) => {
      // The denser layer fades out as the sparser one fades in (their shared dots keep the same strength).
      const weight = k === lo ? 1 - f : k === hi ? f : 0;
      if (weight === 0) { if (!layer.hidden) layer.hidden = true; return; }
      if (layer.hidden) layer.hidden = false;
      layer.style.opacity = String(weight);
      // Screen spacing of this level's dots. The layer is one screen (plus one tile of margin on each side), never
      // the world: its tile size follows the zoom and its offset is the camera modulo one tile, so memory stays at
      // about one viewport at any zoom and any world size. Dots sit at the tile centres, on world multiples of
      // `gap * 2^k`, so they move exactly with the windows.
      const spacing = gap * 2 ** k * z;
      const ox = ((((tx - spacing / 2) % spacing) + spacing) % spacing) - spacing;
      const oy = ((((ty - spacing / 2) % spacing) + spacing) % spacing) - spacing;
      const w = `${Math.ceil(viewWidth + 2 * spacing)}px`, h = `${Math.ceil(viewHeight + 2 * spacing)}px`;
      if (layer.style.width !== w) layer.style.width = w;
      if (layer.style.height !== h) layer.style.height = h;
      layer.style.backgroundSize = `${spacing}px ${spacing}px`;
      layer.style.transform = `translate3d(${ox}px, ${oy}px, 0)`;
    });
  };
  const release = (): void => { for (const layer of layers) { layer.hidden = true; layer.style.willChange = "auto"; } };
  return { root, update, release, dispose() { root.remove(); } };
}
