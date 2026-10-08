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
 * World space: a layer is placed at a multiple of its own spacing near the visible area, so a dot always sits
 * on a world coordinate that is a multiple of the spacing. Panning moves the dots exactly with the windows;
 * when the view crosses a cell the layer hops by one whole spacing, which is invisible because the pattern
 * repeats.
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
    layer.style.opacity = "0";
    layer.style.visibility = "hidden";
    root.append(layer);
    return layer;
  });
  parent.prepend(root);

  let gap = 22;
  let sized = "";
  const measure = (viewWidth: number, viewHeight: number): void => {
    gap = Number.parseFloat(getComputedStyle(root).getPropertyValue("--ui-dot-gap")) || 22;
    // Layer k is on screen from zoom 2^-(k+2) up, so it must cover (view / zoom) world pixels there:
    // the same number of cells for every level.
    const cells = Math.ceil((4 * Math.max(viewWidth, viewHeight)) / gap) + 4;
    layers.forEach((layer, k) => {
      const spacing = gap * 2 ** k;
      layer.style.width = layer.style.height = `${cells * spacing}px`;
      layer.style.backgroundSize = `${spacing}px ${spacing}px`;
    });
  };

  const update = (tx: number, ty: number, z: number, viewWidth: number, viewHeight: number): void => {
    const key = `${Math.round(viewWidth)}x${Math.round(viewHeight)}`;
    if (key !== sized) { sized = key; measure(viewWidth, viewHeight); }
    const level = Math.min(LEVELS - 1, Math.max(0, -Math.log2(z) - 1));
    const lo = Math.floor(level), hi = Math.min(LEVELS - 1, lo + 1), f = level - lo;
    const wx = -tx / z, wy = -ty / z;
    layers.forEach((layer, k) => {
      // The denser layer fades out as the sparser one fades in (their shared dots keep the same strength).
      const weight = k === lo ? 1 - f : k === hi ? f : 0;
      const shown = layer.dataset.on === "1";
      if (weight === 0) { if (shown) { layer.style.opacity = "0"; layer.style.visibility = "hidden"; layer.dataset.on = "0"; } return; }
      if (!shown) { layer.style.visibility = ""; layer.dataset.on = "1"; }
      layer.style.opacity = String(weight);
      const spacing = gap * 2 ** k;
      // One cell of margin on each side; the layer hops by whole spacings, so the dots never slip.
      const ox = (Math.floor(wx / spacing) - 1) * spacing, oy = (Math.floor(wy / spacing) - 1) * spacing;
      layer.style.transform = `translate3d(${tx + ox * z}px, ${ty + oy * z}px, 0) scale(${z})`;
    });
  };
  return { root, update, dispose() { root.remove(); } };
}
