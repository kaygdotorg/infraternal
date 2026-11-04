/**
 * The dotted canvas behind the views (D160): the gradient is fixed to the screen, the dots move with the camera.
 * This module only connects the shared backdrop in packages/ui to the canvas: the dots fill the whole stage
 * behind the chrome, not just the canvas area, so it needs the canvas area's offset inside the stage (measured on
 * mount and on every resize, never per frame).
 *
 * Memory: at most two layers exist, each about one screen (rastered tiles only cover what is on screen; the offset is
 * the camera modulo one tile, and a zoom scales the layer instead of repainting it), never a surface the size of the world, and there is no canvas element at all
 * (`createCanvasBackdrop` draws with CSS tiles). A hidden page releases them (see memory.ts).
 */
import { createCanvasBackdrop, type CanvasBackdrop } from "../../../../packages/ui/src/canvas-backdrop";

/** The canvas's dotted background. */
export interface Backdrop {
  /** Re-measures the canvas area inside the stage. Call on mount and on resize. */
  measure(): void;
  /** Places the dots for the camera transform (canvas-area pixels). */
  update(t: { tx: number; ty: number; z: number; vw: number; vh: number; rest: boolean }): void;
  /** Frees every dot layer's surface (a hidden page); the next `update` brings them back. */
  release(): void;
  /** Removes the layers. */
  dispose(): void;
}

/** Makes the backdrop in `stage`. `viewport` is the canvas area; its offset inside the stage is re-measured by `measure`, never per frame. */
export function createBackdrop(stage: HTMLElement, viewport: HTMLElement): Backdrop {
  const layer: CanvasBackdrop = createCanvasBackdrop(stage);
  const box = { x: 0, y: 0, w: 0, h: 0 };
  const measure = (): void => {
    const s = stage.getBoundingClientRect(), v = viewport.getBoundingClientRect();
    box.x = v.left - s.left; box.y = v.top - s.top; box.w = s.width; box.h = s.height;
  };
  return {
    measure,
    update: ({ tx, ty, z, vw, vh, rest }) => layer.update(tx + box.x, ty + box.y, z, box.w || vw, box.h || vh, rest),
    release: () => layer.release(),
    dispose: () => layer.dispose(),
  };
}
