/**
 * The dotted canvas behind the views (D160): the gradient is fixed to the screen, the dots move with the camera.
 * This module only connects the shared backdrop in packages/ui to the canvas: the dots fill the whole stage
 * behind the chrome, not just the canvas area, so it needs the canvas area's offset inside the stage (measured on
 * mount and on every resize, never per frame).
 *
 * Memory: the layers are viewport-sized tiles that hop by whole spacings, never a surface the size of the world,
 * and there is no canvas element at all (`createCanvasBackdrop` draws with CSS tiles). A page hidden or frozen
 * releases nothing here because there is nothing large to release.
 */
import { createCanvasBackdrop, type CanvasBackdrop } from "../../../../packages/ui/src/canvas-backdrop";

export interface Backdrop {
  /** Re-measures the canvas area inside the stage. Call on mount and on resize. */
  measure(): void;
  /** Places the dots for the camera transform (canvas-area pixels). */
  update(t: { tx: number; ty: number; z: number; vw: number; vh: number }): void;
  dispose(): void;
}

export function createBackdrop(stage: HTMLElement, viewport: HTMLElement): Backdrop {
  const layer: CanvasBackdrop = createCanvasBackdrop(stage);
  const box = { x: 0, y: 0, w: 0, h: 0 };
  const measure = (): void => {
    const s = stage.getBoundingClientRect(), v = viewport.getBoundingClientRect();
    box.x = v.left - s.left; box.y = v.top - s.top; box.w = s.width; box.h = s.height;
  };
  return {
    measure,
    update: ({ tx, ty, z, vw, vh }) => layer.update(tx + box.x, ty + box.y, z, box.w || vw, box.h || vh),
    dispose: () => layer.dispose(),
  };
}
