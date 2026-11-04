/**
 * The terminal's live cursor as its own small layer above the renderer's canvas (D249).
 *
 * Why a layer: the renderer parks itself when nothing changes (D81, D112), so a cursor drawn into its canvas can only
 * blink while the renderer runs. This layer is one absolutely positioned box, placed once per cursor move and blinked
 * by a Web Animations opacity animation, which the compositor runs without the main thread: no timer, no
 * requestAnimationFrame, no renderer frame while it blinks.
 *
 * Geometry is the renderer's `renderCursor` geometry on the same cell grid: the cell origin is `column * cellWidth`,
 * `row * cellHeight` (cell sizes are already rounded to device pixels by the renderer), a bar is
 * `max(2, floor(cellWidth * 0.15))` wide, an underline `max(2, floor(cellHeight * 0.15))` tall. The canvas and this
 * layer share the host's scroll container, so scrolling needs no update.
 *
 * Blink budget: the animation has a finite iteration count, so it ends on its own after `BLINK_LIMIT_MS` without
 * input (a steady cursor, no timer needed to stop it). `restart()` begins it again from the visible phase.
 * Under reduced motion the cursor never blinks.
 */

/** One full blink period: visible for the first half, hidden for the second. */
export const CURSOR_BLINK_PERIOD_MS = 1060;
/** About 30 seconds of blinking without input, then the cursor stays steady. */
export const CURSOR_BLINK_LIMIT_MS = 30_000;
/** How many blink periods fit in the blink limit. */
const CURSOR_BLINK_ITERATIONS = Math.round(CURSOR_BLINK_LIMIT_MS / CURSOR_BLINK_PERIOD_MS);

/** Where and how to draw the cursor: the cell (`column`, `row`), the cell size in pixels, the shape and a CSS colour. */
export interface TerminalCursorPlacement {
  /** The renderer's canvas; the layer sits at its offset inside the host. */
  canvas: HTMLCanvasElement;
  column: number;
  row: number;
  cellWidth: number;
  cellHeight: number;
  style: "bar" | "underline" | "block";
  color: string;
}

/** What the layer shows now (for tests and probes). */
export interface TerminalCursorSnapshot {
  visible: boolean;
  blinking: boolean;
  /** CSS pixels relative to the host's padding box. */
  x: number;
  y: number;
  width: number;
  height: number;
  color: string;
}

/**
 * A cursor box above the terminal canvas that blinks without the main thread. Create it with
 * {@link mountTerminalCursorLayer}; call `place` when the cursor moves, `restart` on input, `hide` and `stopBlink`
 * when it should not show or blink, and `dispose` to remove it.
 */
export class TerminalCursorLayer {
  /** The layer's box. */
  private readonly element: HTMLElement;
  /** The running blink, or `undefined` when steady. */
  private animation: Animation | undefined;
  /** The placement last applied, as a string, so an unchanged cursor writes no style. */
  private key = "";
  /** Whether the layer is visible. */
  private shown = false;
  /** The last placed rectangle, for {@link TerminalCursorLayer.snapshot}. */
  private box = { x: 0, y: 0, width: 0, height: 0 };
  /** The last placed colour. */
  private color = "";
  /** Under reduced motion the cursor never blinks. */
  private readonly reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");

  constructor(host: HTMLElement) {
    const element = document.createElement("div");
    element.className = "terminal-cursor-layer";
    element.setAttribute("aria-hidden", "true");
    element.hidden = true;
    host.append(element);
    this.element = element;
  }

  /** Puts the cursor on its cell. Writes style only when something changed, so a settled cursor costs nothing. */
  place(placement: TerminalCursorPlacement): void {
    const { canvas, column, row, cellWidth, cellHeight, style, color } = placement;
    const key = `${canvas.offsetLeft}|${canvas.offsetTop}|${column}|${row}|${cellWidth}|${cellHeight}|${style}|${color}`;
    if (key !== this.key) {
      this.key = key;
      let width = cellWidth;
      let height = cellHeight;
      if (style === "bar") width = Math.max(2, Math.floor(cellWidth * 0.15));
      if (style === "underline") height = Math.max(2, Math.floor(cellHeight * 0.15));
      const x = canvas.offsetLeft + column * cellWidth;
      const y = canvas.offsetTop + row * cellHeight + (style === "underline" ? cellHeight - height : 0);
      this.box = { x, y, width, height };
      this.color = color;
      const css = this.element.style;
      css.left = `${x}px`;
      css.top = `${y}px`;
      css.width = `${width}px`;
      css.height = `${height}px`;
      css.background = color;
    }
    if (!this.shown) {
      this.shown = true;
      this.element.hidden = false;
    }
  }

  /** Stops blinking and hides the cursor. */
  hide(): void {
    this.stopBlink();
    if (!this.shown) return;
    this.shown = false;
    this.element.hidden = true;
  }

  /** Blinks from the visible phase; any input calls this again to restart the budget. */
  restart(): void {
    if (!this.shown || this.reducedMotion.matches) return;
    if (!this.animation) {
      this.animation = this.element.animate(
        [{ opacity: 1, offset: 0 }, { opacity: 1, offset: 0.5 }, { opacity: 0, offset: 0.5 }, { opacity: 0, offset: 1 }],
        { duration: CURSOR_BLINK_PERIOD_MS, iterations: CURSOR_BLINK_ITERATIONS, easing: "linear" },
      );
      return;
    }
    this.animation.currentTime = 0;
    this.animation.play();
  }

  /** Leaves the cursor solid (hidden page, lost focus, keyboard gone). */
  stopBlink(): void {
    this.animation?.cancel();
    this.animation = undefined;
  }

  /** What the layer shows now. */
  snapshot(): TerminalCursorSnapshot {
    const playing = this.animation?.playState === "running";
    return { visible: this.shown, blinking: playing, ...this.box, color: this.color };
  }

  /** Stops the blink and removes the layer from the page. */
  dispose(): void {
    this.stopBlink();
    this.element.remove();
  }
}

/** Adds a cursor layer to `host` and returns it. The layer starts hidden until the first `place`. */
export function mountTerminalCursorLayer(host: HTMLElement): TerminalCursorLayer {
  return new TerminalCursorLayer(host);
}
