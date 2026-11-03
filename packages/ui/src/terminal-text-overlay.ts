/**
 * One shared canvas layer that draws speculative terminal glyphs and a cursor
 * on top of the renderer's canvas.
 *
 * Why a canvas and not DOM/SVG text: the terminal renderer rasterises glyphs
 * with `CanvasRenderingContext2D.fillText` on a device-pixel backing store.
 * Text drawn any other way (SVG, DOM) antialiases differently and lands on
 * different subpixels, so predicted text looked smeared next to real text.
 * This layer copies the renderer's exact drawing path (same font string,
 * baseline, cell x, backing size and device-pixel transform), so a predicted
 * glyph is pixel-identical to the glyph the host echo later paints, apart
 * from the overlay's opacity cue.
 *
 * Cost model (the overlay runs on every keystroke):
 * - No layout reads per key. The canvas offset inside the host is read only
 *   on `invalidate()` or when the renderer canvas changes size; both share the
 *   host's scroll container, so scrolling needs no update.
 * - Each draw clears only the rows touched by the previous draw and repaints
 *   the pending run (bounded by the caller), so cost scales with pending
 *   glyphs, not with the screen.
 * - No DOM nodes are created per key.
 */

export interface TerminalTextOverlayPosition {
  canvas: HTMLCanvasElement;
  x: number;
  y: number;
  visible: boolean;
  alternate: boolean;
  viewportY: number;
  columns: number;
  rows: number;
  cellWidth: number;
  cellHeight: number;
  naturalCellWidth?: number;
  baseline: number;
  fontFamily: string;
  fontSize: number;
  devicePixelRatio?: number | undefined;
  foreground?: string | undefined;
  /** The terminal's opaque background; covers cells whose confirmed glyph a pending erase removes. */
  background?: string | undefined;
  cursorStyle?: "block" | "underline" | "bar";
  cursorColor?: string;
}

export interface TerminalTextOverlayGlyph {
  text: string;
  x: number;
  y: number;
  cells: number;
}

/** A cell, by whole column and row, that a pending erase has cleared in text the host already confirmed. */
export interface TerminalTextOverlayCell {
  x: number;
  y: number;
}

export interface TerminalTextOverlayCursor {
  x: number;
  y: number;
}

/** What the overlay last drew, in CSS pixels relative to the renderer canvas (for tests and probes). */
export interface TerminalTextOverlaySnapshot {
  visible: boolean;
  text: string;
  glyphs: Array<{ text: string; x: number; y: number }>;
  /** Cells covered with the background, in CSS pixels. */
  erased: Array<{ x: number; y: number }>;
  cursor: { x: number; y: number; width: number; height: number } | undefined;
}

export class TerminalTextOverlay {
  private readonly canvas: HTMLCanvasElement;
  private readonly context: CanvasRenderingContext2D | null;
  private offsetKey = "";
  private drawnRows: [number, number] | undefined;
  private shown = false;
  private last: TerminalTextOverlaySnapshot = { visible: false, text: "", glyphs: [], erased: [], cursor: undefined };
  /** The one subtle cue that a glyph is still unconfirmed; the cursor stays fully opaque. */
  private readonly textAlpha: number;

  constructor(private readonly host: HTMLElement) {
    const canvas = document.createElement("canvas");
    canvas.className = "terminal-text-overlay";
    canvas.setAttribute("aria-hidden", "true");
    canvas.style.visibility = "hidden";
    host.append(canvas);
    this.canvas = canvas;
    this.context = canvas.getContext("2d");
    const alpha = Number.parseFloat(getComputedStyle(host).getPropertyValue("--terminal-prediction-opacity"));
    this.textAlpha = Number.isFinite(alpha) && alpha > 0 && alpha <= 1 ? alpha : 0.72;
  }

  /** Forgets cached geometry; call after a resize, refit or font change. */
  invalidate(): void {
    this.offsetKey = "";
  }

  /** Draws pending glyphs and the cursor on the renderer's cell grid. Returns false when nothing may be shown. */
  show(
    glyphs: readonly TerminalTextOverlayGlyph[],
    cursor: TerminalTextOverlayCursor | undefined,
    position: TerminalTextOverlayPosition,
    erased: readonly TerminalTextOverlayCell[] = [],
  ): boolean {
    const context = this.context;
    if (!context || (!glyphs.length && !cursor && !erased.length) || !position.visible || position.alternate || position.viewportY !== 0
      || position.x < 0 || position.x >= position.columns || position.y < 0 || position.y >= position.rows) {
      this.hide();
      return false;
    }
    const source = position.canvas;
    if (source.width <= 0 || source.height <= 0) {
      this.hide();
      return false;
    }
    const dpr = position.devicePixelRatio ?? window.devicePixelRatio ?? 1;
    this.syncGeometry(source, dpr);

    const { cellWidth, cellHeight } = position;
    // Clear only what the previous draw touched.
    if (this.drawnRows) {
      const [from, to] = this.drawnRows;
      context.clearRect(0, from * cellHeight, source.width / dpr, (to - from + 1) * cellHeight);
    }

    let minRow = Number.POSITIVE_INFINITY;
    let maxRow = Number.NEGATIVE_INFINITY;
    const drawn: TerminalTextOverlaySnapshot["glyphs"] = [];
    // Cells erased out of confirmed text are covered first, so the old glyph is gone before the host repaints.
    const covered: TerminalTextOverlaySnapshot["erased"] = [];
    if (position.background) {
      context.globalAlpha = 1;
      context.fillStyle = position.background;
      for (const cell of erased) {
        const x = cell.x * cellWidth;
        context.fillRect(x, cell.y * cellHeight, cellWidth, cellHeight);
        covered.push({ x, y: cell.y * cellHeight });
        if (cell.y < minRow) minRow = cell.y;
        if (cell.y > maxRow) maxRow = cell.y;
      }
    }
    context.font = `${position.fontSize}px ${position.fontFamily}`;
    context.textBaseline = "alphabetic";
    context.textAlign = "left";
    context.fillStyle = position.foreground ?? "currentColor";
    context.globalAlpha = this.textAlpha;
    for (const glyph of glyphs) {
      // Every glyph is placed on its own cell, exactly like the renderer's grid, so runs never drift.
      const x = glyph.x * cellWidth;
      const y = glyph.y * cellHeight + position.baseline;
      context.fillText(glyph.text, x, y);
      drawn.push({ text: glyph.text, x, y: glyph.y * cellHeight });
      if (glyph.y < minRow) minRow = glyph.y;
      if (glyph.y > maxRow) maxRow = glyph.y;
    }

    context.globalAlpha = 1;
    let cursorBox: TerminalTextOverlaySnapshot["cursor"];
    if (cursor) {
      const style = position.cursorStyle ?? "bar";
      const x = cursor.x * cellWidth;
      const y = cursor.y * cellHeight;
      let width = cellWidth;
      let height = cellHeight;
      // Same geometry as the renderer's renderCursor().
      if (style === "bar") width = Math.max(2, Math.floor(cellWidth * 0.15));
      if (style === "underline") height = Math.max(2, Math.floor(cellHeight * 0.15));
      const top = style === "underline" ? y + cellHeight - height : y;
      context.fillStyle = position.cursorColor ?? position.foreground ?? "currentColor";
      context.fillRect(x, top, width, height);
      cursorBox = { x, y: top, width, height };
      if (cursor.y < minRow) minRow = cursor.y;
      if (cursor.y > maxRow) maxRow = cursor.y;
    }

    this.drawnRows = [minRow, maxRow];
    if (!this.shown) {
      this.canvas.style.visibility = "visible";
      this.shown = true;
    }
    this.last = { visible: true, text: glyphs.map((glyph) => glyph.text).join(""), glyphs: drawn, erased: covered, cursor: cursorBox };
    return true;
  }

  /**
   * Synchronises the canvas with the renderer's current size (the costly part of a first draw after a resize)
   * without drawing or showing anything. A no-op while something is on screen.
   */
  warm(position: TerminalTextOverlayPosition): void {
    const source = position.canvas;
    if (!this.context || this.shown || source.width <= 0 || source.height <= 0) return;
    this.syncGeometry(source, position.devicePixelRatio ?? window.devicePixelRatio ?? 1);
  }

  /** Removes speculative pixels immediately when their input is confirmed or invalidated. */
  hide(): void {
    if (this.context && this.drawnRows) {
      this.context.clearRect(0, 0, this.canvas.width, this.canvas.height);
    }
    this.drawnRows = undefined;
    if (this.shown) {
      this.canvas.style.visibility = "hidden";
      this.shown = false;
    }
    this.last = { visible: false, text: "", glyphs: [], erased: [], cursor: undefined };
  }

  /** What is currently drawn (CSS pixels relative to the renderer canvas). */
  snapshot(): TerminalTextOverlaySnapshot {
    return this.last;
  }

  dispose(): void {
    this.hide();
    this.canvas.remove();
  }

  /** Matches the renderer canvas's offset, CSS size and backing size; reads layout only when something changed. */
  private syncGeometry(source: HTMLCanvasElement, dpr: number): void {
    const key = `${source.width}x${source.height}@${dpr}`;
    if (key === this.offsetKey) return;
    // offsetLeft/Top round rem-based padding to whole CSS pixels. Preserve the
    // renderer's fractional origin, undoing any shared canvas zoom first. These
    // local offsets remain valid while the common scroll container moves.
    const sourceBox = source.getBoundingClientRect();
    const hostBox = this.host.getBoundingClientRect();
    const sourceStyle = getComputedStyle(source);
    const scaleX = sourceBox.width / Number.parseFloat(sourceStyle.width);
    const scaleY = sourceBox.height / Number.parseFloat(sourceStyle.height);
    // A hidden pane can warm before layout; retry its geometry when it is shown.
    if (!(scaleX > 0) || !(scaleY > 0)) return;
    this.offsetKey = key;
    this.canvas.style.left = `${(sourceBox.left - hostBox.left) / scaleX + this.host.scrollLeft - this.host.clientLeft}px`;
    this.canvas.style.top = `${(sourceBox.top - hostBox.top) / scaleY + this.host.scrollTop - this.host.clientTop}px`;
    this.canvas.style.width = source.style.width || `${source.width / dpr}px`;
    this.canvas.style.height = source.style.height || `${source.height / dpr}px`;
    // Resizing a canvas clears it and resets its transform.
    this.canvas.width = source.width;
    this.canvas.height = source.height;
    this.context?.setTransform(dpr, 0, 0, dpr, 0, 0);
    this.drawnRows = undefined;
  }
}

export function mountTerminalTextOverlay(host: HTMLElement): TerminalTextOverlay {
  return new TerminalTextOverlay(host);
}
