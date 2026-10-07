/** Positions one shared, text-only terminal overlay above a renderer canvas. */

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
  cursorStyle?: "block" | "underline" | "bar";
  cursorColor?: string;
}

export interface TerminalTextOverlayGlyph {
  text: string;
  x: number;
  y: number;
  cells: number;
}

export interface TerminalTextOverlayCursor {
  x: number;
  y: number;
}

/** Reusable SVG text layer; callers own when text is safe to show. */
export class TerminalTextOverlay {
  private readonly svg: SVGSVGElement;
  private readonly text: SVGTextElement;
  private readonly cursor: SVGRectElement;

  constructor(private readonly host: HTMLElement) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.classList.add("terminal-text-overlay");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("preserveAspectRatio", "none");
    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("font-weight", "400");
    text.setAttribute("fill", "currentColor");
    const cursor = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    cursor.classList.add("terminal-text-overlay-cursor");
    svg.append(text);
    svg.append(cursor);
    host.append(svg);
    this.svg = svg;
    this.text = text;
    this.cursor = cursor;
  }

  /** Places text runs and the cursor on the renderer's cell grid without measuring glyphs here. */
  show(content: string, position: TerminalTextOverlayPosition): boolean;
  show(
    glyphs: readonly TerminalTextOverlayGlyph[],
    cursor: TerminalTextOverlayCursor | undefined,
    position: TerminalTextOverlayPosition,
  ): boolean;
  show(
    contentOrGlyphs: string | readonly TerminalTextOverlayGlyph[],
    cursorOrPosition: TerminalTextOverlayCursor | TerminalTextOverlayPosition | undefined,
    suppliedPosition?: TerminalTextOverlayPosition,
  ): boolean {
    const legacyContent = typeof contentOrGlyphs === "string" ? contentOrGlyphs : undefined;
    const glyphs = typeof contentOrGlyphs === "string" ? undefined : contentOrGlyphs;
    const cursor = legacyContent === undefined ? cursorOrPosition as TerminalTextOverlayCursor | undefined : undefined;
    const position = legacyContent === undefined
      ? suppliedPosition
      : cursorOrPosition as TerminalTextOverlayPosition | undefined;
    if (!position) return false;
    if ((!legacyContent && !glyphs?.length && !cursor) || !position.visible || position.alternate || position.viewportY !== 0
      || position.x < 0 || position.x >= position.columns || position.y < 0 || position.y >= position.rows) {
      this.hide();
      return false;
    }

    const hostRect = this.host.getBoundingClientRect();
    const canvasRect = position.canvas.getBoundingClientRect();
    if (canvasRect.width <= 0 || canvasRect.height <= 0) {
      this.hide();
      return false;
    }

    this.svg.style.left = `${canvasRect.left - hostRect.left}px`;
    this.svg.style.top = `${canvasRect.top - hostRect.top}px`;
    this.svg.style.width = `${canvasRect.width}px`;
    this.svg.style.height = `${canvasRect.height}px`;
    this.svg.setAttribute("viewBox", `0 0 ${canvasRect.width} ${canvasRect.height}`);
    this.svg.style.visibility = "visible";
    this.text.setAttribute("font-family", position.fontFamily);
    this.text.setAttribute("font-size", String(position.fontSize));
    const cursorStyle = position.cursorStyle ?? "bar";
    if (legacyContent === undefined) {
      this.text.setAttribute("letter-spacing", `${position.cellWidth - (position.naturalCellWidth ?? position.cellWidth)}px`);
    } else {
      this.text.removeAttribute("letter-spacing");
    }
    const firstGlyph = glyphs?.[0];
    const textOrigin = firstGlyph ?? cursor ?? position;
    this.text.setAttribute("x", String(textOrigin.x * position.cellWidth));
    this.text.setAttribute("y", String(textOrigin.y * position.cellHeight + position.baseline));
    this.text.replaceChildren();
    if (legacyContent !== undefined) {
      this.text.textContent = legacyContent;
      this.cursor.style.visibility = "hidden";
      return true;
    }
    const runs: Array<{ x: number; y: number; cells: number; content: string }> = [];
    for (const glyph of glyphs ?? []) {
      const last = runs[runs.length - 1];
      if (last && last.y === glyph.y && last.x + last.cells === glyph.x) {
        last.content += glyph.text;
        last.cells += glyph.cells;
      } else {
        runs.push({ x: glyph.x, y: glyph.y, cells: glyph.cells, content: glyph.text });
      }
    }
    for (const run of runs) {
      const tspan = document.createElementNS("http://www.w3.org/2000/svg", "tspan");
      tspan.setAttribute("x", String(run.x * position.cellWidth));
      tspan.setAttribute("y", String(run.y * position.cellHeight + position.baseline));
      tspan.textContent = run.content;
      this.text.append(tspan);
    }
    if (cursor) {
      const x = cursor.x * position.cellWidth;
      const y = cursor.y * position.cellHeight;
      let width = position.cellWidth;
      let height = position.cellHeight;
      if (cursorStyle === "bar") width = Math.max(2, Math.floor(position.cellWidth * 0.15));
      if (cursorStyle === "underline") height = Math.max(2, Math.floor(position.cellHeight * 0.15));
      this.cursor.setAttribute("x", String(x));
      this.cursor.setAttribute("y", String(cursorStyle === "underline" ? y + position.cellHeight - height : y));
      this.cursor.setAttribute("width", String(width));
      this.cursor.setAttribute("height", String(height));
      this.cursor.setAttribute("fill", position.cursorColor ?? "currentColor");
      this.cursor.style.visibility = "visible";
    } else {
      this.cursor.style.visibility = "hidden";
    }
    return true;
  }

  /** Removes speculative glyphs immediately when their input is invalidated. */
  hide(): void {
    this.svg.style.visibility = "hidden";
    this.text.replaceChildren();
    this.cursor.style.visibility = "hidden";
  }

  dispose(): void {
    this.hide();
    this.svg.remove();
  }
}

export function mountTerminalTextOverlay(host: HTMLElement): TerminalTextOverlay {
  return new TerminalTextOverlay(host);
}
