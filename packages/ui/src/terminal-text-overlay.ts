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
  baseline: number;
  fontFamily: string;
  fontSize: number;
}

/** Reusable SVG text layer; callers own when text is safe to show. */
export class TerminalTextOverlay {
  private readonly svg: SVGSVGElement;
  private readonly text: SVGTextElement;

  constructor(private readonly host: HTMLElement) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.classList.add("terminal-text-overlay");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("preserveAspectRatio", "none");
    const text = document.createElementNS("http://www.w3.org/2000/svg", "text");
    text.setAttribute("font-weight", "400");
    text.setAttribute("fill", "currentColor");
    svg.append(text);
    host.append(svg);
    this.svg = svg;
    this.text = text;
  }

  /** Updates text and cell geometry synchronously with the renderer paint. */
  show(content: string, position: TerminalTextOverlayPosition): boolean {
    if (!content || !position.visible || position.alternate || position.viewportY !== 0
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
    this.text.setAttribute("x", String(position.x * position.cellWidth));
    this.text.setAttribute("y", String(position.y * position.cellHeight + position.baseline));
    this.text.setAttribute("font-family", position.fontFamily);
    this.text.setAttribute("font-size", String(position.fontSize));
    this.text.textContent = content;
    return true;
  }

  /** Removes speculative glyphs immediately when their input is invalidated. */
  hide(): void {
    this.svg.style.visibility = "hidden";
    this.text.textContent = "";
  }

  dispose(): void {
    this.hide();
    this.svg.remove();
  }
}

export function mountTerminalTextOverlay(host: HTMLElement): TerminalTextOverlay {
  return new TerminalTextOverlay(host);
}
