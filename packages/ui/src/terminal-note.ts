/**
 * One quiet note over a terminal: a few words in the corner that never take a click or the cursor line (D309).
 *
 * It is a sibling of the terminal host, not part of the canvas, so it never reaches the renderer's
 * measured cells, the cursor layer or the text selection. It takes no pointer events, so typing,
 * selecting and scrolling pass through it. It sits in the half of the terminal that does not hold the
 * cursor row, so the line being typed on is never covered; the half is chosen when the note appears
 * and stays put while it is up, so it never jumps.
 *
 * Motion: a 120 ms opacity fade only, on the compositor, and none under reduced motion. Showing is
 * decided by the caller (`apps/tracer/src/stale-screen.ts`); this element only draws and removes.
 */

const STYLE = `
.ui-terminal-note { position: absolute; z-index: 2; right: 0.625rem; max-width: calc(100% - 1.25rem); margin: 0; padding: 0.1875rem 0.5rem;
  border-radius: 0.375rem; background: color-mix(in srgb, var(--bg, #101113) 82%, transparent); color: var(--fg-3, #8d9096);
  font: var(--fw-secondary, 400) var(--text-caption, 0.6875rem)/1.3 var(--font-mono, ui-monospace, monospace);
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis; pointer-events: none; user-select: none; opacity: 0;
  transition: opacity 120ms ease-out; }
.ui-terminal-note[data-edge="top"] { top: 0.5rem; }
.ui-terminal-note[data-edge="bottom"] { bottom: 0.5rem; }
.ui-terminal-note[data-shown] { opacity: 1; }
.ui-terminal-note[hidden] { display: none; }
@media (prefers-reduced-motion: reduce) { .ui-terminal-note { transition: none; } }
`;

let styled = false;

export interface TerminalNote {
  /** Shows the note in the half of the terminal away from the cursor row (`cursorRow` of `rows`). */
  show(cursorRow: number, rows: number): void;
  hide(): void;
  readonly visible: boolean;
  dispose(): void;
}

export function mountTerminalNote(host: HTMLElement, text: string): TerminalNote {
  if (!styled) { styled = true; const style = document.createElement("style"); style.textContent = STYLE; document.head.append(style); }
  const element = document.createElement("p");
  element.className = "ui-terminal-note";
  element.setAttribute("role", "status");
  element.hidden = true;
  element.textContent = text;
  // The host is absolutely positioned inside its window; a sibling shares that box without scrolling with the host.
  (host.parentElement ?? host).append(element);
  let visible = false;
  let hideTimer = 0;
  return {
    get visible() { return visible; },
    show(cursorRow, rows) {
      window.clearTimeout(hideTimer);
      element.dataset.edge = cursorRow < rows / 2 ? "bottom" : "top";
      element.hidden = false;
      visible = true;
      // One frame with the element laid out at opacity 0, so the fade has a start.
      requestAnimationFrame(() => { if (visible) element.dataset.shown = ""; });
    },
    hide() {
      if (!visible) return;
      visible = false;
      delete element.dataset.shown;
      hideTimer = window.setTimeout(() => { if (!visible) element.hidden = true; }, 140);
    },
    dispose() {
      window.clearTimeout(hideTimer);
      element.remove();
    },
  };
}
