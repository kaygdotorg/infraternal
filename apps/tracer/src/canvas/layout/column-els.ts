/**
 * Helpers for reading and sizing a view's column elements. A column has two widths: the saved one (`data-w`, which is what the
 * layout stores) and the drawn one (`--w`, which a device may raise to a floor or lower to a ceiling). Keep them apart: only
 * the saved width is ever written back to the model.
 */
import { drawnWidth, type Metrics } from "./geometry";

/** The column elements of a view, in order: plain columns and group wrappers' columns (D212). No DOM setup at load time. */
export function columnEls(colsEl: HTMLElement): HTMLElement[] {
  return [...colsEl.querySelectorAll<HTMLElement>(":scope > .cl-col, :scope > .cl-group > .cl-col")];
}

/**
 * Gives a column its saved width and the width it is drawn at (D309). `data-w` is the saved width: it is what is read back
 * into the model and saved as the column's weight. `--w` is what the stylesheet draws, which on a touch screen is never
 * below the readable minimum. Always set both together, so a device that draws wider never saves what it drew.
 */
export function setColumnWidth(colEl: HTMLElement, w: number, m: Pick<Metrics, "minW" | "maxW">): void {
  colEl.dataset.w = String(w);
  colEl.style.setProperty("--w", `${drawnWidth(w, m)}px`);
}

/** The width a column is drawn at: the width it was given (`data-w`) unless a floor raised it or the ceiling lowered it (`--w`). */
export function drawnWidthOf(colEl: HTMLElement): number {
  return parseFloat(colEl.style.getPropertyValue("--w")) || Number(colEl.dataset.w) || 0;
}
