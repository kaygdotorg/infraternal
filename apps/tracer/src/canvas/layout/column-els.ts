/** The column elements of a view, in order: plain columns and group wrappers' columns (D212). No DOM setup at load time. */
export function columnEls(colsEl: HTMLElement): HTMLElement[] {
  return [...colsEl.querySelectorAll<HTMLElement>(":scope > .cl-col, :scope > .cl-group > .cl-col")];
}
