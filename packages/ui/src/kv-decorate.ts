/**
 * Decorations for a row of the key/value list (kv-list.ts), added after the list has drawn its rows: a value that is a run of
 * short items that never break in the middle (a few account names with their counts), and a chevron on a pressable value that
 * opens a pane under its row. They live here and not in the list because the list is on the first screen's path (D188), and the
 * first screen needs neither: a screen that wants them imports this module, and the list stays as small as it was.
 *
 * - `parts`: the value is a run of items that wraps only between items, stays right-aligned, and tints each item. A name longer
 *   than the row ends in an ellipsis with its full text as the warm tooltip; the note after it (a count) is never cut. The plain
 *   text of the run is the row's `value` (the spoken name and the copy), so nothing is lost for a reader that ignores the items.
 * - `chevron`: a quiet chevron after the value, so a row that is not `wide` still reads as a link to a pane.
 */
import { ICONS } from "./icons";

export interface KeyValuePart { text: string; note?: string }

export interface KeyValueDecoration {
  parts?: KeyValuePart[];
  chevron?: boolean;
}

/** Decorates one `.ui-kv-row` that the list drew. */
export function decorateKeyValueRow(row: Element | null | undefined, decoration: KeyValueDecoration): void {
  const cell = row?.querySelector<HTMLElement>(".ui-kv-value");
  if (!cell) return;
  const { parts, chevron } = decoration;
  const text = cell.querySelector<HTMLElement>(".ui-kv-text");
  if (parts && text?.lastChild) {
    // One wrapper holds the whole run, so drawing the row again replaces the run instead of adding to it (a list that is
    // patched in place keeps this node, and the caller decorates after every `set`).
    const run = document.createDocumentFragment();
    parts.forEach((part, index) => {
      if (index) run.append(" ");
      const item = document.createElement("span");
      item.className = "ui-kv-part";
      const name = document.createElement("span");
      name.className = "ui-kv-part-name";
      name.textContent = part.text;
      if (part.note) name.dataset.tip = part.text;
      item.append(name);
      if (part.note) {
        const note = document.createElement("span");
        note.className = "ui-kv-part-note";
        note.textContent = ` ${part.note}`;
        item.append(note);
      }
      run.append(item);
    });
    const existing = text.querySelector<HTMLElement>(":scope > .ui-kv-parts");
    if (existing) existing.replaceChildren(run);
    else {
      const wrap = document.createElement("span");
      wrap.className = "ui-kv-parts";
      wrap.append(run);
      text.lastChild.replaceWith(wrap);
    }
  }
  if (chevron && cell.classList.contains("ui-kv-press") && !cell.querySelector(".ui-kv-chevron")) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("class", "ui-kv-chevron");
    svg.innerHTML = ICONS.next;
    cell.classList.add("ui-kv-has-chevron");
    cell.append(svg);
  }
}
