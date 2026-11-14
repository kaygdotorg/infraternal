// SPDX-License-Identifier: AGPL-3.0-only
/**
 * One way to cut a search snippet into plain and highlighted parts (#339), shared by the app's palette (core-screen.ts) and the standalone
 * docs search (site-search.ts), so neither can draw a mark twice. Both turn the parts into DOM nodes with `textContent`: no HTML is built
 * from the text, so a query or an index can never inject markup.
 */

/** A stretch of a snippet: `marked` parts are the words that matched the query. */
export interface SnippetPart { text: string; marked: boolean }

/**
 * Cuts `text` into parts at the `[start, end)` offsets in `marks`. Marks may arrive in any order and may overlap or touch (the query
 * "key keys" marks `[0,3]` and `[0,4]`): overlapping ones are joined into one part, so every character is drawn exactly once. Empty
 * parts are left out.
 */
export function snippetParts(text: string, marks: readonly (readonly [number, number])[]): SnippetPart[] {
  const parts: SnippetPart[] = [];
  const joined: [number, number][] = [];
  for (const [start, end] of [...marks].sort((a, b) => a[0] - b[0] || a[1] - b[1])) {
    const last = joined.at(-1);
    if (last && start <= last[1]) last[1] = Math.max(last[1], end);
    else joined.push([start, end]);
  }
  let at = 0;
  for (const [start, end] of joined) {
    if (start > at) parts.push({ text: text.slice(at, start), marked: false });
    if (end > start) parts.push({ text: text.slice(start, end), marked: true });
    at = Math.max(at, end);
  }
  if (at < text.length) parts.push({ text: text.slice(at), marked: false });
  return parts;
}
