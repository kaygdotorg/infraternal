// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Searching the text of the docs (#339, D388: "cmd + k should match everything!"). One pure module, used by the app's palette
 * (docs-search.on-demand.ts) and by the standalone pages' own palette (doc-page.ts), so both rank and highlight the same way.
 *
 * The docs build writes `search.json` next to `index.json` (docs-search-index.ts): per page, its title and its sections, each section
 * being a heading and the plain text under it (the page's opening has no heading). Nothing is sent to a service; the file is fetched
 * only when a search is about to start, and the matching runs in the browser (D46).
 *
 * The rules:
 * - every word of the query must appear in the section (its page title, its heading or its text), in any order, as part of a word;
 * - a section whose heading has every word ranks above one that only has them in its text, and a page whose title has every word
 *   ranks above both. Inside each of those, whole words and words side by side as typed rank first, then the order of the docs;
 * - a hit carries a short snippet of the text around the first match and the places to highlight, so the row can show why it matched.
 */

/** One part of a page: the heading (empty for the page's opening), its anchor (empty for the opening) and the plain text under it. */
export interface SearchSection { heading: string; id: string; text: string }
/** One page of `search.json`: the address under `/docs/` (with the audience on the standalone site), its title and its sections. */
export interface SearchPage { slug: string; title: string; sections: SearchSection[] }

/** A page prepared for matching: the lower-cased texts are made once, when the index loads, not on every keystroke. */
export interface Prepared { page: SearchPage; title: string; headings: string[]; texts: string[] }

/** One result: where it leads (`slug` and `id`, the section's anchor), what to call it, and the snippet with the places to highlight. */
export interface SearchHit {
  slug: string;
  title: string;
  heading: string;
  id: string;
  snippet: string;
  /** `[start, end)` offsets into `snippet` of each place a word of the query matched. */
  marks: [number, number][];
  rank: number;
}

/** How many characters of text a snippet shows, at most. */
const SNIPPET = 110;
/** Words shorter than this are not searched on their own: one letter would match every section. */
const MIN_WORD = 2;

/** Lower-cases and splits a query into its words; words that are too short and repeats are dropped. */
export function queryWords(query: string): string[] {
  return [...new Set(query.toLocaleLowerCase().split(/\s+/).filter((word) => word.length >= MIN_WORD))];
}

/** The pages made ready for `searchDocs`; call once per loaded index. */
export function prepareSearch(pages: readonly SearchPage[]): Prepared[] {
  return pages.map((page) => ({
    page,
    title: page.title.toLocaleLowerCase(),
    headings: page.sections.map((section) => section.heading.toLocaleLowerCase()),
    texts: page.sections.map((section) => section.text.toLocaleLowerCase()),
  }));
}

/** True when `word` stands as a whole word in `text` (a letter or digit on neither side), so "check" beats "checkout". */
function wholeWord(text: string, word: string): boolean {
  for (let at = text.indexOf(word); at >= 0; at = text.indexOf(word, at + 1)) {
    if (!/[\p{L}\p{N}]/u.test(text[at - 1] ?? " ") && !/[\p{L}\p{N}]/u.test(text[at + word.length] ?? " ")) return true;
  }
  return false;
}

/** True when `text` holds every word. */
const hasAll = (text: string, words: readonly string[]): boolean => words.every((word) => text.includes(word));

/**
 * The snippet of `text` around the first place a word matched, cut at word edges and marked with an ellipsis where it is cut. A section
 * with no match in its text (it matched by title or heading) shows its first words.
 */
function snippetOf(text: string, lower: string, words: readonly string[]): { snippet: string; marks: [number, number][] } {
  let first = -1;
  for (const word of words) {
    const at = lower.indexOf(word);
    if (at >= 0 && (first < 0 || at < first)) first = at;
  }
  let start = first < 0 ? 0 : Math.max(0, first - 30);
  if (start > 0) { const space = text.indexOf(" ", start); start = space >= 0 && space < first ? space + 1 : start; }
  let end = Math.min(text.length, start + SNIPPET);
  if (end < text.length) { const space = text.lastIndexOf(" ", end); end = space > start + SNIPPET / 2 ? space : end; }
  const cut = text.slice(start, end);
  const snippet = `${start > 0 ? "…" : ""}${cut}${end < text.length ? "…" : ""}`;
  const shift = start > 0 ? 1 : 0;
  const low = cut.toLocaleLowerCase();
  const marks: [number, number][] = [];
  // Lower-casing can change a length (a few letters in a few scripts); then the marks are skipped rather than drawn in the wrong place.
  if (low.length === cut.length) {
    for (const word of words) {
      for (let at = low.indexOf(word); at >= 0; at = low.indexOf(word, at + word.length)) marks.push([at + shift, at + shift + word.length]);
    }
  }
  return { snippet, marks: marks.sort((a, b) => a[0] - b[0]) };
}

/**
 * The best sections for `query`, most relevant first, at most `limit`. A page's opening and each of its headed sections can each be a
 * hit, so a result lands on the heading's anchor (an empty `id` is the top of the page). Returns nothing for a query with no usable word.
 */
export function searchDocs(prepared: readonly Prepared[], query: string, limit = 24): SearchHit[] {
  const words = queryWords(query);
  if (words.length === 0) return [];
  const hits: SearchHit[] = [];
  for (const [order, entry] of prepared.entries()) {
    const titled = hasAll(entry.title, words);
    for (const [at, section] of entry.page.sections.entries()) {
      const heading = entry.headings[at]!;
      const lower = entry.texts[at]!;
      const inHeading = hasAll(heading, words);
      // A word may be in the title, another in the heading and a third in the text: the section matches when together they hold them all.
      if (!titled && !inHeading && !hasAll(`${entry.title} ${heading} ${lower}`, words)) continue;
      // A page whose title has the words would list every one of its sections: only its opening stands for the title, and a later section needs a word of its own.
      if (titled && !inHeading && section.id !== "" && !words.some((word) => heading.includes(word) || lower.includes(word))) continue;
      const { snippet, marks } = snippetOf(section.text, lower, words);
      // Higher is better; the page order breaks ties, so the docs read in their own order.
      // The class (title, heading, text) is worth far more than the finer signals below, which only order matches inside a class: the words
      // standing as whole words, and the words standing next to each other, as typed.
      const fine = words.filter((word) => wholeWord(`${heading} ${lower}`, word)).length * 1000 + (words.length > 1 && `${heading} ${lower}`.includes(words.join(" ")) ? 3000 : 0);
      const rank = (titled && section.id === "" ? 300000 : titled ? 200000 : inHeading ? 100000 : 0) + fine - order;
      hits.push({ slug: entry.page.slug, title: entry.page.title, heading: section.heading, id: section.id, snippet, marks, rank });
    }
  }
  return hits.sort((a, b) => b.rank - a.rank).slice(0, limit);
}
