// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The text index of the docs (#339, D388): what the docs build writes as `search.json`, so ⌘K can match the words of a page and not only
 * its title and headings. Built at docs-build time, from the same rendered pages as `index.json`; there is no service and no crawler (D46).
 *
 * A page is cut into sections at its level-2 and level-3 headings (the same anchors the table of contents uses). Each section keeps the
 * plain text under its heading, code included, because people search for a command. The page's opening (its summary, and whatever comes
 * before the first heading) is a section with no heading. The footer of a page (decision numbers) is not indexed.
 *
 * The browser side is src/canvas/docs/docs-search.ts, which also owns the `SearchPage` shape.
 */
import type { SearchPage, SearchSection } from "./src/canvas/docs/docs-search";

/** Block tags whose end is a break between words, so the text of two cells or list items does not run together. */
const BLOCK_END = /<\/(?:p|li|h[1-6]|tr|td|th|pre|div|blockquote|figcaption|summary|dt|dd)>|<br\s*\/?>/gi;

/** The plain text of a fragment of HTML: tags dropped, entities decoded, runs of space collapsed. */
export function textOf(html: string): string {
  return html
    .replace(BLOCK_END, " ")
    .replace(/<[^>]+>/g, "")
    .replace(/&#x([0-9a-f]+);/gi, (_all, code: string) => String.fromCodePoint(parseInt(code, 16)))
    .replace(/&#(\d+);/g, (_all, code: string) => String.fromCodePoint(Number(code)))
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Cuts the rendered body of a page (headings already carry their `id`, `anchorHeadings` in docs-build.ts) into its sections.
 * `summary` is the page's one-sentence summary, which opens the first section.
 */
export function sectionsOf(bodyHtml: string, summary: string): SearchSection[] {
  const sections: SearchSection[] = [];
  const heading = /<h([23])[^>]*\sid="([^"]+)"[^>]*>([\s\S]*?)<\/h\1>/g;
  let previous: { heading: string; id: string } = { heading: "", id: "" };
  let from = 0;
  const close = (to: number): void => {
    const text = textOf(`${previous.id === "" ? `${summary} ` : ""}${bodyHtml.slice(from, to)}`);
    // Every section is kept, even one with no text of its own (a heading over subheadings): the heading is still something to find.
    sections.push({ heading: previous.heading, id: previous.id, text });
  };
  for (const match of bodyHtml.matchAll(heading)) {
    close(match.index);
    previous = { heading: textOf(match[3]!), id: match[2]! };
    from = match.index + match[0].length;
  }
  close(bodyHtml.length);
  return sections;
}

/** The `search.json` entry of one page. */
export function searchPageOf(slug: string, title: string, summary: string, bodyHtml: string): SearchPage {
  // The list of pages the build adds under a front page or a section overview repeats every title; it is navigation, not text to find.
  return { slug, title, sections: sectionsOf(bodyHtml.replace(/<ul class="pages">[\s\S]*?<\/ul>/g, ""), summary) };
}
