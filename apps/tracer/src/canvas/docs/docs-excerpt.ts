// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The excerpt a window's "?" shows (issue #304): the most helpful few lines about the thing in front of the person, taken from the
 * docs and never written twice.
 *
 * Source: the docs index (`index.json`). A heading may carry `facts` (the text of its `> [!FACTS]` block, a few short sentences, at most 320
 * characters, written by the docs build) and a page may too; a page with none is previewed by its `summary`. Nothing here reads page bodies.
 *
 * Shape: a LEAD (the first sentence), then two to four BULLETS (the sentences after it), then an optional small TABLE. The writer of the docs
 * needs no extra marker for the usual case: three short sentences in a `[!FACTS]` block are a lead and two bullets. A table is read from the
 * block when the docs build provides one (`factsTable`), so a window whose answer is a few figures shows them as figures.
 */
import type { DocsPreviewContent } from "../../../../../packages/ui/src/docs-preview.on-demand";
import type { DocsHeading, DocsIndexPage } from "./docs-source";

/** At most this many bullets: a preview that scrolls is not a preview. */
export const MAX_BULLETS = 4;

export type { DocsPreviewContent };

/**
 * Sentences of a short text, in order. A full stop (or ! or ?) ends one when a space and a capital letter or a digit follows, so "30 days." and
 * "3.5 days" stay whole and so does "e.g. the cookie". Text with no such stop is one sentence.
 */
export function splitSentences(text: string): string[] {
  return text.trim().split(/(?<=[.!?])\s+(?=[A-Z0-9“"(])/).map((s) => s.trim()).filter(Boolean);
}

/** The excerpt for a page, or for one of its headings. `table` rides along when the build gave one. */
export function excerptOf(page: DocsIndexPage, heading?: DocsHeading): DocsPreviewContent {
  const title = heading?.text ?? page.title;
  const facts = heading ? heading.facts : page.facts;
  const table = heading ? heading.factsTable : page.factsTable;
  const sentences = splitSentences(facts ?? page.summary);
  const [lead, ...rest] = sentences;
  return { title, ...(lead ? { lead } : {}), bullets: rest.slice(0, MAX_BULLETS), ...(table ? { table } : {}) };
}
