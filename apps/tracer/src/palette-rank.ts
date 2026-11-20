// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The command palette's one ranking rule (#442). The palette filters by substring and lists its groups in a fixed order, so a
 * page that is named by what the person typed could sit under a row that merely mentions the words (typing "infraternal
 * multiplexer" listed the Settings row "Offer To Switch", which explains the switch, before the page of that name).
 *
 * The rule: a row can carry a `title`, its own name when its label is a longer trail. When the title is, or starts with, the
 * query (case and a leading "the", "a" or "an" ignored), the group of that row is listed first. Every other order stays as it
 * was: groups keep their relative order, rows keep theirs inside a group, and a query that no title starts with changes
 * nothing. Moving the whole group, not the one row, keeps each group heading shown once.
 */

/** A palette row as far as ranking is concerned: the group it is listed under and, optionally, its own title. */
export interface Rankable {
  group: string;
  /** The row's own name when `label` is a longer trail ("Terminal › The Infraternal Multiplexer" has the title "The Infraternal Multiplexer"). */
  title?: string | undefined;
}

/** A leading "the", "a" or "an" and the space after it, which a title match ignores. */
const LEADING_ARTICLE = /^(?:the|a|an)\s+/;

/**
 * True when `title` equals `needle` or starts with it, ignoring case, surrounding spaces and a leading article of the title.
 * An empty or blank needle matches nothing.
 */
export function titleMatches(title: string, needle: string): boolean {
  const wanted = needle.trim().toLocaleLowerCase();
  if (wanted === "") return false;
  const full = title.trim().toLocaleLowerCase();
  return full.startsWith(wanted) || full.replace(LEADING_ARTICLE, "").startsWith(wanted);
}

/**
 * The rows with the groups that have a title match for `needle` moved to the front; the same array when there is no such group
 * (so the common keystroke allocates nothing). Linear in the number of rows.
 */
export function rankByTitle<T extends Rankable>(rows: T[], needle: string): T[] {
  let lead: Set<string> | undefined;
  for (const row of rows) {
    if (row.title !== undefined && titleMatches(row.title, needle)) (lead ??= new Set()).add(row.group);
  }
  if (!lead) return rows;
  const first: T[] = [], rest: T[] = [];
  for (const row of rows) (lead.has(row.group) ? first : rest).push(row);
  return [...first, ...rest];
}
