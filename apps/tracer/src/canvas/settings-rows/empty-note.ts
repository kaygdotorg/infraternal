// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The one line a Settings window shows when it has nothing to draw (#568). Before, a window with no store behind any of its
 * settings said "Not available yet.", which named neither what was missing nor what would change. The line names the
 * settings that will appear in that window, so the person sees what is coming and why nothing can be changed yet.
 *
 * It gives no date. The table does not decide dates, and an undecided date must not be made up here. The sentence is kept
 * free of the DOM so the wording can be unit-tested without a browser.
 */

/**
 * The sentence for an empty window, from the plain titles of its settings in table order. An empty list means the window
 * has no settings at all (it only lists facts, say), and gets the short line.
 */
export function emptyGroupNote(titles: readonly string[]): string {
  if (titles.length === 0) return "Nothing to set here yet.";
  const names = titles.length === 1 ? titles[0] : `${titles.slice(0, -1).join(", ")} and ${titles[titles.length - 1]}`;
  return `Nothing to set here yet. ${names} will appear here once the server can save ${titles.length === 1 ? "it" : "them"}.`;
}
