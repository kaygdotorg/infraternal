// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The palette action prefix of a docs row (`canvas:docs:<slug>#<heading>`), in a module of its own. The title rows (docs-index.on-demand.ts)
 * and the text rows (docs-search.on-demand.ts) both build their actions with it. It is not kept in either, because one on-demand module
 * importing another makes the bundler pull the other's whole chunk, and the Docs view with it, into the first-screen JavaScript.
 */

/** The prefix every docs row's action starts with; what follows is the page slug and, after `#`, the heading's id. */
export const DOCS_ACTION = "canvas:docs:";
