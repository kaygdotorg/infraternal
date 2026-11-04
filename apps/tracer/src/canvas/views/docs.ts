// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The Docs view (#302): a view like Settings and Mesh, with one window of kind `docs` for each page of the docs build.
 *
 * Its windows come from the docs index (`/docs/index.json`), so a page added to `docs/user/` appears here with no change to the app.
 * The view is offered once the index has loaded (docs/docs-source.ts); a server without docs has no Docs view. It is never saved to
 * the canvas document: the pages are the server's, not the person's layout. Like Settings, its windows have no close button.
 */
import type { Metrics } from "../layout/geometry";
import type { ViewModel } from "../model/types";

/** The Docs view's id. */
export const DOCS_VIEW = "docs";
/**
 * A window's id is `d-<slug>`; the slug is the page's address under `/docs/`, a slash between section and page included
 * (`d-terminal/multiplexer`). The body of the window takes the slug back out of the id (views/body.ts), so the id keeps it whole.
 */
export const docsWindowId = (slug: string): string => `d-${slug}`;

/** What the view needs to know about a page. */
export interface DocsPageRef { slug: string; title: string }

/** Builds the Docs view's model: one window of kind `docs` in its own column for each page, in the given order, at the default column width. */
export function buildDocsView(pages: readonly DocsPageRef[], m: Metrics): ViewModel {
  return {
    id: DOCS_VIEW, name: "Docs", layout: "tiled", nodes: [], x: 0, y: 0,
    cols: pages.map((page) => ({ id: docsWindowId(page.slug), w: m.colW, wins: [{ id: docsWindowId(page.slug), kind: "docs" as const, host: page.title }] })),
  };
}
