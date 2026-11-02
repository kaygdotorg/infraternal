// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs as a source for the command palette (⌘K, #302).
 *
 * The palette finds a docs page by its title and by its headings, nothing else: typing "keys" or "multiplexer" lists
 * the page, typing a heading lists that heading. Enter opens the page in a canvas window (docs-reader.on-demand.ts),
 * at the heading when a heading was chosen.
 *
 * The index is `/docs/index.json`, written by the docs build (docs-build.ts): titles and headings only, a few hundred
 * bytes per page. It is fetched when the palette first opens, never at start-up (docs-index.on-demand.ts), so it adds
 * nothing to the first screen. This file is the only part that ships with the canvas; it is a provider like the others
 * (`core.addPaletteProvider`) whose rows come from a cache that the first open fills, after which the palette
 * refreshes in place. A failed fetch leaves no rows and is tried again at the next open.
 *
 * Heading rows are `queryOnly`: the list at rest shows one row per page and typing reveals the headings.
 * Action ids are `canvas:docs:<slug>` and `canvas:docs:<slug>#<heading>`.
 */
import type { CoreScreen, PaletteEntry } from "../../core-screen";
import { onDemand } from "../../on-demand";
import type { FlowHost } from "../addhost/flow-host";

/** The shape of `index.json` (docs-build.ts `DocsIndexPage`). */
export interface DocsIndexPage { slug: string; title: string; summary: string; headings: { id: string; text: string }[] }

export const DOCS_ACTION = "canvas:docs:";

/** Splits `canvas:docs:<slug>#<heading>`; anything else is not ours. */
export function parseDocsAction(action: string | undefined): { slug: string; heading?: string } | undefined {
  if (!action?.startsWith(DOCS_ACTION)) return undefined;
  const [slug, heading] = action.slice(DOCS_ACTION.length).split("#", 2);
  return slug ? { slug, ...(heading ? { heading } : {}) } : undefined;
}

export interface DocsSource { dispose(): void }

export function installDocsSource(core: CoreScreen, host: FlowHost): DocsSource {
  const controller = new AbortController();
  let pages: DocsIndexPage[] | undefined;
  let rows: PaletteEntry[] = [];
  let loading = false;
  const load = (): void => {
    if (pages || loading) return;
    loading = true;
    void onDemand(() => import("./docs-index.on-demand")).then((module) => module.loadDocsIndex(controller.signal)).then((index) => {
      pages = index.pages;
      rows = index.rows;
      core.refreshPalette();
    })
      // No docs on this server, or offline: the palette simply has no docs rows until its next open.
      .catch(() => {})
      .finally(() => { loading = false; });
  };
  // The provider runs each time the palette opens, which is the moment the index is wanted.
  const removeProvider = core.addPaletteProvider(() => { load(); return rows; });

  const onAction = (event: Event): void => {
    const target = parseDocsAction((event as CustomEvent<{ action?: string }>).detail?.action);
    const page = pages?.find((entry) => entry.slug === target?.slug);
    if (!target || !page) return;
    // The reader's code loads when a page is first opened (D188); it is not part of the canvas.
    void onDemand(() => import("./docs-reader.on-demand")).then(
      (module) => module.openDocsPage({ host, pages: pages ?? [], say: (message) => core.toast.show({ message, tone: "error" }) }, page, target.heading),
      () => core.toast.show({ message: "The page couldn't load. Check your connection and try again.", tone: "error" }),
    );
  };
  window.addEventListener("tracer:canvas-action", onAction, { signal: controller.signal });
  return { dispose() { controller.abort(); removeProvider(); } };
}
