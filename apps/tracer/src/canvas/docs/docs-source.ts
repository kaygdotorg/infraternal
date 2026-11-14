// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs on the canvas (#302): a Docs view with a window for each page, and a source for the command palette (⌘K).
 *
 * Both come from one file, `/docs/index.json`, written by the docs build (docs-build.ts): every page's address (`<section>/<page>`), title, one-line summary and
 * headings, a few hundred bytes per page. There is no list of pages in the app. A page added to `docs/user/` appears in the Docs
 * view and in ⌘K with no change here.
 *
 * This file is only the doorway, because it ships with the canvas and the canvas has a transfer budget (D188). It is a palette
 * provider that returns the rows once they exist, and a start that runs when the browser is idle after start-up or at the first ⌘K,
 * whichever comes first. The start loads docs-index.on-demand.ts, which fetches the index, offers the Docs view, answers the palette's
 * actions and puts the view back after a scene replaced every view. A server without docs has no index: no Docs view, no docs rows,
 * and the next ⌘K tries again.
 */
import type { CoreScreen, PaletteEntry } from "../../core-screen";
import { onDemand } from "../../on-demand";
import type { Ctx } from "../context";

/** The shape of `index.json` (docs-build.ts `DocsIndexPage`). */
/**
 * `facts` is the text of a heading's (or the page's) `> [!FACTS]` block: a few short sentences, the excerpt the "?" preview shows
 * (docs-excerpt.ts). `factsTable` is a small table in that block, when the docs build provides one. Both are optional.
 */
export interface DocsHeading { id: string; text: string; facts?: string; factsTable?: { head: string[]; rows: string[][] } }
export interface DocsIndexPage { slug: string; title: string; summary: string; section?: true; parent?: string; facts?: string; factsTable?: { head: string[]; rows: string[][] }; headings: DocsHeading[] }

export interface DocsSource {
  /**
   * Opens a docs page (at a heading when it has one): its window in the Docs view is focused and in view. Loads the index first if it
   * has not loaded yet. Resolves false when there is no such page (or the docs are not served), so the caller can say so in plain words.
   */
  open(slug: string, heading?: string): Promise<boolean>;
  /** The page and heading from the index (loading it first), for the "?" excerpt; undefined when there is no such page. */
  lookup(slug: string, heading?: string): Promise<{ page: DocsIndexPage; heading?: DocsHeading } | undefined>;
  /** Starts loading the index now, so the first "?" is instant. */
  warm(): void;
  dispose(): void;
}

/** Installs the docs source on a core screen: the pages as palette rows, the "?" lookups, and the search through the pages' text (#339). The index and the search code load lazily; `dispose()` removes it all. */
export function installDocsSource(core: CoreScreen, cx: Ctx): DocsSource {
  const controller = new AbortController();
  let rows: PaletteEntry[] = [];
  let pages: DocsIndexPage[] | undefined;
  let starting: Promise<void> | undefined;
  const start = (): Promise<void> => {
    if (starting) return starting;
    starting = onDemand(() => import("./docs-index.on-demand"))
      .then((module) => module.startDocs(core, cx, controller.signal, (made, index) => { rows = made; pages = index; }))
      // No docs on this server, or offline: nothing is offered, and the next ⌘K tries again.
      .catch(() => { starting = undefined; });
    return starting;
  };
  const removeProvider = core.addPaletteProvider(() => { void start(); return rows; });
  // The text of the pages (#339): the search code and its index load when the palette opens, not before.
  let textSearch: Promise<(query: string) => Promise<PaletteEntry[]>> | undefined;
  const removeSearch = core.addPaletteSearch(async (query) => {
    textSearch ??= onDemand(() => import("./docs-search.on-demand")).then((module) => module.docsSearch()).catch((error) => { textSearch = undefined; throw error; });
    return (await textSearch)(query);
  });
  const idle = (window as { requestIdleCallback?: (callback: () => void, options?: { timeout: number }) => number }).requestIdleCallback;
  const begin = (): void => { void start(); };
  const timer = idle ? idle(begin, { timeout: 5000 }) : window.setTimeout(begin, 2000);
  return {
    async open(slug, heading) {
      await start();
      if (!pages?.some((page) => page.slug === slug)) return false;
      const module = await onDemand(() => import("./docs-body.on-demand"));
      return module.openDocsPage(cx, slug, heading);
    },
    async lookup(slug, heading) {
      await start();
      const page = pages?.find((entry) => entry.slug === slug);
      if (!page) return undefined;
      const at = heading ? page.headings.find((h) => h.id === heading) : undefined;
      return { page, ...(at ? { heading: at } : {}) };
    },
    warm() { void start(); },
    dispose() {
      controller.abort();
      removeProvider();
      removeSearch();
      if (idle) (window as { cancelIdleCallback?: (handle: number) => void }).cancelIdleCallback?.(timer); else window.clearTimeout(timer);
    },
  };
}
