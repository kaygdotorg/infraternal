// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs index and everything made from it (#302). Loaded when the browser is idle after start-up or at the first ⌘K
 * (docs-source.ts), so none of it is part of the canvas.
 *
 * - The palette rows: a row per section, a row per page and a query-only row per heading (D317). Heading rows show only when something
 *   is typed. The palette finds a section or page by its title and a heading by its text, never by a summary. A page's row reads
 *   `Section › Page`, so typing a section's name lists its pages too. Action ids are `canvas:docs:<section>/<page>` and
 *   `canvas:docs:<section>/<page>#<heading>`.
 * - The Docs view (views/docs.ts), offered next to the others once the index is known and the canvas has views, and put back when
 *   a scene replaced every view (the canvas says so with `tracer:canvas-views`).
 * - A palette action flies to the page's window in the Docs view (docs-body.on-demand.ts), at the heading when one was chosen.
 */
import type { CoreScreen, PaletteEntry } from "../../core-screen";
import { onDemand } from "../../on-demand";
import type { Ctx } from "../context";
import { buildDocsView, DOCS_VIEW } from "../views/docs";
import { viewIcon } from "../views/icons";
import type { DocsIndexPage } from "./docs-source";

export const DOCS_ACTION = "canvas:docs:";

/** Splits `canvas:docs:<section>/<page>#<heading>`; anything else is not ours. */
export function parseDocsAction(action: string | undefined): { slug: string; heading?: string } | undefined {
  if (!action?.startsWith(DOCS_ACTION)) return undefined;
  const [slug, heading] = action.slice(DOCS_ACTION.length).split("#", 2);
  return slug ? { slug, ...(heading ? { heading } : {}) } : undefined;
}

/** The rows for an index. Pure, so it is tested without a browser. */
export function docsRows(pages: readonly DocsIndexPage[]): PaletteEntry[] {
  const titles = new Map(pages.map((page) => [page.slug, page.title]));
  return pages.flatMap((page) => {
    const parent = page.parent ? titles.get(page.parent) : undefined;
    const trail = parent ? `${parent} › ${page.title}` : page.title;
    const members = page.section ? pages.filter((member) => member.parent === page.slug).length : 0;
    // A section says how many pages it holds; one with none yet says what it is about. The summary is for reading; only titles are searched.
    const hint = members > 0 ? `${members} ${members === 1 ? "page" : "pages"}` : page.summary;
    return [
      { group: "Docs", glyph: "i", icon: viewIcon("docs"), label: trail, title: page.title, hint, search: "", action: `${DOCS_ACTION}${page.slug}` },
      ...page.headings.map((heading): PaletteEntry => ({ group: "Docs", glyph: "§", icon: viewIcon("docs"), label: heading.text, hint: trail, search: "", queryOnly: true, action: `${DOCS_ACTION}${page.slug}#${heading.id}` })),
    ];
  });
}

/** Fetches `/docs/index.json` (docs-build.ts); rejects when there is no docs tree or it is not an index. */
export async function loadDocsIndex(signal: AbortSignal): Promise<{ pages: DocsIndexPage[]; rows: PaletteEntry[] }> {
  const response = await fetch("/docs/index.json", { signal });
  if (!response.ok) throw new Error(String(response.status));
  const data = await response.json() as { pages?: unknown };
  if (!Array.isArray(data.pages)) throw new Error("not a docs index");
  const pages = data.pages as DocsIndexPage[];
  return { pages, rows: docsRows(pages) };
}

/** Loads the index, then offers the view and answers the palette. Rejects when there is no index (the caller tries again later). */
export async function startDocs(core: CoreScreen, cx: Ctx, signal: AbortSignal, setRows: (rows: PaletteEntry[], pages: DocsIndexPage[]) => void): Promise<void> {
  const { pages, rows } = await loadDocsIndex(signal);
  const offerView = (): void => {
    if (cx.views.size === 0 || cx.views.has(DOCS_VIEW)) return;
    cx.view.addBeside(buildDocsView(pages, cx.state.metrics));
    cx.pill.paint();
    cx.toolbar.update();
  };
  window.addEventListener("tracer:canvas-views", offerView, { signal });
  window.addEventListener("tracer:canvas-action", (event) => {
    const target = parseDocsAction((event as CustomEvent<{ action?: string }>).detail?.action);
    if (!target || !pages.some((page) => page.slug === target.slug)) return;
    offerView();
    // The page reader's code loads when a page is first opened (D188); it is not part of the canvas.
    void onDemand(() => import("./docs-body.on-demand")).then(
      (module) => { if (!module.openDocsPage(cx, target.slug, target.heading)) core.toast.show({ message: "That page isn't available right now.", tone: "error" }); },
      () => core.toast.show({ message: "The page couldn't load. Check your connection and try again.", tone: "error" }),
    );
  }, { signal });
  offerView();
  setRows(rows, pages);
  core.refreshPalette();
}
