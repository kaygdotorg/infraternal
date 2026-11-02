// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs index and the palette rows made from it (#302). Loaded the first time the palette opens (docs-source.ts), so
 * neither the fetch code nor the row building is part of the canvas.
 */
import type { PaletteEntry } from "../../core-screen";
import { ICON_INFO } from "../../../../../packages/ui/src/icons";
import { DOCS_ACTION, type DocsIndexPage } from "./docs-source";

/** The rows for an index: a row per page, and a query-only row per heading. Pure, so it is tested without a browser. */
export function docsRows(pages: readonly DocsIndexPage[]): PaletteEntry[] {
  return pages.flatMap((page) => [
    // The summary is for reading; only the title is searched.
    { group: "Docs", glyph: "i", icon: ICON_INFO, label: page.title, hint: page.summary, search: "", action: `${DOCS_ACTION}${page.slug}` },
    ...page.headings.map((heading): PaletteEntry => ({ group: "Docs", glyph: "§", icon: ICON_INFO, label: heading.text, hint: page.title, search: "", queryOnly: true, action: `${DOCS_ACTION}${page.slug}#${heading.id}` })),
  ]);
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
