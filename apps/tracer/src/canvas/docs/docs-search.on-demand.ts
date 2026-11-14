// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs' text in the palette (#339, D388): answers ⌘K with the sections of the docs whose words match, a heading and a snippet with the
 * match highlighted. Loaded by docs-source.ts when the palette opens, so the code and `/docs/search.json` (the docs build's text index) cost
 * nothing until someone searches. The ranking and the snippets are docs-search.ts, which the standalone pages share.
 *
 * These rows are listed after the palette's own title and heading rows (core-screen.ts), so a match in a title or heading is always above a
 * match in the text. Choosing one runs `canvas:docs:<slug>#<heading>`, the action the heading rows use, so it lands on the heading's anchor.
 */
import type { PaletteEntry } from "../../core-screen";
import { viewIcon } from "../views/icons";
import { DOCS_ACTION } from "./docs-action";
import { prepareSearch, searchDocs, type Prepared, type SearchPage } from "./docs-search";

/** The group the text matches are listed under: apart from "Docs", whose rows are titles and headings. */
export const DOCS_TEXT_GROUP = "Page text";

/** The rows for a query. Pure over a prepared index, so it is tested without a browser. */
export function textRows(prepared: readonly Prepared[], query: string): PaletteEntry[] {
  return searchDocs(prepared, query).map((hit): PaletteEntry => ({
    group: DOCS_TEXT_GROUP, glyph: "§", icon: viewIcon("docs"),
    label: hit.heading || hit.title,
    hint: hit.heading ? hit.title : "",
    search: "",
    snippet: { text: hit.snippet, marks: hit.marks },
    action: `${DOCS_ACTION}${hit.slug}${hit.id ? `#${hit.id}` : ""}`,
  }));
}

/** Fetches the text index once; a server without one (or offline) answers nothing, and the next search asks again. */
export function docsSearch(): (query: string) => Promise<PaletteEntry[]> {
  let loading: Promise<Prepared[]> | undefined;
  const load = (): Promise<Prepared[]> => loading ??= fetch("/docs/search.json")
    .then((response) => { if (!response.ok) throw new Error(String(response.status)); return response.json() as Promise<{ pages: SearchPage[] }>; })
    .then((data) => prepareSearch(data.pages))
    .catch((error) => { loading = undefined; throw error; });
  return async (query) => {
    // The palette calls with "" when it opens: the index starts loading then, so the first keystroke finds it ready.
    const prepared = await load();
    return query === "" ? [] : textRows(prepared, query);
  };
}
