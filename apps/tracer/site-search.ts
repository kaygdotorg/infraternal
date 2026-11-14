// SPDX-License-Identifier: AGPL-3.0-only
/**
 * ⌘K on the standalone pages (#339, D388): a small search palette over the text of the docs. It is a file of its own (`doc-search.js`), imported by
 * `doc.js` (doc-page.ts) the first time the search is opened, and the text index it searches (`search.json`, docs-search-index.ts) is
 * fetched then too, so a page that is only read loads neither.
 *
 * The page names where the indexes are: `data-search` on the top bar's search button lists the docs roots (`/docs/user /docs/admin
 * /docs/dev` on the site, `/docs` on an instance's own docs). The matching, ranking and snippets are src/canvas/docs/docs-search.ts, the
 * same code the app's palette uses. A result is a real link to the heading's anchor, so Enter, a click and "open in a new tab" all work.
 *
 * Keys: ⌘K or Ctrl+K opens it (the search button does too, with a tap on a phone; both are wired in doc-page.ts), ↑ ↓ move, Enter opens,
 * Esc closes and gives focus back.
 */
import { snippetParts } from "./src/snippet-parts";
import { prepareSearch, searchDocs, type Prepared, type SearchHit } from "./src/canvas/docs/docs-search";

/** The `search.json` of each root, loaded once and merged; a root that has none (a build without text search) is left out. */
async function loadIndex(roots: readonly string[]): Promise<{ root: string; prepared: Prepared[] }[]> {
  const loaded = await Promise.all(roots.map(async (root) => {
    const response = await fetch(`${root}/search.json`);
    if (!response.ok) return undefined;
    const data = (await response.json()) as { pages: Parameters<typeof prepareSearch>[0] };
    return { root, prepared: prepareSearch(data.pages) };
  }).map((load) => load.catch(() => undefined)));
  return loaded.filter((entry): entry is { root: string; prepared: Prepared[] } => entry !== undefined);
}

/** The result's snippet as nodes: the words around the match, with each matched word in a `<mark>`. No HTML is ever built from the text. */
function snippetNodes(hit: SearchHit): Node[] {
  return snippetParts(hit.snippet, hit.marks).map((part) => {
    if (!part.marked) return document.createTextNode(part.text);
    const mark = document.createElement("mark");
    mark.textContent = part.text;
    return mark;
  });
}

/**
 * Sets the search up for the page's search button (its `data-search` lists the docs roots) and returns what opens it: `open` shows the
 * dialog, `toggle` is what ⌘K does (it closes an open one). doc-page.ts calls this once, on the first use.
 */
export function installSiteSearch(button: HTMLElement): { open: () => void; toggle: () => void } {
  const roots = (button.dataset.search ?? "").split(" ").filter(Boolean);

  let dialog: HTMLDialogElement | undefined;
  let input: HTMLInputElement;
  let list: HTMLElement;
  let index: Promise<{ root: string; prepared: Prepared[] }[]> | undefined;
  let hits: { hit: SearchHit; href: string }[] = [];
  let selected = 0;

  const select = (next: number): void => {
    if (hits.length === 0) return;
    selected = (next + hits.length) % hits.length;
    list.querySelectorAll<HTMLElement>("[role=option]").forEach((option, at) => option.setAttribute("aria-selected", String(at === selected)));
    const option = list.querySelectorAll<HTMLElement>("[role=option]")[selected]!;
    input.setAttribute("aria-activedescendant", option.id);
    option.scrollIntoView({ block: "nearest" });
  };

  const draw = async (): Promise<void> => {
    const query = input.value;
    const turn = query;
    const found = await (index ??= loadIndex(roots));
    // The words typed while the index was loading are searched now; an older answer is dropped.
    if (turn !== input.value) return;
    hits = found.flatMap(({ root, prepared }, at) => searchDocs(prepared, query).map((hit) => ({ hit: { ...hit, rank: hit.rank - at * 500 }, href: `${root}/${hit.slug}/${hit.id ? `#${hit.id}` : ""}` }))).sort((a, b) => b.hit.rank - a.hit.rank).slice(0, 24);
    selected = 0;
    list.replaceChildren();
    input.removeAttribute("aria-activedescendant");
    if (query.trim().length < 2) {
      const note = document.createElement("p");
      note.className = "search-note";
      note.textContent = found.length === 0 ? "Search is not available right now." : "Type to search the title, headings and text of every page.";
      list.append(note);
      return;
    }
    if (hits.length === 0) {
      const note = document.createElement("p");
      note.className = "search-note";
      note.textContent = "No page matches. Try fewer or different words.";
      list.append(note);
      return;
    }
    hits.forEach(({ hit, href }, at) => {
      const row = document.createElement("a");
      row.className = "search-row";
      row.id = `search-option-${at}`;
      row.href = href;
      row.setAttribute("role", "option");
      row.setAttribute("aria-selected", String(at === 0));
      const head = document.createElement("span");
      head.className = "search-head";
      const title = document.createElement("span");
      title.className = "search-title";
      title.textContent = hit.heading || hit.title;
      const where = document.createElement("span");
      where.className = "search-where";
      where.textContent = hit.heading ? hit.title : "";
      head.append(title, where);
      const text = document.createElement("span");
      text.className = "search-snippet";
      text.append(...snippetNodes(hit));
      row.append(head, text);
      row.addEventListener("pointermove", () => { if (selected !== at) select(at); });
      list.append(row);
    });
    input.setAttribute("aria-activedescendant", "search-option-0");
  };

  /** Builds the dialog the first time it is needed. A `<dialog>` gives the focus trap, Esc and the backdrop for free. */
  const build = (): HTMLDialogElement => {
    const made = document.createElement("dialog");
    made.className = "search";
    made.setAttribute("aria-label", "Search the docs");
    made.innerHTML = '<div class="search-field"><svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="4.5"/><path d="m10.5 10.5 3 3"/></svg><input type="search" role="combobox" aria-expanded="true" aria-controls="search-results" aria-label="Search the docs" placeholder="Search the docs" autocomplete="off" spellcheck="false" enterkeyhint="go"></div><div class="search-results" id="search-results" role="listbox" aria-label="Results"></div><p class="search-foot"><kbd>↑</kbd><kbd>↓</kbd> to navigate <kbd>↵</kbd> to open <kbd>esc</kbd> to close</p>';
    input = made.querySelector("input")!;
    list = made.querySelector(".search-results")!;
    input.addEventListener("input", () => { void draw(); });
    input.addEventListener("keydown", (event) => {
      if (event.key === "ArrowDown") { select(selected + 1); event.preventDefault(); }
      else if (event.key === "ArrowUp") { select(selected - 1); event.preventDefault(); }
      // A search field uses Escape to clear itself first, which would leave the dialog open: Escape always closes it.
      else if (event.key === "Escape") { made.close(); event.preventDefault(); }
      // Enter closes the dialog first: a result on the page being read is only a hash change, which would leave the dialog open over the
      // heading. Closing gives focus back to what opened it; then the address changes. A key press that confirms an IME composition is not Enter.
      else if (event.key === "Enter" && !event.isComposing && hits[selected]) { const href = hits[selected]!.href; made.close(); location.href = href; event.preventDefault(); }
    });
    // A click on the backdrop (the dialog's own box, outside its content) closes it.
    made.addEventListener("click", (event) => { if (event.target === made) made.close(); });
    // Following a result to a heading on this same page does not reload it, so the dialog is closed by the click itself.
    list.addEventListener("click", () => made.close());
    document.body.append(made);
    return made;
  };

  const open = (): void => {
    dialog ??= build();
    if (dialog.open) return;
    dialog.showModal();
    input.value = "";
    void draw();
    input.focus();
  };

  return { open, toggle: () => { if (dialog?.open) dialog.close(); else open(); } };
}
