// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The text search of the docs (#339): how the build cuts a page into sections (docs-search-index.ts) and how a query ranks them and
 * cuts a snippet (src/canvas/docs/docs-search.ts). The palette rows made from the hits are docs-source.test.ts; the browser behaviour of
 * the app's palette and the standalone one is test/docs-search.spec.ts.
 */
import { expect, test } from "bun:test";
import { searchPageOf, sectionsOf, textOf } from "./docs-search-index";
import { textRows } from "./src/canvas/docs/docs-search.on-demand";
import { prepareSearch, queryWords, searchDocs, type SearchPage } from "./src/canvas/docs/docs-search";

test("text keeps the words of cells and list items apart and decodes entities", () => {
  expect(textOf("<ul><li>One</li><li>Two &amp; three</li></ul><table><tr><td>a</td><td>b&lt;c</td></tr></table>")).toBe("One Two & three a b<c");
  expect(textOf("<p>it&#39;s <code>up --dry-run</code></p>")).toBe("it's up --dry-run");
});

test("a page is cut at its headings; the opening has no heading and starts with the summary", () => {
  const body = '<p>Intro words.</p><h2 id="one">One</h2><p>First <b>text</b>.</p><h3 id="deep">Deep</h3><p>Deeper.</p><h2 id="two">Two</h2>';
  expect(sectionsOf(body, "The summary.")).toEqual([
    { heading: "", id: "", text: "The summary. Intro words." },
    { heading: "One", id: "one", text: "First text." },
    { heading: "Deep", id: "deep", text: "Deeper." },
    { heading: "Two", id: "two", text: "" },
  ]);
});

test("the list of pages the build adds is navigation, not text", () => {
  const page = searchPageOf("terminal", "Terminal", "Sessions.", '<p>Real text.</p><h2 id="pages">Pages in this section</h2><ul class="pages"><li><a><strong>Secret title</strong><span>Secret summary</span></a></li></ul>');
  expect(JSON.stringify(page)).not.toContain("Secret");
});

/** A two-page fixture: the keys page and the multiplexer page, each with an intro and some sections. */
const pages: SearchPage[] = [
  { slug: "keys", title: "Keys and how long they last", sections: [
    { heading: "", id: "", text: "Every key, where it lives and when it expires." },
    { heading: "Passkeys", id: "passkeys", text: "A passkey never leaves your device and has no expiry." },
    { heading: "Browser sessions", id: "browser-sessions", text: "A session lasts thirty days. Sign out ends it at once." },
  ] },
  { slug: "terminal/multiplexer", title: "The Infraternal Multiplexer", sections: [
    { heading: "", id: "", text: "Sessions that survive a dropped connection." },
    { heading: "Detach", id: "detach", text: "Close the tab and the session keeps running; reattach from a phone." },
  ] },
];
/** The fixture, prepared once for every test below. */
const prepared = prepareSearch(pages);

test("words match in any order and as part of a word; every word must be there", () => {
  expect(searchDocs(prepared, "expiry passkey").map((hit) => hit.id)).toEqual(["passkeys"]);
  expect(searchDocs(prepared, "pass").map((hit) => hit.id)).toContain("passkeys");
  expect(searchDocs(prepared, "passkey nonsenseword")).toEqual([]);
  expect(searchDocs(prepared, "  a ")).toEqual([]);
  expect(queryWords("Pass  PASS key")).toEqual(["pass", "key"]);
});

test("a title match ranks above a heading match, which ranks above a match in the text", () => {
  // "session" is in the multiplexer's text and a heading of Keys ("Browser sessions") and in a body sentence.
  const ranks = searchDocs(prepared, "session");
  expect(ranks[0]!.id).toBe("browser-sessions");
  expect(ranks.at(-1)!.slug).toBe("terminal/multiplexer");
  // The page title wins over everything: the opening of a page whose title has the word comes first, alone.
  const byTitle = searchDocs(prepared, "multiplexer");
  expect(byTitle.map((hit) => `${hit.slug}#${hit.id}`)).toEqual(["terminal/multiplexer#"]);
  // A later section of that page is listed when it has a word of its own (the title and the text together hold every word).
  expect(searchDocs(prepared, "multiplexer detach").map((hit) => `${hit.slug}#${hit.id}`)).toEqual(["terminal/multiplexer#detach"]);
});

test("a word in the title and another in the text still match the section", () => {
  const hits = searchDocs(prepared, "keys expires");
  expect(hits.map((hit) => hit.id)).toContain("");
});

test("the snippet is cut around the match, with the matched words marked at the right offsets", () => {
  const long = { slug: "long", title: "Long", sections: [{ heading: "Deep", id: "deep", text: `${"filler ".repeat(30)}the needle is here ${"more ".repeat(30)}` }] };
  const [hit] = searchDocs(prepareSearch([long]), "needle");
  expect(hit!.snippet.startsWith("…")).toBe(true);
  expect(hit!.snippet.endsWith("…")).toBe(true);
  expect(hit!.snippet.length).toBeLessThan(130);
  expect(hit!.marks).toHaveLength(1);
  const [start, end] = hit!.marks[0]!;
  expect(hit!.snippet.slice(start, end)).toBe("needle");
});

test("a typical query over the whole user docs stays well inside one frame", async () => {
  // Correctness of the shape only: the speed is measured on the real index and reported on the issue; no wall-clock is asserted in a functional test.
  const many: SearchPage[] = Array.from({ length: 200 }, (_, n) => ({ slug: `p${n}`, title: `Page ${n}`, sections: Array.from({ length: 6 }, (_, k) => ({ heading: `Part ${k}`, id: `part-${k}`, text: `text ${n} ${k} about sessions and keys ${"words ".repeat(60)}` })) }));
  const hits = searchDocs(prepareSearch(many), "sessions keys");
  expect(hits).toHaveLength(24);
});

test("a text hit becomes a palette row that lands on the heading's anchor, apart from the title and heading rows", () => {
  const [row] = textRows(prepared, "thirty days");
  expect(row).toMatchObject({ group: "Page text", label: "Browser sessions", hint: "Keys and how long they last", action: "canvas:docs:keys#browser-sessions" });
  expect(row!.snippet!.text).toContain("thirty days");
  // The opening of a page has no heading: the row is named by the page and opens its top.
  expect(textRows(prepared, "dropped connection")[0]).toMatchObject({ label: "The Infraternal Multiplexer", hint: "", action: "canvas:docs:terminal/multiplexer" });
});

test("inside a class, whole words and words side by side as typed rank above part-word matches", () => {
  const found = searchDocs(prepareSearch([
    { slug: "a", title: "A", sections: [{ heading: "Checkout", id: "checkout", text: "Build a clean checkout of the value." }] },
    { slug: "b", title: "B", sections: [{ heading: "Words", id: "words", text: "The server keeps a check value, not the words." }] },
  ]), "check value");
  expect(found.map((hit) => hit.slug)).toEqual(["b", "a"]);
});
