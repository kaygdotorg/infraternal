// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs in the palette (#302): the heading anchors the docs build writes, the rows made from the index, what the
 * palette's own search text would match, and the action ids. The browser behaviour (search, open, alignment, phone) is
 * test/docs-palette.spec.ts.
 */
import { expect, test } from "bun:test";
import { anchorHeadings, labelCells } from "../../../docs-build";
import { docsRows } from "./docs-index.on-demand";
import { parseDocsAction, type DocsIndexPage } from "./docs-source";

test("headings of level two and three get anchors; the title is not listed", () => {
  const { html, headings } = anchorHeadings("<h1>Keys</h1><h2>The table</h2><p>x</p><h3>WireGuard &amp; mesh</h3><h2>The table</h2>");
  expect(headings).toEqual([{ id: "the-table", text: "The table" }, { id: "wireguard-mesh", text: "WireGuard & mesh" }, { id: "the-table-2", text: "The table" }]);
  expect(html).toContain('<h2 id="the-table">The table</h2>');
  expect(html).toContain('<h2 id="the-table-2">The table</h2>');
  expect(html).toContain("<h1>Keys</h1>");
});

test("an anchor the renderer already wrote is kept, and tags inside a heading are not part of its text", () => {
  const { html, headings } = anchorHeadings('<h2 id="own">Use <code>up</code> codes</h2>');
  expect(headings).toEqual([{ id: "own", text: "Use up codes" }]);
  expect(html).toBe('<h2 id="own">Use <code>up</code> codes</h2>');
});

test("every table cell carries its column heading for the stacked layout", () => {
  const html = labelCells("<table><thead><tr><th>Key</th><th>Lasts</th></tr></thead><tbody><tr><td>Passkey</td><td>No expiry</td></tr></tbody></table>");
  expect(html).toContain('<td data-label="Key">Passkey</td><td data-label="Lasts">No expiry</td>');
  expect(html).toContain("<th>Key</th>");
});

const pages: DocsIndexPage[] = [
  { slug: "keys", title: "Keys and how long they last", summary: "Every key, where it lives and when it expires.", headings: [{ id: "browser-sessions", text: "Browser sessions" }, { id: "passkeys", text: "Passkeys" }] },
  { slug: "multiplexer", title: "The Infraternal Multiplexer", summary: "Sessions that survive disconnects.", headings: [{ id: "what-it-does-for-you", text: "What it does for you" }] },
];

/** The palette indexes `group label (search ?? hint)`; this is the same rule, so the test says what a query finds. */
const searchable = (row: ReturnType<typeof docsRows>[number]): string => `${row.group} ${row.label} ${row.search ?? row.hint}`.toLocaleLowerCase();
const found = (query: string): string[] => docsRows(pages).filter((row) => (query !== "" || !row.queryOnly) && searchable(row).includes(query)).map((row) => row.label);

test("at rest the list shows one row per page and no headings", () => {
  expect(found("")).toEqual(["Keys and how long they last", "The Infraternal Multiplexer"]);
});

test("a title word lists its page first, then any heading that holds the word", () => {
  expect(found("keys")).toEqual(["Keys and how long they last", "Passkeys"]);
  expect(found("multiplexer")).toEqual(["The Infraternal Multiplexer"]);
});

test("a heading word lists that heading; the summary and the page name in a hint are not searched", () => {
  expect(found("passkeys")).toEqual(["Passkeys"]);
  expect(found("survive")).toEqual([]);
  expect(found("where it lives")).toEqual([]);
});

test("every row opens its page, headings at their anchor", () => {
  const actions = docsRows(pages).map((row) => row.action);
  expect(actions).toContain("canvas:docs:keys");
  expect(actions).toContain("canvas:docs:keys#passkeys");
  expect(parseDocsAction("canvas:docs:keys#passkeys")).toEqual({ slug: "keys", heading: "passkeys" });
  expect(parseDocsAction("canvas:docs:multiplexer")).toEqual({ slug: "multiplexer" });
  expect(parseDocsAction("canvas:settings:appearance")).toBeUndefined();
  expect(parseDocsAction("canvas:docs:")).toBeUndefined();
});
