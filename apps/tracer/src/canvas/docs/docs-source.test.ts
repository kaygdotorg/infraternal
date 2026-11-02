// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The docs in the palette (#302): the heading anchors the docs build writes, the rows made from the index, what the
 * palette's own search text would match, and the action ids. The browser behaviour (search, the Docs view, alignment, phone) is
 * test/docs-palette.spec.ts. What the build makes of a page is docs-build.test.ts.
 */
import { expect, test } from "bun:test";
import { anchorHeadings, labelCells } from "../../../docs-build";
import { docsRows, parseDocsAction } from "./docs-index.on-demand";
import type { DocsIndexPage } from "./docs-source";

test("headings of level two and three get anchors; the title is not listed", () => {
  const { html, headings } = anchorHeadings("<h1>Keys</h1><h2>The table</h2><p>x</p><h3>WireGuard &amp; mesh</h3><h2>The table</h2>");
  expect(headings).toEqual([{ id: "the-table", text: "The table", level: 2 }, { id: "wireguard-mesh", text: "WireGuard & mesh", level: 3 }, { id: "the-table-2", text: "The table", level: 2 }]);
  expect(html).toContain('<h2 id="the-table">The table</h2>');
  expect(html).toContain('<h2 id="the-table-2">The table</h2>');
  expect(html).toContain("<h1>Keys</h1>");
});

test("an anchor the renderer already wrote is kept, and tags inside a heading are not part of its text", () => {
  const { html, headings } = anchorHeadings('<h2 id="own">Use <code>up</code> codes</h2>');
  expect(headings).toEqual([{ id: "own", text: "Use up codes", level: 2 }]);
  expect(html).toBe('<h2 id="own">Use <code>up</code> codes</h2>');
});

test("every table cell carries its column heading for the stacked layout", () => {
  const html = labelCells("<table><thead><tr><th>Key</th><th>Lasts</th></tr></thead><tbody><tr><td>Passkey</td><td>No expiry</td></tr></tbody></table>");
  expect(html).toContain('<td data-label="Key">Passkey</td><td data-label="Lasts">No expiry</td>');
  expect(html).toContain("<th>Key</th>");
});

const pages: DocsIndexPage[] = [
  { slug: "terminal", title: "Terminal", summary: "Sessions and windows.", section: true, headings: [{ id: "sessions", text: "Sessions" }] },
  { slug: "terminal/multiplexer", title: "The Infraternal Multiplexer", summary: "Sessions that survive disconnects.", parent: "terminal", headings: [{ id: "what-it-does-for-you", text: "What it does for you" }] },
  { slug: "you", title: "You", summary: "Your account and your devices.", section: true, headings: [] },
  { slug: "reference", title: "Reference", summary: "Lookup tables.", section: true, headings: [] },
  { slug: "reference/keys", title: "Keys and how long they last", summary: "Every key, where it lives and when it expires.", parent: "reference", headings: [{ id: "browser-sessions", text: "Browser sessions" }, { id: "passkeys", text: "Passkeys" }] },
];

/** The palette indexes `group label (search ?? hint)`; this is the same rule, so the test says what a query finds. */
const searchable = (row: ReturnType<typeof docsRows>[number]): string => `${row.group} ${row.label} ${row.search ?? row.hint}`.toLocaleLowerCase();
const found = (query: string): string[] => docsRows(pages).filter((row) => (query !== "" || !row.queryOnly) && searchable(row).includes(query)).map((row) => row.label);

test("at rest the list shows a row per section and per page, and no headings", () => {
  expect(found("")).toEqual(["Terminal", "Terminal › The Infraternal Multiplexer", "You", "Reference", "Reference › Keys and how long they last"]);
});

test("a section row counts its pages, or says what it is about when it has none; a page row gives its summary", () => {
  const hints = Object.fromEntries(docsRows(pages).filter((row) => !row.queryOnly).map((row) => [row.label, row.hint]));
  expect(hints["Terminal"]).toBe("1 page");
  expect(hints["You"]).toBe("Your account and your devices.");
  expect(hints["Terminal › The Infraternal Multiplexer"]).toBe("Sessions that survive disconnects.");
});

test("a title word lists its page first, then any heading that holds the word; a section name lists its pages", () => {
  expect(found("keys")).toEqual(["Reference › Keys and how long they last", "Passkeys"]);
  expect(found("multiplexer")).toEqual(["Terminal › The Infraternal Multiplexer"]);
  expect(found("terminal")).toEqual(["Terminal", "Terminal › The Infraternal Multiplexer"]);
});

test("a heading word lists that heading, with its section and page as the hint; the summary is not searched", () => {
  expect(found("passkeys")).toEqual(["Passkeys"]);
  expect(docsRows(pages).find((row) => row.label === "Passkeys")!.hint).toBe("Reference › Keys and how long they last");
  expect(found("survive")).toEqual([]);
  expect(found("where it lives")).toEqual([]);
});

test("every row opens its page, headings at their anchor, by the section/page address", () => {
  const actions = docsRows(pages).map((row) => row.action);
  expect(actions).toContain("canvas:docs:terminal");
  expect(actions).toContain("canvas:docs:reference/keys");
  expect(actions).toContain("canvas:docs:reference/keys#passkeys");
  expect(parseDocsAction("canvas:docs:reference/keys#passkeys")).toEqual({ slug: "reference/keys", heading: "passkeys" });
  expect(parseDocsAction("canvas:docs:terminal")).toEqual({ slug: "terminal" });
  expect(parseDocsAction("canvas:settings:appearance")).toBeUndefined();
  expect(parseDocsAction("canvas:docs:")).toBeUndefined();
});
