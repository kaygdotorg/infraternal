// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Which docs addresses the check finds in source and in pages (docs-anchors.ts), and what it says about each. The build itself failing
 * on a bad address is docs-build.test.ts.
 */
import { expect, test } from "bun:test";
import { checkReferences, referencesInPage, referencesInSource } from "./docs-anchors";

const pages = [
  { slug: "index", headings: [{ id: "sections" }] },
  { slug: "terminal/multiplexer", headings: [{ id: "the-question-infraternal-asks" }] },
];

test("an address in a quoted string is found with its heading; file names, templates and other strings are not", () => {
  const source = [
    'const A = "/docs/terminal/multiplexer/";',
    "const B = `/docs/terminal/multiplexer/#the-question-infraternal-asks`;",
    "const C = '/docs/';",
    'const D = "/docs/index.json";',
    "const E = `/docs/${slug}/fragment.html`;",
    'const F = "see /docs/terminal/multiplexer/ for more";',
  ].join("\n");
  expect(referencesInSource("a.ts", source)).toEqual([
    { where: "a.ts:1", slug: "terminal/multiplexer" },
    { where: "a.ts:2", slug: "terminal/multiplexer", heading: "the-question-infraternal-asks" },
    { where: "a.ts:3", slug: "index" },
  ]);
});

test("a Settings catalog anchor is found, with or without a heading", () => {
  const source = 'x: { docs: { page: "terminal/multiplexer", heading: "what-it-does-for-you" } },\ny: { docs: { page: "index" } },';
  expect(referencesInSource("catalog.ts", source)).toEqual([
    { where: "catalog.ts:1", slug: "terminal/multiplexer", heading: "what-it-does-for-you" },
    { where: "catalog.ts:2", slug: "index" },
  ]);
});

test("links between pages are found; a link to a heading of the same page has no address", () => {
  const html = '<a href="#local">x</a> <a href="/docs/terminal/multiplexer/#the-question-infraternal-asks">q</a> <a href="/docs/">front</a> <a href="https://example.com/docs/x/">out</a>';
  expect(referencesInPage("terminal/multiplexer", html)).toEqual([
    { where: "page terminal/multiplexer", slug: "terminal/multiplexer", heading: "the-question-infraternal-asks" },
    { where: "page terminal/multiplexer", slug: "index" },
  ]);
});

test("a reference passes when its page and heading exist, and says what is wrong when not", () => {
  const moved = new Map([["multiplexer", "terminal/multiplexer"]]);
  expect(checkReferences([{ where: "a", slug: "terminal/multiplexer", heading: "the-question-infraternal-asks" }, { where: "b", slug: "index" }], pages, moved)).toEqual([]);
  expect(checkReferences([{ where: "a", slug: "multiplexer" }], pages, moved)).toEqual(["a: /docs/multiplexer/ is the old address of terminal/multiplexer; point at /docs/terminal/multiplexer/"]);
  expect(checkReferences([{ where: "a", slug: "keys" }], pages, moved)).toEqual(["a: /docs/keys/ points at a page that does not exist"]);
  expect(checkReferences([{ where: "a", slug: "terminal/multiplexer", heading: "what-it-does-for-you" }], pages, moved)[0]).toContain("page has: the-question-infraternal-asks");
});
