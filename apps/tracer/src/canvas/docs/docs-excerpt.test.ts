// SPDX-License-Identifier: AGPL-3.0-only
/** The excerpt of a docs heading: a lead, two to four bullets, an optional table, and the page's summary when there is nothing more. */
import { expect, test } from "bun:test";
import { MAX_BULLETS, excerptOf, splitSentences } from "./docs-excerpt";
import type { DocsIndexPage } from "./docs-source";

const page: DocsIndexPage = {
  slug: "keys", title: "Keys and how long they last", summary: "This page lists the keys Infraternal uses and when each one expires.",
  headings: [
    { id: "browser-sign-in", text: "Browser sign-in", facts: "Lasts 30 days. Using Infraternal renews the server's copy. The cookie in your browser ends 30 days after you signed in." },
    { id: "passkey", text: "Passkey" },
    { id: "all", text: "All keys at a glance", facts: "Most keys renew by themselves.", factsTable: { head: ["Key", "Lasts"], rows: [["Browser sign-in", "30 days"]] } },
  ],
};

test("sentences split at a stop followed by a capital or a digit, never inside a figure", () => {
  expect(splitSentences("Lasts 3.5 days. Renewed at 30 min. A host offline for 7 days must be added again.")).toEqual(["Lasts 3.5 days.", "Renewed at 30 min.", "A host offline for 7 days must be added again."]);
  expect(splitSentences("One sentence only")).toEqual(["One sentence only"]);
  expect(splitSentences("  ")).toEqual([]);
});

test("a heading with quick facts is a lead and bullets, titled by the heading", () => {
  const e = excerptOf(page, page.headings[0]);
  expect(e.title).toBe("Browser sign-in");
  expect(e.lead).toBe("Lasts 30 days.");
  expect(e.bullets).toEqual(["Using Infraternal renews the server's copy.", "The cookie in your browser ends 30 days after you signed in."]);
  expect(e.table).toBeUndefined();
});

test("a heading with no quick facts falls back to the page's summary, still titled by the heading", () => {
  const e = excerptOf(page, page.headings[1]);
  expect(e).toEqual({ title: "Passkey", lead: "This page lists the keys Infraternal uses and when each one expires.", bullets: [] });
});

test("a table the build provides is carried along", () => {
  expect(excerptOf(page, page.headings[2]).table).toEqual({ head: ["Key", "Lasts"], rows: [["Browser sign-in", "30 days"]] });
});

test("a page without a heading is previewed by its own facts or its summary, and bullets never exceed the cap", () => {
  expect(excerptOf(page).title).toBe("Keys and how long they last");
  const long: DocsIndexPage = { ...page, facts: "One. Two. Three. Four. Five. Six. Seven." };
  expect(excerptOf(long).bullets.length).toBe(MAX_BULLETS);
  expect(excerptOf(long).lead).toBe("One.");
});
