// SPDX-License-Identifier: AGPL-3.0-only
/**
 * What the docs build makes of a page (#302): the summary, the outline check, the table of contents, the footer, and above all
 * that a Markdown file placed in `docs/user/` is built, indexed and given its contents with no list to edit. The shipped pages are
 * checked against the rules the owner set for human readers: a one-sentence summary, a real hierarchy, no decision or issue numbers
 * outside the footer.
 */
import { expect, test } from "bun:test";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { buildDocs, checkOutline, figureOptionsFor, formerSlugsOf, INDEX_SLUG, readUserDocs, renderDoc, splitPage, tocFor, USER_DOCS_DIR, type DocsIndexPage } from "./docs-build";

const page = (title: string, summary: string, body: string, footer = ""): string => `# ${title}\n\n${summary}\n\n${body}${footer ? `\n---\n\n${footer}\n` : ""}`;

test("the title, the summary under it, the body and the footer after the last rule are told apart", () => {
  const parts = splitPage("<h1>Keys</h1>\n<p>Every key, in <strong>one</strong> sentence.</p>\n<h2>First</h2>\n<p>Text.</p>\n<hr />\n<p>Behind this page: D24.</p>\n");
  expect(parts.title).toBe("Keys");
  expect(parts.summary).toBe("Every key, in one sentence.");
  expect(parts.body).toBe("<h2>First</h2>\n<p>Text.</p>");
  expect(parts.notes).toBe("<p>Behind this page: D24.</p>");
});

test("a page without a summary directly under its title does not build", () => {
  expect(() => splitPage("<h1>Keys</h1>\n<h2>First</h2>\n<p>Text.</p>")).toThrow("one-sentence summary");
});

test("a heading that skips a level, a second title or a missing title is reported", () => {
  expect(checkOutline("<h1>T</h1><h2>A</h2><h3>B</h3><h2>C</h2>")).toEqual([]);
  expect(checkOutline("<h1>T</h1><h3>B</h3>")).toEqual(["a level-3 heading follows a level-1 heading; do not skip a level"]);
  expect(checkOutline("<h1>T</h1><h2>A</h2><h4>B</h4>")).toEqual(["a level-4 heading follows a level-2 heading; do not skip a level"]);
  expect(checkOutline("<h1>T</h1><h1>U</h1>")[0]).toContain("exactly one level-1 heading");
  expect(checkOutline("<h2>A</h2>")[0]).toContain("exactly one level-1 heading");
  expect(() => renderDoc("bad", page("Bad", "Summary.", "### Orphan\n\ntext\n"))).toThrow('docs page "bad"');
});

test("the table of contents lists level 2 and 3 headings, nested, in two forms for CSS to choose between", () => {
  const html = tocFor([{ id: "a", text: "A & B", level: 2 }, { id: "b", text: "B", level: 3 }, { id: "c", text: "C", level: 2 }]);
  expect(html).toContain('<li><a href="#a">A &amp; B</a><ol><li><a href="#b">B</a></li></ol></li><li><a href="#c">C</a></li>');
  expect(html).toContain('<details class="toc-fold">');
  expect(html).toContain('<div class="toc-side">');
  expect(tocFor([{ id: "a", text: "A", level: 2 }])).toBe("");
});

test("a rendered page has its head, contents, body and a footer outside the contents", () => {
  const doc = renderDoc("demo", page("Demo", "A demo page.", "## One\n\ntext\n\n### Inside\n\ntext\n\n## Two\n\n| A | B |\n|---|---|\n| 1 | 2 |\n", "Behind this page: D1."));
  expect(doc.title).toBe("Demo");
  expect(doc.summary).toBe("A demo page.");
  expect(doc.headings.map((heading) => [heading.id, heading.level])).toEqual([["one", 2], ["inside", 3], ["two", 2]]);
  expect(doc.html).toContain('<p class="lede">A demo page.</p>');
  expect(doc.html).toContain('<h2 id="one">One</h2>');
  expect(doc.html).toContain('<td data-label="A">1</td>');
  expect(doc.html).toContain('<footer class="notes">');
  expect(doc.html.indexOf('<footer class="notes">')).toBeGreaterThan(doc.html.indexOf('<h2 id="two">'));
  expect(doc.html.slice(0, doc.html.indexOf('<div class="doc-body">'))).not.toContain("Behind this page");
});

/** A folder with a front page and pages, as a person would add them. */
async function fixture(files: Record<string, string>): Promise<{ dir: string; out: string; done(): Promise<void> }> {
  const base = await mkdtemp(join(tmpdir(), "docs-build-"));
  const dir = join(base, "user");
  await mkdir(dir);
  for (const [name, text] of Object.entries(files)) {
    // A name with a slash is a page in a section's folder.
    await mkdir(join(dir, name, ".."), { recursive: true });
    await writeFile(join(dir, name), text);
  }
  return { dir, out: join(base, "out"), done: () => rm(base, { recursive: true, force: true }) };
}

test("a Markdown file placed in the folder is built, indexed and given its contents, with no list to edit", async () => {
  const f = await fixture({
    "index.md": page("Welcome", "Start here.", "## Where to go\n\ntext\n"),
    "20-zebra.md": page("Zebras", "All about zebras.", "## Stripes\n\ntext\n\n## Herds\n\ntext\n"),
    "10-antelope.md": page("Antelopes", "All about antelopes.", "## Speed\n\ntext\n\n### Sprints\n\ntext\n"),
  });
  try {
    const index = await buildDocs(f.out, f.dir);
    // The front page first, then the other pages in file-name order; `NN-` only orders, it is not part of the address.
    expect(index.map((entry: DocsIndexPage) => entry.slug)).toEqual([INDEX_SLUG, "antelope", "zebra"]);
    const json = JSON.parse(await readFile(join(f.out, "index.json"), "utf8")) as { pages: DocsIndexPage[] };
    expect(json.pages.find((entry) => entry.slug === "antelope")).toEqual({ slug: "antelope", title: "Antelopes", summary: "All about antelopes.", headings: [{ id: "speed", text: "Speed" }, { id: "sprints", text: "Sprints" }] });
    const standalone = await readFile(join(f.out, "zebra", "index.html"), "utf8");
    expect(standalone).toContain('<nav class="toc"');
    expect(standalone).toContain('<link rel="stylesheet" href="/docs/doc.css">');
    expect(await readFile(join(f.out, "zebra", "fragment.html"), "utf8")).toContain('<a href="#herds">Herds</a>');
    // The front page lists every page, and its own text comes first.
    const front = await readFile(join(f.out, "index.html"), "utf8");
    expect(front).toContain('<a href="/docs/antelope/"><strong>Antelopes</strong><span>All about antelopes.</span></a>');
    expect(front.indexOf("Where to go")).toBeLessThan(front.indexOf("All pages"));
    // A page dropped in later is picked up by the next build.
    await writeFile(join(f.dir, "cats.md"), page("Cats", "Small tigers.", "## Naps\n\ntext\n\n## Zoomies\n\ntext\n"));
    expect((await buildDocs(f.out, f.dir)).map((entry) => entry.slug)).toContain("cats");
    expect(await readFile(join(f.out, "cats", "index.html"), "utf8")).toContain("Zoomies");
  } finally {
    await f.done();
  }
});

test("quick facts reach index.json, per page and per heading, for the \"?\" preview (#304)", async () => {
  const f = await fixture({
    "facts.md": page("Facts", "A page with facts.", "> [!FACTS]\n> The page in one line.\n\n## With\n\n> [!FACTS]\n> This section in one line.\n\ntext\n\n## Without\n\ntext\n"),
  });
  try {
    await buildDocs(f.out, f.dir);
    const json = JSON.parse(await readFile(join(f.out, "index.json"), "utf8")) as { pages: DocsIndexPage[] };
    expect(json.pages.find((entry) => entry.slug === "facts")).toEqual({
      slug: "facts", title: "Facts", summary: "A page with facts.", facts: "The page in one line.",
      headings: [{ id: "with", text: "With", facts: "This section in one line." }, { id: "without", text: "Without" }],
    });
  } finally {
    await f.done();
  }
});

test("a file name that cannot be a web address, or that repeats another page, is refused", async () => {
  const f = await fixture({ "Bad Name.md": page("A", "B.", "## C\n\ntext\n") });
  try {
    await expect(readUserDocs(f.dir)).rejects.toThrow("lower-case letters");
    await rm(join(f.dir, "Bad Name.md"));
    await writeFile(join(f.dir, "a.md"), page("A", "B.", "## C\n\ntext\n"));
    await writeFile(join(f.dir, "10-a.md"), page("A", "B.", "## C\n\ntext\n"));
    await expect(readUserDocs(f.dir)).rejects.toThrow("already taken");
  } finally {
    await f.done();
  }
});

// ---- the pages that ship ---------------------------------------------------------------------------------

const shipped = async () => {
  const { index, pages } = await readUserDocs(USER_DOCS_DIR);
  const figures = await figureOptionsFor(USER_DOCS_DIR);
  return [{ slug: INDEX_SLUG, text: index ?? "", kind: "page" }, ...pages].map(({ slug, text, kind }) => ({ slug, kind, doc: renderDoc(slug, text, undefined, figures) }));
};

test("every shipped page has a one-sentence summary, a table of contents and a hierarchy that does not skip", async () => {
  const docs = await shipped();
  expect(docs.length).toBeGreaterThanOrEqual(12);
  for (const { slug, kind, doc } of docs) {
    expect(doc.summary.length, `${slug}: summary`).toBeGreaterThan(10);
    expect(doc.summary.length, `${slug}: summary is short`).toBeLessThan(160);
    // One sentence: nothing follows the first full stop.
    expect(/[.!?]\s+\S/.test(doc.summary), `${slug}: summary is one sentence`).toBe(false);
    // The front page and a section's overview get their lists of pages, and with them a heading, only when the tree is built (checked below).
    if (slug !== INDEX_SLUG && kind === "page") {
      expect(doc.headings.length, `${slug}: headings`).toBeGreaterThanOrEqual(2);
      expect(doc.html, `${slug}: contents`).toContain('<nav class="toc"');
    }
    for (const heading of doc.headings) expect(heading.text.length, `${slug}: ${heading.id}`).toBeLessThan(60);
  }
});

test("no decision or issue number appears outside a page's footer", async () => {
  for (const { slug, doc } of await shipped()) {
    const text = doc.html.replace(/<footer class="notes">[\s\S]*?<\/footer>/, "").replace(/<[^>]+>/g, " ").replace(/&#?\w+;/g, " ");
    expect(/\bD\d{1,3}\b/.test(text), `${slug}: decision number in the text`).toBe(false);
    expect(/#\d{2,4}\b/.test(text), `${slug}: issue number in the text`).toBe(false);
  }
});

test("the keys and multiplexer pages keep a footer for their decisions", async () => {
  const docs = await shipped();
  for (const slug of ["reference/keys", "terminal/multiplexer"]) expect(docs.find((entry) => entry.slug === slug)!.doc.html, slug).toMatch(/<footer class="notes">[\s\S]*\bD\d+/);
});

/** The sections of D317 in Settings order, with Get started first and Reference last. */
const SECTIONS = ["start", "terminal", "machines", "mesh", "access", "you", "sharing", "appearance", "reference"];

test("the real tree builds from the real folder, in the sections of D317", async () => {
  const out = await mkdtemp(join(tmpdir(), "docs-real-"));
  try {
    const index = await buildDocs(resolve(out, "docs"));
    const slugs = index.map((entry) => entry.slug);
    expect(slugs).toEqual([INDEX_SLUG, ...SECTIONS.flatMap((section) => [section, ...slugs.filter((slug) => slug.startsWith(`${section}/`))])]);
    expect(slugs).toEqual(expect.arrayContaining(["terminal/multiplexer", "reference/keys"]));
    // The two flat addresses that shipped before the sections still lead to their pages.
    const moved = (await readUserDocs(USER_DOCS_DIR)).pages.flatMap((entry) => entry.former.map((former) => [former, entry.slug]));
    expect(moved).toEqual(expect.arrayContaining([["multiplexer", "terminal/multiplexer"], ["keys", "reference/keys"]]));
    // The front page has its own text and the list of sections, so it has contents like every other page.
    expect(index.find((entry) => entry.slug === INDEX_SLUG)!.headings.map((heading) => heading.id)).toEqual(["finding-your-way", "sections"]);
    expect(await readFile(resolve(out, "docs", "index.html"), "utf8")).toContain('<nav class="toc"');
    // The page script is a file of its own: small, and referenced (deferred) by every standalone page.
    const script = await readFile(resolve(out, "docs", "doc.js"), "utf8");
    expect(script.length, "doc.js stays small").toBeLessThan(12_000);
    expect(await readFile(resolve(out, "docs", "reference", "keys", "index.html"), "utf8")).toContain('<script src="/docs/doc.js" defer></script>');
    expect(await readFile(resolve(out, "docs", "reference", "keys", "fragment.html"), "utf8"), "the canvas fragment carries no script of its own").not.toContain("<script");
    const redirect = await readFile(resolve(out, "docs", "multiplexer", "index.html"), "utf8");
    expect(redirect).toContain('content="0; url=/docs/terminal/multiplexer/"');
  } finally {
    await rm(out, { recursive: true, force: true });
  }
});

test("nested folders make section/page addresses; the section lists its pages and the front page lists the sections", async () => {
  const f = await fixture({
    "index.md": page("Welcome", "Start here.", "## Where to go\n\ntext\n"),
    "10-mesh/index.md": page("Mesh", "How machines reach each other.", "## What it is\n\ntext\n"),
    "10-mesh/20-names.md": page("Names", "What machines are called.", "## Suffix\n\ntext\n\n## Clashes\n\ntext\n"),
    "10-mesh/10-keys.md": page("Mesh keys", "Keys between machines.", "## Rotation\n\ntext\n\n## Overlap\n\ntext\n"),
    "20-solo.md": page("Solo", "A page outside any section.", "## One\n\ntext\n\n## Two\n\ntext\n"),
  });
  try {
    const index = await buildDocs(f.out, f.dir);
    expect(index.map((entry) => entry.slug)).toEqual([INDEX_SLUG, "mesh", "mesh/keys", "mesh/names", "solo"]);
    const mesh = index.find((entry) => entry.slug === "mesh")!;
    expect(mesh.section).toBe(true);
    expect(mesh.headings.map((heading) => heading.id)).toEqual(["what-it-is", "pages-in-this-section"]);
    expect(index.find((entry) => entry.slug === "mesh/keys")).toMatchObject({ parent: "mesh", title: "Mesh keys" });
    expect(index.find((entry) => entry.slug === "solo")).not.toHaveProperty("parent");
    const overview = await readFile(join(f.out, "mesh", "index.html"), "utf8");
    expect(overview.indexOf('href="/docs/mesh/keys/"')).toBeLessThan(overview.indexOf('href="/docs/mesh/names/"'));
    const front = await readFile(join(f.out, "index.html"), "utf8");
    expect(front).toContain('<h2 id="sections">Sections</h2>');
    expect(front).toContain('<a href="/docs/mesh/"><strong>Mesh</strong>');
    expect(front).toContain('<a href="/docs/solo/">');
    expect(front, "the pages of a section are listed on its overview, not on the front page").not.toContain('href="/docs/mesh/keys/"');
    expect(await readFile(join(f.out, "mesh", "keys", "fragment.html"), "utf8")).toContain("Rotation");
  } finally {
    await f.done();
  }
});

test("a section needs an overview, and folders nest one level only", async () => {
  const f = await fixture({ "10-mesh/10-keys.md": page("Keys", "Keys.", "## A\n\ntext\n") });
  try {
    await expect(readUserDocs(f.dir)).rejects.toThrow("needs an index.md");
    await writeFile(join(f.dir, "10-mesh", "index.md"), page("Mesh", "Mesh.", "## A\n\ntext\n"));
    await mkdir(join(f.dir, "10-mesh", "deeper"));
    await expect(readUserDocs(f.dir)).rejects.toThrow("one level only");
    await rm(join(f.dir, "10-mesh", "deeper"), { recursive: true });
    await writeFile(join(f.dir, "mesh.md"), page("Mesh again", "Same name.", "## A\n\ntext\n"));
    await expect(readUserDocs(f.dir)).rejects.toThrow("already taken");
  } finally {
    await f.done();
  }
});

test("a former slug line leaves a redirect page that keeps the heading, and may not hide a live page", async () => {
  expect(formerSlugsOf("<!-- SPDX -->\n<!-- Former slugs: multiplexer, old/place -->\n# T")).toEqual(["multiplexer", "old/place"]);
  expect(formerSlugsOf("# T")).toEqual([]);
  const f = await fixture({
    "10-terminal/index.md": page("Terminal", "Sessions.", "## A\n\ntext\n"),
    "10-terminal/10-multiplexer.md": `<!-- Former slugs: multiplexer -->\n${page("The Multiplexer", "Sessions that survive.", "## A\n\ntext\n\n## B\n\ntext\n")}`,
  });
  try {
    const index = await buildDocs(f.out, f.dir);
    // The old address is not a page of the index, so the app never lists it.
    expect(index.map((entry) => entry.slug)).not.toContain("multiplexer");
    const redirect = await readFile(join(f.out, "multiplexer", "index.html"), "utf8");
    expect(redirect).toContain('<meta http-equiv="refresh" content="0; url=/docs/terminal/multiplexer/">');
    expect(redirect).toContain('location.replace("/docs/terminal/multiplexer/"+location.hash)');
    expect(redirect).toContain('<link rel="canonical" href="/docs/terminal/multiplexer/">');
    await writeFile(join(f.dir, "10-terminal", "20-other.md"), `<!-- Former slugs: terminal -->\n${page("Other", "Another page.", "## A\n\ntext\n")}`);
    await expect(readUserDocs(f.dir)).rejects.toThrow("live address");
  } finally {
    await f.done();
  }
});

test("a link between pages, or a \"?\" in the app, that leads nowhere stops the build and says where", async () => {
  const f = await fixture({
    "10-terminal/index.md": page("Terminal", "Sessions.", "## A\n\ntext\n"),
    "10-terminal/10-multiplexer.md": `<!-- Former slugs: multiplexer -->\n${page("The Multiplexer", "Sessions that survive.", "## Question\n\ntext\n\n## B\n\n[Back](/docs/terminal/#a)\n")}`,
  });
  const app = join(f.out, "..", "app");
  await mkdir(app, { recursive: true });
  try {
    await writeFile(join(app, "good.ts"), 'export const HELP = "/docs/terminal/multiplexer/#question";\nconst c = { docs: { page: "terminal/multiplexer", heading: "b" } };\n');
    await buildDocs(f.out, f.dir, [app]);
    await writeFile(join(app, "bad.ts"), 'export const OLD = "/docs/multiplexer/";\nexport const GONE = "/docs/terminal/multiplexer/#what-it-does";\nconst c = { docs: { page: "nowhere" } };\n');
    const failure = await buildDocs(f.out, f.dir, [app]).then(() => "", (error: Error) => error.message);
    expect(failure).toContain("bad.ts:1: /docs/multiplexer/ is the old address of terminal/multiplexer");
    expect(failure).toContain("bad.ts:2: /docs/terminal/multiplexer/#what-it-does points at a heading that does not exist");
    expect(failure).toContain("bad.ts:3: /docs/nowhere/ points at a page that does not exist");
  } finally {
    await f.done();
  }
});
