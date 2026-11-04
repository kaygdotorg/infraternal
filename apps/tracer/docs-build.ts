// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Renders the user-facing pages of `docs/user/` into static HTML (#298, #302).
 *
 * Docs live in two places: infraternal.com/docs holds the official ones, and `<instance>/docs` holds the pages for
 * the version that instance runs. The app's "?" links therefore point at its own `/docs/<page>/`. Both are this
 * one output: `build.ts` puts it in the web root, and `bun run docs` writes the same tree on its own for a static
 * host. Every URL inside a page starts with `/docs/`, so the tree works wherever it is mounted at that path.
 *
 * The server needs nothing for it: a page is `docs/<slug>/index.html`, which the web root serves for the
 * directory (and for `/docs/<slug>`, by redirect), with the `.br`/`.gz` encodings `precompress` writes next to it. A slug is
 * `<section>/<page>` (D317), so the address of a heading is `/docs/<section>/<page>/#<heading>`.
 * Markdown is rendered by the bundler's built-in renderer, so no dependency is added. The pages are plain HTML
 * and CSS. The one script is `doc.js` (doc-page.ts, deferred): it marks the section being read in the contents and lets a code
 * block be copied. It is a separate file from the app's bundle, so it is never part of the app's JavaScript budget
 * (transfer-budget.ts); the canvas reader runs the same code from an on-demand chunk (docs-body.on-demand.ts).
 *
 * The reading aids (callouts, reasoning blocks, quick facts, citations, quotes, copyable code) are in docs-extras.ts.
 *
 * There is no list of pages. Every `*.md` file under `docs/user/` is a page: the folder is the one place where a
 * page for the people who use Infraternal belongs, and internal planning and engineering notes stay outside it.
 * `index.md` is the front page (the build adds the list of sections under it). A folder is a section and its `index.md`
 * is the section's overview (the build adds the list of its pages); the folder's other files are its pages. Folders
 * nest one level only. Entries are ordered by file name, and a leading `NN-` only orders (`20-terminal/10-multiplexer.md`
 * is `/docs/terminal/multiplexer/`). A page that used to live at another address says so on one comment line,
 * `<!-- Former slugs: multiplexer, old/place -->`, and the build writes a redirect page at each former address, so a
 * link that has already shipped keeps working (`docs-anchors.ts` keeps anything we ship from relying on one).
 *
 * What the build reads out of a page, so nobody has to write it twice:
 * - the title is the one level-1 heading;
 * - the summary is the paragraph right under it (one sentence; the index and the palette show it);
 * - the table of contents is made from the level-2 and level-3 headings (`tocFor`);
 * - everything after the last horizontal rule is the footer, where the decision numbers live.
 * A page whose headings skip a level, or that has no summary, fails the build (`checkOutline`, `splitPage`): the
 * structure a reader relies on cannot rot silently. So does a "?" in the app, or a link between pages, that points at a page
 * or a heading that does not exist (`docs-anchors.ts`).
 */
import { cp, mkdir, readdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { checkReferences, referencesInPage, referencesInTree } from "./docs-anchors";
import { citations, factsOf, readingAids, sourcesOf, type Facts } from "./docs-extras";
import { figures, type FigureManifest, type FigureOptions } from "./docs-figure";

/** The repository root, found from this file's place (`apps/tracer/`). */
const root = resolve(import.meta.dirname, "../..");

/** The one folder whose Markdown files become pages. */
export const USER_DOCS_DIR = resolve(root, "docs/user");
/** Slug of the front page: it is written to `/docs/` and is also a page of the palette and the Docs view. */
export const INDEX_SLUG = "index";
/** Where the app names docs addresses: the build checks that each one lands on a page and heading that exist. */
export const APP_SOURCES = [resolve(root, "apps/tracer/src"), resolve(root, "packages/ui/src")];
/** Top-level names the build writes into the docs tree itself, so no page or section may take them. */
const RESERVED = new Set(["fonts", "figures"]);

/** Escapes text for use in HTML, including inside a double-quoted attribute. */
const escapeHtml = (text: string): string => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/**
 * One searchable heading of a page: `id` is the anchor in the rendered page, `text` its plain title. `facts` is the text of the
 * heading's `> [!FACTS]` block, if the page wrote one (docs-extras.ts): the excerpt the "?" preview shows for this heading.
 */
export interface DocsHeading { id: string; text: string; facts?: string }
/**
 * One page of `index.json`, which the app reads (titles, headings and quick facts, never body text). `slug` is the page's address
 * under `/docs/` (`terminal/multiplexer`). `section` marks the overview of a section; `parent` is the slug of the section a page
 * belongs to. `facts` is the page's own excerpt (a `[!FACTS]` block under the title); a page without one is previewed by its `summary`.
 */
export interface DocsIndexPage { slug: string; title: string; summary: string; section?: true; parent?: string; facts?: string; headings: DocsHeading[] }
/** A heading with its level, which the table of contents needs and the index does not. */
export interface OutlineHeading extends DocsHeading { level: 2 | 3 }

/** The plain text of an HTML fragment: tags removed, common entities decoded and spaces collapsed. */
const plain = (html: string): string => html.replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0*39;/g, "'").trim();

/** A heading's anchor: lower-case words joined by hyphens, numbered when the page already used it. */
function anchorFor(text: string, used: Set<string>): string {
  const base = text.toLowerCase().replace(/[^\p{L}\p{N}]+/gu, "-").replace(/^-+|-+$/g, "") || "section";
  let id = base;
  for (let n = 2; used.has(id); n += 1) id = `${base}-${n}`;
  used.add(id);
  return id;
}

/**
 * Gives every level-2 and level-3 heading an `id` (keeping one the renderer already wrote) and lists them. The ids make a
 * palette result open the page at its heading, and a table-of-contents entry scroll to it. Level 1 is the page title and
 * is not listed twice.
 */
export function anchorHeadings(html: string): { html: string; headings: OutlineHeading[] } {
  const used = new Set<string>();
  const headings: OutlineHeading[] = [];
  const out = html.replace(/<h([23])((?:\s[^>]*)?)>([\s\S]*?)<\/h\1>/g, (_all, level: string, attrs: string, inner: string) => {
    const text = plain(inner);
    const existing = /\sid="([^"]+)"/.exec(attrs)?.[1];
    const id = existing ?? anchorFor(text, used);
    used.add(id);
    headings.push({ id, text, level: level === "2" ? 2 : 3 });
    return `<h${level}${existing ? attrs : `${attrs} id="${id}"`}>${inner}</h${level}>`;
  });
  return { html: out, headings };
}

/**
 * Copies each column's heading onto its cells as `data-label`. A narrow window (the canvas reader on a phone) stacks a row's
 * cells and prints the label before each value (docs-reader.css), so a wide table never needs sideways scrolling there.
 */
export function labelCells(html: string): string {
  return html.replace(/<table>[\s\S]*?<\/table>/g, (table) => {
    const labels = [...table.matchAll(/<th[^>]*>([\s\S]*?)<\/th>/g)].map((match) => plain(match[1]!));
    return table.replace(/<tr[^>]*>([\s\S]*?)<\/tr>/g, (row, inner: string) => {
      if (inner.includes("<th")) return row;
      let column = 0;
      return row.replace(/<td([^>]*)>/g, (_cell, attrs: string) => `<td${attrs} data-label="${escapeHtml(labels[column++] ?? "")}">`);
    });
  });
}

/**
 * The page's outline must be a real hierarchy: one level-1 heading (the title) first, and below it no heading that skips a
 * level (a level 3 needs a level 2 above it). Returns what is wrong, in words for the person writing the page.
 */
export function checkOutline(html: string): string[] {
  const levels = [...html.matchAll(/<h([1-6])[\s>]/g)].map((match) => Number(match[1]));
  const problems: string[] = [];
  const titles = levels.filter((level) => level === 1).length;
  if (titles !== 1) problems.push(`needs exactly one level-1 heading (the title), found ${titles}`);
  else if (levels[0] !== 1) problems.push("the title (level-1 heading) must come first");
  for (let i = 1; i < levels.length; i += 1) {
    if (levels[i]! > levels[i - 1]! + 1) problems.push(`a level-${levels[i]} heading follows a level-${levels[i - 1]} heading; do not skip a level`);
  }
  return problems;
}

/** The title block, the body, and the footer of one rendered page. */
export interface PageParts { title: string; titleHtml: string; summary: string; summaryHtml: string; body: string; notes: string }

/**
 * Splits rendered Markdown into title, summary, body and footer. The summary is the paragraph directly under the title; a
 * page without one fails, because the index and the palette show it. Everything after the last horizontal rule is the
 * footer (kept out of the table of contents, and out of the reading flow).
 */
export function splitPage(html: string): PageParts {
  const head = /^\s*(<h1[^>]*>[\s\S]*?<\/h1>)\s*<p>([\s\S]*?)<\/p>/.exec(html);
  if (!head) throw new Error("a docs page needs a one-sentence summary directly under its title");
  const [whole, titleHtml, summaryHtml] = head as unknown as [string, string, string];
  let body = html.slice(whole.length);
  let notes = "";
  const rules = [...body.matchAll(/<hr\s*\/?>/g)];
  const last = rules.at(-1);
  if (last) {
    notes = body.slice(last.index + last[0].length).trim();
    body = body.slice(0, last.index);
  }
  return { title: plain(titleHtml), titleHtml, summary: plain(summaryHtml), summaryHtml, body: body.trim(), notes };
}

/** A nested list of the headings; a level-3 heading sits under the level-2 heading above it. */
function tocList(headings: readonly OutlineHeading[]): string {
  const groups: { head: OutlineHeading; subs: OutlineHeading[] }[] = [];
  for (const heading of headings) {
    if (heading.level === 3 && groups.length > 0) groups.at(-1)!.subs.push(heading);
    else groups.push({ head: heading, subs: [] });
  }
  const link = (h: OutlineHeading): string => `<a href="#${h.id}">${escapeHtml(h.text)}</a>`;
  return `<ol>${groups.map((g) => `<li>${link(g.head)}${g.subs.length ? `<ol>${g.subs.map((s) => `<li>${link(s)}</li>`).join("")}</ol>` : ""}</li>`).join("")}</ol>`;
}

/**
 * The table of contents, from the headings. It is written twice and CSS shows one: a folded `<details>` where the page is
 * narrow (a phone, or a window one column wide) and a sticky column beside the page where it is wide. A script-free page
 * cannot open or close a `<details>` by width, and a hidden duplicate costs about a kilobyte. A page with fewer than two
 * headings has nothing to jump to and gets none.
 */
export function tocFor(headings: readonly OutlineHeading[]): string {
  if (headings.length < 2) return "";
  const list = tocList(headings);
  return `<nav class="toc" aria-label="On this page"><details class="toc-fold"><summary>On this page</summary>${list}</details><div class="toc-side"><p class="toc-title">On this page</p>${list}</div></nav>`;
}

/** A page ready to be written: its parts as the index sees them, and the body markup both outputs share. */
export interface RenderedDoc { slug: string; title: string; summary: string; headings: OutlineHeading[]; facts: Facts; html: string; figureFiles: string[] }

/**
 * Renders one page. `html` is the page without chrome (docs-reader.on-demand loads it into a canvas window; the standalone page
 * wraps it): a head (title and summary), the table of contents, the body, and the footer. `extra` is markup the build adds at
 * the end of the body (the front page's list of pages).
 */
export function renderDoc(slug: string, markdown: string, extra = (_title: string): string => "", figureOptions: Omit<FigureOptions, "page"> = { manifest: {} }): RenderedDoc {
  const renderer = (Bun as unknown as { markdown: { html(text: string): string } }).markdown;
  // The licence and role comments at the top of a source file are for the repository, not for readers.
  const commentFree = markdown.replace(/<!--[\s\S]*?-->\n?/g, "");
  const { markdown: source, sources } = sourcesOf(commentFree, renderer.html, slug);
  const rendered = renderer.html(source);
  const problems = checkOutline(rendered);
  if (problems.length > 0) throw new Error(`docs page "${slug}": ${problems.join("; ")}`);
  const parts = splitPage(rendered);
  // Callouts, quotes and code blocks first; then the citations, whose list of references ends the body (and is a heading in the
  // contents); then whatever the build itself adds (the front page's list of pages).
  const cited = citations(readingAids(parts.body, slug), sources, slug);
  // Figures (docs-figure.ts) are the page's pictures; the files they use are copied next to the page by buildDocs.
  const pictured = figures(cited.body, { ...figureOptions, page: slug });
  const withExtra = `${pictured.html}\n${cited.references}\n${extra(parts.title)}`;
  // A wide table scrolls by itself instead of widening the page.
  const wrapped = labelCells(withExtra).replace(/<table>/g, '<div class="table"><table>').replace(/<\/table>/g, "</table></div>");
  const { html: body, headings } = anchorHeadings(wrapped);
  const facts = factsOf(body, slug);
  const notes = parts.notes ? `\n<footer class="notes">\n${parts.notes}\n</footer>` : "";
  const html = `<div class="doc">
<div class="doc-head">
${parts.titleHtml}
<p class="lede">${parts.summaryHtml}</p>
</div>
${tocFor(headings)}
<div class="doc-body">
${body}${notes}
</div>
</div>
`;
  return { slug, title: parts.title, summary: parts.summary, headings, facts, html, figureFiles: pictured.files };
}

/**
 * A page as it is read from disk. `kind` is `section` for a folder's `index.md` (the section's overview); `parent` is the slug of the
 * section a page sits in; `former` lists the addresses the page used to have (the comment line `Former slugs:`).
 */
export interface SourcePage { slug: string; text: string; kind: "page" | "section"; parent?: string; former: string[] }

/** A valid name of a page or section after its ordering prefix is removed: lower-case letters, digits and hyphens. */
const NAME = /^[a-z0-9][a-z0-9-]*$/;
/** Matches the `<!-- Former slugs: a, b/c -->` comment line of a moved page. */
const FORMER_SLUGS = /<!--\s*Former slugs:\s*([^>]*?)\s*-->/i;

/** The addresses a page used to have, from its `<!-- Former slugs: a, b/c -->` line. They are paths under `/docs/`, one or two names deep. */
export function formerSlugsOf(markdown: string): string[] {
  const line = FORMER_SLUGS.exec(markdown)?.[1];
  return line ? line.split(",").map((slug) => slug.trim()).filter(Boolean) : [];
}

/** A file or folder name without its ordering prefix (`20-terminal` is `terminal`), refused when it cannot be part of a web address. */
function slugName(name: string): string {
  const slug = name.replace(/\.md$/, "").replace(/^\d+-/, "");
  if (!NAME.test(slug)) throw new Error(`docs entry "${name}": a name is lower-case letters, digits and hyphens`);
  return slug;
}

/**
 * Reads the pages under a folder, in the order of their names. `index.md` is the front page. Every other `*.md` is a page; a folder
 * is a section, which needs an `index.md` of its own (the overview) and holds pages, and nothing deeper (D317: two levels at most).
 * A former address may not be a live one, or be given twice, or the redirect would hide a page.
 */
export async function readUserDocs(dir: string): Promise<{ index: string | undefined; pages: SourcePage[] }> {
  let index: string | undefined;
  const pages: SourcePage[] = [];
  const seen = new Set<string>();
  const take = (slug: string, name: string): void => {
    if (RESERVED.has(slug.split("/")[0]!) || seen.has(slug)) throw new Error(`docs entry "${name}": the name "${slug}" is already taken`);
    seen.add(slug);
  };
  const entries = (await readdir(dir, { withFileTypes: true })).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith(".md")) {
      const text = await Bun.file(resolve(dir, entry.name)).text();
      const slug = slugName(entry.name);
      if (slug === INDEX_SLUG) { index = text; continue; }
      take(slug, entry.name);
      pages.push({ slug, text, kind: "page", former: formerSlugsOf(text) });
    } else if (entry.isDirectory() && !RESERVED.has(entry.name)) {
      const section = slugName(entry.name);
      take(section, entry.name);
      const files = (await readdir(resolve(dir, entry.name), { withFileTypes: true })).sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      const deeper = files.find((file) => file.isDirectory());
      if (deeper) throw new Error(`docs folder "${entry.name}/${deeper.name}": sections nest one level only, so a section holds pages and no folders`);
      const overview = files.find((file) => file.isFile() && file.name.endsWith(".md") && slugName(file.name) === INDEX_SLUG);
      if (!overview) throw new Error(`docs folder "${entry.name}": a section needs an index.md, its overview`);
      const overviewText = await Bun.file(resolve(dir, entry.name, overview.name)).text();
      pages.push({ slug: section, text: overviewText, kind: "section", former: formerSlugsOf(overviewText) });
      for (const file of files) {
        if (!file.isFile() || !file.name.endsWith(".md") || file === overview) continue;
        const text = await Bun.file(resolve(dir, entry.name, file.name)).text();
        const slug = `${section}/${slugName(file.name)}`;
        take(slug, `${entry.name}/${file.name}`);
        pages.push({ slug, text, kind: "page", parent: section, former: formerSlugsOf(text) });
      }
    }
  }
  const formerSeen = new Set<string>();
  for (const page of pages) {
    for (const former of page.former) {
      if (!/^[a-z0-9][a-z0-9-]*(\/[a-z0-9][a-z0-9-]*)?$/.test(former) || RESERVED.has(former.split("/")[0]!)) throw new Error(`docs page "${page.slug}": the former slug "${former}" is not a path of lower-case names under /docs/`);
      if (seen.has(former) || former === INDEX_SLUG || formerSeen.has(former)) throw new Error(`docs page "${page.slug}": the former slug "${former}" is a live address or is claimed twice`);
      formerSeen.add(former);
    }
  }
  return { index, pages };
}

/** Wraps a page title and its body HTML in the full standalone docs page (head, theme colours and layout). */
function page(title: string, body: string): string {
  // The two page colours are the sign-in card's (auth-scheme.ts PAGE), so the browser chrome blends in on a phone.
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#101113" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f6f6f4" media="(prefers-color-scheme: light)">
<title>${escapeHtml(title)}</title>
<link rel="stylesheet" href="/docs/docs.css">
<link rel="stylesheet" href="/docs/doc.css">
<script src="/docs/doc.js" defer></script>
</head><body>
<header><a href="/docs/">Infraternal docs</a></header>
<main>
${body}</main>
</body></html>
`;
}

/** A list of pages under a heading: the title over its one-line summary. Empty when there is nothing to list. */
function pageList(heading: string, pages: readonly { slug: string; title: string; summary: string }[]): string {
  if (pages.length === 0) return "";
  const rows = pages.map((entry) => `<li><a href="/docs/${entry.slug}/"><strong>${escapeHtml(entry.title)}</strong><span>${escapeHtml(entry.summary)}</span></a></li>`).join("\n");
  return `<h2>${heading}</h2>\n<ul class="pages">\n${rows}\n</ul>`;
}

/** The page that stands at a former address: it sends the reader on, keeping the `#heading` the old link had (a refresh alone would drop it). */
function redirectPage(to: string, title: string): string {
  const target = `/docs/${to}/`;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>${escapeHtml(title)} · Infraternal docs</title>
<meta name="robots" content="noindex">
<link rel="canonical" href="${target}">
<meta http-equiv="refresh" content="0; url=${target}">
<script>location.replace(${JSON.stringify(target)}+location.hash)</script>
</head><body><p>This page moved to <a href="${target}">${escapeHtml(title)}</a>.</p></body></html>
`;
}

/** The figures of the pages in `source`: the capture's manifest and folder (docs-figure.ts). A tree with none has none, and its figures are pending. */
export async function figureOptionsFor(source: string = USER_DOCS_DIR): Promise<Omit<FigureOptions, "page"> & { directory: string }> {
  const directory = resolve(source, "figures");
  const manifestFile = Bun.file(resolve(directory, "manifest.json"));
  return { manifest: (await manifestFile.exists() ? await manifestFile.json() : {}) as FigureManifest, directory };
}

/**
 * Writes the docs tree into `out` (for the app build, `<dist>/docs`), reading the pages of `source`. `scan` lists the source folders
 * whose docs addresses are checked against the pages (docs-anchors.ts); the real tree checks the app, a fixture tree none.
 */
export async function buildDocs(out: string, source: string = USER_DOCS_DIR, scan: readonly string[] = source === USER_DOCS_DIR ? APP_SOURCES : []): Promise<DocsIndexPage[]> {
  await mkdir(resolve(out, "fonts"), { recursive: true });
  await Promise.all([
    cp(resolve(import.meta.dirname, "docs.css"), resolve(out, "docs.css")),
    // The structure shared with the canvas reader: summary, table of contents, footer.
    cp(resolve(import.meta.dirname, "doc.css"), resolve(out, "doc.css")),
    // The docs carry their own copy of the font, so the tree stands alone on a static host.
    cp(resolve(import.meta.dirname, "fonts/maple-mono-nf/roman.latin.woff2"), resolve(out, "fonts/roman.latin.woff2")),
  ]);
  // The page script: the section being read, and copying code. Bundled here, minified, as a file of its own.
  const script = await Bun.build({ entrypoints: [resolve(import.meta.dirname, "doc-page.ts")], target: "browser", minify: true, outdir: out, naming: { entry: "doc.js" } });
  if (!script.success) throw new Error(`docs script: ${script.logs.map(String).join("; ")}`);
  const { index: frontText, pages } = await readUserDocs(source);
  // The figures the capture made (docs-figure.ts). A tree with no figures folder simply has none.
  const figureOptions = await figureOptionsFor(source);
  const figureDirectory = figureOptions.directory;
  // Pages first, so a section's overview can list them and the front page can list the sections.
  const made = new Map<string, RenderedDoc>();
  for (const { slug, text, kind } of pages) if (kind === "page") made.set(slug, renderDoc(slug, text, undefined, figureOptions));
  const brief = ({ slug, title, summary }: RenderedDoc) => ({ slug, title, summary });
  for (const { slug, text, kind } of pages) {
    if (kind !== "section") continue;
    const members = pages.filter((member) => member.parent === slug).map((member) => brief(made.get(member.slug)!));
    made.set(slug, renderDoc(slug, text, () => pageList("Pages in this section", members), figureOptions));
  }
  const rendered = pages.map(({ slug }) => made.get(slug)!);
  // The front page lists the sections and the pages that stand outside one. Its text is optional: without it the list stands alone.
  const top = pages.filter((entry) => entry.parent === undefined).map((entry) => brief(made.get(entry.slug)!));
  const listTitle = pages.some((entry) => entry.kind === "section") ? "Sections" : "All pages";
  const front = renderDoc(INDEX_SLUG, frontText ?? "# Documentation\n\nGuides for using Infraternal.\n", () => pageList(listTitle, top), figureOptions);
  const all = [front, ...rendered];
  // Titles and headings only, so the file stays a few hundred bytes per page; the app fetches it when it is idle.
  const index: DocsIndexPage[] = all.map(({ slug, title, summary, headings, facts }) => {
    const from = pages.find((entry) => entry.slug === slug);
    return {
      slug, title, summary, ...(from?.kind === "section" ? { section: true as const } : {}), ...(from?.parent ? { parent: from.parent } : {}),
      ...(facts.page ? { facts: facts.page } : {}),
      headings: headings.map(({ id, text }) => ({ id, text, ...(facts.headings[id] ? { facts: facts.headings[id] } : {}) })),
    };
  });
  // Every "?" in the app and every link between pages must land on a page and heading that exist, or the build stops here.
  const moved = new Map(pages.flatMap((entry) => entry.former.map((former): [string, string] => [former, entry.slug])));
  const problems = checkReferences([...all.flatMap((doc) => referencesInPage(doc.slug, doc.html)), ...await referencesInTree(scan, root)], index, moved);
  if (problems.length > 0) throw new Error(`docs addresses that lead nowhere:\n${problems.join("\n")}`);
  // Only the pictures a page uses are copied, so a retired figure never ships.
  const used = [...new Set(all.flatMap((doc) => doc.figureFiles))];
  if (used.length > 0) {
    await mkdir(resolve(out, "figures"), { recursive: true });
    await Promise.all(used.map((file) => cp(resolve(figureDirectory, file), resolve(out, "figures", file))));
  }
  for (const doc of all) {
    const directory = doc === front ? resolve(out, INDEX_SLUG) : resolve(out, doc.slug);
    await mkdir(directory, { recursive: true });
    // The same body without the page chrome: the app shows it in a canvas window (docs-body.on-demand.ts).
    await writeFile(resolve(directory, "fragment.html"), doc.html);
    if (doc !== front) await writeFile(resolve(directory, "index.html"), page(`${doc.title} · Infraternal docs`, doc.html));
  }
  await writeFile(resolve(out, "index.html"), page("Infraternal docs", front.html));
  // A page that moved leaves a page at each former address; it is not in the index, so the app never lists it.
  for (const [former, slug] of moved) {
    await mkdir(resolve(out, former), { recursive: true });
    await writeFile(resolve(out, former, "index.html"), redirectPage(slug, made.get(slug)!.title));
  }
  await writeFile(resolve(out, "index.json"), JSON.stringify({ pages: index }));
  return index;
}

if (import.meta.main) {
  const out = resolve(process.argv[2] ?? "docs-dist");
  await buildDocs(out);
  console.log(`docs written to ${out}`);
}
