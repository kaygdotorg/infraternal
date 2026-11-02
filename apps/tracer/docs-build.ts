// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Renders the user-facing pages of `docs/` into static HTML (#298).
 *
 * Docs live in two places: infraternal.com/docs holds the official ones, and `<instance>/docs` holds the pages for
 * the version that instance runs. The app's "?" links therefore point at its own `/docs/<page>/`. Both are this
 * one output: `build.ts` puts it in the web root, and `bun run docs` writes the same tree on its own for a static
 * host. Every URL inside a page starts with `/docs/`, so the tree works wherever it is mounted at that path.
 *
 * The server needs nothing for it: a page is `docs/<slug>/index.html`, which the web root serves for the
 * directory (and for `/docs/<slug>`, by redirect), with the `.br`/`.gz` encodings `precompress` writes next to it.
 * Markdown is rendered by the bundler's built-in renderer, so no dependency is added. The pages are plain HTML
 * and CSS with no script, so they are never part of the app's JavaScript budget (transfer-budget.ts).
 *
 * A page is listed here on purpose: only pages written for the people who use Infraternal belong. Internal planning
 * and engineering notes in `docs/` stay out.
 */
import { cp, mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "../..");

/** The published pages, in index order. `summary` is the one line the index shows under the title. */
export const DOCS_PAGES = [
  { slug: "multiplexer", source: "docs/multiplexer.md", summary: "Sessions that survive disconnects, and switching from tmux or Zellij." },
  { slug: "keys", source: "docs/keys.md", summary: "Every key and code, where it lives and when it expires or changes." },
] as const;

const escapeHtml = (text: string): string => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** The first level-1 heading's text, which is the page title. */
function titleOf(html: string): string {
  const match = /<h1[^>]*>([\s\S]*?)<\/h1>/.exec(html);
  if (!match) throw new Error("a docs page needs a level-1 heading");
  return match[1]!.replace(/<[^>]+>/g, "").trim();
}

/** One searchable heading of a page: `id` is the anchor in the rendered page, `text` its plain title. */
export interface DocsHeading { id: string; text: string }
/** One page of `index.json`, which the app's command palette searches (titles and headings only, never body text). */
export interface DocsIndexPage { slug: string; title: string; summary: string; headings: DocsHeading[] }

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
 * palette result open the page at its heading. Level 1 is the page title and is not listed twice.
 */
export function anchorHeadings(html: string): { html: string; headings: DocsHeading[] } {
  const used = new Set<string>();
  const headings: DocsHeading[] = [];
  const out = html.replace(/<h([23])((?:\s[^>]*)?)>([\s\S]*?)<\/h\1>/g, (_all, level: string, attrs: string, inner: string) => {
    const text = plain(inner);
    const existing = /\sid="([^"]+)"/.exec(attrs)?.[1];
    const id = existing ?? anchorFor(text, used);
    used.add(id);
    headings.push({ id, text });
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

function page(title: string, body: string): string {
  // The two page colours are the sign-in card's (auth-scheme.ts PAGE), so the browser chrome blends in on a phone.
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#101113" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f6f6f4" media="(prefers-color-scheme: light)">
<title>${escapeHtml(title)}</title>
<link rel="stylesheet" href="/docs/docs.css">
</head><body>
<header><a href="/docs/">Infraternal docs</a></header>
<main>
${body}
</main>
</body></html>
`;
}

/** Writes the docs tree into `out` (for the app build, `<dist>/docs`). */
export async function buildDocs(out: string): Promise<void> {
  const markdown = (Bun as unknown as { markdown: { html(text: string): string } }).markdown;
  await mkdir(resolve(out, "fonts"), { recursive: true });
  await Promise.all([
    cp(resolve(import.meta.dirname, "docs.css"), resolve(out, "docs.css")),
    // The docs carry their own copy of the font, so the tree stands alone on a static host.
    cp(resolve(import.meta.dirname, "fonts/maple-mono-nf/roman.latin.woff2"), resolve(out, "fonts/roman.latin.woff2")),
  ]);
  const entries: { slug: string; title: string; summary: string }[] = [];
  const index: DocsIndexPage[] = [];
  for (const { slug, source, summary } of DOCS_PAGES) {
    // The licence and role comments at the top of a source file are for the repository, not for readers.
    const text = (await Bun.file(resolve(root, source)).text()).replace(/<!--[\s\S]*?-->\n?/g, "");
    // A wide table scrolls by itself instead of widening the page.
    const { html, headings } = anchorHeadings(labelCells(markdown.html(text)).replace(/<table>/g, '<div class="table"><table>').replace(/<\/table>/g, "</table></div>"));
    const title = titleOf(html);
    entries.push({ slug, title, summary });
    index.push({ slug, title, summary, headings });
    await mkdir(resolve(out, slug), { recursive: true });
    await writeFile(resolve(out, slug, "index.html"), page(`${title} · Infraternal docs`, html));
    // The same body without the page chrome: the app shows it in a canvas window (docs-reader.on-demand.ts).
    await writeFile(resolve(out, slug, "fragment.html"), html);
  }
  // Titles and headings only, so the file stays a few hundred bytes per page; the palette fetches it on its first open.
  await writeFile(resolve(out, "index.json"), JSON.stringify({ pages: index }));
  const list = entries.map((entry) => `<li><a href="/docs/${entry.slug}/"><strong>${escapeHtml(entry.title)}</strong><span>${escapeHtml(entry.summary)}</span></a></li>`).join("\n");
  await writeFile(resolve(out, "index.html"), page("Infraternal docs", `<h1>Documentation</h1>\n<ul class="pages">\n${list}\n</ul>`));
}

if (import.meta.main) {
  const out = resolve(process.argv[2] ?? "docs-dist");
  await buildDocs(out);
  console.log(`docs written to ${out}`);
}
