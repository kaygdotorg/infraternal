// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The "does the page I point at exist" check of the docs build (#311, D317).
 *
 * A "?" in the app lands on a docs page, and on a heading of it when the "?" sits next to a setting. An address is
 * `/docs/<section>/<page>/#<heading>`, and a heading's anchor is its text, so renaming a page or a heading silently breaks
 * every "?" that pointed at it. The build therefore reads the places where the app names a docs address and fails when
 * one of them points at a page or a heading the index does not have. It looks at three kinds of place:
 * - an address written as a string in the app's source (`"/docs/terminal/multiplexer/"`, with or without `#heading`);
 * - a Settings catalog entry, `docs: { page: "terminal/multiplexer", heading: "…" }`, where the page is a slug of the index;
 * - a link from one docs page to another, in the rendered pages.
 * A page that moved is named in the message (the old address still redirects for people, but nothing we ship should rely on it).
 *
 * Test files are not scanned: they name pages that do not exist on purpose.
 */
import { readdir } from "node:fs/promises";
import { relative, resolve } from "node:path";

/** One place that names a docs address. `where` is `file:line` for source, or `page <slug>` for a link between pages. */
export interface DocsReference { where: string; slug: string; heading?: string }

/** The slim shape of the index that the check needs (docs-build.ts `DocsIndexPage`). */
export interface IndexedPage { slug: string; headings: readonly { id: string }[] }

/** `/docs/<path>/` or `/docs/<path>/#heading` as a whole quoted string; `${…}` and file names (`index.json`) never match. */
const ADDRESS = /(["'`])\/docs\/([a-z0-9][a-z0-9/-]*)?(?:\/)?(?:#([A-Za-z0-9_-]+))?\1/g;
/** A Settings catalog entry's anchor: `docs: { page: "…", heading: "…" }`. */
const CATALOG = /\bdocs:\s*\{\s*page:\s*"([^"]+)"(?:\s*,\s*heading:\s*"([^"]+)")?/g;
/** A link in a rendered docs page. */
const HREF = /\shref="\/docs\/([a-z0-9][a-z0-9/-]*)?\/?(?:#([^"]+))?"/g;

const lineOf = (text: string, offset: number): number => text.slice(0, offset).split("\n").length;
/** The front page is `index` in the index and `/docs/` in an address. */
const slugOf = (path: string | undefined): string => path?.replace(/\/$/, "") || "index";

/** Every docs address one source file names. Pure, so it is tested on strings. */
export function referencesInSource(file: string, source: string): DocsReference[] {
  const found: DocsReference[] = [];
  for (const match of source.matchAll(ADDRESS)) found.push({ where: `${file}:${lineOf(source, match.index)}`, slug: slugOf(match[2]), ...(match[3] ? { heading: match[3] } : {}) });
  for (const match of source.matchAll(CATALOG)) found.push({ where: `${file}:${lineOf(source, match.index)}`, slug: slugOf(match[1]), ...(match[2] ? { heading: match[2] } : {}) });
  return found;
}

/** The links of one rendered page to docs pages (to its own headings too, as `#heading` links have no address and are not listed). */
export function referencesInPage(slug: string, html: string): DocsReference[] {
  return [...html.matchAll(HREF)].map((match) => ({ where: `page ${slug}`, slug: slugOf(match[1]), ...(match[2] ? { heading: decodeURIComponent(match[2]) } : {}) }));
}

/**
 * What is wrong with the references, in words for the person who wrote them. `moved` maps a former slug to where its page lives now.
 * An empty list means every reference lands on a page that exists, and on a heading that exists when it names one.
 */
export function checkReferences(references: readonly DocsReference[], pages: readonly IndexedPage[], moved: ReadonlyMap<string, string>): string[] {
  const bySlug = new Map(pages.map((page) => [page.slug, page]));
  const problems: string[] = [];
  for (const reference of references) {
    const address = `/docs/${reference.slug === "index" ? "" : `${reference.slug}/`}${reference.heading ? `#${reference.heading}` : ""}`;
    const page = bySlug.get(reference.slug);
    if (!page) {
      const now = moved.get(reference.slug);
      problems.push(now ? `${reference.where}: ${address} is the old address of ${now}; point at /docs/${now}/` : `${reference.where}: ${address} points at a page that does not exist`);
    } else if (reference.heading && !page.headings.some((heading) => heading.id === reference.heading)) {
      const known = page.headings.map((heading) => heading.id).join(", ");
      problems.push(`${reference.where}: ${address} points at a heading that does not exist; the page has: ${known}`);
    }
  }
  return problems;
}

/** The source files whose references are checked: the app and the shared components. */
export async function sourceFiles(directory: string): Promise<string[]> {
  const files: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.name === "node_modules") continue;
    const path = resolve(directory, entry.name);
    if (entry.isDirectory()) files.push(...await sourceFiles(path));
    else if (/\.(ts|svelte)$/.test(entry.name) && !/\.(test|spec)\.ts$/.test(entry.name)) files.push(path);
  }
  return files;
}

/** Reads every source file under `directories` and lists the docs addresses they name. */
export async function referencesInTree(directories: readonly string[], base: string): Promise<DocsReference[]> {
  const found: DocsReference[] = [];
  for (const directory of directories) {
    for (const file of await sourceFiles(directory)) found.push(...referencesInSource(relative(base, file), await Bun.file(file).text()));
  }
  return found;
}
