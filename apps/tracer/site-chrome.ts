// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The frame around every standalone page of the site: the docs, the landing page, `/install`, the releases and the changelog (#339, D388).
 *
 * One function, `sitePage`, writes the whole document, so a page's head, top bar and footer cannot drift apart. The top bar is the app's
 * capsule in miniature: the product's name on the left, a capsule in the middle that says where you are and shows the ⌘K hint, and the
 * site's links on the right. It is plain HTML and CSS (`site.css`). The only script is `doc.js`, which also copies a code block when
 * it is clicked; the page loads nothing from a third party and sets no cookie (D46).
 *
 * The docs have three audiences (D388): `/docs/user`, `/docs/admin` and `/docs/dev`. A page of the docs also gets a left column that lists
 * the pages of its audience (`sideNav`); on a narrow screen that column is one folded row, like the contents.
 *
 * The page never stops the browser's own zoom (D159): the viewport tag has no scale limit, and every length is in rem.
 */

/** Escapes text for use in HTML, including inside a double-quoted attribute. */
export const escapeHtml = (text: string): string => text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

/** The three groups of readers the docs are written for (D388). The folder name under `/docs/` is the id. */
export type Audience = "user" | "admin" | "dev";

/** What each audience is called, and the one sentence that says who it is for. */
export const AUDIENCES: Record<Audience, { label: string; blurb: string }> = {
  user: { label: "User guide", blurb: "For the people who use Infraternal: terminals, machines, the mesh and your account." },
  admin: { label: "Admin guide", blurb: "For whoever runs a server: installing, updating, rolling back and the command line." },
  dev: { label: "Developer docs", blurb: "For people who build on or contribute to Infraternal: how it is put together." },
};

/** One-word names of the audiences, for the tabs of the side column, where three full names would not fit on one row. */
const SHORT: Record<Audience, string> = { user: "User", admin: "Admin", dev: "Developer" };

/** The part of the site a page belongs to; the matching link in the top bar is marked as the current one. */
export type Area = "home" | "docs" | "install" | "releases" | "changelog";

/** One page as the side column needs it: its address under the audience, its title, and the section it sits in. */
export interface NavPage { slug: string; title: string; parent?: string; section?: true }

/** Everything `sitePage` needs to write one document. */
export interface Chrome {
  /** The `<title>` text, without the site name (it is added). */
  title: string;
  /** The page's own markup, placed inside `<main>`. */
  body: string;
  /** Where the page belongs, for the current-link mark in the top bar. */
  area: Area;
  /** The text of the capsule: where you are, such as "User guide / Multiplexer". Defaults to the title. */
  here?: string;
  /** Extra classes for `<main>`: `docs` gives the reading layout, `site` the landing and install layout. */
  main: "docs" | "site";
  /** The left column of a docs page (from `sideNav`), written inside the page's grid. */
  side?: string;
}

/** The site's links, in the order of the top bar and the footer. The `href`s are the addresses D388 names. */
const LINKS: readonly { area: Area; href: string; label: string }[] = [
  { area: "docs", href: "/docs/", label: "Docs" },
  { area: "install", href: "/install/", label: "Install" },
  { area: "releases", href: "/releases/", label: "Releases" },
  { area: "changelog", href: "/changelog/", label: "Changelog" },
];

/** The magnifier of the ⌘K hint: drawn as a line icon on the app's stroke width. */
const SEARCH_ICON = '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="4.5"/><path d="m10.5 10.5 3 3"/></svg>';
/** The two-line "menu" icon of the phone's link button. */
const MENU_ICON = '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M3 5.5h10M3 10.5h10"/></svg>';

/** The capsule text: "Area / Page" keeps the area in its own span, so a phone can show the page title alone. */
function placeName(here: string): string {
  const cut = here.lastIndexOf(" / ");
  return cut < 0 ? escapeHtml(here) : `<span class="bar-area">${escapeHtml(here.slice(0, cut))} / </span>${escapeHtml(here.slice(cut + 3))}`;
}

/**
 * The top bar. Three tracks like the app's: the name, the capsule, the links. On a phone the links fold into one button
 * (`<details>`, so it needs no script) and the capsule keeps the place name and the ⌘K hint. The hint is a label, not a button: nothing
 * would happen when it is pressed yet, and a control that does nothing is not shown (TASTE, "No dead buttons").
 */
function topBar(here: string, area: Area): string {
  const link = (entry: (typeof LINKS)[number]): string => `<a href="${entry.href}"${entry.area === area ? ' aria-current="page"' : ""}>${entry.label}</a>`;
  return `<header class="bar"><div class="bar-in">
<a class="pill bar-brand" href="/">infraternal</a>
<div class="pill bar-capsule"><span class="bar-here">${placeName(here)}</span><span class="bar-kbd" aria-label="Search is opened with Command K">${SEARCH_ICON}<kbd>⌘K</kbd></span></div>
<nav class="bar-end" aria-label="Site"><div class="pill bar-links">${LINKS.map(link).join("")}</div><details class="bar-menu"><summary class="pill" aria-label="Menu">${MENU_ICON}</summary><div class="pill bar-sheet">${LINKS.map(link).join("")}</div></details></nav>
</div></header>`;
}

/** The footer: the site's links again, the licence of the pages (D388: AGPL-3.0-only, in the footer), and where the source lives. */
function footer(): string {
  return `<footer class="foot"><div class="foot-in">
<nav aria-label="Footer">${LINKS.map((entry) => `<a href="${entry.href}">${entry.label}</a>`).join("")}<a href="https://github.com/kaygdotorg/infraternal">Source</a></nav>
<p>The text and pictures of these pages are licensed AGPL-3.0-only. This site sets no cookies and loads nothing from other sites.</p>
</div></footer>`;
}

/** Writes one complete document. Every standalone page goes through here. */
export function sitePage(chrome: Chrome): string {
  const here = chrome.here ?? chrome.title;
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#101113" media="(prefers-color-scheme: dark)">
<meta name="theme-color" content="#f6f6f4" media="(prefers-color-scheme: light)">
<title>${escapeHtml(chrome.title)} · Infraternal</title>
<link rel="icon" href="/docs/icons/light.svg" type="image/svg+xml" media="(prefers-color-scheme: light)">
<link rel="icon" href="/docs/icons/dark.svg" type="image/svg+xml" media="(prefers-color-scheme: dark)">
<link rel="icon" href="/docs/icons/dark-32.png" type="image/png" sizes="32x32">
<link rel="apple-touch-icon" href="/docs/icons/apple-touch-icon.png" sizes="180x180">
<link rel="stylesheet" href="/docs/docs.css">
<link rel="stylesheet" href="/docs/doc.css">
<link rel="stylesheet" href="/docs/site.css">
<script src="/docs/doc.js" defer></script>
</head><body>
${topBar(here, chrome.area)}
<main class="${chrome.main}">
${chrome.side ? `<div class="docs-grid">\n${chrome.side}\n<div class="docs-col">\n${chrome.body}</div>\n</div>` : chrome.body}</main>
${footer()}
</body></html>
`;
}

/** A nested list of the pages: each section with the pages inside it. `current` is the slug being read, marked as the current page. */
function pageTree(base: string, pages: readonly NavPage[], current: string): string {
  const row = (page: NavPage): string => `<a href="${base}/${page.slug}/"${page.slug === current ? ' aria-current="page"' : ""}>${escapeHtml(page.title)}</a>`;
  const tops = pages.filter((page) => page.parent === undefined);
  return `<ul>${tops.map((top) => {
    const kids = pages.filter((page) => page.parent === top.slug);
    return `<li>${row(top)}${kids.length ? `<ul>${kids.map((kid) => `<li>${row(kid)}</li>`).join("")}</ul>` : ""}</li>`;
  }).join("")}</ul>`;
}

/**
 * The left column of a docs page: the three audiences as tabs, then the pages of the one being read. It is written twice and CSS shows
 * one, like the contents (`tocFor` in docs-build.ts): a folded row on a narrow screen, a sticky column where the page is wide.
 */
export function sideNav(audience: Audience, pages: readonly NavPage[], current: string): string {
  const tabs = (Object.keys(AUDIENCES) as Audience[]).map((id) => `<a href="/docs/${id}/"${id === audience ? ' aria-current="true"' : ""}>${SHORT[id]}</a>`).join("");
  const list = pageTree(`/docs/${audience}`, pages, current);
  return `<nav class="side" aria-label="Docs"><details class="side-fold"><summary>${AUDIENCES[audience].label}</summary><div class="side-tabs">${tabs}</div>${list}</details><div class="side-rail"><div class="side-tabs">${tabs}</div>${list}</div></nav>`;
}
