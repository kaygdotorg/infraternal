// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Reads a docs page inside the canvas (#302): a window of kind `flow`, made by the same flow host the add-host
 * wizard uses, so it has the one window frame, header pill, close button and tiling of every other window and is
 * never saved to the canvas document.
 *
 * The body is `/docs/<slug>/fragment.html`, the page the docs build rendered without its chrome, set in
 * `docs-reader.css` with the app's own colours and type scale (the standalone pages follow the system scheme; this one
 * follows the theme the person picked). One window per page: opening a page that is already open brings its window
 * into view and goes to the heading. Links inside a page stay in the canvas: a heading link scrolls the window, a link to
 * another docs page opens that page, anything else opens a new tab.
 *
 * Loaded when a page is first opened; it is never part of the canvas chunk.
 */
import type { FlowHost, FlowSurface } from "../addhost/flow-host";
import type { DocsIndexPage } from "./docs-source";

export interface DocsReaderEnv {
  host: FlowHost;
  pages: readonly DocsIndexPage[];
  /** A plain-words failure for the shared toast. */
  say(message: string): void;
}

interface OpenPage { surface: FlowSurface; scroller: HTMLElement; article: HTMLElement }
const open = new Map<string, OpenPage>();
let style: Promise<void> | undefined;
const HEADING_AIR = 12;

/** Links the reader's stylesheet once; a missing file must not stop the page from showing. */
function loadStyle(): Promise<void> {
  style ??= new Promise((resolve) => {
    const link = Object.assign(document.createElement("link"), { rel: "stylesheet", href: "./docs-reader.css" });
    link.addEventListener("load", () => resolve(), { once: true });
    link.addEventListener("error", () => resolve(), { once: true });
    document.head.append(link);
  });
  return style;
}

/** Scrolls the window's own scroller so the heading is at its top. Never `scrollIntoView`: that would move the canvas. */
function goTo(page: OpenPage, id: string | undefined): void {
  const target = id ? page.article.querySelector<HTMLElement>(`#${CSS.escape(id)}`) : null;
  // A little air above the heading, so it never touches the window's header pill.
  page.scroller.scrollTop = target ? Math.max(0, target.offsetTop - HEADING_AIR) : 0;
}

function keepInCanvas(env: DocsReaderEnv, page: OpenPage, event: MouseEvent): void {
  const link = (event.target as Element | null)?.closest<HTMLAnchorElement>("a[href]");
  if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return;
  const href = link.getAttribute("href") ?? "";
  if (href.startsWith("#")) { event.preventDefault(); goTo(page, decodeURIComponent(href.slice(1))); return; }
  const docs = /^\/docs\/([^/#?]+)\/?(?:#(.+))?$/.exec(href);
  const target = docs && env.pages.find((entry) => entry.slug === docs[1]);
  if (target) { event.preventDefault(); void openDocsPage(env, target, docs[2] ? decodeURIComponent(docs[2]) : undefined); return; }
  link.target = "_blank";
  link.rel = "noopener noreferrer";
}

export async function openDocsPage(env: DocsReaderEnv, entry: DocsIndexPage, heading: string | undefined): Promise<void> {
  const existing = open.get(entry.slug);
  if (existing) { existing.surface.reveal?.(); goTo(existing, heading); return; }
  let html: string;
  try {
    const [, response] = await Promise.all([loadStyle(), fetch(`/docs/${encodeURIComponent(entry.slug)}/fragment.html`)]);
    if (!response.ok) throw new Error(String(response.status));
    html = await response.text();
  } catch {
    env.say("The page couldn't load. Check your connection and try again.");
    return;
  }
  // A second request that raced the first one: the window is already there.
  const raced = open.get(entry.slug);
  if (raced) { raced.surface.reveal?.(); goTo(raced, heading); return; }
  const surface = env.host.open({ title: entry.title });
  const scroller = document.createElement("div");
  scroller.className = "dr-scroll";
  const article = document.createElement("article");
  article.className = "dr-page";
  // The fragment is this build's own static output (docs-build.ts), served from the same origin.
  article.innerHTML = html;
  scroller.append(article);
  surface.body.replaceChildren(scroller);
  const page: OpenPage = { surface, scroller, article };
  open.set(entry.slug, page);
  article.addEventListener("click", (event) => keepInCanvas(env, page, event));
  surface.onGone?.(() => { if (open.get(entry.slug) === page) open.delete(entry.slug); });
  surface.reveal?.();
  goTo(page, heading);
}
