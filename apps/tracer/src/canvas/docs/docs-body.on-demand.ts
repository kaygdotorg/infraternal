// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The body of a window in the Docs view (#302): one docs page, read inside the canvas.
 *
 * The Docs view (views/docs.ts) has a window of kind `docs` for each page, tiled like Settings. This file is what goes inside such a
 * window. The body is `/docs/<section>/<page>/fragment.html`, the page the docs build rendered without its chrome (docs-build.ts: summary,
 * table of contents, text, footer), set in `docs-reader.css` and `doc.css` with the app's own colours and type scale, so it follows
 * the theme the person picked. The window scrolls by itself. The table of contents is a sticky column when the window is wide and a
 * folded row when it is not (doc.css decides by the window's width).
 *
 * Links inside a page stay in the canvas: a link to a heading scrolls this window, a link to another docs page flies to that page's
 * window, and anything else opens a new tab.
 *
 * Loaded when a docs window first comes near the screen (views/body.ts), or when a page is opened from the palette; it is never part
 * of the canvas chunk. The page itself is fetched when its window is drawn, so a Docs view nobody visits costs nothing.
 */
import type { Ctx } from "../context";
import { enhanceDoc } from "./doc-enhance";

/** A docs page drawn in a window: its scroller, its article, and a promise that settles when the page text has loaded. */
interface Mounted { scroller: HTMLElement; article: HTMLElement; ready: Promise<void> }
/** The docs pages that are drawn now, by slug. */
const mounted = new Map<string, Mounted>();
/** A heading asked for before the window had its page: applied as soon as it has. */
const wanted = new Map<string, string | undefined>();
/** The stylesheet load, shared so the files are linked once. */
let style: Promise<void> | undefined;
/** Space in pixels left above a heading when the page scrolls to it. */
const HEADING_AIR = 12;

/** Links the reader's two stylesheets once; a missing file must not stop the page from showing. */
function loadStyle(): Promise<void> {
  style ??= Promise.all(["./docs-reader.css", "/docs/doc.css"].map((href) => new Promise<void>((resolve) => {
    const link = Object.assign(document.createElement("link"), { rel: "stylesheet", href });
    link.addEventListener("load", () => resolve(), { once: true });
    link.addEventListener("error", () => resolve(), { once: true });
    document.head.append(link);
  }))).then(() => undefined);
  return style;
}

/** Scrolls the window's own scroller so the heading is at its top. Never `scrollIntoView`: that would move the canvas. */
function goTo(page: Mounted, id: string | undefined): void {
  const target = id ? page.article.querySelector<HTMLElement>(`#${CSS.escape(id)}`) : null;
  // A little air above the heading, so it never touches the window's header pill.
  page.scroller.scrollTop = target ? Math.max(0, target.offsetTop - HEADING_AIR) : 0;
}

/** Scrolls the page of `slug` to a heading (or to its top), as soon as that page is in its window. */
export function showHeading(slug: string, id: string | undefined): void {
  const page = mounted.get(slug);
  if (page) void page.ready.then(() => goTo(page, id));
  else wanted.set(slug, id);
}

/** Goes to a page of the Docs view: its window is focused and fully in view (the camera settles on it), at the heading if one is given. */
export function openDocsPage(cx: Ctx, slug: string, heading: string | undefined): boolean {
  const rec = cx.views.get("docs")?.wins.get(`d-${slug}`);
  if (!rec) return false;
  showHeading(slug, heading);
  cx.win.setActive(rec);
  cx.nav.focusWindow(rec);
  return true;
}

/**
 * Decides what a click on a link inside a docs page does. A heading link scrolls this window; a link to another docs page that has a window flies
 * to that window; any other link opens in a new tab. Modified clicks (command, control, shift or a non-primary button) are left to the browser.
 */
function keepInCanvas(cx: Ctx, slug: string, page: Mounted, event: MouseEvent): void {
  const link = (event.target as Element | null)?.closest<HTMLAnchorElement>("a[href]");
  if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey) return;
  const href = link.getAttribute("href") ?? "";
  if (href.startsWith("#")) { event.preventDefault(); goTo(page, decodeURIComponent(href.slice(1))); return; }
  const docs = /^\/docs\/([a-z0-9/-]*?)\/?(?:#(.+))?$/.exec(href);
  const target = docs ? docs[1] || "index" : undefined;
  if (docs && target && target !== slug && cx.views.get("docs")?.wins.has(`d-${target}`)) {
    event.preventDefault();
    openDocsPage(cx, target, docs[2] ? decodeURIComponent(docs[2]) : undefined);
    return;
  }
  link.target = "_blank";
  link.rel = "noopener noreferrer";
}

/** Draws the page of `slug` into a docs window's body. Returns what to run when the window goes away. */
export function mountDocsBody(cx: Ctx, slug: string, body: HTMLElement): () => void {
  const scroller = document.createElement("div");
  scroller.className = "dr-scroll";
  const article = document.createElement("article");
  article.className = "dr-page";
  scroller.append(article);
  body.append(scroller);
  let gone = false;
  const ready = (async () => {
    try {
      const [, response] = await Promise.all([loadStyle(), fetch(`/docs/${slug.split("/").map(encodeURIComponent).join("/")}/fragment.html`)]);
      if (!response.ok) throw new Error(String(response.status));
      const html = await response.text();
      if (gone) return;
      // The fragment is this build's own static output (docs-build.ts), served from the same origin.
      article.innerHTML = html;
    } catch {
      if (!gone) cx.toast.show({ message: "The page couldn't load. Check your connection and try again.", tone: "error" });
    }
  })();
  const page: Mounted = { scroller, article, ready };
  mounted.set(slug, page);
  // The section being read in the contents, and copying code (doc-enhance.ts); started when the page is in the window.
  let stopEnhancing = (): void => {};
  void ready.then(() => { if (!gone) stopEnhancing = enhanceDoc(article, scroller); });
  const onClick = (event: MouseEvent): void => keepInCanvas(cx, slug, page, event);
  article.addEventListener("click", onClick);
  if (wanted.has(slug)) { const id = wanted.get(slug); wanted.delete(slug); showHeading(slug, id); }
  return () => {
    gone = true;
    stopEnhancing();
    article.removeEventListener("click", onClick);
    if (mounted.get(slug) === page) mounted.delete(slug);
    scroller.remove();
  };
}
