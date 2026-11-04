// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The two things a docs page does once it is on screen (#302): it marks the section being read in the table of contents, and it
 * lets a code block be copied.
 *
 * One module for both places a page lives. The standalone page runs it from `doc.js` (doc-page.ts, deferred, scrolling with the
 * window); the canvas reader runs it on the window's own scroller (docs-body.on-demand.ts). Neither adds to the app's critical
 * JavaScript: the first is a separate file, the second an on-demand chunk.
 *
 * Reading position. The current section is the last heading whose top has passed a line a little under the top of the scroller;
 * at the very end of the page it is the last heading, so a short last section is not unreachable. It is written as
 * `aria-current="location"` on every contents link to that heading (the folded row and the side rail both), which is also what
 * a screen reader announces and what the stylesheet highlights. Scrolling is read in one animation frame at most, and only layout
 * reads happen in it, so a page of any length stays cheap. A rail taller than the window follows the highlight by scrolling
 * itself: never `scrollIntoView`, which would move the canvas camera.
 *
 * Figures. A figure (docs-figure.ts) is a picture of the product and, sometimes, a clip. In the standalone page the browser picks
 * the picture by the window's width and the reader's colour scheme (the markup's `<source media>`); in a canvas window the page is
 * as wide as the window and the scheme is the app theme's, so `chooseFigures` rewrites those `media` conditions to the matching
 * size and scheme and follows the window and the theme as they change. A clip is a muted looping video laid over the picture,
 * created when the figure first comes on screen, playing only while it is on screen, and never under reduced motion or a
 * data-saving connection: the still is already there.
 *
 * Copying. A click on a code block copies it when no text is selected (a drag selects, as always); on touch it takes a double tap,
 * because one tap is how a finger starts a scroll; Enter copies a focused block. The confirmation is the shared one for text that
 * copies (copy-feedback.ts `copyTextInPlace`): the code fades and "Copied" takes its place. There is no copy button (TASTE:
 * copy without buttons).
 */
import { copyTextInPlace } from "../../../../../packages/ui/src/copy-feedback";

/** How far under the scroller's top a heading counts as "being read" (px). */
const LINE = 64;
/** Two taps this close (ms) on the same block are a double tap. */
const DOUBLE_TAP = 350;
/** A canvas window narrower than this (CSS px) gets the phone pictures. */
const PHONE_WINDOW = 520;

/** True when the page is drawn in a dark scheme: the app theme's, or the browser's when the page does not say. */
function darkScheme(): boolean {
  const scheme = getComputedStyle(document.documentElement).colorScheme;
  return scheme === "dark" ? true : scheme === "light" ? false : window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/**
 * Starts the reading marker, the figure choice and the click-to-copy on a docs page. `root` is the page; `scroller` is the element that scrolls it,
 * or `null` when the whole window scrolls. Returns the function that stops all of it.
 */
export function enhanceDoc(root: HTMLElement, scroller: HTMLElement | null): () => void {
  const headings = [...root.querySelectorAll<HTMLElement>(".doc-body h2[id], .doc-body h3[id]")];
  const links = new Map<string, HTMLAnchorElement[]>();
  for (const link of root.querySelectorAll<HTMLAnchorElement>(".toc a[href^='#']")) {
    const id = decodeURIComponent(link.getAttribute("href")!.slice(1));
    const list = links.get(id) ?? [];
    list.push(link);
    links.set(id, list);
  }
  const rail = root.querySelector<HTMLElement>(".toc");
  let current: string | undefined;
  let frame = 0;

  const update = (): void => {
    frame = 0;
    const top = scroller ? scroller.getBoundingClientRect().top : 0;
    const scrolled = scroller ? scroller.scrollTop : window.scrollY;
    const room = scroller ? scroller.scrollHeight - scroller.clientHeight : document.documentElement.scrollHeight - window.innerHeight;
    let id: string | undefined;
    for (const heading of headings) {
      if (heading.getBoundingClientRect().top - top > LINE) break;
      id = heading.id;
    }
    if (scrolled > 0 && room > 4 && scrolled >= room - 2 && headings.length > 0) id = headings.at(-1)!.id;
    if (id === current) return;
    for (const link of links.get(current ?? "") ?? []) link.removeAttribute("aria-current");
    current = id;
    for (const link of links.get(id ?? "") ?? []) link.setAttribute("aria-current", "location");
    // Keep the highlighted entry inside a rail that scrolls (a long page on a short window).
    const entry = (links.get(id ?? "") ?? []).find((link) => link.closest(".toc-side"));
    if (rail && entry && rail.scrollHeight > rail.clientHeight) {
      const box = rail.getBoundingClientRect();
      const at = entry.getBoundingClientRect();
      if (at.top < box.top) rail.scrollTop += at.top - box.top;
      else if (at.bottom > box.bottom) rail.scrollTop += at.bottom - box.bottom;
    }
  };
  const schedule = (): void => { if (!frame) frame = requestAnimationFrame(update); };
  const target: HTMLElement | Window = scroller ?? window;
  target.addEventListener("scroll", schedule, { passive: true });
  window.addEventListener("resize", schedule);
  schedule();
  // Headings move when the page font arrives; read the position again then.
  void document.fonts?.ready.then(schedule);

  // ---- figures ----
  const figures = [...root.querySelectorAll<HTMLElement>(".figure")];
  const inWindow = scroller !== null;
  const phone = (): boolean => (inWindow ? root.clientWidth < PHONE_WINDOW : window.matchMedia("(max-width: 36rem)").matches);
  const variant = (): { size: "phone" | "desktop"; scheme: "ink" | "paper" } => ({ size: phone() ? "phone" : "desktop", scheme: darkScheme() ? "ink" : "paper" });
  const clips = new Map<HTMLElement, HTMLVideoElement>();
  const motion = !window.matchMedia("(prefers-reduced-motion: reduce)").matches && !(navigator as { connection?: { saveData?: boolean } }).connection?.saveData;
  const chooseFigures = (): void => {
    const { size, scheme } = variant();
    for (const figure of figures) {
      if (inWindow) {
        // The chosen source matches always, the others never; the browser takes the first match, as it does in a page.
        for (const source of figure.querySelectorAll<HTMLSourceElement>("picture source")) source.media = source.srcset.includes(`.${size}.${scheme}.`) ? "all" : "not all";
        const chosen = figure.querySelector<HTMLSourceElement>('picture source[media="all"]');
        if (chosen) { const img = figure.querySelector("img")!; img.width = Number(chosen.getAttribute("width")); img.height = Number(chosen.getAttribute("height")); }
      }
      const video = clips.get(figure);
      const template = figure.dataset.clip;
      if (video && template) {
        const src = template.replace("{size}", size).replace("{scheme}", scheme);
        if (!video.src.endsWith(src)) { video.src = src; video.poster = figure.querySelector("img")?.currentSrc ?? ""; }
      }
    }
  };
  const startClip = (figure: HTMLElement): HTMLVideoElement => {
    const video = document.createElement("video");
    video.className = "figure-clip";
    video.muted = true; video.loop = true; video.playsInline = true; video.preload = "auto"; video.setAttribute("aria-hidden", "true"); video.tabIndex = -1;
    video.addEventListener("playing", () => { video.dataset.playing = ""; });
    figure.querySelector(".figure-media")!.append(video);
    clips.set(figure, video);
    chooseFigures();
    return video;
  };
  const watcher = motion && "IntersectionObserver" in window ? new IntersectionObserver((entries) => {
    for (const entry of entries) {
      const figure = entry.target as HTMLElement;
      if (entry.isIntersecting) void (clips.get(figure) ?? startClip(figure)).play().catch(() => {});
      else clips.get(figure)?.pause();
    }
  }, { threshold: 0.4 }) : undefined;
  for (const figure of figures) if (figure.dataset.clip && watcher) watcher.observe(figure);
  chooseFigures();
  // The window and the theme change under the page: its width, and the colour scheme the app sets on the root.
  const resize = inWindow && "ResizeObserver" in window ? new ResizeObserver(chooseFigures) : undefined;
  resize?.observe(root);
  const theme = new MutationObserver(chooseFigures);
  theme.observe(document.documentElement, { attributes: true, attributeFilter: ["style", "data-theme"] });
  const scheme = window.matchMedia("(prefers-color-scheme: dark)");
  scheme.addEventListener("change", chooseFigures);

  // ---- copying ----
  let pointer = "mouse";
  let lastTap = 0;
  let lastBlock: Element | null = null;
  const blockOf = (event: Event): HTMLElement | null => {
    const block = (event.target as Element | null)?.closest<HTMLElement>(".doc-code") ?? null;
    return block && root.contains(block) ? block : null;
  };
  const copy = (block: HTMLElement, instant: boolean): void => {
    void copyTextInPlace(block, (block.querySelector("pre")?.textContent ?? "").replace(/\n$/, ""), instant);
  };
  const onPointerDown = (event: PointerEvent): void => { pointer = event.pointerType; };
  const onClick = (event: MouseEvent): void => {
    const block = blockOf(event);
    if (!block || !(window.getSelection()?.isCollapsed ?? true)) return;
    if (pointer === "touch") {
      const double = lastBlock === block && event.timeStamp - lastTap < DOUBLE_TAP;
      lastBlock = block;
      lastTap = double ? 0 : event.timeStamp;
      if (!double) return;
    }
    copy(block, false);
  };
  const onKey = (event: KeyboardEvent): void => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const block = blockOf(event);
    if (!block || event.target !== block.querySelector("pre")) return;
    event.preventDefault();
    copy(block, true);
  };
  root.addEventListener("pointerdown", onPointerDown);
  root.addEventListener("click", onClick);
  root.addEventListener("keydown", onKey);

  return () => {
    watcher?.disconnect();
    resize?.disconnect();
    theme.disconnect();
    scheme.removeEventListener("change", chooseFigures);
    for (const video of clips.values()) { video.pause(); video.removeAttribute("src"); video.load(); video.remove(); }
    if (frame) cancelAnimationFrame(frame);
    target.removeEventListener("scroll", schedule);
    window.removeEventListener("resize", schedule);
    root.removeEventListener("pointerdown", onPointerDown);
    root.removeEventListener("click", onClick);
    root.removeEventListener("keydown", onKey);
  };
}
