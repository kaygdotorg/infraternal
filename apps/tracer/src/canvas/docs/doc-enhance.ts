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
    if (frame) cancelAnimationFrame(frame);
    target.removeEventListener("scroll", schedule);
    window.removeEventListener("resize", schedule);
    root.removeEventListener("pointerdown", onPointerDown);
    root.removeEventListener("click", onClick);
    root.removeEventListener("keydown", onKey);
  };
}
