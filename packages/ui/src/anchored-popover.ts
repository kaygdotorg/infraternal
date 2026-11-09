/**
 * The anchored popover (D125, D127, D160): a floating card that opens from a window's header control and stays
 * inside that window. It is the shared placement and motion for every popover a window header opens; the
 * session manager uses it, and the details popover can adopt it.
 *
 * - Material: the caller's content sits in an `.ui-overlay-surface` (the one overlay material), so content
 *   behind it reads as soft shapes. Nothing here paints a fill of its own.
 * - Placement: under the anchor, aligned to its start or end edge, and kept one window-header inset away from
 *   the window's edges on every side, so at its maximum height the gap is the same left, right and bottom.
 *   The visible viewport and an optional bottom limit (a key tray) only ever shrink it further.
 * - Motion: a pointer open grows from the anchor (scale 0.96 → 1 with opacity, 200 ms strong ease-out); closing
 *   is quicker (130 ms). Keyboard opens and closes are instant: the popover reads the input source (input-source.ts) itself,
 *   when it opens and when it closes, so no caller passes (or can get wrong) whether a key caused it (#427). Web Animations without fill leave nothing
 *   transformed at rest, so text stays crisp (TASTE section 5).
 * - At a point: `at` places it at a pointer position (a right-click) instead of under the anchor: it opens down and
 *   right of the point, flips to the other side when it would leave the screen, and is kept one inset inside the
 *   screen. The anchor then only names the thing the menu is about (it gets `aria-expanded` and the focus back).
 * - Dismissal: a press outside (the anchor toggles it itself) or Escape closes it, and so does the anchor leaving the visible area.
 * - It moves with its anchor (TASTE: anchored popovers move with their anchor). An anchor inside a window gets its popover INSIDE that
 *   window, positioned in the window's own coordinates, so whatever moves the window moves the popover in the same frame and by the same
 *   amount: the camera's pan and zoom, a column's scroll, a layout change. Following from script is always a frame behind, and a native
 *   scroll on the compositor is behind by more; mounting it in the window cannot lag. An anchor outside any window (the sidebar's
 *   footer) floats over the screen, which does not move.
 */
import { currentUiScale } from "./ui-scale";
import { triggeredByKeyboard } from "./input-source";

/** What a caller may still want to know for its own reasons (where to put focus): which input opened a popover. Motion never takes it from here. */
export type PopoverSource = "pointer" | "keyboard";

export interface AnchoredPopoverOptions {
  /** The positioned ancestor the popover is appended to (the screen). */
  stage: HTMLElement;
  anchor: HTMLElement;
  /** Accessible name of the dialog. */
  label: string;
  /** Extra classes on the root, next to `ui-overlay-surface`. */
  className?: string;
  /** Which anchor edge the popover lines up with. Default `start`. */
  align?: "start" | "end";
  /**
   * Which side of the anchor it opens on. Default `below`. `above` is for an anchor at the bottom of its screen (the
   * sidebar's profile pill): the popover grows upward from the anchor and keeps the same gap.
   */
  side?: "below" | "above";
  /**
   * Size to the content (a short menu) instead of the full `maxWidth`; `maxWidth` still caps it. The popover is
   * measured after the caller has filled it, so call `place()` again once the rows are in.
   */
  hug?: boolean;
  maxWidth?: number;
  /** Opens at this point (client coordinates) instead of under the anchor; see the module doc. */
  at?: { x: number; y: number };
  /** The y below which the popover must not reach (a key tray's top); read on every placement. */
  bottomLimit?(): number | undefined;
}

/** The handle of an open popover: its `root` to fill, `place()` to re-measure, `close()` to dismiss. */
export interface AnchoredPopover {
  readonly root: HTMLElement;
  /** Re-places it, for content whose size changed. */
  place(): void;
  /**
   * Closes it: with a short fade after a pointer or touch, at once after a key. The argument is ignored (motion reads the input
   * source itself); it is accepted only so wrappers that still carry a source for their own focus handling keep compiling.
   */
  close(source?: PopoverSource): void;
}

const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
/** The window header's padding: the gap kept between the popover and its window's edges. */
const INSET = 8;
const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Opens the popover; `onClosed` runs once it has gone. The caller fills `root` before or after. */
export function openAnchoredPopover(options: AnchoredPopoverOptions, onClosed: () => void): AnchoredPopover {
  const { stage, anchor } = options;
  const root = document.createElement("section");
  root.className = `ui-overlay-surface ui-anchored-popover ${options.className ?? ""}`.trim();
  root.setAttribute("role", "dialog");
  root.setAttribute("aria-label", options.label);

  const above = options.side === "above";
  const placeAt = (at: { x: number; y: number }): void => {
    const screen = stage.getBoundingClientRect();
    const view = window.visualViewport;
    const right = Math.min(screen.right, view ? view.offsetLeft + view.width : innerWidth) - INSET;
    const bottom = Math.min(screen.bottom, view ? view.offsetTop + view.height : innerHeight) - INSET;
    root.style.maxWidth = `${Math.round(Math.min(options.maxWidth ?? 400, right - screen.left - INSET))}px`;
    const width = root.offsetWidth, height = root.offsetHeight;
    const left = Math.round(Math.max(screen.left + INSET, Math.min(at.x, right - width)));
    // Flips above the point when the room below is smaller than the menu and the room above is larger.
    const flip = at.y + height > bottom && at.y - screen.top > bottom - at.y;
    const top = Math.round(Math.max(screen.top + INSET, flip ? at.y - height : Math.min(at.y, bottom - height)));
    root.style.left = `${left - screen.left}px`;
    root.style.top = `${top - screen.top}px`;
    root.style.maxHeight = `${Math.max(0, Math.floor(bottom - top))}px`;
    root.style.transformOrigin = `${Math.round(at.x - left)}px ${flip ? "100%" : "0"}`;
  };
  // Inside the anchor's window, unless the popover opens upward from a screen-level anchor (see the header comment).
  const inside = above || options.at ? null : anchor.closest<HTMLElement>(".ui-window");
  const place = (): void => {
    if (options.at) { placeAt(options.at); return; }
    const box = anchor.getBoundingClientRect();
    if (inside) {
      // The window's own coordinates: `zoom` is whatever scale sits above the window (the camera), so every number below is in the
      // window's layout pixels, and the popover scales and moves with it. Positions are relative to the window's padding box.
      const hr = inside.getBoundingClientRect();
      const zoom = hr.width / inside.offsetWidth || 1;
      const frame = getComputedStyle(inside);
      const bl = parseFloat(frame.borderLeftWidth) || 0, bt = parseFloat(frame.borderTopWidth) || 0;
      const aLeft = (box.left - hr.left) / zoom - bl, aRight = (box.right - hr.left) / zoom - bl, aBottom = (box.bottom - hr.top) / zoom - bt;
      const innerW = inside.clientWidth, innerH = inside.clientHeight;
      const room = Math.min((options.maxWidth ?? 400) * currentUiScale(), innerW - INSET * 2);
      if (options.hug) { root.style.width = ""; root.style.maxWidth = `${Math.round(room)}px`; }
      const width = options.hug ? Math.min(room, root.offsetWidth) : room;
      const wanted = options.align === "end" ? aRight - width : aLeft;
      const left = Math.round(Math.max(INSET, Math.min(wanted, innerW - INSET - width)));
      const top = Math.round(aBottom + INSET);
      // The visible area only ever shrinks it (a window taller than the screen, a key tray).
      const visible = Math.min(options.bottomLimit?.() ?? Infinity, (window.visualViewport?.height ?? innerHeight) - INSET);
      const bottom = Math.min(innerH - INSET, (visible - hr.top) / zoom - bt);
      root.style.left = `${left}px`;
      if (!options.hug) root.style.width = `${Math.round(room)}px`;
      root.style.top = `${top}px`;
      root.style.maxHeight = `${Math.max(0, Math.floor(bottom - top))}px`;
      root.style.transformOrigin = `${Math.round(aLeft + (aRight - aLeft) / 2 - left)}px 0`;
      return;
    }
    const screen = stage.getBoundingClientRect();
    // An anchor outside any window (the sidebar's footer, the "+" beside the top pill) is bounded by the screen it floats over.
    const win = screen;
    const inset = INSET;
    const room = Math.min((options.maxWidth ?? 400) * currentUiScale(), win.width - inset * 2);
    if (options.hug) { root.style.width = ""; root.style.maxWidth = `${Math.round(room)}px`; }
    const width = options.hug ? Math.min(room, root.offsetWidth) : room;
    const wanted = options.align === "end" ? box.right - width : box.left;
    const left = Math.round(Math.max(win.left + inset, Math.min(wanted, win.right - inset - width)));
    root.style.left = `${left - screen.left}px`;
    if (!options.hug) root.style.width = `${Math.round(room)}px`;
    const x = Math.round(box.left + box.width / 2 - left);
    if (above) {
      const bottom = Math.round(box.top - INSET);
      const limit = Math.max(win.top + inset, screen.top + INSET);
      root.style.top = "auto";
      root.style.bottom = `${Math.round(screen.bottom - bottom)}px`;
      root.style.maxHeight = `${Math.max(0, Math.floor(bottom - limit))}px`;
      root.style.transformOrigin = `${x}px 100%`;
      return;
    }
    const top = Math.round(box.bottom + INSET);
    const bottom = Math.min(win.bottom - inset, options.bottomLimit?.() ?? screen.bottom, (window.visualViewport?.height ?? innerHeight) - INSET);
    root.style.top = `${top - screen.top}px`;
    root.style.maxHeight = `${Math.max(0, Math.floor(bottom - top))}px`;
    root.style.transformOrigin = `${x}px 0`;
  };
  // Placed before it is attached: the measurements are read while no new content is pending, so the browser
  // lays out once, after the single write below.
  place();
  (inside ?? stage).append(root);
  if (!triggeredByKeyboard()) {
    if (reduced()) root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: "ease" });
    else root.animate([{ opacity: 0, transform: `translateY(${above ? 4 : -4}px) scale(0.96)` }, { opacity: 1, transform: "none" }], { duration: 200, easing: EASE });
  }
  anchor.setAttribute("aria-expanded", "true");

  let closed = false;
  const events = new AbortController();
  const close = (): void => {
    if (closed) return;
    closed = true;
    events.abort();
    anchor.setAttribute("aria-expanded", "false");
    const done = (): void => { root.remove(); onClosed(); };
    if (triggeredByKeyboard() || reduced()) { done(); return; }
    root.style.pointerEvents = "none";
    root.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: `translateY(${above ? 2 : -2}px) scale(0.98)` }],
      { duration: 130, easing: EASE, fill: "forwards" }).onfinish = done;
  };
  // A confirmation anchored inside the popover lives on the body; pressing it must not dismiss the popover.
  document.addEventListener("pointerdown", (event) => {
    const target = event.target as Element;
    if (root.contains(target) || anchor.contains(target) || target.closest?.(".ui-confirm-tip")) return;
    close();
  }, { capture: true, signal: events.signal });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || document.querySelector(".ui-confirm-tip")) return;
    event.stopPropagation();
    close();
    anchor.focus({ preventScroll: true });
  }, { capture: true, signal: events.signal });
  window.addEventListener("resize", place, { signal: events.signal });
  window.visualViewport?.addEventListener("resize", place, { signal: events.signal });
  if (inside) {
    // A press inside the popover is not a press on the window behind it (a terminal would take focus and, on a phone, the keyboard).
    root.addEventListener("click", (event) => event.stopPropagation(), { signal: events.signal });
    // The window changing size moves the anchor within it.
    const resized = new ResizeObserver(place);
    resized.observe(inside);
    events.signal.addEventListener("abort", () => resized.disconnect());
    // The anchor leaving the visible area (the canvas panned away, the window closed) closes it: a popover with nothing to point at is clutter.
    // Only a button that WAS on screen and has left it closes the popover: one opened for a button that was never in view (a script, a test) is not dismissed by that.
    let seen = false;
    const watched = new IntersectionObserver((entries) => { for (const entry of entries) { if (entry.isIntersecting) seen = true; else if (seen) close(); } });
    watched.observe(anchor);
    events.signal.addEventListener("abort", () => watched.disconnect());
  }
  return { root, place, close };
}
