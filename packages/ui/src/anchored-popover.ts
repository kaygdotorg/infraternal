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
 *   is quicker (130 ms). Keyboard opens and closes are instant. Web Animations without fill leave nothing
 *   transformed at rest, so text stays crisp (TASTE section 5).
 * - At a point: `at` places it at a pointer position (a right-click) instead of under the anchor: it opens down and
 *   right of the point, flips to the other side when it would leave the screen, and is kept one inset inside the
 *   screen. The anchor then only names the thing the menu is about (it gets `aria-expanded` and the focus back).
 * - Dismissal: a press outside (the anchor toggles it itself) or Escape closes it.
 */
import { currentUiScale } from "./ui-scale";
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

export interface AnchoredPopover {
  readonly root: HTMLElement;
  /** Re-places it, for content whose size changed. */
  place(): void;
  close(source: PopoverSource): void;
}

const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";
/** The window header's padding: the gap kept between the popover and its window's edges. */
const INSET = 8;
const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Opens the popover; `onClosed` runs once it has gone. The caller fills `root` before or after. */
export function openAnchoredPopover(options: AnchoredPopoverOptions, source: PopoverSource, onClosed: () => void): AnchoredPopover {
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
  const place = (): void => {
    if (options.at) { placeAt(options.at); return; }
    const box = anchor.getBoundingClientRect();
    const host = anchor.closest(".ui-window");
    const screen = stage.getBoundingClientRect();
    // An anchor outside any window (the sidebar's footer, the "+" beside the top pill) is bounded by the screen it floats over.
    const win = host?.getBoundingClientRect() ?? screen;
    const frame = parseFloat(getComputedStyle(host ?? anchor).borderLeftWidth) || 0;
    const inset = INSET + frame;
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
  stage.append(root);
  if (source === "pointer") {
    if (reduced()) root.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: "ease" });
    else root.animate([{ opacity: 0, transform: `translateY(${above ? 4 : -4}px) scale(0.96)` }, { opacity: 1, transform: "none" }], { duration: 200, easing: EASE });
  }
  anchor.setAttribute("aria-expanded", "true");

  let closed = false;
  const events = new AbortController();
  const close = (how: PopoverSource): void => {
    if (closed) return;
    closed = true;
    events.abort();
    anchor.setAttribute("aria-expanded", "false");
    const done = (): void => { root.remove(); onClosed(); };
    if (how === "keyboard" || reduced()) { done(); return; }
    root.style.pointerEvents = "none";
    root.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: `translateY(${above ? 2 : -2}px) scale(0.98)` }],
      { duration: 130, easing: EASE, fill: "forwards" }).onfinish = done;
  };
  // A confirmation anchored inside the popover lives on the body; pressing it must not dismiss the popover.
  document.addEventListener("pointerdown", (event) => {
    const target = event.target as Element;
    if (root.contains(target) || anchor.contains(target) || target.closest?.(".ui-confirm-tip")) return;
    close("pointer");
  }, { capture: true, signal: events.signal });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || document.querySelector(".ui-confirm-tip")) return;
    event.stopPropagation();
    close("keyboard");
    anchor.focus({ preventScroll: true });
  }, { capture: true, signal: events.signal });
  window.addEventListener("resize", place, { signal: events.signal });
  window.visualViewport?.addEventListener("resize", place, { signal: events.signal });
  return { root, place, close };
}
