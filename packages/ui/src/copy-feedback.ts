/**
 * Copy feedback (DECISIONS 103): the icon turns into a tick, holds, and turns back;
 * the morph uses opacity, scale, and a subtle blur, while the tick draws on behind it.
 * One shared primitive for every such action, so copy and download confirm the same way
 * (owner: download had no feedback).
 *
 * Motion lives in the shared styles.css (`.swap`): this file only toggles
 * `data-done`. Transitions, not keyframes, so a second tap mid-way retargets from the
 * current state instead of restarting. Both glyphs share one cell; the outgoing one
 * fades, shrinks, and blurs while the incoming tick fades and grows, so the eye reads
 * one morph. The tick uses the same path as the tick primitive (DECISIONS 99) and
 * starts drawing 50 ms after the icon transition. Going back is quicker than coming in.
 */
import { TICK_PATH } from "./tick";
import { flashTip, refreshTip } from "./tooltip";

// Long enough to register, short enough to be gone before the next glance (owner:
// 1.4 s was too long).
const HOLD = 900;

// A real clipboard: a board with a clip that overlaps its top edge (geometry after
// Lucide's "clipboard", ISC licence). The earlier glyphs read as a battery and as two
// squares (owner feedback).
export const CLIPBOARD = `<rect x="8" y="2" width="8" height="4" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/>`;
// Download: an arrow landing in a tray.
export const DOWNLOAD = `<path d="M12 4v11"/><path d="M7.5 10.5L12 15l4.5-4.5"/><path d="M4.5 15.5v2A2.5 2.5 0 0 0 7 20h10a2.5 2.5 0 0 0 2.5-2.5v-2"/>`;
const TICK_ICON = `<svg class="is-done" viewBox="0 0 24 24" aria-hidden="true"><path pathLength="1" d="${TICK_PATH}"/></svg>`;

/** The whole content of an icon-only action button: its icon, with the tick behind it. */
export const swapIcon = (paths: string) => `<span class="swap"><svg class="is-idle" viewBox="0 0 24 24" aria-hidden="true">${paths}</svg>${TICK_ICON}</span>`;

/** An inline tick for text that copies (no idle glyph): it morphs in with the same motion as `swapIcon`. */
export const inlineTick = (): string => `<span class="swap ui-inline-tick" aria-hidden="true">${TICK_ICON}</span>`;

const timers = new WeakMap<HTMLElement, number>();

/** Plays the icon → tick → icon swap; keyboard activations expose the result instantly. */
export function confirmAction(button: HTMLElement, doneLabel: string, instant = false): void {
  // Text cells have no label of their own: the empty idle label restores to "no attribute".
  const idle = button.dataset.idleLabel ??= button.getAttribute("aria-label") ?? "";
  clearTimeout(timers.get(button));
  button.toggleAttribute("data-instant", instant);
  button.dataset.done = "";
  button.setAttribute("aria-label", doneLabel);
  refreshTip(button);
  timers.set(button, window.setTimeout(() => {
    delete button.dataset.done;
    button.removeAttribute("data-instant");
    if (idle) button.setAttribute("aria-label", idle); else button.removeAttribute("aria-label");
    refreshTip(button);
  }, HOLD));
}

/**
 * Copies `text` and confirms after acceptance; keyboard activation is immediate. This is the one
 * copy gesture of the product (sign-in, recovery, key/value cells, About). Elements that have no
 * tooltip of their own (a text cell) pass `tip: true` to show the shared "Copied" tooltip too.
 */
export async function copyFeedback(button: HTMLElement, text: string, instant = false, tip = false): Promise<boolean> {
  try {
    if (!navigator.clipboard) return false;
    await navigator.clipboard.writeText(text);
    confirmAction(button, "Copied", instant);
    if (tip) flashTip(button, "Copied", HOLD);
    return true;
  } catch {
    return false;
  }
}
