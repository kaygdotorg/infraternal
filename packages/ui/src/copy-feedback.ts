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
 *
 * Text that copies (a value in a key/value list) does not use the tick: `confirmInPlace` fades the text out and puts a
 * clipboard icon with "Copied" in its place (owner, 2026-11-01), and there is no tooltip for it.
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

const timers = new WeakMap<HTMLElement, number>();
const placeTimers = new WeakMap<HTMLElement, number>();

/** How long the in-place confirmation stays before the text fades back (the same hold as the icon swap). */
const PLACE_HOLD = HOLD;
/** The overlay is emptied after its fade-out, so a screen reader reads "Copied" once per copy and the node holds nothing at rest. */
const PLACE_FADE = 240;

/**
 * The confirmation for text that copies (owner, 2026-11-01): the text itself fades out and a small clipboard icon with
 * "Copied" takes its place, in the same spot, then the text fades back. No tooltip, no extra width: the cell keeps its box
 * (the text only loses opacity), and the confirmation is laid over it at the cell's own edge (`.ui-copied`, styles.css).
 *
 * Why not the tick: a tick next to the words is an icon that changes; here the words are the thing being copied, so the
 * words are what answers. Icon buttons (sign-in, recovery) keep the icon-to-tick swap above.
 *
 * Motion is transitions on opacity, so a second copy mid-way retargets; reduced motion keeps the crossfade (it is only
 * opacity) and drops the icon's small scale. A keyboard activation shows the result with no fade (`data-instant`).
 * The overlay is created on the first copy, so a list of many cells builds no extra nodes.
 */
export function confirmInPlace(cell: HTMLElement, label: string, icon: boolean, instant = false): void {
  let done = cell.querySelector<HTMLElement>(":scope > .ui-copied");
  if (!done) {
    done = document.createElement("span");
    done.className = "ui-copied";
    done.setAttribute("role", "status");
    cell.append(done);
  }
  done.replaceChildren();
  if (icon) {
    const holder = document.createElement("span");
    holder.className = "ui-copied-icon";
    holder.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${CLIPBOARD}</svg>`;
    done.append(holder);
  }
  done.append(document.createTextNode(label));
  window.clearTimeout(placeTimers.get(cell));
  cell.toggleAttribute("data-instant", instant);
  cell.dataset.copied = "";
  const overlay = done;
  placeTimers.set(cell, window.setTimeout(() => {
    delete cell.dataset.copied;
    placeTimers.set(cell, window.setTimeout(() => { cell.removeAttribute("data-instant"); overlay.replaceChildren(); }, PLACE_FADE));
  }, PLACE_HOLD));
}

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
 * Puts `text` on the clipboard. The async API exists only in secure contexts (https or
 * localhost): on a plain-http LAN origin `navigator.clipboard` is undefined, so a hidden textarea
 * and `execCommand("copy")` is the fallback. It is taken synchronously when the async API is
 * missing, so it still runs inside the user's gesture, and also after a rejected async write.
 */
export async function writeClipboard(text: string): Promise<boolean> {
  if (navigator.clipboard?.writeText) {
    try { await navigator.clipboard.writeText(text); return true; } catch { /* fall through to the legacy path */ }
  }
  return legacyCopy(text);
}

function legacyCopy(text: string): boolean {
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.setAttribute("aria-hidden", "true");
  // Off-screen but selectable; 16 px keeps iOS from zooming. Restores the focus it borrowed.
  area.style.cssText = "position:fixed;top:0;left:0;width:1px;height:1px;opacity:0;font-size:16px;pointer-events:none";
  const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const selection = document.getSelection();
  const saved = selection && selection.rangeCount ? selection.getRangeAt(0) : null;
  document.body.append(area);
  area.focus({ preventScroll: true });
  area.select();
  area.setSelectionRange(0, text.length);
  let ok = false;
  try { ok = document.execCommand("copy"); } catch { ok = false; }
  area.remove();
  if (saved && selection) { selection.removeAllRanges(); selection.addRange(saved); }
  previous?.focus({ preventScroll: true });
  return ok;
}

/**
 * Copies `text` and confirms an icon button: the icon turns into a tick (sign-in, recovery). If both clipboard paths
 * fail the warm tooltip says "Couldn't copy" instead of ticking. Keyboard activation is immediate.
 */
export async function copyFeedback(button: HTMLElement, text: string, instant = false): Promise<boolean> {
  if (await writeClipboard(text)) {
    confirmAction(button, "Copied", instant);
    return true;
  }
  flashTip(button, "Couldn't copy", HOLD);
  return false;
}

/**
 * Copies `text` and confirms a piece of text that copies (key/value cells, About): the text fades out and a clipboard
 * icon with "Copied" replaces it in place (`confirmInPlace`). If both clipboard paths fail the same spot says "Couldn't copy".
 */
export async function copyTextInPlace(cell: HTMLElement, text: string, instant = false): Promise<boolean> {
  const ok = await writeClipboard(text);
  confirmInPlace(cell, ok ? "Copied" : "Couldn't copy", ok, instant);
  return ok;
}

/**
 * Reads the clipboard. Like writing, the async API exists only in secure contexts; on a plain-http
 * origin it is missing and a page cannot read the clipboard at all, so this returns `undefined` and
 * the caller offers a paste target instead (the system paste menu fills it).
 */
export async function readClipboard(): Promise<string | undefined> {
  if (!navigator.clipboard?.readText) return undefined;
  try { return await navigator.clipboard.readText(); } catch { return undefined; }
}
