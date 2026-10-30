// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Renaming in place (#259): a name turns into a one-line field. Enter saves, Escape cancels, leaving the field saves.
 * Every surface that renames something where it is listed (a session row, a Mesh host's card, a host in the Views
 * tree) uses this, so the keys and the focus behave the same everywhere (D160).
 *
 * The surface decides where the field goes (`place`) and what happens on screen afterwards (`close`); this module
 * owns the field itself and its keys:
 * - Keys typed in the field never reach the shortcuts and the canvas behind it (`stopPropagation` on keydown).
 * - A rename ends exactly once: Enter then the blur that follows it must not save twice.
 * - `commit` gets the raw text. Trimming, "unchanged" and "empty" are the surface's call, because only it knows what
 *   a name may be and what an unchanged name means there.
 *
 * `onDoubleActivate` is the gesture that starts it: a double click with a mouse, a double tap with a finger or pen.
 * Touch needs its own detection: a double tap is not reliably a `dblclick` on every phone browser, and the browser's
 * own double-tap zoom must not run on the name (`touch-action: manipulation`).
 */

export interface InlineRenameOptions {
  /** The name as it is now; selected on open so typing replaces it. */
  value: string;
  /** The field's accessible name, for example "Host name". */
  label: string;
  /** Extra classes for the field: a surface's own sizing. */
  className?: string;
  /** Puts the field on screen, in place of the name or over it. */
  place(input: HTMLInputElement): void;
  /** The person saved (Enter, or left the field). Not called after Escape. */
  commit(value: string): void;
  /** The field is done: take it off screen and show the name again. Called once, after `commit`. */
  close(): void;
}

export interface InlineRename {
  readonly input: HTMLInputElement;
  /** Ends the rename as if Enter (`true`) or Escape (`false`) was pressed. */
  finish(commit: boolean): void;
}

/** Opens the field and focuses it with its text selected. Keyboard focus is taken without scrolling the page. */
export function beginInlineRename(options: InlineRenameOptions): InlineRename {
  const input = document.createElement("input");
  input.className = `ui-inline-rename${options.className ? ` ${options.className}` : ""}`;
  input.type = "text";
  input.value = options.value;
  input.setAttribute("aria-label", options.label);
  input.spellcheck = false;
  input.autocomplete = "off";
  input.autocapitalize = "off";
  options.place(input);
  input.focus({ preventScroll: true });
  input.select();
  let done = false;
  const finish = (commit: boolean): void => {
    if (done) return;
    done = true;
    if (commit) options.commit(input.value);
    options.close();
  };
  input.addEventListener("keydown", (event) => {
    event.stopPropagation();
    if (event.isComposing) return; // Enter that picks an input-method candidate is not a save
    if (event.key === "Enter") { event.preventDefault(); finish(true); }
    else if (event.key === "Escape") { event.preventDefault(); finish(false); }
  });
  input.addEventListener("blur", () => finish(true));
  // The surface's own gestures (a drag on a card, a row's swipe or press) must not start from inside the field.
  input.addEventListener("pointerdown", (event) => event.stopPropagation());
  input.addEventListener("dblclick", (event) => event.stopPropagation());
  return { input, finish };
}

/** A second tap this soon after the first, and this close to it, is a double tap. */
const DOUBLE_TAP_MS = 320;
const DOUBLE_TAP_SLOP = 24;

/**
 * Calls `handler` on a double click (mouse) or a double tap (touch, pen). A tap that moved is a drag or a scroll and
 * does not count. The element opts out of the browser's double-tap zoom, so the second tap is ours.
 */
export function onDoubleActivate(target: HTMLElement, handler: (event: Event) => void, signal: AbortSignal): void {
  target.style.touchAction ||= "manipulation";
  target.addEventListener("dblclick", (event) => { event.preventDefault(); handler(event); }, { signal });
  let down: { x: number; y: number } | undefined;
  let last: { x: number; y: number; at: number } | undefined;
  target.addEventListener("pointerdown", (event) => { down = event.pointerType === "mouse" ? undefined : { x: event.clientX, y: event.clientY }; }, { signal });
  target.addEventListener("pointerup", (event) => {
    if (!down || event.pointerType === "mouse") return;
    const moved = Math.hypot(event.clientX - down.x, event.clientY - down.y) > DOUBLE_TAP_SLOP / 2;
    down = undefined;
    if (moved) { last = undefined; return; }
    const now = event.timeStamp;
    if (last && now - last.at <= DOUBLE_TAP_MS && Math.hypot(event.clientX - last.x, event.clientY - last.y) <= DOUBLE_TAP_SLOP) {
      last = undefined;
      handler(event);
    } else last = { x: event.clientX, y: event.clientY, at: now };
  }, { signal });
  target.addEventListener("pointercancel", () => { down = undefined; }, { signal });
}
