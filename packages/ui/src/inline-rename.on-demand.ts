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
 * `inlineRename` is the simple case of the same field: it replaces an element in the flow and puts it back. The account
 * card uses it. It is `beginInlineRename` with a `place`/`close` pair, never a second field.
 *
 * The gesture that starts it, `onDoubleActivate`, is double-activate.ts: it is tiny and sits with the tree that listens for it, while this
 * module (the field, where it goes, its keys) is an on-demand module (D188), loaded when a rename starts.
 */

export interface InlineRenameOptions {
  /** The name as it is now; selected on open so typing replaces it. */
  value: string;
  /** The field's accessible name, for example "Host name". */
  label: string;
  /** Extra classes for the field: a surface's own sizing. */
  className?: string;
  /** Shown while the field is empty; says what an empty value does ("Automatic name"). */
  placeholder?: string;
  /** Puts the field on screen, in place of the name or over it. */
  place(input: HTMLInputElement): void;
  /** The person saved (Enter, or left the field). Not called after Escape. */
  commit(value: string): void;
  /** The field is done: take it off screen and show the name again. Called once, after `commit`. */
  close(): void;
}

/** The handle for a rename in progress. */
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
  if (options.placeholder) input.placeholder = options.placeholder;
  input.dataset.ownsEscape = ""; // the core screen leaves this Escape to the field (an open sidebar stays open)
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

/** Options for {@link inlineRename}. */
export interface InlineRenameInFlow {
  /** The current name, selected on open. */
  value: string;
  /** The accessible name of the field ("Session name"). */
  label: string;
  /** Shown while empty; says what an empty value does ("Automatic name"). */
  placeholder?: string;
  /** Called once: the new text on Enter or blur, `undefined` on Escape. The caller decides what empty means. */
  done(value: string | undefined): void;
}

/**
 * Renames a name that sits in the flow of its parent (a line of the account card): the field takes the element's place and
 * the element comes back when it closes, so a surface that does not redraw is already right. The field takes the
 * element's font, so every list keeps its own type.
 */
export function inlineRename(target: HTMLElement, options: InlineRenameInFlow): InlineRename {
  const style = getComputedStyle(target);
  let result: string | undefined;
  let field: HTMLInputElement | undefined;
  return beginInlineRename({
    value: options.value, label: options.label, className: "ui-inline-rename-flow",
    ...(options.placeholder ? { placeholder: options.placeholder } : {}),
    place(input) {
      input.style.font = style.font;
      input.style.letterSpacing = style.letterSpacing;
      field = input;
      target.replaceWith(input);
    },
    commit(value) { result = value; },
    close() {
      if (field?.isConnected) field.replaceWith(target);
      options.done(result);
    },
  });
}

/**
 * The least room the field's text gets (layout px): about eight characters. A shorter name is given this much, so a
 * two-letter host is not renamed in a field the size of a caret.
 */
const MIN_TEXT_PX = 72;
/** How far the field's box reaches past the name's box on each side (it is also the field's own padding there). */
const FIELD_PAD_PX = 4;

/**
 * Puts the field exactly over a name that sits inside something that must not hold a field itself (a button, a
 * pill): the field is a child of `container`, which becomes the positioned parent, and the name is hidden under it
 * (it keeps its space, so nothing around it moves). `scale` is the zoom the container is drawn at. Returns what
 * `close` calls: it takes the field off and shows the name again.
 *
 * Invariant: the field never reaches beyond the name's own box by more than `FIELD_PAD_PX`. What is drawn beside a name
 * (a machine's mark, a status dot, a note, the window's actions) starts at least a gap after it, so the field cannot sit
 * under any of it, whatever the width of the name (a status dot over the last letter was the bug that made this a rule,
 * #259). The one case where the surroundings move: a name whose box is narrower than its own text in the field (a name
 * too short to type in, or a phone, where the field's text is 16 px and the name's is smaller). Its hidden box is
 * widened to the field's text width (at least `MIN_TEXT_PX`), so the pill grows by that much and its neighbours
 * follow; they never get covered. A long name is already ellipsized by its surface and stays in its box; the field
 * scrolls its text there as any field does.
 */
export function placeOverName(name: HTMLElement, container: HTMLElement, input: HTMLInputElement, scale = 1): () => void {
  const positioned = getComputedStyle(container).position !== "static";
  if (!positioned) container.style.position = "relative";
  const widened = name.style.minWidth;
  // The field's own type decides how wide its text is, so it is measured in the field's font, in the container (which
  // may be drawn at a zoom: the rect is divided by it).
  // A fine pointer types in the name's own size, so the name keeps its size and position when it becomes a field; a touch device keeps
  // the field's 16 px (below that, iOS zooms into the field).
  const nameType = getComputedStyle(name);
  const fontCss = matchMedia("(pointer: coarse)").matches ? "" : `font:${nameType.font};letter-spacing:${nameType.letterSpacing};`;
  input.style.cssText = `position:absolute;visibility:hidden;${fontCss}`;
  container.append(input);
  const type = getComputedStyle(input);
  const probe = document.createElement("span");
  probe.style.cssText = `position:absolute;visibility:hidden;white-space:pre;font-family:${type.fontFamily};font-size:${type.fontSize};font-weight:${type.fontWeight};letter-spacing:${type.letterSpacing}`;
  probe.textContent = input.value;
  container.append(probe);
  const textPx = probe.getBoundingClientRect().width / scale;
  probe.remove();
  const room = Math.max(MIN_TEXT_PX, Math.ceil(textPx));
  if (name.getBoundingClientRect().width / scale < room) name.style.minWidth = `${room}px`;
  // Measured after the widening: the layout above has moved by now.
  const at = name.getBoundingClientRect(), box = container.getBoundingClientRect();
  // The text starts where the name's text started: the field's own padding is taken back from its left edge.
  const left = (at.left - box.left) / scale - FIELD_PAD_PX;
  // Only the part of the name's box that is visible counts: a surface that clips its name (an ellipsis in a pill that
  // cannot grow) hides the rest of a widened box, and the field must stop where the clip does.
  let right = at.right;
  for (let el = name.parentElement; el && el !== container; el = el.parentElement) {
    if (getComputedStyle(el).overflowX !== "visible") right = Math.min(right, el.getBoundingClientRect().right);
  }
  // A clip that cuts the name's own room short (a pill that cannot grow, on a phone, beside a status icon) must not cut the
  // typing room too: the field takes the free room after the name, up to whatever is drawn next to it, until its text fits.
  const wanted = at.left + (textPx + 1) * scale;
  if (right < wanted) {
    let free = box.right;
    search: for (let el: HTMLElement | null = name; el && el !== container; el = el.parentElement) {
      for (let sibling = el.nextElementSibling; sibling; sibling = sibling.nextElementSibling) {
        const r = sibling.getBoundingClientRect();
        if (sibling === input || r.width < 0.5 || r.height < 0.5 || getComputedStyle(sibling).visibility === "hidden") continue;
        free = r.left - (FIELD_PAD_PX + 1) * scale; // the field's box reaches its padding and the caret pixel past `right`
        break search;
      }
    }
    right = Math.max(right, Math.min(wanted, free));
  }
  // One pixel more than the name, so the caret at the end of a name that fills the box does not scroll the text.
  const width = (right - at.left) / scale + 2 * FIELD_PAD_PX + 1;
  input.style.cssText = `${fontCss}position:absolute;z-index:calc(var(--z-content) + 1);left:${left}px;top:${(at.top - box.top + at.height / 2) / scale}px;transform:translateY(-50%);width:${width}px;padding:0 ${FIELD_PAD_PX}px;max-width:calc(100% - ${Math.max(left, 0)}px)`;
  const hidden = name.style.visibility;
  name.style.visibility = "hidden";
  return () => {
    input.remove();
    name.style.visibility = hidden;
    name.style.minWidth = widened;
    if (!positioned) container.style.position = "";
  };
}
