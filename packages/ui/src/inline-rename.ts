/**
 * Renaming a name where it stands (TASTE "Edit in place"): the text becomes a field with the same type, Enter saves,
 * Escape cancels, a press elsewhere saves. The caller decides what an empty value means (the sidebar and the session
 * manager restore the automatic name). The field replaces `target` while it is open and the target comes back when it
 * closes, so a surface that does not redraw (a host's caption) is already right; one that redraws simply replaces it.
 *
 * The field takes its font from the text it replaces, so every list keeps its own type; its look (a quiet fill, no border,
 * no ring) is `.ui-rename-input` in styles.css. Keys inside it never reach the row, the window or the canvas.
 */
export interface InlineRenameOptions {
  /** The current name, selected on open. */
  value: string;
  /** The accessible name of the field ("Session name"). */
  label: string;
  /** Shown while empty; says what an empty value does ("Automatic name"). */
  placeholder?: string;
  /** Called once: the new text on Enter or blur, `undefined` on Escape. */
  done(value: string | undefined): void;
}

export interface InlineRename { readonly input: HTMLInputElement; cancel(): void }

export function inlineRename(target: HTMLElement, options: InlineRenameOptions): InlineRename {
  const input = document.createElement("input");
  input.className = "ui-rename-input";
  input.dataset.ownsEscape = ""; // the core screen leaves this Escape to the field (an open sidebar stays open)
  input.value = options.value;
  input.setAttribute("aria-label", options.label);
  if (options.placeholder) input.placeholder = options.placeholder;
  input.spellcheck = false;
  input.autocomplete = "off";
  const style = getComputedStyle(target);
  input.style.font = style.font;
  input.style.letterSpacing = style.letterSpacing;
  target.replaceWith(input);
  input.focus({ preventScroll: true });
  input.select();
  let finished = false;
  const finish = (commit: boolean): void => {
    if (finished) return;
    finished = true;
    window.removeEventListener("keydown", onKey, true);
    if (input.isConnected) input.replaceWith(target);
    options.done(commit ? input.value : undefined);
  };
  // In the capture phase on the window, so keys typed in the field never reach a row, a window or the canvas.
  const onKey = (event: KeyboardEvent): void => {
    if (event.target !== input) return;
    event.stopPropagation();
    if (event.key === "Enter") { event.preventDefault(); finish(true); }
    else if (event.key === "Escape") { event.preventDefault(); finish(false); }
  };
  window.addEventListener("keydown", onKey, true);
  input.addEventListener("blur", () => finish(true));
  return { input, cancel: () => finish(false) };
}
