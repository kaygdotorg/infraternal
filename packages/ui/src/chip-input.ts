/**
 * A text field that turns recognised tokens into pill chips while you keep
 * typing (D160: one component, reused by every multi-value field).
 *
 * - The consumer resolves text to a chip (`resolve`). A token becomes a chip as
 *   soon as it is unambiguous (`resolve(token, false)` returns a chip), or when
 *   a delimiter ends it: space, comma or Enter (`resolve(token, true)`).
 * - Paste splits on spaces, commas and new lines; every token that resolves
 *   becomes a chip, and the rest stays in the field to fix.
 * - Backspace in an empty field first selects the last chip, then removes it.
 * - Chips wrap inside the field; the field's height follows a spring so the
 *   layout below glides instead of jumping. At rest the height is `auto`.
 * - Chips enter and leave with a short spring (scale + fade), interruptible.
 */
import { Spring } from "./spring";

export interface Chip {
  id: string;
  label: string;
  /** Static SVG markup shown before the label. */
  icon?: string;
}

export interface ChipInputOptions {
  /** Maps text to a chip; `delimited` is true when the user ended the token. */
  resolve(token: string, delimited: boolean): Chip | undefined;
  /** Called after chips change (added or removed), with the current chips. */
  onChange?(chips: Chip[]): void;
  /** Called on every keystroke with the unfinished token. */
  onToken?(token: string): void;
  /** Called on Enter with no token left to commit. */
  onSubmit?(): void;
  placeholder: string;
  label: string;
}

export interface ChipInputController {
  readonly element: HTMLElement;
  readonly input: HTMLInputElement;
  chips(): Chip[];
  add(chip: Chip): void;
  remove(id: string): void;
  has(id: string): boolean;
  /** Tries to commit the current token; returns true when it became a chip. */
  commit(): boolean;
  clearToken(): void;
  dispose(): void;
}

const reduced = (): boolean => matchMedia("(prefers-reduced-motion: reduce)").matches;
const escapeHtml = (value: string): string => value.replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[char]!));

export function mountChipInput(host: HTMLElement, options: ChipInputOptions): ChipInputController {
  const field = document.createElement("div");
  field.className = "ui-chip-field";
  const flow = document.createElement("div");
  flow.className = "ui-chip-flow";
  const input = document.createElement("input");
  input.type = "text";
  input.className = "ui-chip-text";
  input.autocomplete = "off";
  input.autocapitalize = "off";
  input.spellcheck = false;
  input.inputMode = "url";
  input.placeholder = options.placeholder;
  input.setAttribute("aria-label", options.label);
  flow.append(input);
  field.append(flow);
  host.append(field);

  const chips = new Map<string, { chip: Chip; element: HTMLElement }>();
  let armed: string | undefined;

  // Height glide: measure before and after a change, spring between, then go back to auto.
  let gliding = false;
  let goal = 0;
  const height = new Spring(0, (value) => {
    if (!gliding) return;
    field.style.height = `${value}px`;
    if (value === goal) { gliding = false; field.style.height = ""; }
  }, { visualDuration: 0.3, bounce: 0.12 });
  const glide = (change: () => void): void => {
    const from = field.getBoundingClientRect().height;
    change();
    if (reduced()) return;
    field.style.height = "";
    const to = field.getBoundingClientRect().height;
    if (Math.abs(to - from) < 0.5) return;
    if (!gliding) { gliding = true; height.set(from, true); field.style.height = `${from}px`; }
    goal = to;
    height.set(to);
  };

  const emit = (): void => {
    // With chips present the placeholder would only be clipped; the chips say what the field holds.
    input.placeholder = chips.size ? "" : options.placeholder;
    options.onChange?.([...chips.values()].map((entry) => entry.chip));
  };
  const disarm = (): void => {
    if (!armed) return;
    chips.get(armed)?.element.removeAttribute("data-armed");
    armed = undefined;
  };

  function add(chip: Chip): void {
    if (chips.has(chip.id)) return;
    const element = document.createElement("span");
    element.className = "ui-chip";
    element.dataset.chip = chip.id;
    element.innerHTML = `${chip.icon ?? ""}<span class="ui-chip-label">${escapeHtml(chip.label)}</span>
      <button class="ui-chip-remove" type="button" tabindex="-1" aria-label="Remove ${escapeHtml(chip.label)}"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="m5 5 6 6M11 5l-6 6"/></svg></button>`;
    element.querySelector("button")!.addEventListener("click", (event) => { event.preventDefault(); remove(chip.id); input.focus({ preventScroll: true }); });
    glide(() => flow.insertBefore(element, input));
    chips.set(chip.id, { chip, element });
    if (!reduced()) {
      const spring = new Spring(0, (value) => {
        if (value === 1) { element.style.transform = ""; element.style.opacity = ""; return; }
        element.style.transform = `scale(${0.86 + 0.14 * value})`;
        element.style.opacity = String(Math.min(1, Math.max(0, value)));
      }, { visualDuration: 0.26, bounce: 0.22 });
      requestAnimationFrame(() => spring.set(1));
    }
    emit();
  }

  function remove(id: string): void {
    const entry = chips.get(id);
    if (!entry) return;
    chips.delete(id);
    if (armed === id) armed = undefined;
    const drop = (): void => glide(() => entry.element.remove());
    if (reduced()) drop();
    else entry.element.animate([{ opacity: 1, transform: "scale(1)" }, { opacity: 0, transform: "scale(0.86)" }], { duration: 120, easing: "ease-out", fill: "forwards" }).onfinish = drop;
    emit();
  }

  function commitToken(token: string, delimited: boolean): boolean {
    const text = token.trim();
    if (!text) return false;
    const chip = options.resolve(text, delimited);
    if (!chip) return false;
    add(chip);
    return true;
  }

  const onInput = (): void => {
    disarm();
    const value = input.value;
    // A delimiter typed or pasted ends tokens; whatever does not resolve stays to be fixed.
    if (/[\s,]/.test(value)) {
      const parts = value.split(/[\s,]+/);
      const tail = /[\s,]$/.test(value) ? "" : parts.pop() ?? "";
      const rest = parts.filter((part) => part && !commitToken(part, true));
      input.value = [...rest, tail].filter(Boolean).join(" ") + (rest.length && !tail ? " " : "");
    }
    // An unambiguous token commits without a delimiter.
    if (input.value && !/\s/.test(input.value) && commitToken(input.value, false)) input.value = "";
    options.onToken?.(input.value.trim());
  };

  const onKeyDown = (event: KeyboardEvent): void => {
    if (event.key === "Enter") {
      event.preventDefault();
      if (input.value.trim()) {
        if (commitToken(input.value, true)) { input.value = ""; options.onToken?.(""); }
      } else options.onSubmit?.();
      return;
    }
    if (event.key === "Backspace" && input.selectionStart === 0 && input.selectionEnd === 0) {
      const last = [...chips.keys()].at(-1);
      if (!last) return;
      event.preventDefault();
      if (armed === last) remove(last);
      else { disarm(); armed = last; chips.get(last)!.element.dataset.armed = "true"; }
      return;
    }
    if (event.key !== "Shift") disarm();
  };

  const onFieldDown = (event: PointerEvent): void => {
    if (event.target === field || event.target === flow) { event.preventDefault(); input.focus({ preventScroll: true }); }
  };

  input.addEventListener("input", onInput);
  input.addEventListener("keydown", onKeyDown);
  field.addEventListener("pointerdown", onFieldDown);

  return {
    element: field,
    input,
    chips: () => [...chips.values()].map((entry) => entry.chip),
    add,
    remove,
    has: (id) => chips.has(id),
    commit() {
      if (!commitToken(input.value, true)) return false;
      input.value = "";
      options.onToken?.("");
      return true;
    },
    clearToken() { input.value = ""; options.onToken?.(""); },
    dispose() {
      input.removeEventListener("input", onInput);
      input.removeEventListener("keydown", onKeyDown);
      field.removeEventListener("pointerdown", onFieldDown);
      field.remove();
    },
  };
}
