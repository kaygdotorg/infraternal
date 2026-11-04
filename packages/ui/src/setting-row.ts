// SPDX-License-Identifier: AGPL-3.0-only
/**
 * One setting as a row (issue #304), in one column on one left edge: its name, a one-line plain explanation, its value with
 * a Reset that appears only when the value is not the default, and under them the default and the allowed range.
 *
 *   Connection keys
 *   How often every machine swaps the keys that encrypt mesh traffic (WireGuard).
 *   [ 7 d ] (↺)
 *   Default 7 d · allowed 1 to 30 days
 *
 * Stacked rather than side by side because a window can be a fifth of the screen wide (five to a row): a field beside the
 * name would leave the name a sliver and wrap it.
 *
 * The value control depends on the kind (`setting-value.ts`): a **typed** value (a duration, a count, a text) is a text field
 * in the setting's own unit; a **choice** is the shared segmented control; a **switch** is the shared switch. Only a typed
 * value can be wrong. Enter or leaving the field saves a valid value; a value that is out of range or not understood is
 * **refused inline**: the field turns to the danger colour, one plain sentence appears under the row saying what is allowed
 * and what is still in use, and nothing is saved. Escape, or Reset, puts the saved value back. A refusal slides in (height and
 * opacity, interruptible) and is read out to assistive technology. A choice and a switch save as soon as they are changed.
 *
 * Reset is an icon button with the shared warm tooltip ("Reset to 7 d", taken from its aria-label). It keeps its place when
 * it is not needed (it fades), so the control never moves when the value changes.
 *
 * Quiet by TASTE: no ring from the mouse (the shared focus-ring helper owns rings), no border change on selection, the
 * "found" highlight (⌘K jumped here) is a faint fill that fades, never an outline. Text is crisp at rest: nothing here
 * leaves a transform or will-change behind.
 */
import { createCapsuleTabs, type CapsuleTabs } from "./capsule-tabs";
import { enhanceSwitch, type UiSwitch } from "./switch";
import { captionFor, defaultValue, formatValue, isTyped, parseValue, type SettingValue, type ValueSpec } from "./setting-value";

/** What a setting row needs: its id, plain title and help, the rules for its value, where it starts and what happens on a save. */
export interface SettingRowOptions {
  id: string;
  title: string;
  /** One line, plain words. */
  explain: string;
  spec: ValueSpec;
  /** The saved value to start from; the default when absent. */
  value?: SettingValue;
  /**
   * Called with a valid new value after it is saved. A store that can say no (a server) returns a promise: when it resolves to a
   * sentence, or fails, the row puts the previous value back and shows the sentence as a refusal, so the screen never keeps a
   * value that was not stored.
   */
  onSave?(value: SettingValue): void | Promise<string | void>;
}

/** A setting row on screen: its element, its value, and the ways to put a stored value in, highlight it and let it go. */
export interface SettingRow {
  readonly root: HTMLElement;
  value(): SettingValue;
  /** Puts a value that came from the store on screen (not a save): a row is drawn before a server has answered. */
  set(value: SettingValue): void;
  /** Quiet highlight that fades: how ⌘K shows which row it jumped to. */
  found(): void;
  dispose(): void;
}

/** Counter-clockwise arrow: back to the default. */
const RESET_ICON = '<path d="M4.5 12a7.5 7.5 0 1 0 2.4-5.5"/><path d="M4.5 4.5v4h4"/>';

/** Gives each row its own element ids, so its label and help can be read out with its field. */
let serial = 0;

/** Builds one setting row: the control for its kind, a Reset, its default and range, and an inline refusal for a bad value. */
export function createSettingRow(options: SettingRowOptions): SettingRow {
  const { spec } = options;
  const n = ++serial;
  let saved: SettingValue = options.value ?? defaultValue(spec);
  const root = document.createElement("div");
  root.className = "ui-setting";
  root.dataset.setting = options.id;
  root.dataset.kind = spec.kind;
  root.innerHTML = `
    <div class="ui-setting-names">
      <label class="ui-setting-title" id="ui-setting-${n}-title"></label>
      <span class="ui-setting-explain" id="ui-setting-${n}-explain"></span>
      <span class="ui-setting-caption"></span>
    </div>
    <div class="ui-setting-control">
      <button type="button" class="ui-setting-reset" data-shown="false" inert><svg viewBox="0 0 24 24" aria-hidden="true">${RESET_ICON}</svg></button>
    </div>
    <div class="ui-setting-refusal" aria-hidden="true"><div><p id="ui-setting-${n}-refusal" role="status"></p></div></div>`;
  const q = <T extends HTMLElement>(selector: string): T => root.querySelector<T>(selector)!;
  q(".ui-setting-title").textContent = options.title;
  q(".ui-setting-explain").textContent = options.explain;
  q(".ui-setting-caption").textContent = captionFor(spec);
  const reset = q<HTMLButtonElement>(".ui-setting-reset");
  const control = q<HTMLElement>(".ui-setting-control");
  const refusal = q<HTMLElement>(".ui-setting-refusal");
  const refusalText = q<HTMLElement>(".ui-setting-refusal p");
  const defaultText = formatValue(spec, defaultValue(spec));
  reset.setAttribute("aria-label", `Reset to ${defaultText}`);

  const cleanups: Array<() => void> = [];
  /** The control puts `value` on screen without saving it. */
  let paintControl: (value: SettingValue) => void;
  let input: HTMLInputElement | undefined;

  const paintReset = (): void => {
    const changed = saved !== defaultValue(spec);
    reset.dataset.shown = String(changed);
    reset.toggleAttribute("inert", !changed);
  };
  const refuse = (message: string | undefined): void => {
    root.toggleAttribute("data-invalid", message !== undefined);
    input?.setAttribute("aria-invalid", String(message !== undefined));
    refusal.setAttribute("aria-hidden", String(message === undefined));
    // The text stays while it slides away, so the row does not collapse on an empty box.
    if (message !== undefined) refusalText.textContent = message;
  };
  const show = (): void => { paintControl(saved); refuse(undefined); paintReset(); };
  const save = (value: SettingValue): void => {
    const before = saved;
    saved = value;
    show();
    const outcome = options.onSave?.(saved);
    if (!(outcome instanceof Promise)) return;
    const undo = (message: string): void => { if (saved !== value) return; saved = before; paintControl(saved); paintReset(); refuse(message); };
    outcome.then((message) => { if (typeof message === "string") undo(message); }, () => undo("It could not be saved. The old value is still in use."));
  };

  if (isTyped(spec)) {
    input = document.createElement("input");
    input.className = "ui-setting-input ui-setting-field";
    input.id = `ui-setting-${n}`;
    input.type = "text";
    input.inputMode = spec.kind === "text" ? "text" : "numeric";
    input.autocomplete = "off";
    input.setAttribute("autocapitalize", "none");
    input.spellcheck = false;
    input.setAttribute("aria-describedby", `ui-setting-${n}-explain ui-setting-${n}-refusal`);
    q<HTMLLabelElement>(".ui-setting-title").htmlFor = input.id;
    control.prepend(input);
    const field = input;
    paintControl = (value) => { field.value = formatValue(spec, value); };
    const commit = (): void => {
      const parsed = parseValue(spec, field.value, saved);
      if (!parsed.ok) { refuse(parsed.message); return; }
      save(parsed.value);
    };
    // Typing shows a refusal as soon as the text cannot be a valid value, without saving; a valid draft clears it.
    const onInput = (): void => { const parsed = parseValue(spec, field.value, saved); refuse(parsed.ok ? undefined : parsed.message); };
    const onKey = (event: KeyboardEvent): void => {
      if (event.key === "Enter") { event.preventDefault(); commit(); }
      else if (event.key === "Escape" && (field.value !== formatValue(spec, saved) || root.hasAttribute("data-invalid"))) { event.stopPropagation(); show(); }
    };
    // Leaving the field with a valid draft saves it; with a refused one, the refusal stays until the person fixes it or presses Escape.
    const onBlur = (): void => { const parsed = parseValue(spec, field.value, saved); if (parsed.ok && parsed.value !== saved) commit(); else if (parsed.ok) show(); };
    const onFocus = (): void => field.select();
    field.addEventListener("input", onInput);
    field.addEventListener("keydown", onKey);
    field.addEventListener("blur", onBlur);
    field.addEventListener("focus", onFocus);
    cleanups.push(() => { field.removeEventListener("input", onInput); field.removeEventListener("keydown", onKey); field.removeEventListener("blur", onBlur); field.removeEventListener("focus", onFocus); });
  } else if (spec.kind === "choice") {
    const tabs: CapsuleTabs = createCapsuleTabs(spec.options.map((o) => ({ id: o.id, label: o.label })), String(saved), (id) => save(id), options.title);
    tabs.root.classList.add("ui-setting-field");
    control.prepend(tabs.root);
    paintControl = (value) => tabs.select(String(value), true);
    cleanups.push(() => tabs.dispose());
  } else {
    const label = document.createElement("label");
    label.className = "ui-setting-field ui-setting-switch";
    label.innerHTML = '<input type="checkbox">';
    const box = label.querySelector<HTMLInputElement>("input")!;
    box.setAttribute("aria-label", options.title);
    box.setAttribute("aria-describedby", `ui-setting-${n}-explain`);
    const toggle: UiSwitch = enhanceSwitch(box);
    control.prepend(label);
    paintControl = (value) => toggle.set(value === true);
    const onChange = (): void => save(box.checked);
    box.addEventListener("change", onChange);
    cleanups.push(() => { box.removeEventListener("change", onChange); toggle.dispose(); });
  }

  const onReset = (): void => save(defaultValue(spec));
  reset.addEventListener("click", onReset);
  show();

  let foundTimer = 0;
  return {
    root,
    value: () => saved,
    set(value) { saved = value; show(); },
    found() {
      root.removeAttribute("data-found");
      void root.offsetWidth; // restart the fade when ⌘K jumps to the same row twice
      root.setAttribute("data-found", "");
      window.clearTimeout(foundTimer);
      foundTimer = window.setTimeout(() => root.removeAttribute("data-found"), 1800);
    },
    dispose() {
      window.clearTimeout(foundTimer);
      for (const stop of cleanups) stop();
      reset.removeEventListener("click", onReset);
      root.remove();
    },
  };
}
