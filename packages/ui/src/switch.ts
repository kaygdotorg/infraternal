/** Native, keyboard-operable switches with the shared theme and focus treatment. */

/** The handle returned by {@link enhanceSwitch}. `dispose()` removes the listener it added. */
export interface UiSwitch {
  /** Synchronizes the visual accessibility state with the native checkbox state. */
  set(checked: boolean): void;
  dispose(): void;
}

/**
 * Enhances an existing checkbox without replacing its label or native input behavior.
 * Sets `role="switch"` and keeps `aria-checked` in step with the input. Throws if `input` is not a checkbox.
 * Use `set()` instead of assigning `input.checked`, because assigning does not fire `change`.
 */
export function enhanceSwitch(input: HTMLInputElement): UiSwitch {
  if (input.type !== "checkbox") throw new Error("A shared switch must use a checkbox input");
  input.classList.add("ui-switch");
  input.setAttribute("role", "switch");
  input.setAttribute("aria-checked", String(input.checked));

  const sync = (): void => input.setAttribute("aria-checked", String(input.checked));
  input.addEventListener("change", sync);
  return {
    set(checked) {
      input.checked = checked;
      sync();
    },
    dispose() { input.removeEventListener("change", sync); },
  };
}
