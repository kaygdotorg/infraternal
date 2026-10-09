/** Native, keyboard-operable switches with the shared theme and focus treatment. */

export interface UiSwitch {
  /** Synchronizes the visual accessibility state with the native checkbox state. */
  set(checked: boolean): void;
  dispose(): void;
}

/** Enhances an existing checkbox without replacing its label or native input behavior. */
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
