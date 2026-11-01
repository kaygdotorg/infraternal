/**
 * The slider (#283): one native range input in the product's look, with a value readout. Native, so it is keyboard-complete
 * (arrows, Home, End, Page keys) and announced as a slider with its value text, and a touch drag follows the finger 1:1.
 * The track fills up to the thumb through `--fill` (a percentage written on every input). Flat: a hairline track, a plain
 * thumb, no glow (TASTE "No fake glass"). Rings come from the shared focus-ring helper only.
 *
 * `createSlider({ label, min, max, step, value, format, onInput })` returns `{ root, set(value), dispose() }`. `onInput` runs
 * on every move of the thumb (live), `format` writes the value as words for the readout and for assistive technology.
 */
export interface SliderOptions {
  label: string;
  min: number;
  max: number;
  step: number;
  value: number;
  format(value: number): string;
  onInput(value: number): void;
}

export interface Slider {
  readonly root: HTMLElement;
  /** Moves the thumb without calling `onInput` (the value changed elsewhere). */
  set(value: number): void;
  dispose(): void;
}

export function createSlider(options: SliderOptions): Slider {
  const root = document.createElement("div");
  root.className = "ui-slider";
  const input = document.createElement("input");
  input.type = "range";
  input.className = "ui-slider-input";
  input.min = String(options.min);
  input.max = String(options.max);
  input.step = String(options.step);
  input.setAttribute("aria-label", options.label);
  const readout = document.createElement("output");
  readout.className = "ui-slider-value";
  readout.setAttribute("aria-hidden", "true");
  root.append(input, readout);

  const paint = (value: number): void => {
    input.value = String(value);
    input.style.setProperty("--fill", `${((value - options.min) / (options.max - options.min)) * 100}%`);
    input.setAttribute("aria-valuetext", options.format(value));
    readout.textContent = options.format(value);
  };
  const onInput = (): void => {
    const value = Number(input.value);
    paint(value);
    options.onInput(value);
  };
  input.addEventListener("input", onInput);
  paint(options.value);
  return { root, set: paint, dispose() { input.removeEventListener("input", onInput); root.remove(); } };
}
