/**
 * Mockup scaffolding for the clusters review round: a quiet pill at the bottom centre that
 * steps through the scenes, labelled "mockup". It exists only behind `?proto=clusters` and is
 * not part of any design. A scene may add a second row with a capsule-tabs switch (for example
 * who is signed in). The scene's "try this" line rides on the shared warm tooltip (long-press
 * on touch), so no extra text is drawn on the canvas.
 */
import { createCapsuleTabs, type CapsuleTabs } from "../../../packages/ui/src/capsule-tabs";

export interface StepperOptions {
  label: string;
  tabs: Array<{ id: string; label: string }>;
  selected: string;
  onChange(id: string): void;
}

export interface Stepper {
  set(index: number, name: string, hint: string, options?: StepperOptions): void;
  dispose(): void;
}

const ARROW_L = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15 6l-6 6 6 6"/></svg>';
const ARROW_R = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>';

export function mountStepper(parent: HTMLElement, opts: { count: number; onStep(delta: number): void }): Stepper {
  const root = document.createElement("div");
  root.className = "cl-stepper";
  root.setAttribute("role", "group");
  root.setAttribute("aria-label", "Mockup scenes");
  const row = document.createElement("div");
  row.className = "cl-stepper-options ui-pill";
  row.hidden = true;
  const pill = document.createElement("div");
  pill.className = "cl-stepper-pill ui-pill";
  pill.innerHTML = `<span class="cl-stepper-tag">mockup</span>
    <button type="button" class="cl-stepper-btn" data-dir="-1" aria-label="Previous scene">${ARROW_L}</button>
    <span class="cl-stepper-name" tabindex="0"><span class="cl-stepper-count"></span><span class="cl-stepper-title"></span></span>
    <button type="button" class="cl-stepper-btn" data-dir="1" aria-label="Next scene">${ARROW_R}</button>`;
  root.append(row, pill);
  parent.append(root);
  const count = pill.querySelector<HTMLElement>(".cl-stepper-count")!;
  const title = pill.querySelector<HTMLElement>(".cl-stepper-title")!;
  const name = pill.querySelector<HTMLElement>(".cl-stepper-name")!;
  const onClick = (e: MouseEvent): void => {
    const b = (e.target as Element).closest<HTMLButtonElement>(".cl-stepper-btn");
    if (b) opts.onStep(Number(b.dataset.dir));
  };
  pill.addEventListener("click", onClick);
  let tabs: CapsuleTabs | undefined;
  return {
    set(index, sceneName, hint, options) {
      count.textContent = `${index + 1}/${opts.count}`;
      title.textContent = sceneName;
      name.dataset.tip = hint;
      name.setAttribute("aria-label", `Scene ${index + 1} of ${opts.count}: ${sceneName}. ${hint}`);
      tabs?.dispose();
      tabs = undefined;
      row.hidden = !options;
      if (options) {
        tabs = createCapsuleTabs(options.tabs, options.selected, (id) => options.onChange(id), options.label);
        row.replaceChildren(tabs.root);
      }
    },
    dispose() { pill.removeEventListener("click", onClick); tabs?.dispose(); root.remove(); },
  };
}
