/**
 * The one tick (DECISIONS 99). Every checkmark in infraternal uses this primitive —
 * checkboxes, stepper steps, completed bootstrap steps, "copied" — so the same spring
 * interaction appears wherever a tick appears (code reuse rule).
 *
 * ONE critically damped spring value t (0 → 1, visual duration 0.2 s, no overshoot: TASTE §3) drives everything:
 *   fill   scale(t)                       — grows from the centre
 *   box    scale(1 + 0.35 · max(0, t − 1)) — stays at 1: t never passes 1
 *   tick   strokeDashoffset 1 − clamp(t)   — draws on as the fill grows
 *   label  opacity 1 − (1 − 0.42) · clamp(t), strike scaleX((clamp(t) − 0.12) / 0.72)
 * Pointer toggles animate; keyboard toggles are instant (no animation for keyboard
 * actions). Pressing squishes the row slightly.
 */
import { Spring } from "./spring";

/** The checkmark geometry, shared with copy feedback so every tick is the same tick. */
export const TICK_PATH = "M5 14L8.5 17.5L19 6.5";

/** Tuning constants for the animation: box swell, label opacity when done, strike-through delay and end point (see the formulas above). */
const SWELL = 0.35, DONE_OPACITY = 0.42, STRIKE_LAG = 0.12, RULE_END = 0.84;
/** Limits a value to 0 to 1. */
const clamp01 = (v: number) => Math.min(1, Math.max(0, v));

/**
 * A tick control. `set(checked, instant)` moves it, animated unless `instant` is true (use that for keyboard actions
 * and first paint); `checked` is the current target state.
 */
export interface Tick { set(checked: boolean, instant?: boolean): void; readonly checked: boolean }

/**
 * Builds the box (fill + tick) inside `host` and returns its controller.
 * @param checked the initial state, shown without animation
 * @param extras.word an element (the label) that fades when checked
 * @param extras.rule an element drawn as a strike-through over the label
 * @example
 * const t = tick(document.querySelector(".box")!); t.set(true);
 */
export function tick(host: HTMLElement, checked = false, extras: { word?: HTMLElement; rule?: HTMLElement } = {}): Tick {
  host.classList.add("tick");
  host.innerHTML = `<span class="tick-fill"></span><svg viewBox="0 0 24 24" aria-hidden="true"><path pathLength="1" d="${TICK_PATH}"/></svg>`;
  const fill = host.querySelector<HTMLElement>(".tick-fill")!;
  const path = host.querySelector<SVGPathElement>("path")!;
  let on = checked;
  const spring = new Spring(checked ? 1 : 0, (t) => {
    const held = clamp01(t);
    fill.style.transform = `scale(${Math.max(t, 0)})`;
    host.style.transform = `scale(${1 + SWELL * Math.max(0, t - 1)})`;
    path.style.strokeDashoffset = String(1 - held);
    if (extras.word) extras.word.style.opacity = String(1 - (1 - DONE_OPACITY) * held);
    if (extras.rule) extras.rule.style.transform = `scaleX(${clamp01((held - STRIKE_LAG) / (RULE_END - STRIKE_LAG))})`;
  });
  return {
    get checked() { return on; },
    set(next: boolean, instant = false) { on = next; host.dataset.checked = String(next); spring.set(next ? 1 : 0, instant); },
  };
}

/**
 * Upgrades a native checkbox (kept for forms and accessibility) into a spring check.
 * The input stays in the DOM but visually hidden, and a tick box is inserted after it. A pointer toggle animates;
 * a keyboard toggle is instant. Returns the same controller as {@link tick}.
 */
export function springCheckbox(input: HTMLInputElement): Tick {
  const box = document.createElement("span");
  input.after(box);
  input.classList.add("visually-hidden");
  const t = tick(box, input.checked);
  const row = input.closest("label") ?? box;
  let viaPointer = false;
  row.addEventListener("pointerdown", (e) => { if ((e as PointerEvent).button === 0) { viaPointer = true; row.toggleAttribute("data-pressed", true); } });
  const up = () => row.removeAttribute("data-pressed");
  row.addEventListener("pointerup", up);
  row.addEventListener("pointercancel", () => { viaPointer = false; up(); });
  input.addEventListener("change", () => { t.set(input.checked, !viaPointer); viaPointer = false; });
  return t;
}
