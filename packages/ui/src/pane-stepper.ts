/**
 * One step transition for every multi-step card (D160): the add-host wizard
 * today, the sign-in card next.
 *
 * - The viewport's height follows a spring from wherever it currently is, so a
 *   step change during a transition retargets smoothly instead of snapping.
 * - The outgoing pane and the incoming pane overlap. Each pane rides its own
 *   spring along a "slot" axis: -1 (left, gone), 0 (centred, visible),
 *   +1 (right, gone). Continue moves the old pane to -1 and brings the new one
 *   in from +1; Back mirrors it. Interrupting simply retargets the springs.
 * - Outgoing panes are absolutely positioned in the viewport (a stacking
 *   wrapper), so layout never jumps while both are present.
 * - Crisp text: at rest a pane's transform and opacity are removed entirely and
 *   the viewport returns to `height: auto` and visible overflow, so settled text
 *   sits on no transformed or clipped layer.
 * - Reduced motion: an opacity crossfade only, with no movement or height glide.
 */
import { Spring } from "./spring";

export type StepDirection = 1 | -1 | 0;

const SLIDE = 20;
const PANE_SPRING = { visualDuration: 0.34 } as const;
const HEIGHT_SPRING = { visualDuration: 0.36 } as const;

export class PaneStepper {
  private current: HTMLElement | undefined;
  private readonly panes = new Map<HTMLElement, Spring>();
  private readonly height: Spring;
  private moving = false;
  private goal = 0;

  constructor(private readonly viewport: HTMLElement) {
    viewport.classList.add("ui-pane-viewport");
    this.height = new Spring(0, (value) => {
      if (!this.moving) return;
      this.viewport.style.height = `${value}px`;
      if (value === this.goal) this.settleHeight();
    }, HEIGHT_SPRING);
  }

  /** The pane on screen (or arriving). */
  get active(): HTMLElement | undefined { return this.current; }

  /** Shows `pane`, moving in `direction` (1 forward, -1 back, 0 replace in place). */
  show(pane: HTMLElement, direction: StepDirection): void {
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
    const from = this.viewport.getBoundingClientRect().height;
    const old = this.current;
    pane.classList.add("ui-pane");
    this.viewport.append(pane);
    this.current = pane;
    if (!old) { this.track(pane, 0, true); return; }

    // Leave in a stacking layer at its current spot so the new pane takes the flow.
    old.classList.add("is-leaving");
    old.inert = true;
    if (reduce || direction === 0) {
      this.crossfade(old, pane);
    } else {
      this.track(pane, direction, true);
      this.slotOf(pane).set(0);
      this.slotOf(old).set(-direction);
    }
    this.glideHeight(from, reduce);
  }

  private crossfade(old: HTMLElement, pane: HTMLElement): void {
    this.panes.get(old)?.set(0, true);
    old.style.transform = "";
    old.animate([{ opacity: getComputedStyle(old).opacity }, { opacity: 0 }], { duration: 160, easing: "ease-out" }).onfinish = () => this.drop(old);
    pane.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 180, easing: "ease-out" });
    this.track(pane, 0, true);
  }

  private slotOf(pane: HTMLElement): Spring {
    return this.panes.get(pane) ?? this.track(pane, 0, true);
  }

  /** Gives `pane` its slot spring, starting at `slot`. */
  private track(pane: HTMLElement, slot: number, instant: boolean): Spring {
    const enter = slot;
    const spring = new Spring(slot, (value) => {
      if (value === 0 && pane === this.current) {
        pane.style.transform = "";
        pane.style.opacity = "";
        return;
      }
      if (pane !== this.current && Math.abs(value) >= 1) { this.drop(pane); return; }
      pane.style.transform = `translate3d(${value * SLIDE}px, 0, 0)`;
      // The springs are critically damped, so `value` never crosses 0; the clamp below only guards the endpoints.
      const away = pane === this.current && enter !== 0 ? value * Math.sign(enter) : Math.abs(value);
      pane.style.opacity = String(Math.max(0, Math.min(1, 1 - away)));
    }, PANE_SPRING);
    if (instant) spring.set(slot, true);
    this.panes.set(pane, spring);
    return spring;
  }

  private drop(pane: HTMLElement): void {
    this.panes.delete(pane);
    pane.remove();
  }

  private target(): number { return this.current?.offsetHeight ?? 0; }

  private glideHeight(from: number, reduce: boolean): void {
    const to = this.target();
    if (reduce || Math.abs(to - from) < 0.5) { if (!this.moving) this.settleHeight(); return; }
    if (!this.moving) {
      this.moving = true;
      this.viewport.classList.add("is-moving");
      this.height.set(from, true);
      this.viewport.style.height = `${from}px`;
    }
    this.goal = to;
    this.height.set(to);
  }

  private settleHeight(): void {
    this.moving = false;
    this.viewport.style.height = "";
    this.viewport.classList.remove("is-moving");
  }
}
