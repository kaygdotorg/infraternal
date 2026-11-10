/**
 * Pill morph (D160): the top-middle pill becomes a panel and back, as one continuous shape.
 * It is the morph the `?` shortcuts view uses (shortcuts-view.ts), taken out so other panels
 * (the view list, a floating terminal) share it.
 *
 * The caller builds `panel` (in the shared overlay material, `ui-overlay-surface`) and passes
 * the content nodes that should fade in. The panel is laid out once at its final size and a
 * spring opens a `clip-path: inset(... round r)` from the pill's rectangle to the panel, so
 * width, height and corner radius move together and nothing reflows. The pill fades out over the
 * first third, the content fades in after the shape has settled, and closing reverses the same
 * spring from wherever it is (interruptible). At rest no clip, transform or opacity is left
 * on anything. Reduced motion: a crossfade. Opened or closed from the keyboard (Enter on the focused pill, Escape), the
 * morph has no motion at all (#427, input-source.ts): the panel is whole in the first frame and gone in the first frame.
 *
 * `openHeight` makes the open state show only the top part of a taller panel (a floating
 * terminal that is a clipped view of a full window). `setReveal(e)` then grows the visible part
 * from `openHeight` to the whole panel, which is how that terminal expands into its slot.
 */
import { Spring } from "./spring";
import { markMotion } from "./input-source";

export interface PillMorphOptions {
  /** The pill that morphs (the session capsule). */
  pill: HTMLElement;
  /** The positioned container the panel is mounted in (the screen). */
  stage: HTMLElement;
  /** The panel to show; the morph appends, positions and sizes it. */
  panel: HTMLElement;
  /** Nodes inside the panel that fade in once the shape is whole. */
  content: HTMLElement[];
  /** Preferred panel width in px (clamped to the stage). */
  width: number;
  /** Visible height when open; the panel may be taller (see above). Default: all of it. */
  openHeight?: number;
  /** Cap on the panel height, when it scrolls inside. */
  maxHeight?: number;
  /** Runs after the panel is gone (closed or disposed). */
  onClosed?(): void;
}

export interface PillMorph {
  readonly isOpen: boolean;
  readonly panel: HTMLElement;
  open(): void;
  close(instant?: boolean): void;
  /** Resizes the open panel (anchored top centre on the pill); `shown` is the visible height. */
  setBox(width: number, height?: number, shown?: number): void;
  /** 0 = the open shape, 1 = the whole panel. */
  setReveal(amount: number): void;
  /** The panel's resting position in client coordinates (before any transform). */
  restRect(): DOMRect;
  dispose(): void;
}

const clamp01 = (value: number): number => Math.min(1, Math.max(0, value));
const smooth = (from: number, to: number, value: number): number => { const t = clamp01((value - from) / (to - from)); return t * t * (3 - 2 * t); };

/** Builds the morph for one pill and panel (see the module note); nothing is drawn until `open()`. */
export function createPillMorph(options: PillMorphOptions): PillMorph {
  const { pill, stage, panel, content } = options;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");
  // Insets of the visible shape inside the panel: the pill, and the open shape.
  let pillInset = { top: 0, right: 0, bottom: 0, left: 0, radius: 19 };
  let openInset = { bottom: 0, radius: 18 };
  let openState = false;
  let reveal = 0;
  let t = 0;

  const apply = (value: number): void => {
    t = value;
    if (value >= 0.99 && reveal >= 0.99) {
      panel.style.clipPath = "";
      for (const node of content) node.style.opacity = "";
      pill.style.opacity = "0";
      return;
    }
    const k = Math.max(0, value);
    const rest = 1 - reveal;
    const lerp = (a: number, b: number): number => (a + (b - a) * k) * rest;
    const radius = pillInset.radius + (openInset.radius - pillInset.radius) * k;
    panel.style.clipPath = `inset(0px ${lerp(pillInset.right, 0)}px ${lerp(pillInset.bottom, openInset.bottom)}px ${lerp(pillInset.left, 0)}px round ${radius}px)`;
    const show = String(smooth(0.7, 1, k));
    for (const node of content) node.style.opacity = show;
    pill.style.opacity = String(1 - smooth(0, 0.35, k));
  };
  const spring = new Spring(0, apply, { visualDuration: 0.4 });

  const finishClose = (): void => {
    panel.remove();
    pill.style.opacity = "";
    pill.style.pointerEvents = "";
    pill.removeAttribute("aria-expanded");
    reveal = 0;
    options.onClosed?.();
  };

  /**
   * Positions the panel centred on the pill (inside the stage) and measures the two shapes of the
   * morph. `height` and `shown` (the visible part when open) are optional: the panel's own height
   * and `openHeight` apply when omitted.
   */
  const layout = (preferred: number, height?: number, shown?: number): void => {
    const screen = stage.getBoundingClientRect();
    const rect = pill.getBoundingClientRect();
    const width = Math.min(preferred, screen.width - 24);
    const left = Math.max(12, Math.min(screen.width - width - 12, rect.left - screen.left + rect.width / 2 - width / 2));
    const top = rect.top - screen.top;
    panel.style.left = `${Math.round(left)}px`;
    panel.style.top = `${Math.round(top)}px`;
    panel.style.width = `${Math.round(width)}px`;
    if (height !== undefined) panel.style.height = `${Math.round(height)}px`;
    if (options.maxHeight) panel.style.maxHeight = `${Math.floor(options.maxHeight)}px`;
    const full = panel.offsetHeight;
    const visible = Math.min(full, shown ?? full);
    pillInset = {
      top: 0, bottom: Math.max(0, full - rect.height),
      left: Math.max(0, rect.left - screen.left - left), right: Math.max(0, left + width - (rect.right - screen.left)), radius: Math.min(rect.height / 2, 24),
    };
    openInset = { bottom: Math.max(0, full - visible), radius: parseFloat(getComputedStyle(panel).borderTopLeftRadius) || 18 };
  };

  const close = (instant = false): void => {
    if (!openState) return;
    openState = false;
    // The pill's own fade (its opacity transition) follows the same answer: a key brings it back at once.
    if (markMotion(pill) || instant) { spring.set(0, true); finishClose(); return; }
    if (reduced.matches) {
      pill.style.opacity = "";
      panel.animate([{ opacity: 1 }, { opacity: 0 }], { duration: 140, easing: "ease-out", fill: "forwards" }).onfinish = () => { if (!openState) finishClose(); };
      return;
    }
    panel.style.boxShadow = "none";
    spring.set(0);
    const wait = (): void => { if (openState) return; if (spring.value > 0.002) { requestAnimationFrame(wait); return; } finishClose(); };
    requestAnimationFrame(wait);
  };

  const open = (): void => {
    if (openState) return;
    openState = true;
    reveal = 0;
    panel.style.opacity = "";
    stage.append(panel);
    layout(options.width, undefined, options.openHeight);
    pill.setAttribute("aria-expanded", "true");
    pill.style.pointerEvents = "none";
    if (markMotion(pill)) { spring.set(1, true); return; }
    if (reduced.matches) {
      pill.style.opacity = "0";
      panel.animate([{ opacity: 0 }, { opacity: 1 }], { duration: 160, easing: "ease-out" });
      spring.set(1, true);
      apply(1);
      return;
    }
    panel.style.boxShadow = "none";
    spring.set(0, true);
    apply(0);
    spring.set(1);
    const settle = (): void => {
      if (!openState) return;
      if (spring.value < 0.999) { requestAnimationFrame(settle); return; }
      panel.style.boxShadow = "";
      panel.animate([{ boxShadow: "none" }, { boxShadow: getComputedStyle(panel).boxShadow }], { duration: 160, easing: "ease-out" });
    };
    requestAnimationFrame(settle);
  };

  return {
    get isOpen() { return openState; },
    panel,
    open,
    close,
    /** Re-lays the open panel: a new width, an optional new full height, and how much of it shows. */
    setBox(width, height, shown) { layout(width, height, shown); apply(t); },
    setReveal(amount) { reveal = clamp01(amount); apply(t); },
    restRect() {
      const screen = stage.getBoundingClientRect();
      return new DOMRect(screen.left + (parseFloat(panel.style.left) || 0), screen.top + (parseFloat(panel.style.top) || 0), panel.offsetWidth, panel.offsetHeight);
    },
    dispose() { close(true); },
  };
}
