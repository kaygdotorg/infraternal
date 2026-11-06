/**
 * Warm tooltips: the one tooltip for every icon-only control (owner rule: wherever an
 * icon stands without a label, it gets this tooltip).
 *
 * Behaviour (one group per page, one floating surface):
 * - Cold: the first tooltip waits 400 ms, then pops from its trigger (opacity and scale
 *   0.94 → 1, 160 ms strong ease-out, origin on the trigger's side).
 * - Warm: while a tooltip is open, or within 300 ms of one closing, the next trigger
 *   shows its tooltip at once with no pop (after the first, delay and animation
 *   are skipped). If the surface is still up, it travels to the new trigger and the label
 *   slides in the direction of travel (140 ms, 10 px).
 * - Leaving waits an 80 ms grace, so crossing the gap between two icons never
 *   flickers closed and open again.
 * - Keyboard focus shows the tooltip at once with no motion. Escape hides it.
 * - Touch: a 500 ms long press shows the label. The click that ends that press is
 *   swallowed, because the user asked "what is this?", not "do this".
 * - Reduced motion: opacity only.
 * - Components can request a timed confirmation label with flashTip(); its temporary
 *   data-tip is restored when the label expires.
 * - Point-anchored calls can opt into two lines and a side for that call only.
 * - Size: the surface is as wide as its label up to a cap (17.5rem, never wider than the viewport minus its margins) and
 *   wraps beyond it; a label is never cut off with an ellipsis (only the opt-in two-line link preview is clamped). The
 *   size is read back from a hidden copy of the surface, so it holds at every UI size. It flips to the other side when
 *   its side does not fit, and shifts (arrow included) to stay inside the viewport.
 *
 * Which elements: anything with `data-tip`, plus every button or link that has an
 * aria-label and no visible text. The rule is therefore enforced automatically.
 * `data-tip-off` opts out (the d-pad, whose hold is its own gesture).
 * `data-tip-side` = top | bottom picks a side. Otherwise the tooltip goes above,
 * or below near the top edge.
 * Labels are read live, so a control whose aria-label changes (copy → "Copied")
 * updates an open tooltip through `refreshTip`.
 */

const DELAY = 400, WARM = 300, GRACE = 80, LONG_PRESS = 500, SLOP = 10;
const POP = 160, SWAP = 140, SHIFT = 10, TRAVEL = 200, OUT = 100;
const GAP = 8, MARGIN = 8;
const EASE = "cubic-bezier(0.23, 1, 0.32, 1)";

type Side = "top" | "bottom";
/** Optional layout for one point-anchored tooltip: a clamped two-line preview (a long link). Every other tooltip shows its whole label. */
export interface PointTooltipOptions {
  /** Permit a two-line label with the shared content-width rule. */
  lines?: 2;
  /** Place the tooltip above or below the point anchor's corresponding edge. */
  side?: Side;
}
const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

let pos: HTMLDivElement, surface: HTMLDivElement, arrow: HTMLDivElement, measure: HTMLDivElement, measureSurface: HTMLDivElement;
let current: HTMLElement | null = null;
let openTimer = 0, closeTimer = 0, pressTimer = 0, warmUntil = 0, shown = false;
let swallowClick = false, press0: { x: number; y: number } | null = null;
let pointAnchor: HTMLElement | null = null, pointLabel = "", pointRect: DOMRect | undefined, pointOptions: PointTooltipOptions | undefined;
const temporaryTips = new WeakMap<HTMLElement, { previous: string | undefined; timer: number }>();

/** The tooltip and confirmation styles, installed once by `buildStyleOnly`. */
const STYLE = `
.tip-pos { position: fixed; left: 0; top: 0; z-index: 1002; pointer-events: none; will-change: transform; }
.tip, .tip-sizer { position: relative; box-sizing: border-box; padding: 0.375rem 0.625rem; border-radius: 0.5rem; width: max-content; max-width: min(17.5rem, calc(100vw - 2 * ${MARGIN}px)); overflow: hidden;
  font: var(--fw-label, 500) var(--text-secondary, 0.75rem)/1.2 var(--font-ui, "Maple Mono NF", ui-monospace, monospace); letter-spacing: 0; }
.tip-label.is-leaving { position: absolute; left: 0.625rem; top: 0.375rem; white-space: nowrap; }
.tip-arrow { position: absolute; left: 0; width: 0.5rem; height: 0.5rem; margin-left: -0.25rem; transform-origin: center;
  background: var(--overlay, var(--fg)); border-radius: 1.5px; }
/* The measuring copy of the surface (see place) takes the same rules as .tip under a hidden host, so padding, border, font
   and cap are never restated as pixel constants that drift when a token changes. Its own class keeps the .tip element unique in the page. */
.tip-pos.tip-measure { visibility: hidden; will-change: auto; }
[data-tip], button[aria-label], a[aria-label] { -webkit-touch-callout: none; }
.ui-confirm-tip { position: fixed; z-index: 1001; display: grid; width: max-content; max-width: min(21.25rem, calc(100vw - 1.5rem)); gap: 0.75rem; padding: 0.875rem 0.875rem 0.75rem;
  border-radius: 0.875rem; opacity: 0; transform: scale(0.96); pointer-events: none;
  transition: opacity 150ms ease-out, transform 180ms cubic-bezier(0.23, 1, 0.32, 1); }
.ui-confirm-tip[hidden] { display: none !important; }
.ui-confirm-tip[data-open="true"] { opacity: 1; transform: none; pointer-events: auto; }
.ui-confirm-tip-arrow { position: absolute; left: var(--ui-confirm-tail, 50%); width: 0.625rem; height: 0.625rem; margin-left: -0.3125rem; background: inherit;
  border: inherit; border-radius: 2px; transform: rotate(45deg); }
.ui-confirm-tip[data-side="bottom"] .ui-confirm-tip-arrow { top: -0.3125rem; border-right: 0; border-bottom: 0; clip-path: polygon(0 0, 100% 0, 0 100%); }
.ui-confirm-tip[data-side="top"] .ui-confirm-tip-arrow { bottom: -0.3125rem; border-top: 0; border-left: 0; clip-path: polygon(0 100%, 100% 100%, 100% 0); }
.ui-confirm-tip-text { display: grid; gap: 0.1875rem; }
.ui-confirm-tip-message { margin: 0; color: var(--fg); font: 500 var(--text-body, 0.8125rem)/1.45 var(--font-ui, "Geist Mono", ui-monospace, monospace); letter-spacing: 0; }
.ui-confirm-tip-detail { margin: 0; white-space: pre-line; overflow-wrap: anywhere; color: var(--fg-2); font: 450 var(--text-secondary, 0.75rem)/1.5 var(--font-ui, "Geist Mono", ui-monospace, monospace); letter-spacing: 0; }
.ui-confirm-tip-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 0.375rem; }
:is(.ui-confirm-tip, .ui-confirm-bar) button { display: inline-grid; width: 1.75rem; height: 1.75rem; place-items: center; padding: 0; border: 0; border-radius: 999px; background: transparent;
  color: var(--fg-2); cursor: pointer;
  transition: transform 120ms cubic-bezier(0.23, 1, 0.32, 1), background-color 120ms ease, color 120ms ease; }
:is(.ui-confirm-tip, .ui-confirm-bar) button svg { width: 1rem; height: 1rem; fill: none; stroke: currentColor; stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; }
:is(.ui-confirm-tip, .ui-confirm-bar) button:active { transform: scale(0.97); }
:is(.ui-confirm-tip, .ui-confirm-bar) button:focus { outline: none; }
:root[data-focus-ring="on"] :is(.ui-confirm-tip, .ui-confirm-bar) button:focus-visible { outline: 2px solid color-mix(in oklab, var(--fg) 55%, transparent); outline-offset: 2px; }
@media (hover: hover) and (pointer: fine) { :is(.ui-confirm-tip, .ui-confirm-bar) button:not(.ui-confirm-yes):hover { background: var(--hover); color: var(--fg); } }
/* The overlay material gives its text a soft halo in the tint colour (styles.css), meant for text that sits straight on
   a busy terminal. The confirmation is a near-opaque card of its own, where the halo is only a dark smear around the
   glyphs (it read as blurred text on the confirm button and the grey effect line), so nothing inside it takes one. */
.ui-confirm-tip, .ui-confirm-tip * { text-shadow: none; }
:is(.ui-confirm-tip, .ui-confirm-bar) .ui-confirm-yes { background: var(--fg); color: var(--bg); }
:is(.ui-confirm-tip, .ui-confirm-bar) .ui-confirm-yes svg { stroke-width: 2; }
/* The secondary action keeps to the start of the row so the answer and the dismissal stay together on the right. */
.ui-confirm-tip .ui-confirm-alt { margin-right: auto; }
/* With three actions a phone-width card stacks them full width in priority order (answer, way out, dismiss), never a ragged wrap. */
@media (max-width: 480px) {
  .ui-confirm-tip[data-stack] .ui-confirm-tip-actions { display: grid; grid-template-columns: minmax(0, 1fr); justify-content: stretch; gap: 0.25rem; }
  .ui-confirm-tip[data-stack] .ui-confirm-yes { order: 1; }
  .ui-confirm-tip[data-stack] .ui-confirm-alt { order: 2; margin-right: 0; }
  .ui-confirm-tip[data-stack] .ui-confirm-no { order: 3; }
  .ui-confirm-tip[data-stack][data-named] button { width: 100%; }
}
/* Named actions: the buttons carry their words. */
.ui-confirm-tip[data-named] button { display: inline-flex; align-items: center; justify-content: center; width: auto; min-width: 0; max-width: 100%; overflow: hidden; padding: 0 0.75rem; font: 500 var(--text-secondary, 0.75rem)/1 var(--font-ui, "Geist Mono", ui-monospace, monospace); letter-spacing: 0; white-space: nowrap; }
/* A label that still does not fit (a long host name) is cut with an ellipsis inside its button, never run past the card's edge. */
.ui-confirm-tip[data-named] button > span { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
/* Two named actions sit side by side and share the row; the dismissal is a real button with a quiet flat fill, not loose text. */
.ui-confirm-tip[data-named]:not([data-stack]) .ui-confirm-tip-actions { flex-wrap: nowrap; }
.ui-confirm-tip[data-named] .ui-confirm-no { background: color-mix(in oklab, var(--fg) 10%, transparent); color: var(--fg); }
/* A confirmation is a decision, so it is a solid card in the theme's surface colour at every transparency setting, never glass.
   A backdrop blur does not reliably reach a terminal's own drawing layer (the text stayed readable through blur(32px) in a
   production build), so no blur value can promise that nothing behind is legible. The arrow inherits this fill. */
.ui-confirm-tip.ui-overlay-surface { --ui-overlay-background: var(--overlay-solid); -webkit-backdrop-filter: none; backdrop-filter: none; }
.ui-confirm-tip[data-side="center"] .ui-confirm-tip-arrow { display: none; }
.ui-confirm-tip-message { overflow-wrap: anywhere; }
@media (pointer: coarse) {
  .ui-confirm-tip { gap: 0.875rem; padding: 1rem; }
  .ui-confirm-tip[data-named] button { width: auto; padding: 0 0.75rem; }
  :is(.ui-confirm-tip, .ui-confirm-bar) button { width: 2.75rem; height: 2.75rem; }
  :is(.ui-confirm-tip, .ui-confirm-bar) button svg { width: 1.125rem; height: 1.125rem; }
}
@media (prefers-reduced-motion: reduce) { .ui-confirm-tip { transition: opacity 120ms ease; transform: none; } }
`;

function build() {
  buildStyleOnly();
  pos = document.createElement("div");
  pos.className = "tip-pos";
  pos.setAttribute("aria-hidden", "true"); // the trigger's aria-label already names it
  pos.innerHTML = `<div class="tip"><span class="tip-label"></span></div><div class="tip-arrow"></div>`;
  pos.style.visibility = "hidden";
  surface = pos.querySelector(".tip")!;
  surface.classList.add("ui-overlay-surface");
  arrow = pos.querySelector(".tip-arrow")!;
  measure = document.createElement("div");
  measure.className = "tip-pos tip-measure";
  measure.setAttribute("aria-hidden", "true");
  // Its label has its own class: `.tip-label` is how callers (and tests) find the visible label, and must stay unique.
  measure.innerHTML = `<div class="tip-sizer ui-overlay-surface"><span class="tip-measure-label"></span></div>`;
  measureSurface = measure.firstElementChild as HTMLDivElement;
  document.body.append(pos, measure);
  // The width is measured once per show; a face that arrives later changes every glyph, so an open tooltip re-measures.
  document.fonts?.addEventListener("loadingdone", () => { if (shown && current) place(current, false); });
}

export interface ConfirmTipOptions {
  /** Accessible name for the small, trigger-anchored confirmation group. */
  label: string;
  /**
   * The shape every confirmation uses (TASTE: messages say what happens, in plain words):
   * - `title`: the question as a plain sentence about the thing, e.g. "Remove asha's access to build-01?" No arrows,
   *   ids or enum names.
   * - `effect`: one line on what changes for the person, e.g. "She will no longer be able to open terminals there."
   * - `confirmLabel` and `cancelLabel`: the actions by name ("Remove access", "Keep it"), never "OK" or "Yes".
   * - `named`: show the two actions as labelled buttons instead of the compact check and cross. Use it whenever the
   *   action is destructive or the words carry meaning.
   * `message` and `detail` are the earlier names of `title` and `effect` and still work.
   */
  title?: string;
  effect?: string;
  named?: boolean;
  /** The question, at body size (the earlier name of `title`). */
  message?: string;
  /** One secondary line explaining the consequence (the earlier name of `effect`). */
  detail?: string;
  /** The same two lines with entity chips in them (`entityText`); they replace `title` and `effect` on screen, which stay the plain text. */
  titleNode?: Node;
  effectNode?: Node;
  confirmLabel: string;
  /** Disable the confirming action while keeping its explanation visible. */
  confirmDisabled?: boolean;
  cancelLabel: string;
  /**
   * Inner SVG markup (24 px grid, stroked) for the confirming button instead of the tick. The tick means "yes, do it";
   * an action that is not a yes (try again) names itself with its own glyph.
   */
  confirmIcon?: string;
  /**
   * A third, quiet action for a way out that is neither the answer nor a dismissal (for example "Remove host" when
   * retrying is no longer possible). It sits at the start of the row, in the ghost style of the cancel button, and
   * closes the tip like the others. Only drawn with `named`: an icon needs a glyph this action does not have.
   */
  secondary?: { label: string; onSelect(): void };
  onConfirm(): void;
  onCancel?(): void;
  /** A card the confirmation must stay inside (a window), with the same 9 px inset the window's own overlays keep. */
  boundary?: HTMLElement | null;
}

export interface ConfirmTipController { close(restoreFocus?: boolean): void }

/** The longest button label drawn in full; the accessible name and the tooltip keep the whole text. A button is a verb, never a sentence. */
const MAX_BUTTON_LABEL = 28;
/** A button label as drawn: whole when short, cut with an ellipsis past `MAX_BUTTON_LABEL`. */
function capLabel(label: string): string { return label.length > MAX_BUTTON_LABEL ? `${label.slice(0, MAX_BUTTON_LABEL - 1)}…` : label; }

let activeConfirmTip: ConfirmTipController | undefined;
let confirmTipSerial = 0;

/** Mounts a single reusable, trigger-anchored confirmation for a reversible choice. */
export function mountConfirmTip(anchorOrNull: HTMLElement | null, options: ConfirmTipOptions): ConfirmTipController {
  // No anchor means the question is not about anything on screen (it started from the palette): it sits centred, with no tail.
  const anchor = anchorOrNull ?? document.createElement("span");
  const centred = anchorOrNull === null;
  activeConfirmTip?.close(false);
  buildStyleOnly();

  const tip = document.createElement("div");
  tip.className = "ui-confirm-tip ui-overlay-surface";
  tip.id = `ui-confirm-tip-${++confirmTipSerial}`;
  tip.hidden = true;
  tip.setAttribute("role", "dialog");
  tip.setAttribute("aria-label", options.label);
  tip.dataset.open = "false";

  const arrow = document.createElement("span");
  arrow.className = "ui-confirm-tip-arrow";
  arrow.setAttribute("aria-hidden", "true");
  const text = document.createElement("div");
  text.className = "ui-confirm-tip-text";
  const message = document.createElement("p");
  message.className = "ui-confirm-tip-message";
  if (options.titleNode) message.append(options.titleNode); else message.textContent = options.title ?? options.message ?? options.label;
  text.append(message);
  const effectText = options.effect ?? options.detail;
  if (effectText || options.effectNode) {
    const detail = document.createElement("p");
    detail.className = "ui-confirm-tip-detail";
    if (options.effectNode) detail.append(options.effectNode); else detail.textContent = effectText!;
    text.append(detail);
  }

  const actions = document.createElement("div");
  actions.className = "ui-confirm-tip-actions";
  // Icon buttons with warm tooltips: × cancels, ✓ confirms; the label names each action.
  const cancel = document.createElement("button");
  cancel.type = "button";
  cancel.className = "ui-confirm-no";
  cancel.setAttribute("aria-label", options.cancelLabel);
  cancel.dataset.tip = options.cancelLabel;
  cancel.innerHTML = options.named ? `<span></span>` : `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m7 7 10 10M17 7 7 17"/></svg>`;
  if (options.named) { cancel.querySelector("span")!.textContent = capLabel(options.cancelLabel); tip.dataset.named = ""; }
  const confirm = document.createElement("button");
  confirm.type = "button";
  confirm.disabled = options.confirmDisabled ?? false;
  confirm.className = "ui-confirm-yes";
  confirm.setAttribute("aria-label", options.confirmLabel);
  confirm.dataset.tip = options.confirmLabel;
  confirm.innerHTML = options.named ? `<span></span>` : `<svg viewBox="0 0 24 24" aria-hidden="true">${options.confirmIcon ?? '<path d="m5.5 12.5 4 4 9-9"/>'}</svg>`;
  if (options.named) confirm.querySelector("span")!.textContent = capLabel(options.confirmLabel);
  if (options.named && options.secondary) {
    const alt = document.createElement("button");
    alt.type = "button";
    alt.className = "ui-confirm-alt";
    alt.textContent = options.secondary.label;
    tip.dataset.stack = "";
    alt.addEventListener("click", () => { instance.close(false); options.secondary!.onSelect(); });
    actions.append(alt);
  }
  actions.append(cancel, confirm);
  tip.append(arrow, text, actions);
  document.body.append(tip);

  anchor.setAttribute("aria-expanded", "true");
  anchor.setAttribute("aria-controls", tip.id);
  tip.hidden = false;

  let closing = false;
  let controller: ConfirmTipController | undefined;
  const place = (): void => {
    if (tip.hidden) return;
    const bound = options.boundary?.getBoundingClientRect();
    if (centred) {
      // Centred in the boundary (or the viewport); `data-side="center"` hides the tail.
      tip.style.maxWidth = `${Math.max(160, Math.floor((bound ? bound.width : innerWidth) - 18))}px`;
      const w = tip.offsetWidth, h = tip.offsetHeight;
      tip.style.left = `${Math.max(9, (bound ? bound.left + bound.width / 2 : innerWidth / 2) - w / 2)}px`;
      tip.style.top = `${Math.max(9, (bound ? bound.top + bound.height / 2 : innerHeight / 2) - h / 2)}px`;
      tip.style.transformOrigin = "50% 50%";
      tip.dataset.side = "center";
      return;
    }
    const anchorRect = anchor.getBoundingClientRect();
    // A narrow card (a phone window) is narrower than the tip's own cap: the tip never outgrows its 9 px insets.
    if (bound) tip.style.maxWidth = `${Math.max(160, Math.floor(bound.width - 18))}px`;
    // Layout size: the open animation scales the tip, and a scaled rect would misplace it.
    const width = tip.offsetWidth;
    const height = tip.offsetHeight;
    const minX = bound ? bound.left + 9 : 12, maxX = (bound ? bound.right - 9 : innerWidth - 12) - width;
    const minY = bound ? bound.top + 9 : 12, maxY = (bound ? bound.bottom - 9 : innerHeight - 12) - height;
    const left = Math.max(minX, Math.min(maxX, anchorRect.left + anchorRect.width / 2 - width / 2));
    const below = (bound ? bound.bottom : innerHeight) - anchorRect.bottom;
    const side = below >= height + 18 || below >= anchorRect.top - (bound?.top ?? 0) ? "bottom" : "top";
    const top = Math.max(minY, Math.min(Math.max(minY, maxY), side === "bottom" ? anchorRect.bottom + 8 : anchorRect.top - height - 8));
    tip.style.left = `${left}px`;
    tip.style.top = `${top}px`;
    const tail = Math.max(16, Math.min(width - 16, anchorRect.left + anchorRect.width / 2 - left));
    tip.style.setProperty("--ui-confirm-tail", `${tail}px`);
    // Grow from the tail, so the popover visibly comes out of its trigger.
    tip.style.transformOrigin = `${tail}px ${side === "bottom" ? "0%" : "100%"}`;
    tip.dataset.side = side;
  };
  const onKeyDown = (event: KeyboardEvent): void => {
    if (event.key !== "Escape") return;
    event.preventDefault();
    controller?.close(true);
    options.onCancel?.();
  };
  const onOutside = (event: PointerEvent): void => {
    if (event.target instanceof Node && (tip.contains(event.target) || anchor.contains(event.target))) return;
    controller?.close(false);
    options.onCancel?.();
  };
  const cleanup = (): void => {
    document.removeEventListener("keydown", onKeyDown, true);
    document.removeEventListener("pointerdown", onOutside, true);
    window.removeEventListener("resize", place);
    window.removeEventListener("scroll", place, true);
  };
  const instance: ConfirmTipController = {
    close(restoreFocus = true) {
      if (closing) return;
      closing = true;
      cleanup();
      anchor.setAttribute("aria-expanded", "false");
      anchor.removeAttribute("aria-controls");
      tip.dataset.open = "false";
      if (restoreFocus && anchor.isConnected) anchor.focus({ preventScroll: true });
      if (activeConfirmTip === controller) activeConfirmTip = undefined;
      window.setTimeout(() => { tip.remove(); }, 190);
    },
  };
  controller = instance;
  activeConfirmTip = instance;

  cancel.addEventListener("click", () => { instance.close(true); options.onCancel?.(); });
  confirm.addEventListener("click", () => { instance.close(false); options.onConfirm(); });
  document.addEventListener("keydown", onKeyDown, true);
  document.addEventListener("pointerdown", onOutside, true);
  window.addEventListener("resize", place);
  window.addEventListener("scroll", place, true);
  place();
  requestAnimationFrame(() => {
    if (closing || !tip.isConnected) return;
    tip.dataset.open = "true";
    cancel.focus({ preventScroll: true });
  });
  return instance;
}

/** Puts the tooltip and confirmation styles on the page; a surface that borrows the confirmation's buttons (`.ui-confirm-bar`) calls it before it opens. */
export function installTooltipStyles(): void { buildStyleOnly(); }

function buildStyleOnly(): void {
  if (document.getElementById("ui-tooltip-style")) return;
  const style = document.createElement("style");
  style.id = "ui-tooltip-style";
  style.textContent = STYLE;
  document.head.appendChild(style);
}

function labelOf(el: HTMLElement): string {
  if (pointAnchor === el) return pointLabel;
  return el.dataset.tip || el.getAttribute("aria-label") || "";
}

/** The tooltip trigger for an event target, or null. */
function triggerOf(target: EventTarget | null): HTMLElement | null {
  if (!(target instanceof Element)) return null;
  const el = target.closest<HTMLElement>("[data-tip], button[aria-label], a[aria-label]");
  if (!el || el.closest("[data-tip-off]")) return null;
  if (el.dataset.tip) return el;
  // Icon-only: no text of its own (SVG titles do not count). textContent, not innerText: a row whose text is
  // momentarily not rendered (a hidden span, an animating list) still has a name of its own, so its aria-label is
  // never shown as a tooltip.
  const text = [...el.childNodes].some((n) => n.nodeType === 3 ? n.textContent!.trim() : n instanceof HTMLElement && !(n instanceof SVGElement) && n.textContent?.trim());
  return text ? null : el;
}

/**
 * The side the surface opens on: the one asked for (a point call's option, `data-tip-side`) or above by default, flipped
 * to the other side when the first does not fit in the viewport and the other does.
 */
function sideOf(el: HTMLElement, r: DOMRect, h: number): Side {
  const want = (pointAnchor === el ? pointOptions?.side : undefined) ?? (el.dataset.tipSide as Side | undefined) ?? "top";
  const fitsTop = r.top - GAP - h >= MARGIN, fitsBottom = r.bottom + GAP + h <= innerHeight - MARGIN;
  if (want === "top") return fitsTop || !fitsBottom ? "top" : "bottom";
  return fitsBottom || !fitsTop ? "bottom" : "top";
}

/**
 * Places the surface for `el`; returns the travel direction (−1 left, 1 right).
 *
 * The size is never computed from constants: a hidden copy of the surface (same CSS, so the real padding, border, font
 * and cap) is given the label and read back, and the visible surface gets exactly that width. A tooltip therefore fits
 * its text at every root font size and wraps at its cap instead of cutting the text off (an earlier `+ 22` pixel
 * allowance went stale when the padding became rem-based and the UI scale 110 %, and every label lost its last letters
 * to an ellipsis).
 */
function place(el: HTMLElement, animateMove: boolean): number {
  const text = labelOf(el);
  const twoLines = pointAnchor === el && pointOptions?.lines === 2;
  if (twoLines) { pos.dataset.tipLines = "2"; measure.dataset.tipLines = "2"; }
  else { delete pos.dataset.tipLines; delete measure.dataset.tipLines; }
  measureSurface.firstElementChild!.textContent = text;
  const measured = measureSurface.getBoundingClientRect();
  // The width is rounded up so sub-pixel text never wraps; the height is exact, so the arrow sits on the real edge.
  const w = Math.ceil(measured.width), h = measured.height;
  const r = pointAnchor === el && pointRect ? pointRect : el.getBoundingClientRect();
  const side = sideOf(el, r, h);
  const cx = r.left + r.width / 2;
  const x = Math.max(MARGIN, Math.min(cx - w / 2, innerWidth - MARGIN - w));
  const y = Math.max(MARGIN, Math.min(side === "top" ? r.top - GAP - h : r.bottom + GAP, innerHeight - MARGIN - h));
  const prev = new DOMMatrix(getComputedStyle(pos).transform).m41;
  pos.style.transition = animateMove && !reduced() ? `transform ${TRAVEL}ms ${EASE}` : "none";
  pos.style.transform = `translate(${x}px, ${y}px)`;
  surface.style.width = `${w}px`;
  // The arrow follows the anchor, but never leaves the surface when a shift moved the surface off-centre.
  const tail = Math.max(12, Math.min(w - 12, cx - x));
  arrow.style.transition = pos.style.transition;
  arrow.style.top = side === "top" ? `calc(${h}px - 0.25rem)` : "-0.25rem";
  arrow.style.transform = `translateX(${tail}px) rotate(45deg)`;
  surface.style.transformOrigin = `${tail}px ${side === "top" ? "100%" : "0%"}`;
  pos.dataset.side = side;
  return x >= prev ? 1 : -1;
}

function setLabel(text: string, dir: number) {
  const old = surface.querySelector<HTMLElement>(".tip-label:not(.is-leaving)")!;
  if (old.textContent === text) return;
  if (dir === 0 || reduced() || !shown) { old.textContent = text; return; }
  // Slide: the old label leaves against the travel, the new one arrives with it.
  old.classList.add("is-leaving");
  old.animate([{ opacity: 1, transform: "none" }, { opacity: 0, transform: `translateX(${-dir * SHIFT}px)` }], { duration: SWAP, easing: EASE, fill: "forwards" }).onfinish = () => old.remove();
  const next = document.createElement("span");
  next.className = "tip-label";
  next.textContent = text;
  surface.appendChild(next);
  next.animate([{ opacity: 0, transform: `translateX(${dir * SHIFT}px)` }, { opacity: 1, transform: "none" }], { duration: SWAP, easing: EASE });
}

function show(el: HTMLElement, how: "pop" | "instant", pointCall = false) {
  if (!pos) build();
  clearTimeout(closeTimer); clearTimeout(openTimer);
  // Point labels belong to one trigger; a later normal tooltip must not inherit the previous target or position.
  if (pointAnchor && (pointAnchor !== el || !pointCall)) clearPointAnchor();
  const travelling = shown && current !== el;
  current = el;
  const dir = place(el, travelling);
  setLabel(labelOf(el), travelling ? dir : 0);
  pos.getAnimations().forEach((a) => a.cancel());
  pos.style.visibility = "visible";
  if (!shown && how === "pop") {
    const from = reduced() ? { opacity: 0 } : { opacity: 0, transform: "scale(0.94)" };
    const to = reduced() ? { opacity: 1 } : { opacity: 1, transform: "scale(1)" };
    surface.animate([from, to], { duration: POP, easing: EASE });
    arrow.animate([{ opacity: 0 }, { opacity: 1 }], { duration: POP, easing: EASE });
  }
  shown = true;
  watch();
}

function hide(instant = false) {
  clearTimeout(openTimer); clearTimeout(closeTimer);
  if (!shown) {
    if (current === pointAnchor) clearPointAnchor();
    current = null;
    return;
  }
  shown = false;
  if (current === pointAnchor) clearPointAnchor();
  current = null;
  warmUntil = performance.now() + WARM;
  if (instant) { pos.style.visibility = "hidden"; return; }
  pos.animate([{ opacity: 1 }, { opacity: 0 }], { duration: OUT, easing: EASE }).onfinish = () => { if (!shown) pos.style.visibility = "hidden"; };
}

const warm = () => shown || performance.now() < warmUntil;

/** Takes the tooltip down if it is the one open on `el` (a state that explained itself has ended). */
export function dismissTip(el: HTMLElement): void { if (shown && current === el) hide(); }

/** Hides any tooltip at once (a view change, a flight, a page that lost focus). */
export function hideTips(): void { hide(true); }

/** How the open tooltip was asked for: a hover tip lives only while its element is connected and hovered. */
let byHover = false;
let watchdog = 0;
function watch(): void {
  window.clearInterval(watchdog);
  watchdog = window.setInterval(() => {
    if (!shown || !current) { window.clearInterval(watchdog); return; }
    if (!current.isConnected || (byHover && !current.matches(":hover"))) hide(true);
  }, 200);
}

/**
 * Re-reads the label of `el` if its tooltip is open (for live labels like "Copied"). With `animate`, a label that
 * changes while the tooltip stays (a button that turns into another while Option is held) glides: the surface eases to
 * its new width and the words slide, instead of snapping.
 */
export function refreshTip(el: HTMLElement, animate = false) {
  if (!(shown && current === el)) return;
  if (!animate || reduced()) { place(el, false); setLabel(labelOf(el), 0); return; }
  const dir = place(el, true);
  surface.style.transition = `width ${TRAVEL}ms ${EASE}`;
  window.setTimeout(() => { surface.style.transition = ""; }, TRAVEL + 40);
  setLabel(labelOf(el), dir);
}

/**
 * Shows a short confirmation ("Copied") on `el` for `duration` ms, then restores its normal
 * tooltip label. The same surface and pop as every tooltip, so confirmations look like the
 * rest of the product. A repeated call keeps the original label to restore, not the previous
 * confirmation.
 */
export function flashTip(el: HTMLElement, text: string, duration = 900): void {
  const pending = temporaryTips.get(el);
  if (pending) clearTimeout(pending.timer);
  const normalTip = pending ? pending.previous : el.dataset.tip;
  el.dataset.tip = text;
  byHover = false;
  show(el, shown ? "instant" : "pop");
  const timer = window.setTimeout(() => {
    const active = temporaryTips.get(el);
    if (!active || active.timer !== timer) return;
    if (current === el) hide();
    if (normalTip === undefined) delete el.dataset.tip;
    else el.dataset.tip = normalTip;
    temporaryTips.delete(el);
  }, Math.max(0, duration));
  temporaryTips.set(el, { previous: normalTip, timer });
}

/**
 * Peeks the tooltip of `el` for `duration` ms without a hover (a tap on a mark whose tap does nothing
 * else). A live label that changes while it is up is followed (refreshTip), and a newer tooltip is
 * never closed by it.
 */
export function peekTip(el: HTMLElement, duration = 2600): void {
  byHover = false;
  show(el, shown ? "instant" : "pop");
  const mine = current;
  window.clearTimeout(closeTimer);
  closeTimer = window.setTimeout(() => { if (shown && current === mine) hide(); }, duration);
}

/** Shows the shared warm tooltip at a pointer position while it remains over `anchor`. */
export function hoverTipAt(anchor: HTMLElement, text: string, x: number, y: number, options: PointTooltipOptions = {}): void {
  pointAnchor = anchor;
  pointLabel = text;
  pointRect = new DOMRect(x, y, 0, 0);
  pointOptions = options;
  if (warm()) {
    byHover = true;
    show(anchor, "instant", true);
  } else {
    clearTimeout(openTimer);
    current = anchor;
    openTimer = window.setTimeout(() => {
      if (current !== anchor || !anchor.matches(":hover")) return;
      byHover = true;
      show(anchor, "pop", true);
    }, DELAY);
  }
}

/** Shows a shared tooltip at a pointer position for a short touch or click confirmation. */
export function peekTipAt(anchor: HTMLElement, text: string, x: number, y: number, duration = 2600, options: PointTooltipOptions = {}): void {
  pointAnchor = anchor;
  pointLabel = text;
  pointRect = new DOMRect(x, y, 0, 0);
  pointOptions = options;
  byHover = false;
  show(anchor, shown ? "instant" : "pop", true);
  const mine = current;
  window.clearTimeout(closeTimer);
  closeTimer = window.setTimeout(() => { if (shown && current === mine) hide(); }, duration);
}

/** Closes the point-anchored tooltip only when the specified trigger owns it. */
export function hideTipAt(anchor: HTMLElement): void {
  if (current !== anchor && pointAnchor === anchor) clearPointAnchor();
  if (current !== anchor) return;
  hide(true);
}

function clearPointAnchor(): void {
  pointAnchor = null;
  pointLabel = "";
  pointRect = undefined;
  pointOptions = undefined;
  if (pos) delete pos.dataset.tipLines;
  if (measure) delete measure.dataset.tipLines;
}

/** Installs the page-wide tooltip group. Call once; works for elements added later. */
export function installTooltips() {
  const fine = () => matchMedia("(hover: hover) and (pointer: fine)").matches;
  document.addEventListener("pointerover", (e) => {
    if (e.pointerType === "touch" || !fine()) return;
    const el = triggerOf(e.target);
    if (!el) return;
    if (el === current) { clearTimeout(closeTimer); return; }
    const open = (how: "pop" | "instant"): void => { if (el.isConnected && el.matches(":hover")) { byHover = true; show(el, how); } };
    if (warm()) open("instant");
    else { clearTimeout(openTimer); openTimer = window.setTimeout(() => open("pop"), DELAY); current = el; }
  });
  document.addEventListener("pointerout", (e) => {
    if (e.pointerType === "touch") return;
    const el = triggerOf(e.target);
    if (!el || el.contains(e.relatedTarget as Node)) return;
    if (!shown) { clearTimeout(openTimer); current = null; return; }
    clearTimeout(closeTimer);
    closeTimer = window.setTimeout(() => hide(), GRACE);
  });
  // Keyboard: at once, no motion (no animation for keyboard actions).
  document.addEventListener("focusin", (e) => {
    const el = triggerOf(e.target);
    // Only real Tab navigation shows a tooltip on focus; programmatic focus stays quiet.
    if (el && document.documentElement.dataset.focusRing === "on" && (e.target as HTMLElement).matches(":focus-visible")) { byHover = false; show(el, "instant"); }
  });
  document.addEventListener("focusout", (e) => { if (triggerOf(e.target) === current) hide(true); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") hide(true); });
  // A click answers the question the tooltip asked: hide it (it would cover the result).
  document.addEventListener("pointerdown", (e) => {
    if (e.pointerType !== "touch") { if (current && e.target instanceof Node && current.contains(e.target)) hide(true); return; }
    const el = triggerOf(e.target);
    if (!el) return;
    press0 = { x: e.clientX, y: e.clientY };
    clearTimeout(pressTimer);
    pressTimer = window.setTimeout(() => { swallowClick = true; byHover = false; show(el, "pop"); }, LONG_PRESS);
  }, true);
  document.addEventListener("pointermove", (e) => {
    if (press0 && Math.hypot(e.clientX - press0.x, e.clientY - press0.y) > SLOP) { clearTimeout(pressTimer); press0 = null; }
  }, true);
  const release = () => { clearTimeout(pressTimer); press0 = null; if (shown && swallowClick) closeTimer = window.setTimeout(() => hide(), 900); };
  document.addEventListener("pointerup", release, true);
  document.addEventListener("pointercancel", release, true);
  document.addEventListener("click", (e) => { if (swallowClick) { swallowClick = false; e.preventDefault(); e.stopPropagation(); } }, true);
  document.addEventListener("contextmenu", (e) => { if (triggerOf(e.target)) e.preventDefault(); });
  // Scrolling moves the trigger: follow it (no animation). Hide only if it left the screen.
  addEventListener("scroll", () => {
    if (!shown || !current) return;
    const r = current.getBoundingClientRect();
    if (r.bottom < 0 || r.top > innerHeight) hide(true); else place(current, false);
  }, true);
  addEventListener("resize", () => hide(true));
  addEventListener("blur", () => hide(true));
}
