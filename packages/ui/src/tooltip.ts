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
 * - Components can request a timed confirmation label with showTip(); its temporary
 *   data-tip is restored when the label expires.
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
const reduced = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

let pos: HTMLDivElement, surface: HTMLDivElement, arrow: HTMLDivElement, measure: HTMLSpanElement;
let current: HTMLElement | null = null;
let openTimer = 0, closeTimer = 0, pressTimer = 0, warmUntil = 0, shown = false;
let swallowClick = false, press0: { x: number; y: number } | null = null;
const temporaryTips = new WeakMap<HTMLElement, { previous: string | undefined; timer: number }>();

const STYLE = `
.tip-pos { position: fixed; left: 0; top: 0; z-index: 1000; pointer-events: none; will-change: transform; }
.tip { position: relative; box-sizing: border-box; padding: 6px 10px; border-radius: 8px; white-space: nowrap; overflow: hidden;
  font: 500 13px/1.2 var(--font-ui, "Geist Mono", ui-monospace, monospace); letter-spacing: 0; }
.tip-label { display: block; }
.tip-label.is-leaving { position: absolute; left: 10px; top: 6px; }
.tip-arrow { position: absolute; left: 0; width: 8px; height: 8px; margin-left: -4px; transform-origin: center;
  background: var(--overlay, var(--fg)); border-radius: 1.5px; }
.tip-measure { position: fixed; visibility: hidden; white-space: nowrap; pointer-events: none;
  font: 500 13px/1.2 var(--font-ui, "Geist Mono", ui-monospace, monospace); }
[data-tip], button[aria-label], a[aria-label] { -webkit-touch-callout: none; }
.ui-confirm-tip { position: fixed; z-index: 1001; display: grid; width: max-content; max-width: min(340px, calc(100vw - 24px)); gap: 12px; padding: 14px 14px 12px;
  border-radius: 14px; opacity: 0; transform: scale(0.96); pointer-events: none;
  transition: opacity 150ms ease-out, transform 180ms cubic-bezier(0.23, 1, 0.32, 1); }
.ui-confirm-tip[hidden] { display: none !important; }
.ui-confirm-tip[data-open="true"] { opacity: 1; transform: none; pointer-events: auto; }
.ui-confirm-tip-arrow { position: absolute; left: var(--ui-confirm-tail, 50%); width: 10px; height: 10px; margin-left: -5px; background: inherit;
  border: inherit; border-radius: 2px; transform: rotate(45deg); }
.ui-confirm-tip[data-side="bottom"] .ui-confirm-tip-arrow { top: -5px; border-right: 0; border-bottom: 0; }
.ui-confirm-tip[data-side="top"] .ui-confirm-tip-arrow { bottom: -5px; border-top: 0; border-left: 0; }
.ui-confirm-tip-text { display: grid; gap: 3px; }
.ui-confirm-tip-message { margin: 0; color: var(--fg); font: 500 13px/1.45 var(--font-ui, "Geist Mono", ui-monospace, monospace); letter-spacing: -0.01em; }
.ui-confirm-tip-detail { margin: 0; color: var(--fg-2); font: 450 12px/1.5 var(--font-ui, "Geist Mono", ui-monospace, monospace); letter-spacing: -0.01em; }
.ui-confirm-tip-actions { display: flex; justify-content: flex-end; gap: 6px; }
.ui-confirm-tip button { display: inline-grid; width: 28px; height: 28px; place-items: center; padding: 0; border: 0; border-radius: 999px; background: transparent;
  color: var(--fg-2); cursor: pointer;
  transition: transform 120ms cubic-bezier(0.23, 1, 0.32, 1), background-color 120ms ease, color 120ms ease; }
.ui-confirm-tip button svg { width: 16px; height: 16px; fill: none; stroke: currentColor; stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; }
.ui-confirm-tip button:active { transform: scale(0.97); }
.ui-confirm-tip button:focus { outline: none; }
:root[data-focus-ring="on"] .ui-confirm-tip button:focus-visible { outline: 2px solid color-mix(in oklab, var(--fg) 55%, transparent); outline-offset: 2px; }
@media (hover: hover) and (pointer: fine) { .ui-confirm-tip button:not(.ui-confirm-yes):hover { background: var(--hover); color: var(--fg); } }
.ui-confirm-tip .ui-confirm-yes { background: var(--fg); color: var(--bg); }
.ui-confirm-tip .ui-confirm-yes svg { stroke-width: 2; }
@media (pointer: coarse) {
  .ui-confirm-tip { gap: 14px; padding: 16px; }
  .ui-confirm-tip-message { font-size: 15px; }
  .ui-confirm-tip-detail { font-size: 14px; }
  .ui-confirm-tip button { width: 44px; height: 44px; }
  .ui-confirm-tip button svg { width: 18px; height: 18px; }
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
  measure = document.createElement("span");
  measure.className = "tip-measure";
  document.body.append(pos, measure);
}

export interface ConfirmTipOptions {
  /** Accessible name for the small, trigger-anchored confirmation group. */
  label: string;
  /** The question, at body size. */
  message: string;
  /** One secondary line explaining the consequence. */
  detail?: string;
  confirmLabel: string;
  cancelLabel: string;
  onConfirm(): void;
  onCancel?(): void;
}

export interface ConfirmTipController { close(restoreFocus?: boolean): void }

let activeConfirmTip: ConfirmTipController | undefined;
let confirmTipSerial = 0;

/** Mounts a single reusable, trigger-anchored confirmation for a reversible choice. */
export function mountConfirmTip(anchor: HTMLElement, options: ConfirmTipOptions): ConfirmTipController {
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
  message.textContent = options.message;
  text.append(message);
  if (options.detail) {
    const detail = document.createElement("p");
    detail.className = "ui-confirm-tip-detail";
    detail.textContent = options.detail;
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
  cancel.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m7 7 10 10M17 7 7 17"/></svg>`;
  const confirm = document.createElement("button");
  confirm.type = "button";
  confirm.className = "ui-confirm-yes";
  confirm.setAttribute("aria-label", options.confirmLabel);
  confirm.dataset.tip = options.confirmLabel;
  confirm.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m5.5 12.5 4 4 9-9"/></svg>`;
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
    const anchorRect = anchor.getBoundingClientRect();
    const width = tip.getBoundingClientRect().width;
    const height = tip.getBoundingClientRect().height;
    const left = Math.max(12, Math.min(innerWidth - width - 12, anchorRect.left + anchorRect.width / 2 - width / 2));
    const below = innerHeight - anchorRect.bottom;
    const side = below >= height + 18 || below >= anchorRect.top ? "bottom" : "top";
    const top = side === "bottom" ? anchorRect.bottom + 8 : Math.max(12, anchorRect.top - height - 8);
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

function buildStyleOnly(): void {
  if (document.getElementById("ui-tooltip-style")) return;
  const style = document.createElement("style");
  style.id = "ui-tooltip-style";
  style.textContent = STYLE;
  document.head.appendChild(style);
}

function labelOf(el: HTMLElement): string {
  return el.dataset.tip || el.getAttribute("aria-label") || "";
}

/** The tooltip trigger for an event target, or null. */
function triggerOf(target: EventTarget | null): HTMLElement | null {
  if (!(target instanceof Element)) return null;
  const el = target.closest<HTMLElement>("[data-tip], button[aria-label], a[aria-label]");
  if (!el || el.closest("[data-tip-off]")) return null;
  if (el.dataset.tip) return el;
  // Icon-only: no visible text of its own (SVG titles do not count).
  const text = [...el.childNodes].some((n) => n.nodeType === 3 ? n.textContent!.trim() : n instanceof HTMLElement && !(n instanceof SVGElement) && n.innerText?.trim());
  return text ? null : el;
}

function sideOf(el: HTMLElement, r: DOMRect, h: number): Side {
  const want = el.dataset.tipSide as Side | undefined;
  if (want) return want;
  return r.top - GAP - h < MARGIN ? "bottom" : "top";
}

/** Places the surface for `el`; returns the travel direction (−1 left, 1 right). */
function place(el: HTMLElement, animateMove: boolean): number {
  const text = labelOf(el);
  measure.textContent = text;
  const w = Math.ceil(measure.getBoundingClientRect().width) + 22, h = 27;
  const r = el.getBoundingClientRect();
  const side = sideOf(el, r, h);
  const cx = r.left + r.width / 2;
  const x = Math.min(Math.max(MARGIN, cx - w / 2), innerWidth - MARGIN - w);
  const y = side === "top" ? r.top - GAP - h : r.bottom + GAP;
  const prev = new DOMMatrix(getComputedStyle(pos).transform).m41;
  pos.style.transition = animateMove && !reduced() ? `transform ${TRAVEL}ms ${EASE}` : "none";
  pos.style.transform = `translate(${x}px, ${y}px)`;
  surface.style.width = `${w}px`;
  arrow.style.transition = pos.style.transition;
  arrow.style.top = side === "top" ? `${h - 4}px` : "-4px";
  arrow.style.transform = `translateX(${cx - x}px) rotate(45deg)`;
  surface.style.transformOrigin = `${cx - x}px ${side === "top" ? "100%" : "0%"}`;
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

function show(el: HTMLElement, how: "pop" | "instant") {
  if (!pos) build();
  clearTimeout(closeTimer); clearTimeout(openTimer);
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
}

function hide(instant = false) {
  clearTimeout(openTimer); clearTimeout(closeTimer);
  if (!shown) { current = null; return; }
  shown = false;
  current = null;
  warmUntil = performance.now() + WARM;
  if (instant) { pos.style.visibility = "hidden"; return; }
  pos.animate([{ opacity: 1 }, { opacity: 0 }], { duration: OUT, easing: EASE }).onfinish = () => { if (!shown) pos.style.visibility = "hidden"; };
}

const warm = () => shown || performance.now() < warmUntil;

/** Re-reads the label of `el` if its tooltip is open (for live labels like "Copied"). */
export function refreshTip(el: HTMLElement) {
  if (shown && current === el) { place(el, false); setLabel(labelOf(el), 0); }
}

/** Shows a short confirmation beside a control, then restores its normal tooltip label. */
export function showTip(el: HTMLElement, label: string, duration = 900): void {
  const previous = temporaryTips.get(el);
  if (previous) clearTimeout(previous.timer);
  const normalTip = previous ? previous.previous : el.dataset.tip;
  el.dataset.tip = label;
  show(el, "instant");
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

/** Installs the page-wide tooltip group. Call once; works for elements added later. */
export function installTooltips() {
  const fine = () => matchMedia("(hover: hover) and (pointer: fine)").matches;
  document.addEventListener("pointerover", (e) => {
    if (e.pointerType === "touch" || !fine()) return;
    const el = triggerOf(e.target);
    if (!el) return;
    if (el === current) { clearTimeout(closeTimer); return; }
    if (warm()) show(el, "instant");
    else { clearTimeout(openTimer); openTimer = window.setTimeout(() => show(el, "pop"), DELAY); current = el; }
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
    if (el && document.documentElement.dataset.focusRing !== "off" && (e.target as HTMLElement).matches(":focus-visible")) show(el, "instant");
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
    pressTimer = window.setTimeout(() => { swallowClick = true; show(el, "pop"); }, LONG_PRESS);
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
}
