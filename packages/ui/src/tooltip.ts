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

const STYLE = `
.tip-pos { position: fixed; left: 0; top: 0; z-index: 1000; pointer-events: none; will-change: transform; }
.tip { position: relative; box-sizing: border-box; padding: 6px 10px; border-radius: 8px; white-space: nowrap; overflow: hidden;
  font: 500 12.5px/1.2 var(--font-ui, "Geist Mono", ui-monospace, monospace); letter-spacing: 0;
  background: var(--tip-bg, var(--fg, #f4f4f5)); color: var(--tip-fg, var(--bg, #0a0a0a));
  box-shadow: 0 6px 20px -6px rgb(0 0 0 / 0.45); }
.tip-label { display: block; }
.tip-label.is-leaving { position: absolute; left: 10px; top: 6px; }
.tip-arrow { position: absolute; left: 0; width: 8px; height: 8px; margin-left: -4px; transform-origin: center;
  background: var(--tip-bg, var(--fg, #f4f4f5)); border-radius: 1.5px; }
.tip-measure { position: fixed; visibility: hidden; white-space: nowrap; pointer-events: none;
  font: 500 12.5px/1.2 var(--font-ui, "Geist Mono", ui-monospace, monospace); }
[data-tip], button[aria-label], a[aria-label] { -webkit-touch-callout: none; }
`;

function build() {
  const style = document.createElement("style");
  style.textContent = STYLE;
  document.head.appendChild(style);
  pos = document.createElement("div");
  pos.className = "tip-pos";
  pos.setAttribute("aria-hidden", "true"); // the trigger's aria-label already names it
  pos.innerHTML = `<div class="tip"><span class="tip-label"></span></div><div class="tip-arrow"></div>`;
  pos.style.visibility = "hidden";
  surface = pos.querySelector(".tip")!;
  arrow = pos.querySelector(".tip-arrow")!;
  measure = document.createElement("span");
  measure.className = "tip-measure";
  document.body.append(pos, measure);
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
    if (el && (e.target as HTMLElement).matches(":focus-visible")) show(el, "instant");
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
