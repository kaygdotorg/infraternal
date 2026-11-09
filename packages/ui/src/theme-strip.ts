// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The theme strip (#323, D322, D341): one row of cards that scrolls sideways, one card for each Appearance theme, then a dotted
 * card with a large plus that adds another. A card is a live picture of its theme, not a name in a list:
 *
 * - the **material**: a window-sized pane at the theme's tint and blur over real terminal text, so what the theme does to
 *   what is behind it is seen, not read;
 * - the **font**: "Aa" set in the theme's font;
 * - the **Colors**: the palette's dots, and the card itself;
 * - the **UI size**: the sample grows and shrinks with it;
 * - the name and "N% tint · N% blur" under the picture.
 *
 * The card shows the theme as it is (owner, D322 round 2: "if dark show dark cards, if light then show light cards in that theme"):
 * in the theme's own Colors, over the background it chose (a gradient, or the scheme's plain colour), with its tint and blur applied.
 *
 * Selecting a card is a radio (arrow keys move and select, Home and End jump; Tab leaves the group). The strip is a plain
 * horizontal scroller: touch, wheel and keys all work natively, `overscroll-behavior-x: contain` stops a swipe at its ends
 * from moving the canvas behind it (D159: one finger inside a window scrolls inside it), and the card after the last visible
 * one peeks in, which is what says there is more. The **reset** button sits on its own card, on a built-in theme that has been
 * changed, and nowhere else.
 *
 * This module only draws. The model (what a theme is, what changed, what a new one copies) belongs to the caller, so the
 * Appearance window and any later place that lists themes share the one component (D160).
 */
import { ICONS } from "./icons";
import { RESET_ICON } from "./setting-row";
import { TICK_PATH } from "./tick";

/** The look of a theme's Colors: the four colours of the card, and the palette dots drawn on it. */
export interface ThemeHalf { bg: string; fg: string; fg2: string; accent: string; dots: string[] }

/** Theme values used to paint one selectable material card. */
export interface ThemeCard {
  id: string;
  name: string;
  /** How much of what is behind shows as the theme's colour: 0 to 100. */
  tint: number;
  /** 0 to 100; 100 is the strongest blur (24 px). */
  blur: number;
  /** The film grain of the theme's windows as a CSS image (a tile of noise), or "none". It is laid on the glass, under the text. */
  grainImage: string;
  /** The theme's font, for the "Aa" sample. */
  fontFamily: string;
  fontWeight: number;
  /** The whole UI's size, as a percentage of the standard (50 to 150). */
  uiSize: number;
  /** The words for assistive technology and the tooltip: font and Colors by name. */
  description: string;
  /** The theme's Colors. */
  colors: ThemeHalf;
  /** The theme's background as a CSS image (`--p-bg-image`), or "" for Solid: the scheme's own colour alone. */
  background: string;
  /** Shown only for a built-in theme that has been changed: a button that puts its defaults back. */
  resettable?: boolean;
}

/** Content and callbacks supplied when creating a strip of theme cards. */
export interface ThemeStripOptions {
  /** The group's accessible name. */
  label: string;
  /** Lines of terminal text drawn behind every card's material. */
  behind: readonly string[];
  /** The name the add card tells (its tooltip names the theme a new one is copied from). */
  addTip(selected: ThemeCard | undefined): string;
  onSelect(id: string): void;
  onAdd(): void;
  onReset(id: string): void;
}

/** Stable strip surface whose cards update in place when slider values change. */
export interface ThemeStrip {
  readonly root: HTMLElement;
  /** Draws the cards. Existing cards are updated in place (a slider drag repaints one card, never rebuilds the strip). */
  update(cards: readonly ThemeCard[], selected: string): void;
  /** Scrolls a card fully into view (only this strip moves, never the pane or the canvas). */
  reveal(id: string, smooth?: boolean): void;
  dispose(): void;
}

/** Creates the small, decorative glyphs used by card controls. */
const SVG = (inner: string): string => `<svg viewBox="0 0 24 24" aria-hidden="true">${inner}</svg>`;
/** The face of a card: the material over the terminal text, and the caption. */
function halfMarkup(behind: readonly string[]): string {
  const lines = behind.map((line) => `<span>${line.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</span>`).join("");
  return `<span class="ui-theme-term" aria-hidden="true">${lines}</span>`
    + `<span class="ui-theme-glass"><span class="ui-theme-aa">Aa</span><span class="ui-theme-prompt">$ ls</span></span>`
    + `<span class="ui-theme-cap"><span class="ui-theme-name"></span><span class="ui-theme-meta"></span><span class="ui-theme-dots"><i></i><i></i><i></i></span></span>`;
}

/** DOM handles and updater for one card retained in the strip. */
interface Drawn { root: HTMLElement; pick: HTMLButtonElement; reset: HTMLButtonElement; paint(card: ThemeCard, selected: boolean): void }

/** Builds one card and wires its selection and reset controls. */
function drawCard(behind: readonly string[], handlers: { select(id: string): void; reset(id: string): void }): Drawn {
  const root = document.createElement("div");
  root.className = "ui-theme";
  const pick = document.createElement("button");
  pick.type = "button";
  pick.className = "ui-theme-pick";
  pick.setAttribute("role", "radio");
  const face = document.createElement("span");
  face.className = "ui-theme-half";
  face.innerHTML = halfMarkup(behind);
  const tick = document.createElement("span");
  tick.className = "ui-theme-tick";
  tick.setAttribute("aria-hidden", "true");
  tick.innerHTML = SVG(`<path d="${TICK_PATH}"/>`);
  pick.append(face);
  const reset = document.createElement("button");
  reset.type = "button";
  reset.className = "ui-theme-reset";
  reset.hidden = true;
  reset.innerHTML = SVG(RESET_ICON);
  // The tick and the reset stand half outside the card, so they are beside the button, which clips its picture to the rounded card.
  root.append(pick, tick, reset);
  let id = "";
  pick.addEventListener("click", () => handlers.select(id));
  reset.addEventListener("click", () => handlers.reset(id));
  return {
    root, pick, reset,
    paint(card, selected) {
      id = card.id;
      root.dataset.id = card.id;
      root.toggleAttribute("data-selected", selected);
      const meta = `${card.tint}% tint · ${card.blur}% blur`;
      pick.setAttribute("aria-checked", String(selected));
      pick.setAttribute("aria-label", `${card.name}, ${meta}, ${card.description}`);
      pick.tabIndex = selected ? 0 : -1;
      root.style.setProperty("--p-tint", String(card.tint));
      root.style.setProperty("--p-blur", String(card.blur));
      root.style.setProperty("--p-grain-img", card.grainImage);
      root.style.setProperty("--p-size", String(card.uiSize / 100));
      root.style.setProperty("--p-font", `"${card.fontFamily}", ui-monospace, monospace`);
      root.style.setProperty("--p-weight", String(card.fontWeight));
      const colors = card.colors;
      face.style.setProperty("--p-bg", colors.bg);
      face.style.setProperty("--p-fg", colors.fg);
      face.style.setProperty("--p-fg2", colors.fg2);
      face.style.setProperty("--p-accent", colors.accent);
      face.style.setProperty("--p-bg-image", card.background || "none");
      face.querySelectorAll<HTMLElement>(".ui-theme-dots i").forEach((dot, i) => dot.style.setProperty("--dot", colors.dots[i] ?? colors.accent));
      face.querySelector(".ui-theme-name")!.textContent = card.name;
      face.querySelector(".ui-theme-meta")!.textContent = meta;
      reset.hidden = !card.resettable;
      reset.setAttribute("aria-label", `Reset ${card.name}`);
      reset.dataset.tip = `Reset ${card.name}`;
    },
  };
}

/** Creates an accessible, in-place-updatable row of theme cards. */
export function createThemeStrip(options: ThemeStripOptions): ThemeStrip {
  const root = document.createElement("div");
  root.className = "ui-theme-strip";
  root.setAttribute("role", "radiogroup");
  root.setAttribute("aria-label", options.label);
  const add = document.createElement("button");
  add.type = "button";
  add.className = "ui-theme-add";
  add.setAttribute("aria-label", "Add a theme");
  add.innerHTML = SVG(ICONS.plus);
  root.append(add);

  const drawn = new Map<string, Drawn>();
  let order: readonly ThemeCard[] = [];
  let current = "";
  const handlers = { select: (id: string) => options.onSelect(id), reset: (id: string) => options.onReset(id) };
  add.addEventListener("click", () => options.onAdd());

  // Until the person scrolls, selects or types here, the strip keeps showing the selected card as the window's size settles: a
  // window is narrower for the first frames of its flight into view, and a card revealed then must not stay scrolled past once it
  // has its width. After any gesture the person's own scroll position is left alone.
  let touched = false;
  for (const type of ["pointerdown", "touchstart", "wheel", "keydown"]) root.addEventListener(type, () => { touched = true; }, { passive: true, capture: true });
  const settle = new ResizeObserver(() => { if (!touched && current) { root.scrollLeft = 0; reveal(current); } });
  settle.observe(root);

  // The edges fade only while there is more to scroll that way: `data-fade` on the strip says which (the same attribute as the
  // vertical scroll fade of `scroll-fade.ts`, which this does not touch: it is imported by deferred code with 369 B of room, D188).
  // One attribute write per change of state, from a passive scroll listener, at most once a frame.
  let fadeFrame = 0;
  const fade = (): void => {
    fadeFrame = 0;
    const left = root.scrollLeft > 1, right = root.scrollLeft + root.clientWidth < root.scrollWidth - 1;
    const next = [left ? "left" : "", right ? "right" : ""].filter(Boolean).join(" ");
    if (next) { if (root.dataset.fade !== next) root.dataset.fade = next; } else if (root.dataset.fade !== undefined) delete root.dataset.fade;
  };
  const scheduleFade = (): void => { if (!fadeFrame) fadeFrame = requestAnimationFrame(fade); };
  root.addEventListener("scroll", scheduleFade, { passive: true });
  const fadeObserver = new ResizeObserver(scheduleFade);
  fadeObserver.observe(root);

  const reveal = (id: string, smooth = false): void => {
    const card = drawn.get(id)?.root;
    // A strip that has no width yet (its window is not laid out) has nothing to scroll to: a first call there would scroll a whole card.
    if (!card || root.clientWidth === 0) return;
    // Scroll the strip itself: `scrollIntoView` would also scroll the pane, the window's column and the camera. Offsets, not
    // rects: a rect carries the canvas camera's zoom, which scrollLeft does not, and the strip would overshoot by the zoom.
    // A card that is cut off lands at its snap position (its start, on the strip's padding), so the strip's own scroll snapping
    // and this agree and the card is never nudged to a place the snapping then moves it from.
    const room = parseFloat(getComputedStyle(root).scrollPaddingInlineStart) || 0;
    const left = card.offsetLeft - room - root.scrollLeft;
    const right = card.offsetLeft + card.offsetWidth + room - (root.scrollLeft + root.clientWidth);
    if (left < 0 || right > 0) root.scrollTo({ left: card.offsetLeft - room, behavior: smooth ? "smooth" : "instant" });
  };

  // The wheel: a sideways swipe over the strip scrolls the strip while it can, and the canvas gets it at the strip's end. That rule is the
  // canvas's own (`gestures.ts`, D329); nothing here handles the wheel.

  // Arrow keys move the selection (a radio group), Home and End jump; the card that is selected is the one Tab lands on.
  root.addEventListener("keydown", (event) => {
    if (!(event.target as Element).closest(".ui-theme-pick")) return;
    const i = order.findIndex((card) => card.id === current);
    const to = event.key === "ArrowRight" || event.key === "ArrowDown" ? i + 1 : event.key === "ArrowLeft" || event.key === "ArrowUp" ? i - 1 : event.key === "Home" ? 0 : event.key === "End" ? order.length - 1 : -1;
    if (to < 0) return;
    event.preventDefault();
    const next = order[Math.max(0, Math.min(order.length - 1, to))];
    if (!next || next.id === current) return;
    options.onSelect(next.id);
    drawn.get(next.id)?.pick.focus({ preventScroll: true });
    reveal(next.id);
  });

  return {
    root,
    update(cards, selected) {
      order = cards;
      current = selected;
      const keep = new Set(cards.map((card) => card.id));
      for (const [id, item] of drawn) if (!keep.has(id)) { item.root.remove(); drawn.delete(id); }
      cards.forEach((card, index) => {
        let item = drawn.get(card.id);
        if (!item) { item = drawCard(options.behind, handlers); drawn.set(card.id, item); }
        item.paint(card, card.id === selected);
        // Keep the order without touching a card that is already in place (a focused button must not lose focus).
        if (root.children[index] !== item.root) root.insertBefore(item.root, root.children[index] ?? add);
      });
      const chosen = cards.find((card) => card.id === selected);
      add.dataset.tip = options.addTip(chosen);
      scheduleFade();
    },
    reveal,
    dispose() { settle.disconnect(); fadeObserver.disconnect(); if (fadeFrame) cancelAnimationFrame(fadeFrame); root.remove(); drawn.clear(); },
  };
}
