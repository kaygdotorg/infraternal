// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The inside of Settings -> Appearance -> Themes (D322, #323): the strip of theme cards on top, and under it the
 * controls that edit the selected theme, in the owner's order (D338, round 4): UI size, Colour, Backgrounds, Windows (Tint, Blur, Grain), Fonts, plus a
 * name for a theme the person made. "Themes" is called Colour here (singular, UK spelling, D338). The background is Solid or Gradient (round 2: Plain became Solid,
 * Soft went, Mesh became Gradient): the choices on offer are the selected Colour's own (`gradients.ts`), and the person can make their own.
 *
 * Everything is the product's own: the strip is `packages/ui/src/theme-strip.ts`, the sliders are the UI size slider, and the
 * Fonts list is the option list the Settings windows share (`choiceBlock`), so its rows, ticks and subtitles are the ones the owner
 * already knows; the Colour list uses the same row (hover, tick column, edges) with the circles of D338. Only the wiring to the theme
 * store is new. The strip scrolls away with the pane (a solid band
 * stuck to the top of a translucent window would look wrong in exactly the themes this shows), and a change far down it needs no
 * strip to be seen: the Fonts and Colour lists restyle the window they are in as they change.
 *
 * Loaded on demand, from the Themes window only.
 */
import { FONTS, fontById } from "../../../../../packages/ui/src/fonts";
import { createThemeStrip, type ThemeCard, type ThemeHalf } from "../../../../../packages/ui/src/theme-strip";
import { createCapsuleTabs } from "../../../../../packages/ui/src/capsule-tabs";
import { createSlider, type Slider } from "../../../../../packages/ui/src/slider";
import { choiceBlock, heading, paintChoice } from "../../../../../packages/ui/src/settings-panels";
import { ICONS } from "../../../../../packages/ui/src/icons";
import { TICK_PATH } from "../../../../../packages/ui/src/tick";
import { THEMES, type Theme } from "../../../../../packages/ui/src/themes";
import { UI_SIZE } from "../../../../../packages/ui/src/ui-scale";
import { el } from "../dom";
import { themeStore } from "./controller";
import { grainImage } from "./grain";
import { FAMILIES, familyOf, versionIn } from "./colors";
import { backgroundCss, CUSTOM_ID, customGradient, DEFAULT_GRADIENT, gradientsFor, isSolid, MAX_STOPS, MIN_STOPS, SOLID_CUSTOM_ID, solidsFor } from "./gradients";

/** Terminal text behind every card's material: dense and plain, so a blur that is too weak shows at once. */
const BEHIND = [
  "git log --oneline -12 | head",
  "3fa4460 tracer, ui: dots sit on the",
  "cdddcb4 tracer: Mesh grants are ed",
  "cargo test -p infraternal --release",
  "running 48 tests; vt::wide_cells ok",
  "Oct  8 16:02:11 build-01 sshd[2113]",
  "kernel: nf_conntrack: table full",
  "  PID USER      PR  NI    VIRT   RES",
  " 2113 kayg      20   0  912340 88112",
  " 2114 kayg      20   0  411208 20456",
];

/** A scheme's four colours and its three palette dots (the accent, a red and a blue of the theme's own ANSI colours). */
function halfOf(theme: Theme): ThemeHalf {
  return { bg: theme.bg, fg: theme.fg, fg2: theme.fg2, accent: theme.accent, dots: [theme.accent, theme.ansi[1], theme.ansi[4]] };
}

/** Fills `pane` with the Themes window and returns the way to take it down again. It edits the page's one store (`themeStore`). */
export function renderThemeEditor(pane: HTMLElement): () => void {
  // The page follows the selected theme from the moment the screen mounts (`startThemes`), not only while this window exists: a window
  // that is scrolled out of the grid is taken down, and the look must stay.
  const store = themeStore();
  if (!store) { pane.append(el("p", "cl-settings-later", "Themes are not available on this screen.")); return () => undefined; }
  const disposers: Array<() => void> = [];

  // ---- the strip ---------------------------------------------------------------------------------------
  const top = el("div", "cl-theme-top");
  const strip = createThemeStrip({
    label: "Themes",
    behind: BEHIND,
    addTip: (selected) => (selected ? `New theme from ${selected.name}` : "New theme"),
    onSelect: (id) => store.select(id),
    onReset: (id) => store.reset(id),
    onAdd: () => {
      const made = store.add();
      // The new card is brought into view by the strip alone; the name field takes the cursor on a desktop. On a phone the field
      // would bring up the keyboard over the card just made (TASTE: the keyboard opens only for a real text field the person chose).
      requestAnimationFrame(() => {
        strip.reveal(made.id, true);
        if (matchMedia("(pointer: fine)").matches) { nameInput.focus({ preventScroll: true }); nameInput.select(); }
      });
    },
  });
  top.append(strip.root);
  pane.append(top);

  // ---- the controls under it ---------------------------------------------------------------------------
  const root = el("div", "ui-sp");
  root.dataset.ticks = "";
  const section = (title: string, ...nodes: Node[]): HTMLElement => { const s = el("section"); s.append(heading(title), ...nodes); return s; };

  // A theme the person made has a name they can change; a built-in theme's name is fixed, so its row is closed (a height glide).
  const nameInput = el("input", "ui-setting-input cl-theme-name-input");
  nameInput.type = "text";
  nameInput.maxLength = 24;
  nameInput.setAttribute("aria-label", "Theme name");
  nameInput.autocomplete = "off";
  nameInput.spellcheck = false;
  nameInput.addEventListener("input", () => { if (nameInput.value.trim()) store.edit({ name: nameInput.value.trim() }); });
  nameInput.addEventListener("blur", () => { nameInput.value = store.selected().name; });
  const nameRow = el("div", "cl-theme-name");
  const nameInner = el("div");
  nameInner.append(section("Name", nameInput));
  nameRow.append(nameInner);

  const tint = createSlider({ label: "Tint", min: 0, max: 100, step: 1, value: store.selected().tint, format: (v) => `${v}%`, onInput: (v) => store.edit({ tint: v }) });
  const blur = createSlider({ label: "Blur", min: 0, max: 100, step: 1, value: store.selected().blur, format: (v) => `${v}%`, onInput: (v) => store.edit({ blur: v }) });
  const grain = createSlider({ label: "Grain", min: 0, max: 100, step: 1, value: store.selected().grain, format: (n) => `${n}%`, onInput: (n) => store.edit({ grain: n }) });
  const size = createSlider({ label: "UI size", min: UI_SIZE.min, max: UI_SIZE.max, step: UI_SIZE.step, value: store.selected().uiSize, format: (v) => `${v}%`, onInput: (v) => store.edit({ uiSize: v }) });
  const sliders: Slider[] = [tint, blur, grain, size];
  disposers.push(() => { for (const s of sliders) s.dispose(); });

  // Fonts: the product's option list.
  const font = choiceBlock("Fonts", FONTS.map((f) => ({ id: f.id, label: f.label, hint: f.hint })), "font", () => store.selected().font, (id) => store.edit({ font: id }));

  // Colour: a row for each scheme, the name in one column and the circles in another. A circle is a version of the scheme (its background
  // with its accent), the light one first and the dark one second; a click on either chooses that version, which is how a person gets
  // to light or dark (D338). A scheme with one version has one circle, in the column of the version it has, so the circles of one kind
  // stay in one column down the list. A click on a name picks the version in the mode the person is in. The product's own row
  // (`ui-sp-row`: hover, tick column, edges) with its own two columns; the circles are buttons with a name, so the shared warm tooltip
  // tells which is which.
  const colour = el("section");
  colour.dataset.kind = "colour";
  colour.append(heading("Colour"));
  const colourList = el("div", "ui-sp-list");
  colourList.setAttribute("role", "radiogroup");
  colourList.setAttribute("aria-label", "Colour");
  const dots = new Map<string, HTMLButtonElement>(), rowOf = new Map<string, HTMLElement>();
  for (const f of FAMILIES) {
    const row = el("div", "ui-sp-row cl-colour-row");
    row.dataset.id = f.id;
    // The text sits in a label exactly one line tall, and the circles in a cell of the same height (`1lh`), so the two are centred together
    // by construction (TASTE: an icon and its text share one centre line), and the button around the label keeps the whole row as its target.
    const name = el("button", "cl-colour-name");
    name.type = "button";
    name.append(el("span", "cl-colour-label", f.name));
    name.addEventListener("click", () => store.edit({ colors: versionIn(f, THEMES[store.selected().colors]?.dark ?? true) }));
    const modes = el("span", "cl-colour-modes");
    for (const mode of ["light", "dark"] as const) {
      const id = f[mode];
      if (!id) { modes.append(el("span", "cl-colour-slot")); continue; }
      const t = THEMES[id]!;
      const dot = el("button", "cl-colour-dot");
      dot.type = "button";
      dot.setAttribute("role", "radio");
      dot.setAttribute("aria-label", f.light && f.dark ? `${f.name}, ${mode}` : f.name);
      dot.dataset.id = id;
      dot.dataset.mode = mode;
      dot.style.cssText = `--c-bg:${t.bg};--c-accent:${t.accent}`;
      dot.addEventListener("click", () => store.edit({ colors: id }));
      dots.set(id, dot);
      modes.append(dot);
    }
    const tick = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    tick.setAttribute("class", "ui-sp-tick");
    tick.setAttribute("viewBox", "0 0 24 24");
    tick.setAttribute("aria-hidden", "true");
    tick.innerHTML = `<path d="${TICK_PATH}"/>`;
    row.append(name, modes, tick);
    rowOf.set(f.id, row);
    colourList.append(row);
  }
  colour.append(colourList);

  // ---- the background: Solid or Gradient, each with the Colour's own choices and the person's own ----------------------------
  // A choice stays chosen when the person flips to the other kind and back: each tab remembers its own.
  const kindOf = (b: string): "solid" | "gradient" => (isSolid(b) ? "solid" : "gradient");
  let lastSolid = isSolid(store.selected().background) ? store.selected().background : "solid";
  let lastGradient = isSolid(store.selected().background) ? DEFAULT_GRADIENT : store.selected().background;
  const tabs = createCapsuleTabs([{ id: "solid", label: "Solid" }, { id: "gradient", label: "Gradient" }], kindOf(store.selected().background),
    (id) => store.edit({ background: id === "solid" ? lastSolid : lastGradient }), "Background");
  disposers.push(() => tabs.dispose());
  // A swatch is a picture and a name for assistive technology and the shared warm tooltip: no text on it. Custom is marked by a dashed
  // ring and a small pen, so the person can tell which one is theirs.
  const PEN = '<svg class="cl-bg-pen" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20l1-4L16.5 4.5a2 2 0 0 1 3 3L8 19zM14 7l3 3"/></svg>';
  const swatches = new Map<string, HTMLButtonElement>();
  const gallery = (label: string, items: Array<{ id: string; name: string; custom?: boolean }>, remember: (id: string) => void): HTMLElement => {
    const g = el("div", "cl-bg-gallery");
    g.setAttribute("role", "radiogroup");
    g.setAttribute("aria-label", label);
    for (const item of items) {
      const b = el("button", "cl-bg-swatch");
      b.type = "button";
      b.setAttribute("role", "radio");
      b.setAttribute("aria-label", item.name);
      b.dataset.id = item.id;
      if (item.custom) b.dataset.custom = "";
      b.innerHTML = `<span class="cl-bg-preview" aria-hidden="true">${item.custom ? PEN : ""}</span>`;
      b.addEventListener("click", () => { remember(item.id); store.edit({ background: item.id }); });
      swatches.set(item.id, b);
      g.append(b);
    }
    return g;
  };
  const glide = (inner: HTMLElement): HTMLElement => { const outer = el("div", "cl-glide"); const box = el("div"); box.append(inner); outer.append(box); return outer; };
  const solidGallery = gallery("Solid", [...solidsFor(THEMES.mocha!).map((x) => ({ id: x.id, name: x.name })), { id: SOLID_CUSTOM_ID, name: "Custom", custom: true }], (id) => { lastSolid = id; });
  const gradientGallery = gallery("Gradient", [...gradientsFor(THEMES.mocha!).map((x) => ({ id: x.id, name: x.name })), { id: CUSTOM_ID, name: "Custom", custom: true }], (id) => { lastGradient = id; });
  // Your own solid: one colour. Your own gradient: up to four colours and an angle. Native colour fields (a real picker on every platform).
  const solidInput = el("input", "cl-bg-stop");
  solidInput.type = "color";
  solidInput.setAttribute("aria-label", "Solid colour");
  solidInput.addEventListener("input", () => store.edit({ customSolid: solidInput.value }));
  const solidBox = el("div", "cl-bg-custom");
  solidBox.append(solidInput);
  const stopsRow = el("div", "cl-bg-stops");
  const angle = createSlider({ label: "Gradient angle", min: 0, max: 360, step: 5, value: store.selected().custom.angle, format: (v) => `${v}°`, onInput: (v) => store.edit({ custom: { ...store.selected().custom, angle: v } }) });
  disposers.push(() => angle.dispose());
  const customBox = el("div", "cl-bg-custom");
  customBox.append(stopsRow, angle.root);
  const solidCustomGlide = glide(solidBox), customGlide = glide(customBox);
  const solidBlock = el("div", "cl-bg-block"), gradientBlock = el("div", "cl-bg-block");
  solidBlock.append(solidGallery, solidCustomGlide);
  gradientBlock.append(gradientGallery, customGlide);
  let stopsDrawn = -1;
  const drawStops = (list: string[]): void => {
    stopsRow.replaceChildren();
    list.forEach((hex, i) => {
      const input = el("input", "cl-bg-stop");
      input.type = "color";
      input.value = hex;
      input.setAttribute("aria-label", `Gradient colour ${i + 1}`);
      input.addEventListener("input", () => { const c = store.selected().custom; store.edit({ custom: { ...c, stops: c.stops.map((x, j) => (j === i ? input.value : x)) } }); });
      stopsRow.append(input);
    });
    const act = (label: string, icon: string, on: () => void, disabled: boolean): void => {
      const b = el("button", "ui-window-action cl-bg-act");
      b.type = "button";
      b.setAttribute("aria-label", label);
      b.disabled = disabled;
      b.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${icon}</svg>`;
      b.addEventListener("click", on);
      stopsRow.append(b);
    };
    const c = (): typeof list => store.selected().custom.stops;
    act("Add a colour", ICONS.plus, () => { const s = c(); store.edit({ custom: { ...store.selected().custom, stops: [...s, s[s.length - 1]!] } }); }, list.length >= MAX_STOPS);
    act("Remove the last colour", '<path d="M5 12h14"/>', () => { store.edit({ custom: { ...store.selected().custom, stops: c().slice(0, -1) } }); }, list.length <= MIN_STOPS);
    stopsDrawn = list.length;
  };
  // Tint, Blur and Grain sit under one heading, "Windows" (owner, round 4): they are what the windows are made of. Stacked in a narrow window, three columns in a
  // wide one (D338); each slider is under its own label. The window decides, from its own width (a container query on this wrapper in `clusters.css`), never the
  // viewport: a wide screen with a narrow window stays stacked.
  const field = (label: string, slider: Slider): HTMLElement => { const f = el("div", "cl-field"); f.append(el("span", "cl-field-label", label), slider.root); return f; };
  const triple = el("div", "cl-triple");
  const tripleGrid = el("div", "cl-triple-grid");
  tripleGrid.append(field("Tint", tint), field("Blur", blur), field("Grain", grain));
  triple.append(tripleGrid);
  root.append(section("UI size", size.root), colour, section("Backgrounds", tabs.root, solidBlock, gradientBlock), section("Windows", triple), font);
  // The name row sits between the strip and the controls and is outside the controls' grid, so closed it leaves no gap behind.
  pane.append(nameRow, root);

  // ---- one paint for every change ---------------------------------------------------------------------
  const cards = (): ThemeCard[] => store.themes().map((p) => {
    const theme = THEMES[p.colors] ?? THEMES.mocha!;
    const face = fontById(p.font) ?? FONTS[0]!;
    return {
      id: p.id, name: p.name, tint: p.tint, blur: p.blur, grainImage: grainImage(p.grain), fontFamily: face.family, fontWeight: face.bodyWeight, uiSize: p.uiSize,
      description: `${face.label}, ${theme.name}, ${p.background === "solid" ? "solid background" : p.background === SOLID_CUSTOM_ID ? "your own solid colour" : isSolid(p.background) ? `${p.background.slice(6)} solid` : p.background === CUSTOM_ID ? "your own gradient" : `${p.background} gradient`}, UI size ${p.uiSize}%`,
      colors: halfOf(theme), background: backgroundCss(p.background, p.custom, theme, p.customSolid), resettable: store.changed(p.id),
    };
  });
  let shown = "";
  const paint = (): void => {
    const now = store.selected();
    strip.update(cards(), now.id);
    tint.set(now.tint);
    blur.set(now.blur);
    grain.set(now.grain);
    size.set(now.uiSize);
    paintChoice(font, now.font);
    const here = familyOf(now.colors).id;
    for (const [id, row] of rowOf) { row.toggleAttribute("data-current", id === here); row.setAttribute("aria-checked", String(id === here)); }
    for (const [id, dot] of dots) dot.setAttribute("aria-checked", String(id === now.colors));
    // Background: the tabs, the Colour's own solids and gradients drawn in the selected Colour, the custom ones, and the person's colours.
    const theme = THEMES[now.colors] ?? THEMES.mocha!;
    const kind = kindOf(now.background);
    if (kind === "solid") lastSolid = now.background; else lastGradient = now.background;
    tabs.select(kind, true);
    solidBlock.hidden = kind !== "solid";
    gradientBlock.hidden = kind !== "gradient";
    solidCustomGlide.toggleAttribute("data-open", now.background === SOLID_CUSTOM_ID);
    solidCustomGlide.firstElementChild!.toggleAttribute("inert", now.background !== SOLID_CUSTOM_ID);
    customGlide.toggleAttribute("data-open", now.background === CUSTOM_ID);
    customGlide.firstElementChild!.toggleAttribute("inert", now.background !== CUSTOM_ID);
    const paintSwatch = (id: string, css: string): void => { swatches.get(id)!.querySelector<HTMLElement>(".cl-bg-preview")!.style.background = css; };
    for (const x of solidsFor(theme)) paintSwatch(x.id, x.colour || theme.bg);
    paintSwatch(SOLID_CUSTOM_ID, now.customSolid);
    for (const g of gradientsFor(theme)) paintSwatch(g.id, g.css);
    paintSwatch(CUSTOM_ID, customGradient(now.custom));
    for (const [id, b] of swatches) b.setAttribute("aria-checked", String(id === now.background));
    if (document.activeElement !== solidInput) solidInput.value = now.customSolid;
    if (stopsDrawn !== now.custom.stops.length) drawStops(now.custom.stops);
    else stopsRow.querySelectorAll<HTMLInputElement>(".cl-bg-stop").forEach((input, i) => { if (document.activeElement !== input) input.value = now.custom.stops[i]!; });
    angle.set(now.custom.angle);
    const custom = !store.isBuiltIn(now.id);
    nameRow.toggleAttribute("data-open", custom);
    nameInner.toggleAttribute("inert", !custom);
    // The field follows the theme unless the person is typing in it.
    if (document.activeElement !== nameInput) nameInput.value = now.name;
    // A card chosen by key or tap, or made just now, is brought fully into view (the strip scrolls, nothing else).
    if (shown !== now.id) { strip.reveal(now.id, shown !== ""); shown = now.id; }
  };
  paint();
  disposers.push(store.onChange(paint));
  // The first paint happens before the strip has a width; reveal the selected card once it has one.
  requestAnimationFrame(() => strip.reveal(store.selectedId()));

  return () => { for (const d of disposers) d(); strip.dispose(); top.remove(); nameRow.remove(); root.remove(); };
}
