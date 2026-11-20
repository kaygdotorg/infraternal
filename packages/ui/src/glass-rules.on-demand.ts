// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The glass contrast rules (D365) and the solutions they are made of, for the active theme, level and look.
 *
 * This is an on-demand chunk (D188): it holds everything that needs the contrast solver (`glass-contrast.ts`), so the critical
 * path of the app carries none of that arithmetic. `themes.ts` requests it, through `glass-adapt.on-demand.ts` (which imports it and re-exports `installGlassRules`), from the first
 * `applyTheme` (the start of boot, in parallel with the first paint). The rules and the adaptive trackers ask the solver the same
 * question the same way, and they travel as one chunk.
 *
 * What the solver starts from. The level's own opacity when no look is active. When a look is active (D322, D338: the person's
 * theme sets the floating cards' fill through `--look-tint` on the root, Tinted 75% for instance), the look's tint is the starting
 * point, and the opacity is raised above it only where 4.5:1 cannot otherwise be reached (D365 wins only where it is needed). The
 * text colours are solved against that same fill, so the rules and the look can never disagree about what a card is painted with.
 */
import { CARD_LEVELS, activeGlass, GLASS_ADAPT_VARS, TINT_USERS, glassTint, levelName, levelOpacity, mix, type Theme } from "./themes";
import { ANY_BACKDROP, MAX_DRIFT, MAX_SHIFT, hexToRgb, luminanceOf, solveGlass, type BackdropRange, type GlassFills, type GlassRole, type GlassSolution } from "./glass-contrast";

/**
 * The fill opacity a glass card starts from: the active look's tint (0 to 1) when the root carries a look, else `undefined`.
 * Read from the root's own `--look-tint`, which `applyLook` writes, so nothing has to be told when a look changes.
 */
export function lookTint(): number | undefined {
  if (typeof document === "undefined") return undefined;
  const root = document.documentElement;
  if (!root.hasAttribute("data-look")) return undefined;
  const tint = parseFloat(root.style.getPropertyValue("--look-tint"));
  return tint >= 0 && tint <= 1 ? tint : undefined;
}

/** Where the solver starts for `level` of `active`: the look's tint when one is active, else the level's own opacity. */
export const nominalOpacity = (active: Theme, level: number): number => lookTint() ?? levelOpacity(active, level);

/**
 * How much of a glass card's area a single block of one of the terminal's own colours is assumed to cover, at most (20%).
 * A card blurs what is behind it, so a block shows as its average: a status line, a few highlighted rows or a progress
 * bar are a small share of a popover. This is a bound chosen on measured trade-offs, not a law: over a whole card of
 * a bright colour (inverse video, a full-screen pager) the approved thin levels cannot hold 4.5:1 and the glass's own
 * text halo carries what it can. Raising it to 30% raises 8 of 30 theme and level pairs, 50% raises 16 and puts Clear on
 * Frosted's opacity on ink, mocha, rosepine, nord and dracula (the sweep is in the audit's note and on #448). The audit
 * (`glass-contrast.test.ts`) holds every theme and level over every one of its 18 terminal colours up to this bound.
 */
export const THEMED_COVERAGE = 0.2;

/**
 * What a theme's own surfaces can have behind a glass card: the page colour at one end and, at the other, the page colour
 * mixed `coverage` of the way toward the most extreme colour the terminal can paint a block in (the theme's eight ANSI
 * colours, their bright forms, its text colour and its background). A programme can fill a block with any of them, so the
 * range is bounded by the theme's own palette and nothing outside it. A remote window's picture is not in it.
 */
export function themedBackdrop(active: Theme, coverage = THEMED_COVERAGE): BackdropRange {
  // Ordered by the luminance of what the card actually shows (the block's colour averaged with the page at `coverage`), which is not
  // always the block's own order: a saturated red and a grey of equal luminance mix differently with the page colour.
  const shown = [active.bg, ...[active.fg, ...active.ansi, ...active.bright].map((colour) => mix(active.bg, colour, coverage))]
    .sort((x, y) => luminanceOf(hexToRgb(x)) - luminanceOf(hexToRgb(y)));
  return { dark: hexToRgb(shown[0]!), light: hexToRgb(shown[shown.length - 1]!) };
}

/** CSS custom property each glass text role is written to. `secondary` is the quieter label colour (`--ui-text-secondary`). */
export const GLASS_ROLE_VARS = {
  fg: "--fg", fg2: "--fg-2", fg3: "--fg-3", secondary: "--ui-glass-secondary",
  accent: "--accent", ok: "--ok", danger: "--danger", warn: "--warn",
} as const;

/** Every text colour a theme puts on glass, by role (see {@link GLASS_ROLE_VARS}). */
export const glassRoles = (active: Theme): GlassRole[] => Object.entries({
  fg: active.fg, fg2: active.fg2, fg3: active.fg3, secondary: mix(active.fg, active.bg, 0.2),
  accent: active.accent, ok: active.ok, danger: active.ansi[1], warn: active.ansi[3],
}).map(([role, colour]) => ({ role, colour }));

/**
 * The fill states a glass surface paints under its labels, taken from the stylesheet's own tokens and rounded up by two
 * points for compositing: hovered (`--hover`, the text colour at 6%), a chip or a hovered chip (the text colour at 9%),
 * selected (`--accent-soft`, the accent at 16%) and a selected row that is also hovered. Nothing in the stylesheet fills
 * a control on press (the press is a scale), so there is no pressed fill to model.
 */
export function glassFills(active: Theme): GlassFills {
  const text = hexToRgb(active.fg), accent = hexToRgb(active.accent);
  const hover = { rgb: text, alpha: 0.08 }, chip = { rgb: text, alpha: 0.11 }, selected = { rgb: accent, alpha: 0.18 };
  return [[hover], [chip], [selected], [selected, hover]];
}

/**
 * The themed set for `level` of `active`: the level's approved opacity, kept, with each text role moved in lightness as
 * far as it must to reach 4.5:1 over the theme's own backdrop ({@link themedBackdrop}) in every fill state. Opacity is
 * raised only for a theme and level where no text colour can reach the line at the approved value (`raised`).
 */
export function glassFor(active: Theme, level: number, range: BackdropRange = themedBackdrop(active), nominal = nominalOpacity(active, level)): GlassSolution {
  return solveGlass(hexToRgb(glassTint(active)), nominal, active.dark, glassRoles(active), { range, fills: glassFills(active) });
}

/**
 * The static floor for `level` of `active`: holds over any backdrop from pure black to pure white, for a picture the
 * theme knows nothing about. Text moves at most {@link MAX_SHIFT} so its tiers stay apart and the tint raises
 * instead, and the tint's lightness stays within {@link MAX_DRIFT} of its own over either extreme (so a light theme over
 * a dark picture is a pale card, not a grey slab).
 */
export function glassFloor(active: Theme, level: number, nominal = nominalOpacity(active, level)): GlassSolution {
  return solveGlass(hexToRgb(glassTint(active)), nominal, active.dark, glassRoles(active), { range: ANY_BACKDROP, fills: glassFills(active), maxShift: MAX_SHIFT, maxDrift: MAX_DRIFT });
}

/** The one adopted sheet that holds the glass contrast rules; created on first use and rewritten when its inputs change. */
let glassSheet: CSSStyleSheet | undefined;
/** What the sheet was last written for (theme, level and the look's tint, as text), so asking again for the same costs nothing. */
let glassSheetKey = "";
/** The look tint part of {@link glassSheetKey}, as text; empty when no look was active. */
let glassSheetLook = "";

/**
 * Writes the contrast layer of the glass material (D365) for the theme, level and look that are active now.
 *
 * Two sets per level: the *themed* set ({@link glassFor}), which holds over the theme's own palette, keeps the starting
 * opacity and solves the text colours, and the *static floor* ({@link glassFloor}), which holds over anything from pure black to
 * pure white. The themed set applies everywhere. A glass surface that `glass-under.on-demand.ts` finds over a picture or a terminal carries
 * `data-glass-under` on itself and takes the floor; a sampler may refine that by writing {@link GLASS_ADAPT_VARS} on the same
 * surface, and it takes those values instead. Each set writes the glass tint's opacity and the colour of every text role on the
 * glass surface itself (and so on its children), leaving the page's own tokens alone. Specificity of the themed set is zero, like
 * the level rules in `themes.ts`; the floor's is the same as a look's fill rule and comes later, which is right because the
 * floor was solved from that look's own tint.
 *
 * Called by every `applyTheme`; rewrites only when the theme, level or look tint changed, and follows the look by itself
 * (the first call starts one observer on the root), because a look is applied after the theme and moves with a slider.
 */
export function installGlassRules(): void {
  if (typeof CSSStyleSheet === "undefined") return;
  const { theme: active, level: cardLevel } = activeGlass();
  const look = `${lookTint() ?? ""}`;
  const key = `${active.name}|${cardLevel}|${look}`;
  if (key === glassSheetKey) return;
  glassSheetKey = key;
  glassSheetLook = look;
  const tint = hexToRgb(glassTint(active)).join(" ");
  const write = (sol: GlassSolution, fallback?: GlassSolution): string => {
    const own = `--overlay: ${fallback ? `var(${GLASS_ADAPT_VARS.overlay}, rgb(${tint} / ${sol.alpha}))` : `rgb(${tint} / ${sol.alpha})`};`;
    return own + Object.entries(GLASS_ROLE_VARS).map(([role, name]) => `${name}: ${fallback ? `var(${GLASS_ADAPT_VARS.role(role)}, ${sol.colours[role]})` : sol.colours[role]};`).join("");
  };
  const css: string[] = [];
  // Without a look every level is written (a level can be chosen by `data-card` alone). With a look the product pins the card level, so
  // only that one is solved: a tint slider moves this on every frame, and eight solves cost about 3 ms where two cost under 1 ms.
  for (const level of look ? [String(cardLevel)] : Object.keys(CARD_LEVELS)) {
    const name = levelName(Number(level)).toLowerCase();
    css.push(`:where(:root[data-card="${name}"]) :where(${TINT_USERS}) { ${write(glassFor(active, Number(level)))} }`);
    // On the surface itself: `glass-under.on-demand.ts` marks the surface it finds over a picture or a terminal.
    const floor = glassFloor(active, Number(level));
    css.push(`:root[data-card="${name}"] :is(${TINT_USERS})[data-glass-under] { ${write(floor, floor)} }`);
  }
  if (!glassSheet) {
    glassSheet = new CSSStyleSheet();
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, glassSheet];
    followLook();
  }
  glassSheet.replaceSync(css.join("\n"));
  document.documentElement.setAttribute("data-glass-rules", "");
}

/** Whether {@link followLook} has started. */
let following = false;
/**
 * Rewrites the rules when the look's tint changes. Watches only the root's `style` and `data-look` attributes, and each
 * callback is one string comparison until the tint really moved; the rewrite waits for the next frame, so a slider drag solves
 * at most once per frame.
 */
function followLook(): void {
  if (following) return;
  following = true;
  let frame = 0;
  new MutationObserver(() => {
    if (frame || `${lookTint() ?? ""}` === glassSheetLook) return;
    frame = requestAnimationFrame(() => { frame = 0; installGlassRules(); });
  }).observe(document.documentElement, { attributes: true, attributeFilter: ["style", "data-look"] });
}
