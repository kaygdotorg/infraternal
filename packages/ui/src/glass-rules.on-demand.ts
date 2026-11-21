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
import { CARD_LEVELS, activeGlass, GLASS_ADAPT_VARS, TINT_USERS, THEMES, glassTint, levelName, levelOpacity, mix, type Theme } from "./themes";
import { ADAPT_LIMIT, ANY_BACKDROP, MAX_DRIFT, MAX_SHIFT, hexToRgb, luminanceOf, solveGlass, type BackdropRange, type GlassFills, type GlassRole, type GlassSolution } from "./glass-contrast";

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
 * a bright colour (inverse video, a full-screen pager) the approved thin levels cannot hold 4.5:1 and the card turns solid. Raising it to 30% raises 8 of 30 theme and level pairs, 50% raises 16 and puts Clear on
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
 * The answer for a backdrop that was *seen* (a sampled picture or the cells of a terminal), as opposed to the theme's own
 * palette. It varies opacity only up to {@link ADAPT_LIMIT}, and keeps the fill within {@link MAX_DRIFT} of the tint's own
 * lightness; when the line cannot be held inside that (a light card over a black picture, a dark one over white) the
 * answer is the theme's solid card ({@link GlassSolution.solid}), never a flat grey slab and never a glow behind the text.
 */
export function glassSeen(active: Theme, level: number, range: BackdropRange, nominal = nominalOpacity(active, level)): GlassSolution {
  return solveGlass(hexToRgb(glassTint(active)), nominal, active.dark, glassRoles(active), { range, fills: glassFills(active), maxAlpha: ADAPT_LIMIT, maxDrift: MAX_DRIFT });
}

/**
 * The static floor for `level` of `active`: holds over any backdrop from pure black to pure white, for a picture the
 * theme knows nothing about. Text moves at most {@link MAX_SHIFT} so its tiers stay apart and the tint raises
 * instead, up to {@link ADAPT_LIMIT}, and the tint's lightness stays within {@link MAX_DRIFT} of its own over either
 * extreme. Where that cannot hold the line (a light theme over black, a dark one over white) the answer is the solid card.
 */
export function glassFloor(active: Theme, level: number, nominal = nominalOpacity(active, level)): GlassSolution {
  return solveGlass(hexToRgb(glassTint(active)), nominal, active.dark, glassRoles(active), { range: ANY_BACKDROP, fills: glassFills(active), maxShift: MAX_SHIFT, maxAlpha: ADAPT_LIMIT, maxDrift: MAX_DRIFT });
}

/** Solved answers for the rules, by kind, theme, level and starting opacity. A theme's answer never changes, so a switch back is a lookup. */
const solutions = new Map<string, GlassSolution>();
function memo(kind: string, active: Theme, level: number, solve: () => GlassSolution): GlassSolution {
  // The starting opacity is in the key because a look's tint moves it (see `nominalOpacity`).
  const key = `${kind}|${active.name}|${level}|${nominalOpacity(active, level)}`;
  let hit = solutions.get(key);
  if (!hit) {
    if (solutions.size > 512) solutions.clear();
    hit = solve();
    solutions.set(key, hit);
  }
  return hit;
}

/**
 * Solves the answers for the other themes at the level in force, one theme per idle slice, so a later theme switch finds them
 * in the memo and its click does no contrast arithmetic (#567). Nothing waits on this: a theme that is not ready yet is solved
 * in the switch itself, as before. Started once; the rest of the page's work always goes first.
 */
let warming = false;
function warmThemes(level: number): void {
  if (warming || typeof requestIdleCallback === "undefined") return;
  warming = true;
  const queue = Object.values(THEMES);
  const step = (deadline: IdleDeadline): void => {
    while (queue.length && deadline.timeRemaining() > 1.5) {
      const next = queue.shift()!;
      memo("themed", next, level, () => glassFor(next, level));
      memo("floor", next, level, () => glassFloor(next, level));
    }
    if (queue.length) requestIdleCallback(step);
  };
  requestIdleCallback(step);
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
  // A solid answer is the opaque tint with no blur. The blur is switched by the surface's `data-glass-answer` (written by the
  // trackers in `glass-adapt.on-demand.ts`), not by a custom property: a glass answer must leave the card's own blur alone
  // (the palette sets its own), which a property that the floor defaults to 0 could not do.
  const write = (sol: GlassSolution, level: number, fallback?: GlassSolution): string => {
    const own = `--overlay: ${fallback ? `var(${GLASS_ADAPT_VARS.overlay}, rgb(${tint} / ${sol.alpha}))` : `rgb(${tint} / ${sol.alpha})`};`;
    const blurRule = !fallback && sol.solid ? " --ui-overlay-blur: 0px;" : "";
    return own + blurRule + Object.entries(GLASS_ROLE_VARS).map(([role, name]) => `${name}: ${fallback ? `var(${GLASS_ADAPT_VARS.role(role)}, ${sol.colours[role]})` : sol.colours[role]};`).join("");
  };
  const css: string[] = [];
  // Only the level in force is solved and written. `applyTheme` is the one writer of `data-card` and always asks for these rules in
  // the same task, so no other level can be on the root, and a theme switch solves one level, not eight (the eight cost about 2 ms
  // of the click, #567). Each answer is memoised, so returning to a theme costs nothing. The rules are on the root before the
  // browser paints, so there is no frame in which a card shows the previous theme's text colours: the cut is not deferred.
  for (const level of [String(cardLevel)]) {
    const name = levelName(Number(level)).toLowerCase();
    const themed = memo("themed", active, Number(level), () => glassFor(active, Number(level)));
    css.push(`:where(:root[data-card="${name}"]) :where(${TINT_USERS}) { ${write(themed, Number(level))} }`);
    // A themed card that cannot hold the line is the solid card; it has to beat a look's fill rule, so it is written at the floor's specificity.
    if (themed.solid) css.push(`:root[data-card="${name}"] :is(${TINT_USERS}) { ${write(themed, Number(level))} }`);
    // On the surface itself: `glass-under.on-demand.ts` marks the surface it finds over a picture or a terminal.
    const floor = memo("floor", active, Number(level), () => glassFloor(active, Number(level)));
    css.push(`:root[data-card="${name}"] :is(${TINT_USERS})[data-glass-under] { ${write(floor, Number(level), floor)} }`);
    // Solid means no blur: on the floor until a tracker answers with glass, and whenever a tracker answers solid.
    css.push(`:root[data-card="${name}"] :is(${TINT_USERS})${floor.solid ? '[data-glass-under]:not([data-glass-answer="glass"])' : '[data-glass-answer="solid"]'} { --ui-overlay-blur: 0px; }`);
  }
  if (!glassSheet) {
    glassSheet = new CSSStyleSheet();
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, glassSheet];
    followLook();
  }
  glassSheet.replaceSync(css.join("\n"));
  warmThemes(cardLevel);
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
