/**
 * The categorical colours of named things (tags, groups): one curated palette per colour scheme, defined once as theme
 * tokens (`--ui-ent-0` ... `--ui-ent-11` and `--ui-ent-text`, set on every `.ui-entity` chip and every `.ui-entity-card` (a card that carries a tag's colour) by `entityPaletteCss`, see
 * themes.ts) so a tag has the same colour in every window, dialog and list, in every theme.
 *
 * Contrast is a guarantee, not a hope. Each scheme has ONE chip text colour (near-black on the pale dark-scheme fills,
 * white on the deeper light-scheme fills) and every fill is nudged in lightness until it clears 4.5:1 against that text.
 * A gradient chip (a host across its tags, a user across their groups) only ever blends palette fills, and a blend
 * of two colours that each clear 4.5:1 against the same text clears it too, so the worst case is the worst single stop.
 * `entityTextFor` picks the better of the two text colours for a colour a person chose themselves.
 */
import { contrastRatio, oklabToHex } from "./color";

/** How many colours the palette has; {@link entityColorIndex} returns 0 to this number minus one. */
export const ENTITY_COLORS = 12;
/** Chip text on the pale fills of the dark scheme. */
const DARK_TEXT = "#17171a";
/** Chip text on the deeper fills of the light scheme. */
const LIGHT_TEXT = "#ffffff";
/** The WCAG AA contrast ratio for normal text; every fill must reach it against its scheme's text colour. */
const MIN_CONTRAST = 4.5;

/** An OKLCH colour (lightness, chroma, hue in degrees) as hex. */
const oklch = (l: number, c: number, hueDegrees: number): string => {
  const h = (hueDegrees * Math.PI) / 180;
  return oklabToHex([l, c * Math.cos(h), c * Math.sin(h)]);
};

/** The palette of one scheme: twelve hues, a fixed chroma, lightness moved only as far as the contrast needs. */
export function entityPalette(dark: boolean): { fills: string[]; text: string } {
  const text = dark ? DARK_TEXT : LIGHT_TEXT;
  const fills: string[] = [];
  for (let i = 0; i < ENTITY_COLORS; i++) {
    const hue = (i * 30 + 12) % 360;
    let l = dark ? 0.8 : 0.5, fill = oklch(l, dark ? 0.1 : 0.15, hue);
    for (let guard = 0; guard < 40 && contrastRatio(fill, text) < MIN_CONTRAST; guard++) {
      l += dark ? 0.01 : -0.01;
      fill = oklch(l, dark ? 0.1 : 0.15, hue);
    }
    fills.push(fill);
  }
  return { fills, text };
}

/** Stable palette index for a name (FNV-1a), so the same tag always gets the same colour. */
export function entityColorIndex(name: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < name.length; i++) { h ^= name.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return (h >>> 0) % ENTITY_COLORS;
}

/** The better text colour for a chosen hex fill. */
export const entityTextFor = (hex: string): string => (contrastRatio(hex, DARK_TEXT) >= contrastRatio(hex, LIGHT_TEXT) ? DARK_TEXT : LIGHT_TEXT);

/** CSS declaring the tokens for both schemes on every chip, and on every card that wears a tag's colour. */
export function entityPaletteCss(): string[] {
  return ([["dark", true], ["light", false]] as const).map(([scheme, dark]) => {
    const p = entityPalette(dark);
    return `:root[data-scheme="${scheme}"] .ui-entity, :root[data-scheme="${scheme}"] .ui-entity-card { ${p.fills.map((f, i) => `--ui-ent-${i}: ${f};`).join(" ")} --ui-ent-text: ${p.text}; }`;
  });
}
