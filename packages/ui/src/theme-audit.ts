// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The contrast audit of D365, as code: every colour scheme must pass it before it may be offered.
 *
 * Primary text `fg` keeps its stricter 7:1 line from D80. Every other text colour reaches at least 4.5:1 against the scheme background;
 * all interface roles (`fg`, `fg2`, `fg3`, accent and status colours) also pass on the floating-card surface. ANSI black and white are
 * included because both slots can be foreground terminal text, just like the six hue slots.
 *
 * A colour that fails is repaired by {@link repair}, which changes only its OKLab lightness (its hue and chroma stay), moving it by the
 * least amount that reaches the ratio. The scheme tables in `themes.ts` hold the repaired values; `scripts/theme-palettes.ts` shows each
 * change next to the published value (the log in docs/design/THEME-AUDIT.md). The unit test `theme-audit.test.ts` runs {@link auditTheme}
 * on every scheme, so a palette that drifts below the line fails the build.
 */
import { hexToOklab, oklabToHex } from "./color";
import { overlayMaterial, type Theme } from "./themes";

/** The relative luminance of a `#rrggbb` colour (WCAG 2). */
export function luminance(hex: string): number {
  const channel = (index: number): number => {
    const v = parseInt(hex.slice(index, index + 2), 16) / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

/** The WCAG contrast ratio of two `#rrggbb` colours, 1 to 21. */
export function contrast(a: string, b: string): number {
  const [hi, lo] = [Math.max(luminance(a), luminance(b)), Math.min(luminance(a), luminance(b))];
  return (hi + 0.05) / (lo + 0.05);
}

/** The colour under floating cards (the palette, popovers, the sidebar) at Solid, the surface the card text sits on. */
export const cardSurface = (theme: Theme): string => overlayMaterial(theme).surface;

/** One colour of a scheme that is below its line: what it is, the colour, the ratio it has and the one it needs. */
export interface AuditFailure { role: string; colour: string; ratio: number; need: number }

/** Names of the eight ANSI slots, all of which can carry terminal foreground text. */
const ANSI_NAMES = ["black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"] as const;

/** Every text colour of a scheme with the ratio D365 asks of it, in the order they are reported. */
export function rolesOf(theme: Theme): Array<{ role: string; colour: string; need: number }> {
  return [
    { role: "fg", colour: theme.fg, need: 7 },
    { role: "fg2", colour: theme.fg2, need: 4.5 },
    { role: "fg3", colour: theme.fg3, need: 4.5 },
    { role: "accent", colour: theme.accent, need: 4.5 },
    { role: "ok", colour: theme.ok, need: 4.5 },
    { role: "danger", colour: theme.ansi[1], need: 4.5 },
    { role: "warn", colour: theme.ansi[3], need: 4.5 },
    ...ANSI_NAMES.flatMap((name, i) => [
      { role: `ansi ${name}`, colour: theme.ansi[i]!, need: 4.5 },
      { role: `bright ${name}`, colour: theme.bright[i]!, need: 4.5 },
    ]),
  ];
}

/** The colours of `theme` that are below D365's lines. Empty means the scheme passes. */
export function auditTheme(theme: Theme): AuditFailure[] {
  const out: AuditFailure[] = [];
  for (const { role, colour, need } of rolesOf(theme)) {
    const ratio = contrast(colour, theme.bg);
    if (ratio < need) out.push({ role, colour, ratio, need });
  }
  const surface = cardSurface(theme);
  for (const [role, colour, need] of [
    ["fg on cards", theme.fg, 7], ["fg2 on cards", theme.fg2, 4.5], ["fg3 on cards", theme.fg3, 4.5],
    ["accent on cards", theme.accent, 4.5], ["ok on cards", theme.ok, 4.5],
    ["danger on cards", theme.ansi[1], 4.5], ["warn on cards", theme.ansi[3], 4.5],
  ] as const) {
    const ratio = contrast(colour, surface);
    if (ratio < need) out.push({ role, colour, ratio, need });
  }
  return out;
}

/**
 * Repairs one colour against `bg`: keeps its OKLab hue and chroma and moves its lightness, away from the background's, by the least
 * amount that reaches `need` (plus a small margin so rounding to eight bits cannot drop it back under). A colour that already passes
 * comes back unchanged. If the colour cannot reach the ratio by lightness alone (it would need to pass black or white), the nearest
 * extreme is returned and the caller's audit reports it.
 */
export function repair(colour: string, bg: string, need: number): string {
  if (contrast(colour, bg) >= need) return colour;
  const [, a, b] = hexToOklab(colour);
  const bgL = hexToOklab(bg)[0];
  const direction = hexToOklab(colour)[0] >= bgL ? 1 : -1;
  let L = hexToOklab(colour)[0];
  for (let step = 0; step < 400; step++) {
    L += direction * 0.0025;
    const next = oklabToHex([Math.max(0, Math.min(1, L)), a, b]);
    if (contrast(next, bg) >= need + 0.02) return next;
    if (L <= 0 || L >= 1) return next;
  }
  return colour;
}
