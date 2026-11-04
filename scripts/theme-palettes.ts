// SPDX-License-Identifier: AGPL-3.0-only
/**
 * The published palettes of the colour schemes added by D329 (#323), and the D80 repair of each.
 *
 * Run `bun scripts/theme-palettes.ts` from the repository root. For every scheme it prints (1) the `theme(...)` lines to paste into
 * `packages/ui/src/themes.ts`, with every colour repaired by `repair` (OKLab lightness only: D80), and (2) a log of each colour that
 * changed, as published -> repaired with both ratios. The log is the record D80 asks for; it is kept in docs/design/THEME-AUDIT.md.
 *
 * Each entry holds the colours the upstream project publishes for the scheme (the source and licence are in THIRD_PARTY_NOTICES.md).
 * `bright` hues are the upstream's bright slot where it has one, else the hue moved 0.06 in OKLab lightness away from the background.
 * Black and white of the ANSI tables are not hues (see `theme-audit.ts`); they take the scheme's surface and softest text.
 */
import { auditTheme, cardSurface, contrast, repair } from "../packages/ui/src/theme-audit";
import { hexToOklab, oklabToHex } from "../packages/ui/src/color";
import type { Ansi, Theme } from "../packages/ui/src/themes";
import { gradientColours } from "../apps/tracer/src/canvas/themes/gradients";

interface Published {
  id: string; name: string; dark: boolean; source: string;
  bg: string; fg: string; fg2: string; fg3: string; accent: string;
  /** red, green, yellow, blue, magenta, cyan (published). */
  hues: [string, string, string, string, string, string];
  /** The upstream's own bright slots for the six hues, when it publishes them. */
  bright?: [string, string, string, string, string, string];
  /** ANSI black and white as the upstream publishes them, else derived. */
  black?: string; white?: string;
}

const SCHEMES: Published[] = [
  { id: "solarized-light", name: "Solarized Light", dark: false, source: "Solarized (Ethan Schoonover), base3 background",
    bg: "#fdf6e3", fg: "#586e75", fg2: "#657b83", fg3: "#93a1a1", accent: "#268bd2",
    hues: ["#dc322f", "#859900", "#b58900", "#268bd2", "#d33682", "#2aa198"], black: "#073642", white: "#eee8d5" },
  { id: "solarized-dark", name: "Solarized Dark", dark: true, source: "Solarized (Ethan Schoonover), base03 background",
    bg: "#002b36", fg: "#93a1a1", fg2: "#839496", fg3: "#586e75", accent: "#268bd2",
    hues: ["#dc322f", "#859900", "#b58900", "#268bd2", "#d33682", "#2aa198"], black: "#073642", white: "#eee8d5" },
  { id: "everforest-light", name: "Everforest Light", dark: false, source: "Everforest (sainnhe), light medium",
    bg: "#fdf6e3", fg: "#5c6a72", fg2: "#829181", fg3: "#a6b0a0", accent: "#8da101",
    hues: ["#f85552", "#8da101", "#dfa000", "#3a94c5", "#df69ba", "#35a77c"], black: "#5c6a72", white: "#e6e2cc" },
  { id: "everforest-dark", name: "Everforest Dark", dark: true, source: "Everforest (sainnhe), dark medium",
    bg: "#2d353b", fg: "#d3c6aa", fg2: "#9da9a0", fg3: "#7a8478", accent: "#a7c080",
    hues: ["#e67e80", "#a7c080", "#dbbc7f", "#7fbbb3", "#d699b6", "#83c092"], black: "#475258", white: "#d3c6aa" },
  { id: "kanagawa-lotus", name: "Kanagawa Lotus", dark: false, source: "Kanagawa (rebelot), Lotus",
    bg: "#f2ecbc", fg: "#545464", fg2: "#43436c", fg3: "#8a8980", accent: "#4d699b",
    hues: ["#c84053", "#6f894e", "#77713f", "#4d699b", "#b35b79", "#597b75"], black: "#1f1f28", white: "#c7d7e0" },
  { id: "kanagawa-wave", name: "Kanagawa Wave", dark: true, source: "Kanagawa (rebelot), Wave",
    bg: "#1f1f28", fg: "#dcd7ba", fg2: "#c8c093", fg3: "#727169", accent: "#7e9cd8",
    hues: ["#e46876", "#98bb6c", "#e6c384", "#7e9cd8", "#957fb8", "#7aa89f"], bright: ["#e82424", "#98bb6c", "#e6c384", "#7fb4ca", "#938aa9", "#7aa89f"], black: "#16161d", white: "#c8c093" },
  { id: "ayu-light", name: "Ayu Light", dark: false, source: "Ayu (ayu-theme), light",
    bg: "#fafafa", fg: "#5c6166", fg2: "#787b80", fg3: "#8a9199", accent: "#f2ae49",
    hues: ["#e65050", "#86b300", "#f2ae49", "#399ee6", "#a37acc", "#4cbf99"], black: "#000000", white: "#c7c7c7" },
  { id: "ayu-dark", name: "Ayu Dark", dark: true, source: "Ayu (ayu-theme), dark",
    bg: "#0b0e14", fg: "#bfbdb6", fg2: "#8a9199", fg3: "#565b66", accent: "#e6b450",
    hues: ["#d95757", "#aad94c", "#e6b450", "#59c2ff", "#d2a6ff", "#95e6cb"], black: "#11151c", white: "#c7c7c7" },
  { id: "github-light", name: "GitHub Light", dark: false, source: "GitHub Primer, light",
    bg: "#ffffff", fg: "#1f2328", fg2: "#59636e", fg3: "#818b98", accent: "#0969da",
    hues: ["#cf222e", "#1a7f37", "#9a6700", "#0969da", "#8250df", "#1b7c83"], black: "#24292f", white: "#6e7781" },
  { id: "github-dark", name: "GitHub Dark", dark: true, source: "GitHub Primer, dark",
    bg: "#0d1117", fg: "#e6edf3", fg2: "#9198a1", fg3: "#6e7681", accent: "#4493f8",
    hues: ["#ff7b72", "#3fb950", "#d29922", "#58a6ff", "#bc8cff", "#39c5cf"], bright: ["#ffa198", "#56d364", "#e3b341", "#79c0ff", "#d2a8ff", "#56d4dd"], black: "#484f58", white: "#b1bac4" },
  { id: "flexoki-light", name: "Flexoki Light", dark: false, source: "Flexoki (Steph Ango), light (the 600 steps on paper)",
    bg: "#fffcf0", fg: "#100f0f", fg2: "#6f6e69", fg3: "#b7b5ac", accent: "#205ea6",
    hues: ["#af3029", "#66800b", "#ad8301", "#205ea6", "#a02f6f", "#24837b"], black: "#100f0f", white: "#6f6e69" },
  { id: "flexoki-dark", name: "Flexoki Dark", dark: true, source: "Flexoki (Steph Ango), dark (the 400 steps on black)",
    bg: "#100f0f", fg: "#cecdc3", fg2: "#878580", fg3: "#575653", accent: "#4385be",
    hues: ["#d14d41", "#879a39", "#d0a215", "#4385be", "#ce5d97", "#3aa99f"], black: "#1c1b1a", white: "#cecdc3" },
  { id: "gruvbox-light", name: "Gruvbox Light", dark: false, source: "Gruvbox (morhetz), light medium",
    bg: "#fbf1c7", fg: "#3c3836", fg2: "#665c54", fg3: "#7c6f64", accent: "#b57614",
    hues: ["#9d0006", "#79740e", "#b57614", "#076678", "#8f3f71", "#427b58"], bright: ["#cc241d", "#98971a", "#d79921", "#458588", "#b16286", "#689d6a"], black: "#fbf1c7", white: "#7c6f64" },
  { id: "tokyo-day", name: "Tokyo Night Day", dark: false, source: "Tokyo Night (folke/tokyonight.nvim), day",
    bg: "#e1e2e7", fg: "#3760bf", fg2: "#6172b0", fg3: "#848cb5", accent: "#2e7de9",
    hues: ["#f52a65", "#587539", "#8c6c3e", "#2e7de9", "#9854f1", "#007197"], black: "#b4b5b9", white: "#6172b0" },
  { id: "frappe", name: "Catppuccin Frappé", dark: true, source: "Catppuccin, Frappé",
    bg: "#303446", fg: "#c6d0f5", fg2: "#a5adce", fg3: "#737994", accent: "#ca9ee6",
    hues: ["#e78284", "#a6d189", "#e5c890", "#8caaee", "#f4b8e4", "#81c8be"], black: "#51576d", white: "#b5bfe2" },
  { id: "macchiato", name: "Catppuccin Macchiato", dark: true, source: "Catppuccin, Macchiato",
    bg: "#24273a", fg: "#cad3f5", fg2: "#a5adcb", fg3: "#6e738d", accent: "#c6a0f6",
    hues: ["#ed8796", "#a6da95", "#eed49f", "#8aadf4", "#f5bde6", "#8bd5ca"], black: "#494d64", white: "#b8c0e0" },
  { id: "owl-light", name: "Light Owl", dark: false, source: "Night Owl (Sarah Drasner), Light Owl",
    bg: "#fbfbfb", fg: "#403f53", fg2: "#5d5f77", fg3: "#989fb1", accent: "#4876d6",
    hues: ["#de3d3b", "#08916a", "#daaa01", "#4876d6", "#994cc3", "#0c969b"], black: "#403f53", white: "#d9d9d9" },
  { id: "owl-night", name: "Night Owl", dark: true, source: "Night Owl (Sarah Drasner), Night Owl",
    bg: "#011627", fg: "#d6deeb", fg2: "#a1b0c3", fg3: "#5f7e97", accent: "#82aaff",
    hues: ["#ef5350", "#addb67", "#ecc48d", "#82aaff", "#c792ea", "#7fdbca"], black: "#011627", white: "#ffffff" },
];

/** Moves a colour's OKLab lightness by `delta`, keeping hue and chroma. */
const shifted = (hex: string, delta: number): string => { const [l, a, b] = hexToOklab(hex); return oklabToHex([Math.max(0, Math.min(1, l + delta)), a, b]); };

const log: string[] = [];
const out: string[] = [];
for (const s of SCHEMES) {
  const note = (role: string, from: string, to: string): void => { if (from !== to) log.push(`| ${s.name} | ${role} | ${from} (${contrast(from, s.bg).toFixed(2)}:1) | ${to} (${contrast(to, s.bg).toFixed(2)}:1) |`); };
  const fix = (role: string, colour: string, need: number): string => { const r = repair(colour, s.bg, need); note(role, colour, r); return r; };
  const names = ["red", "green", "yellow", "blue", "magenta", "cyan"];
  const hues = s.hues.map((h, i) => fix(`ansi ${names[i]}`, h, 4.5));
  const brights = s.hues.map((h, i) => fix(`bright ${names[i]}`, s.bright?.[i] ?? shifted(h, s.dark ? 0.06 : -0.06), 4.5));
  const fg = fix("fg", s.fg, 7), fg2 = fix("fg2", s.fg2, 4.5), fg3 = fix("fg3", s.fg3, 3), accent = fix("accent", s.accent, 3);
  // ok is the scheme's green; danger (ansi 1) and warn (ansi 3) are held to 3:1 and the hues are already held to 4.5:1.
  const ok = hues[1]!;
  const black = s.black ?? s.bg, white = s.white ?? s.fg2;
  const ansi = [black, ...hues, white] as Ansi;
  const bright = [s.dark ? fg3 : fg2, ...brights, fg] as Ansi;
  let theme: Theme = { name: s.name, dark: s.dark, bg: s.bg, fg, fg2, fg3, accent, ok, ansi, bright };
  // Text on the floating cards: the card surface is the background lifted toward white, so a dark scheme's text needs a little more.
  const surface = cardSurface(theme);
  const onCards = (role: string, colour: string, need: number): string => { const r = repair(colour, surface, need); if (r !== colour) log.push(`| ${s.name} | ${role} (on cards) | ${colour} (${contrast(colour, surface).toFixed(2)}:1 on the card) | ${r} (${contrast(r, surface).toFixed(2)}:1 on the card) |`); return r; };
  // Text over the backgrounds a theme can paint (every gradient and solid colour of the scheme): primary text keeps 4.5:1 over the strongest of them.
  let fgBack = fg;
  for (const colour of gradientColours(theme)) { const r = repair(fgBack, colour, 4.5); if (r !== fgBack) { log.push(`| ${s.name} | fg (over the background ${colour}) | ${fgBack} (${contrast(fgBack, colour).toFixed(2)}:1) | ${r} (${contrast(r, colour).toFixed(2)}:1) |`); fgBack = r; } }
  const fgCards = onCards("fg", fgBack, 7), fg2Cards = onCards("fg2", fg2, 4.5);
  theme = { ...theme, fg: fgCards, fg2: fg2Cards, bright: [bright[0]!, ...bright.slice(1, 7), fgCards] as Ansi };
  const failures = auditTheme(theme);
  if (failures.length) throw new Error(`${s.id} still fails: ${failures.map((f) => `${f.role} ${f.ratio.toFixed(2)}`).join(", ")}`);
  const q = (v: string): string => JSON.stringify(v);
  out.push(`  // ${s.source}\n  ${s.id.includes("-") ? q(s.id) : s.id}: theme(${q(s.name)}, ${s.dark}, ${q(s.bg)}, ${q(theme.fg)}, ${q(theme.fg2)}, ${q(fg3)}, ${q(accent)}, ${q(ok)},\n    [${ansi.map(q).join(", ")}],\n    [${theme.bright.map(q).join(", ")}]),`);
}
console.log(out.join("\n"));
console.log("\n--- D80 log: published -> repaired (OKLab lightness only) ---");
console.log("| Scheme | Colour | Published (ratio on bg) | Repaired (ratio on bg) |\n|---|---|---|---|");
console.log(log.join("\n"));
